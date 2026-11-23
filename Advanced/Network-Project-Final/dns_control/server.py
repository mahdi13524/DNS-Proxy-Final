"""Local dashboard and actual DNS UDP listener sharing one resolver and metrics."""
import argparse
import ipaddress
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from collections import deque
from . import config, lists, upstream
from .resolver import Resolver
from .simulator import LocalSimulatorController

ENGINE = Resolver()
ROOT = config.ROOT
ACTIVITY_LOG = ROOT / "log.txt"
SIMULATOR = LocalSimulatorController()


def read_activity(query_string=""):
    """Read the persistent shared console/dashboard log and apply safe filters."""
    params = parse_qs(query_string, keep_blank_values=False)
    domain_filter = params.get("domain", [""])[0].strip().casefold()
    source_filter = params.get("source", [""])[0].strip().upper()
    status_filter = params.get("status", [""])[0].strip().upper()
    try:
        limit = max(1, min(500, int(params.get("limit", ["150"])[0])))
    except (TypeError, ValueError):
        limit = 150

    if not ACTIVITY_LOG.exists():
        return []
    try:
        with ACTIVITY_LOG.open("r", encoding="utf-8", errors="replace") as log:
            recent_lines = deque(log, maxlen=5000)
    except OSError:
        return []

    results = []
    for raw_line in reversed(recent_lines):
        fields = raw_line.rstrip("\r\n").split(" | ")
        if len(fields) < 6:
            continue
        timestamp, domain, source, status, ip, ttl = fields[:6]
        ms = fields[6] if len(fields) > 6 else None
        via = fields[7] if len(fields) > 7 else "console"
        if domain_filter and domain_filter not in domain.casefold():
            continue
        if source_filter and source.upper() != source_filter:
            continue
        if status_filter and status.upper() != status_filter:
            continue
        results.append({
            "time": timestamp, "domain": domain, "source": source,
            "status": status, "ip": None if ip == "-" else ip,
            "ttl": None if ttl == "-" else ttl,
            "ms": None if ms in (None, "-") else ms,
            "via": via,
        })
        if len(results) >= limit:
            break
    return results


class API(BaseHTTPRequestHandler):
    def _headers(self, status, content_type, length):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(length))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
    def output(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self._headers(status, 'application/json; charset=utf-8', len(data))
        self.wfile.write(data)
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/stats':
            snapshot = ENGINE.snapshot()
            snapshot["simulator"] = SIMULATOR.snapshot(snapshot["config"])
            return self.output(snapshot)
        if path == '/api/cache':
            with ENGINE.lock:
                cfg = config.load()
                entries = ENGINE.cache.snapshot()
                return self.output({
                    "enabled": cfg["cache_enabled"] == "true",
                    "size": len(entries),
                    "max_entries": int(cfg["cache_max_entries"]),
                    "unlimited": int(cfg["cache_max_entries"]) == 0,
                    "entries": entries,
                })
        if path == '/api/activity':
            with ENGINE.lock:
                return self.output({"entries": read_activity(urlsplit(self.path).query)})
        if path == '/api/simulator':
            cfg = config.load()
            return self.output(SIMULATOR.snapshot(cfg))
        if path == '/api/lists':
            ads = lists.inspect('ads')
            sanctions = lists.inspect('sanctions')
            return self.output({
                'ads': ads['domains'], 'sanctions': sanctions['domains'],
                'ads_warnings': ads['warnings'], 'sanctions_warnings': sanctions['warnings'],
            })
        if path == '/api/health': return self.output(upstream.health(config.load()))
        if path == '/api/export':
            data = ENGINE.csv()
            self._headers(200, 'text/csv; charset=utf-8', len(data))
            return self.wfile.write(data)
        if path in ('/', '/index.html'):
            data = (ROOT / 'dashboard.html').read_bytes()
            self._headers(200, 'text/html; charset=utf-8', len(data))
            return self.wfile.write(data)
        return self.output({'error':'Not found'},404)
    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ('/api/resolve','/api/batch','/api/lists','/api/config','/api/cache/clear','/api/reload','/api/simulator'):
            return self.output({'error':'Not found'},404)
        try:
            size = int(self.headers.get('Content-Length','0'))
            max_payload = 131072 if path == '/api/lists' else 4096
            if size < 0 or size > max_payload: raise ValueError('Invalid payload size')
            payload = json.loads(self.rfile.read(size)) if size else {}
            if not isinstance(payload,dict): raise ValueError('Invalid payload')
            if path == '/api/simulator':
                running = payload.get("running")
                if type(running) is not bool:
                    raise ValueError("Choose whether the local simulator should run.")
                cfg = config.load()
                if running:
                    state = SIMULATOR.start(cfg)
                else:
                    state = SIMULATOR.stop()
                    state = SIMULATOR.snapshot(cfg)
                return self.output({"simulator": state})
            if path == '/api/batch':
                domains = payload.get('domains')
                if not isinstance(domains,list) or not 1 <= len(domains) <= 10:
                    raise ValueError('Batch must contain between 1 and 10 domains')
                results = []
                for raw in domains:
                    if not isinstance(raw,str) or len(raw) > 253:
                        invalid_domain = raw if isinstance(raw,str) else '(non-string)'
                        ENGINE._write_activity({
                            'domain': invalid_domain, 'source': 'NONE',
                            'status': 'INVALID_INPUT', 'ip': None, 'ttl': None,
                            'ms': 0, 'via': 'batch',
                        })
                        results.append({'domain':raw if isinstance(raw,str) else '',
                                        'source':'NONE','status':'INVALID_INPUT',
                                        'ip':None,'ttl':None,'ms':None})
                        continue
                    try:
                        event = ENGINE.resolve(raw, via='batch')
                        results.append({key:event.get(key) for key in
                                        ('domain','source','status','ip','ttl','ms','time','trace')})
                    except ValueError:
                        results.append({'domain':raw.strip(),'source':'NONE',
                                        'status':'INVALID_INPUT','ip':None,'ttl':None,'ms':None})
                summary = {
                    'total':len(results),
                    'success':sum(1 for item in results if item['status']=='OK'),
                    'blocked':sum(1 for item in results if item['source'] in ('AD_BLOCK','SANCTION')),
                    'errors':sum(1 for item in results if item['status']!='OK'),
                    'upstream':sum(1 for item in results if item['source']=='UPSTREAM')
                }
                return self.output({'results':results,'summary':summary})
            with ENGINE.lock:
                if path == '/api/resolve': result = ENGINE.resolve(payload.get('domain',''))
                elif path == '/api/lists':
                    if payload.get('action') == 'replace':
                        result = lists.replace(payload.get('list'), payload.get('content'))
                    else:
                        result = {'domains':lists.edit(payload.get('list'),payload.get('domain'),payload.get('action'))}
                    ENGINE.cache.clear()
                elif path == '/api/config':
                    changes = payload.get('settings',{})
                    if not isinstance(changes,dict) or not changes or set(changes)-config.EDITABLE: raise ValueError('Unsupported setting')
                    changes = {k:str(v).lower() if isinstance(v,bool) else str(v) for k,v in changes.items()}
                    for key in ('cache_enabled','real_dns_enabled','filter_enabled'):
                        if key in changes and changes[key] not in ('true','false'): raise ValueError('Invalid boolean')
                    if 'upstream_port' in changes and not (1 <= int(changes['upstream_port']) <= 65535):
                        raise ValueError('Upstream port must be between 1 and 65535')
                    if 'local_ttl' in changes and not (0 <= int(changes['local_ttl']) <= 86400):
                        raise ValueError('Local TTL must be between 0 and 86400')
                    if 'cache_max_entries' in changes and not (0 <= int(changes['cache_max_entries']) <= 1000000):
                        raise ValueError('Cache capacity must be 0 (unlimited) or between 1 and 1000000')
                    if 'timeout' in changes and not (0.1 <= float(changes['timeout']) <= 30): raise ValueError('Invalid timeout')
                    for key in ('sinkhole_ip','proxy_ip','upstream_ip'):
                        if key in changes:
                            ipaddress.IPv4Address(changes[key])
                    config.save(changes); ENGINE.cache.clear()
                    updated_config = config.load()
                    SIMULATOR.reconcile(updated_config)
                    result = {'config':updated_config}
                elif path == '/api/cache/clear': ENGINE.cache.clear(); result = {'ok':True}
                else:
                    ENGINE.cache.clear()
                    ads = lists.inspect('ads')
                    sanctions = lists.inspect('sanctions')
                    result = {
                        'ok': True,
                        'lists': {'ads': len(ads['domains']), 'sanctions': len(sanctions['domains'])},
                        'warnings': {'ads': ads['warnings'], 'sanctions': sanctions['warnings']},
                    }
            return self.output(result)
        except (ValueError, TypeError, KeyError, OSError) as exc:
            return self.output({'error':str(exc)},400)
    def log_message(self, *_): pass

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            import dns.message, dns.rdatatype, dns.rcode, dns.rrset
            data, sock = self.request
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            if not request.question: response.set_rcode(dns.rcode.FORMERR)
            elif request.question[0].rdtype != dns.rdatatype.A: response.set_rcode(dns.rcode.NOTIMP)
            else:
                q = request.question[0]
                result = ENGINE.resolve(q.name.to_text(), via='udp')
                if result['status'] == 'OK':
                    response.answer.append(dns.rrset.from_text(q.name, max(0,int(result['ttl'] or 0)), 'IN','A', result['ip']))
                elif result['status'] == 'NOT_FOUND': response.set_rcode(dns.rcode.NXDOMAIN)
                else: response.set_rcode(dns.rcode.SERVFAIL)
            sock.sendto(response.to_wire(),self.client_address)
        except Exception:
            # Malformed datagrams must not crash the UDP listener.
            return

class DNSUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description='DNS Control Center')
    parser.add_argument('--web-port',type=int,default=8080)
    parser.add_argument('--dns-port',type=int,default=5353)
    parser.add_argument('--host',default='127.0.0.1',help='Bind locally by default')
    args = parser.parse_args()
    with DNSUDPServer((args.host,args.dns_port),DNSHandler) as dns_server, ThreadingHTTPServer((args.host,args.web_port),API) as web_server:
        SIMULATOR.start_if_available(config.load())
        thread = threading.Thread(target=dns_server.serve_forever,daemon=True)
        thread.start()
        print(f'Dashboard: http://{args.host}:{args.web_port} | DNS UDP: {args.host}:{args.dns_port}')
        try: web_server.serve_forever()
        except KeyboardInterrupt: pass
        finally:
            dns_server.shutdown()
            SIMULATOR.stop()

if __name__ == '__main__': main()
