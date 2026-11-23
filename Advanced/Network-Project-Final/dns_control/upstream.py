import ipaddress
import socket
import time

def query(domain, cfg):
    host, port, timeout = cfg['upstream_ip'], int(cfg['upstream_port']), float(cfg['timeout'])
    if cfg['real_dns_enabled'].lower() == 'true':
        try:
            import dns.resolver
            import dns.exception
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host]
            resolver.port = port
            resolver.timeout = resolver.lifetime = timeout
            response = resolver.resolve(domain, 'A', raise_on_no_answer=False)
            if not response.rrset: return 'NOT_FOUND', None, None
            return 'OK', response[0].address, int(response.rrset.ttl)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): return 'NOT_FOUND', None, None
        except (dns.exception.DNSException, OSError, ValueError): return 'SERVER_ERROR', None, None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(('QUERY ' + domain).encode(), (host, port))
            raw, _ = sock.recvfrom(1024)
        parts = raw.decode().strip().split()
        if parts == ['NOT_FOUND']: return 'NOT_FOUND', None, None
        if len(parts) != 3 or parts[0] != 'OK': return 'SERVER_ERROR', None, None
        ipaddress.ip_address(parts[1]); ttl = int(parts[2])
        if ttl <= 0: return 'SERVER_ERROR', None, None
        return 'OK', parts[1], ttl
    except (OSError, ValueError, UnicodeError): return 'SERVER_ERROR', None, None

def health(cfg):
    start = time.perf_counter()
    status, _, _ = query('example.com', cfg)
    return {'online': status in ('OK','NOT_FOUND'), 'status': status, 'ms': round((time.perf_counter()-start)*1000, 2), 'server': f"{cfg['upstream_ip']}:{cfg['upstream_port']}"}
