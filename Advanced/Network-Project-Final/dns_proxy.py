"""Console DNS Proxy implementing the exact Phase 1 assignment protocol.
The optional web dashboard runs separately via python -m dns_control.
"""
from __future__ import annotations
from collections import OrderedDict, Counter
from datetime import datetime
from pathlib import Path
import ipaddress
import math
import re
import socket
import time

ROOT = Path(__file__).resolve().parent
REQUIRED = ('upstream_ip', 'upstream_port', 'sinkhole_ip', 'proxy_ip', 'ad_list_file', 'sanction_list_file')
VALID = re.compile(r'^[A-Za-z0-9.-]+$')


def normalized(value):
    value = value.strip().lower()
    return value[:-1] if value.endswith('.') else value


def valid_domain(value):
    if not value or not VALID.fullmatch(value) or value.startswith('.') or '..' in value:
        return False
    name = normalized(value)
    return bool(name) and all(name.split('.'))


def matching(name, entries):
    return any(name == item or name.endswith('.' + item) for item in entries)


def read_config():
    result = {}
    for line in (ROOT / 'config.txt').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise ValueError('invalid config line')
        key, val = line.split('=', 1)
        result[key.strip()] = val.strip()
    for key in REQUIRED:
        if not result.get(key):
            raise ValueError('missing ' + key)
    for key in ('upstream_ip', 'sinkhole_ip', 'proxy_ip'):
        ipaddress.IPv4Address(result[key])
    port = int(result['upstream_port'])
    if not 1 <= port <= 65535:
        raise ValueError('invalid upstream_port')
    result['upstream_port'] = port
    result['upstream_timeout_sec'] = float(result.get('upstream_timeout_sec', '2'))
    result['local_ttl'] = int(result.get('local_ttl', '60'))
    result['cache_max_entries'] = int(result.get('cache_max_entries', '100000'))
    if result['upstream_timeout_sec'] <= 0 or result['local_ttl'] < 0 or result['cache_max_entries'] < 0:
        raise ValueError('invalid numeric config value')
    for key in ('cache_enabled', 'real_dns_enabled'):
        val = result.get(key, 'true' if key == 'cache_enabled' else 'false').lower()
        if val not in ('true', 'false'):
            raise ValueError('invalid ' + key)
        result[key] = val == 'true'
    for key in ('ad_list_file', 'sanction_list_file'):
        if not (ROOT / result[key]).is_file():
            raise ValueError('missing file: ' + result[key])
    return result


def load_list(path):
    items = set()
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not valid_domain(line) or '*' in line:
            print(f'Warning: bad line in {path.name}: {number}', flush=True)
            continue
        items.add(normalized(line))
    return items


class Proxy:
    def __init__(self, config):
        self.config = config
        self.ads, self.sanctions = self.load_lists()
        self.cache = OrderedDict()
        self.counts = Counter()
        self.domain_counts = Counter()

    def load_lists(self):
        return (load_list(ROOT / self.config['ad_list_file']),
                load_list(ROOT / self.config['sanction_list_file']))

    def query(self, domain):
        c = self.config
        if c['real_dns_enabled']:
            try:
                import dns.resolver
                import dns.exception
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [c['upstream_ip']]
                resolver.port = c['upstream_port']
                resolver.timeout = resolver.lifetime = c['upstream_timeout_sec']
                answer = resolver.resolve(domain, 'A')
                return 'OK', str(answer[0].address), int(answer.rrset.ttl)
            except ImportError:
                return 'SERVER_ERROR', '-', '-'
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return 'NOT_FOUND', '-', '-'
            except (dns.exception.DNSException, OSError, ValueError):
                return 'SERVER_ERROR', '-', '-'
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(c['upstream_timeout_sec'])
                sock.sendto(('QUERY ' + domain).encode('ascii'), (c['upstream_ip'], c['upstream_port']))
                reply = sock.recvfrom(4096)[0].decode('ascii').strip().split()
            if reply == ['NOT_FOUND']:
                return 'NOT_FOUND', '-', '-'
            if len(reply) == 3 and reply[0] == 'OK':
                ipaddress.IPv4Address(reply[1])
                ttl = int(reply[2])
                if ttl < 0:
                    raise ValueError('invalid TTL')
                return 'OK', reply[1], ttl
        except (OSError, UnicodeError, ValueError, OverflowError):
            pass
        return 'SERVER_ERROR', '-', '-'

    def resolve(self, raw):
        name = normalized(raw) if raw.strip() else '(empty)'
        c = self.config
        if not valid_domain(raw.strip()):
            result = (name, 'NONE', 'INVALID_INPUT', '-', '-')
        elif matching(name, self.ads):
            result = (name, 'AD_BLOCK', 'OK', c['sinkhole_ip'], c['local_ttl'])
        elif matching(name, self.sanctions):
            result = (name, 'SANCTION', 'OK', c['proxy_ip'], c['local_ttl'])
        else:
            item = self.cache.get(name) if c['cache_enabled'] else None
            remaining = item[1] - time.monotonic() if item else 0
            if item and remaining > 0:
                result = (name, 'CACHE', 'OK', item[0], max(1, math.ceil(remaining)))
            else:
                self.cache.pop(name, None)
                status, ip, ttl = self.query(name)
                result = (name, 'UPSTREAM', status, ip, ttl)
                if status == 'OK' and c['cache_enabled'] and int(ttl) > 0:
                    maximum = int(c['cache_max_entries'])
                    if maximum > 0 and name not in self.cache and len(self.cache) >= maximum:
                        self.cache.popitem(last=False)
                    self.cache[name] = (ip, time.monotonic() + int(ttl))
        self.counts['Total'] += 1
        self.counts[result[1]] += 1
        self.counts[result[2]] += 1
        if result[0] != '(empty)' and result[2] != 'INVALID_INPUT':
            self.domain_counts[result[0]] += 1
        if result[2] != 'OK':
            self.counts['ERRORS'] += 1
        try:
            with (ROOT / 'log.txt').open('a', encoding='utf-8') as file:
                file.write(f'{datetime.now():%Y-%m-%d %H:%M:%S} | ' + ' | '.join(map(str, result)) + '\n')
        except OSError:
            pass
        return result

    def show_cache(self):
        now = time.monotonic()
        for name, (ip, deadline) in list(self.cache.items()):
            if deadline <= now:
                del self.cache[name]
            else:
                print(f'{name} | {ip} | {max(1, math.ceil(deadline - now))}')
        if not self.cache:
            print('Cache is empty.')

    def show_stats(self):
        c = self.counts
        # Keep the original summary line for compatibility with existing demonstrations.
        print(' | '.join(f'{k}: {c[k]}' for k in ('Total', 'AD_BLOCK', 'SANCTION', 'CACHE', 'UPSTREAM', 'ERRORS')))
        print('SUCCESS: {} | NOT_FOUND: {} | INVALID_INPUT: {}'.format(
            c['OK'], c['NOT_FOUND'], c['INVALID_INPUT']))
        top = self.domain_counts.most_common(5)
        print('Top domains: ' + (', '.join(f'{name} ({count})' for name, count in top) if top else 'None'))

    def show_health(self):
        start = time.perf_counter()
        status, ip, ttl = self.query('example.com')
        elapsed = (time.perf_counter() - start) * 1000
        online = status in ('OK', 'NOT_FOUND')
        print('Upstream : {}:{} | Status : {} | Result : {} | Response : {:.2f} ms'.format(
            self.config['upstream_ip'], self.config['upstream_port'],
            'ONLINE' if online else 'OFFLINE', status, elapsed))
        if status == 'OK':
            print(f'Probe IP : {ip} | TTL : {ttl}')

    @staticmethod
    def show_help():
        print('Commands: help or ? | health | stats | cache | reload | exit')
        print('Enter a domain name to resolve it through the DNS Proxy.')


def main():
    try:
        proxy = Proxy(read_config())
    except (OSError, ValueError, KeyError) as exc:
        print(f'Config error: {exc}')
        return 1
    print('DNS Proxy ready.')
    while True:
        try:
            raw = input('Enter domain (or exit): ').strip()
        except (EOFError, KeyboardInterrupt):
            print('Bye.')
            break
        command = raw.lower()
        if command == 'exit':
            print('Bye.')
            break
        if command in ('help', '?'):
            proxy.show_help()
            continue
        if command == 'health':
            proxy.show_health()
            continue
        if command == 'stats':
            proxy.show_stats()
            continue
        if command == 'cache':
            proxy.show_cache()
            continue
        if command == 'reload':
            try:
                ads, sanctions = proxy.load_lists()
                proxy.ads, proxy.sanctions = ads, sanctions
                print('Lists reloaded.')
            except OSError as exc:
                print(f'Reload error: {exc}')
            continue
        domain, source, status, ip, ttl = proxy.resolve(raw)
        print(f'Domain : {domain}\nSource : {source}\nStatus : {status}\nIP : {ip}\nTTL : {ttl}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
