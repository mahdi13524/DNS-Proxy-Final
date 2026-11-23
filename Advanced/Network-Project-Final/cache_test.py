"""Manual FIFO/TTL cache check. Start upstream.py before running this script."""
import time
from dns_proxy import Proxy, read_config

cfg = read_config()
cfg['real_dns_enabled'] = False
cfg['cache_enabled'] = True
cfg['cache_max_entries'] = 2
proxy = Proxy(cfg)

for domain in ('site1.example.net', 'site2.example.net', 'site3.example.net'):
    result = proxy.resolve(domain)
    print(f'{domain}: Source={result[1]} Status={result[2]} IP={result[3]} TTL={result[4]}')

print('\nCache after inserting three domains into a two-entry FIFO cache:')
proxy.show_cache()

if 'site1.example.net' in proxy.cache:
    raise SystemExit('FAIL: oldest cache entry was not evicted')
if set(proxy.cache) != {'site2.example.net', 'site3.example.net'}:
    raise SystemExit(f'FAIL: unexpected cache entries: {list(proxy.cache)}')

print('\nPASS: FIFO eviction is working.')
print('Wait at least 30 seconds and run this script again to observe TTL expiry.')
