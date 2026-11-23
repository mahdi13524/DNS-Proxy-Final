import csv
import io
import threading
import time
from collections import Counter, deque
from datetime import datetime
from . import config, lists, upstream
from .cache import TTLCache
from .domain import normalize, valid, matches

ACTIVITY_LOG = config.ROOT / 'log.txt'

class Resolver:
    def __init__(self):
        self.lock = threading.RLock()
        self.cache = TTLCache()
        self.events = deque(maxlen=500)
        self.counts = Counter()
        self.upstream_counts = Counter()
        self.upstream_events = deque(maxlen=100)
        self.upstream_sequence = 0
        self.started = time.monotonic()
    def resolve(self, raw, via='dashboard'):
        """Resolve normally and attach an observational Decision X-Ray trace.

        Traces describe only branches actually evaluated, with skipped branches
        clearly marked. They never cause extra DNS traffic or change decisions.
        """
        domain = normalize(raw)
        if not valid(domain):
            self._write_activity({
                "domain": domain or "(empty)", "source": "NONE",
                "status": "INVALID_INPUT", "ip": None, "ttl": None,
                "ms": 0, "via": via,
            })
            raise ValueError('Invalid domain')
        start = time.perf_counter()
        trace = []

        def step(key, state, detail):
            trace.append({'key': key, 'state': state, 'detail': detail})

        with self.lock:
            cfg = config.load()
            upstream_id = None
            upstream_ms = None
            step('validation', 'passed', 'دامنه معتبر است؛ نام استانداردشده: ' + domain)
            filters_on = cfg['filter_enabled'] == 'true'
            if not filters_on:
                step('advertising', 'disabled', 'فیلترینگ از تنظیمات غیرفعال است.')
                step('sanctions', 'disabled', 'فیلترینگ از تنظیمات غیرفعال است.')
            else:
                ads_match = matches(domain, lists.read('ads'))
                step('advertising', 'matched' if ads_match else 'passed',
                     'دامنه در فهرست تبلیغات تطبیق داشت.' if ads_match else 'دامنه در فهرست تبلیغات پیدا نشد.')

            if filters_on and ads_match:
                step('sanctions', 'skipped', 'به دلیل اولویت فهرست تبلیغات بررسی نشد.')
                step('cache', 'skipped', 'پاسخ محلی تولید شد؛ کش بررسی نشد.')
                step('upstream', 'skipped', 'نیازی به درخواست شبکه نبود.')
                source, status, ip, ttl = 'AD_BLOCK', 'OK', cfg['sinkhole_ip'], int(cfg['local_ttl'])
            else:
                sanction_match = matches(domain, lists.read('sanctions')) if filters_on else False
                if filters_on:
                    step('sanctions', 'matched' if sanction_match else 'passed',
                         'دامنه در فهرست تحریم تطبیق داشت.' if sanction_match else 'دامنه در فهرست تحریم پیدا نشد.')
                if sanction_match:
                    step('cache', 'skipped', 'پاسخ محلی تولید شد؛ کش بررسی نشد.')
                    step('upstream', 'skipped', 'نیازی به درخواست شبکه نبود.')
                    source, status, ip, ttl = 'SANCTION', 'OK', cfg['proxy_ip'], int(cfg['local_ttl'])
                else:
                    cache_on = cfg['cache_enabled'] == 'true'
                    hit = self.cache.get(domain) if cache_on else None
                    if not cache_on:
                        step('cache', 'disabled', 'کش از تنظیمات غیرفعال است؛ نه خوانده می‌شود و نه نوشته.')
                    elif hit:
                        step('cache', 'matched', 'Cache Hit؛ پاسخ معتبر با TTL باقی‌مانده یافت شد.')
                    else:
                        step('cache', 'miss', 'Cache Miss؛ رکورد معتبر در کش وجود ندارد.')
                    if hit:
                        step('upstream', 'skipped', 'Cache Hit؛ هیچ درخواست Upstream ارسال نشد.')
                        source, status, (ip, ttl) = 'CACHE', 'OK', hit
                    else:
                        source = 'UPSTREAM'
                        upstream_start = time.perf_counter()
                        status, ip, ttl = upstream.query(domain, cfg)
                        upstream_ms = round((time.perf_counter() - upstream_start) * 1000, 2)
                        self.upstream_sequence += 1
                        upstream_id = self.upstream_sequence
                        self.upstream_counts['requests'] += 1
                        self.upstream_counts[status] += 1
                        self.upstream_counts['total_ms'] += upstream_ms
                        upstream_event = {
                            'id': upstream_id, 'domain': domain, 'status': status,
                            'ip': ip, 'ttl': ttl, 'ms': upstream_ms,
                            'time': datetime.now().isoformat(timespec='seconds')
                        }
                        self.upstream_events.appendleft(upstream_event)
                        mode = 'DNS واقعی' if cfg['real_dns_enabled'] == 'true' else 'UDP شبیه‌ساز'
                        step('upstream', 'matched' if status == 'OK' else 'error',
                             f'درخواست واقعی #{upstream_id} ({mode}) به {cfg["upstream_ip"]}:{cfg["upstream_port"]}؛ وضعیت: {status}؛ زمان: {upstream_ms} ms')
                        if status == 'OK' and cache_on:
                            self.cache.put(domain, ip, ttl, int(cfg['cache_max_entries']))

            step('result', 'matched' if status == 'OK' else 'error',
                 f'نتیجه: {source} / {status} | IP: {ip if ip is not None else "-"} | TTL: {ttl if ttl is not None else "-"}')
            event = {
                'domain': domain, 'source': source, 'status': status, 'ip': ip,
                'ttl': ttl, 'ms': round((time.perf_counter()-start)*1000,2),
                'upstream_id': upstream_id, 'upstream_ms': upstream_ms,
                'time': datetime.now().isoformat(timespec='seconds'), 'via': via,
                'trace': trace
            }
            self.events.appendleft(event)
            self._write_activity(event)
            self.counts['total'] += 1
            self.counts[source] += 1
            self.counts[status] += 1
            return event
    @staticmethod
    def _write_activity(event):
        """Append a durable, pipe-delimited record shared with the console log."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = lambda value: str(value).replace("|", "/").replace("\\r", " ").replace("\\n", " ")
            fields = (
                timestamp,
                clean(event.get("domain") or "(empty)"),
                clean(event.get("source") or "NONE"),
                clean(event.get("status") or "UNKNOWN"),
                clean(event.get("ip") or "-"),
                clean(event.get("ttl") if event.get("ttl") is not None else "-"),
                clean(event.get("ms") if event.get("ms") is not None else "-"),
                clean(event.get("via") or "dashboard"),
            )
            with ACTIVITY_LOG.open("a", encoding="utf-8") as log:
                log.write(" | ".join(fields) + "\n")
        except OSError:
            # Logging must never interrupt DNS resolution.
            pass

    def snapshot(self):
        with self.lock:
            upstream_total = self.upstream_counts['requests']
            upstream = {
                'requests': upstream_total,
                'success': self.upstream_counts['OK'],
                'not_found': self.upstream_counts['NOT_FOUND'],
                'errors': self.upstream_counts['SERVER_ERROR'],
                'avg_ms': round(self.upstream_counts['total_ms'] / upstream_total, 2) if upstream_total else 0,
                'last': self.upstream_events[0] if self.upstream_events else None
            }
            return {
                'stats':dict(self.counts), 'events':list(self.events),
                'upstream':upstream, 'upstream_events':list(self.upstream_events),
                'cache_size':self.cache.count(),
                'uptime_sec':int(time.monotonic()-self.started),
                'top_domains':Counter(e['domain'] for e in self.events).most_common(8),
                'config':config.load()
            }
    def csv(self):
        with self.lock:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['time','domain','source','status','ip','ttl','ms','via'])
            writer.writeheader();writer.writerows(({key: event.get(key) for key in writer.fieldnames} for event in self.events))
            return output.getvalue().encode('utf-8-sig')
