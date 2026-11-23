"""Runs the 13 assignment acceptance scenarios against a local UDP simulator."""
import importlib.util
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('assignment_proxy', ROOT / 'dns_proxy.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def parse_config(text):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            result[k.strip()] = v.strip()
    return result

def render_config(data):
    return ''.join(f'{k}={v}\n' for k, v in data.items())

def start_upstream(port):
    proc = subprocess.Popen(
        [sys.executable, '-u', str(ROOT / 'upstream.py')],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    # Probe UDP itself; a live process does not always mean bind() is ready.
    deadline = time.monotonic() + 12.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            error = proc.stderr.read().decode('utf-8', errors='replace') if proc.stderr else ''
            raise RuntimeError('Upstream exited during startup: ' + error)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(0.25)
                probe.sendto(b'QUERY readiness-check.invalid', ('127.0.0.1', port))
                reply, _ = probe.recvfrom(1024)
                if reply.strip() == b'NOT_FOUND':
                    return proc
        except OSError:
            time.sleep(0.1)
    stop_upstream(proc)
    raise RuntimeError('Upstream did not answer its UDP readiness probe')
def stop_upstream(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

def run():
    config_path = ROOT / 'config.txt'
    original = config_path.read_text(encoding='utf-8')
    cfg = parse_config(original)
    cfg.update({
        'upstream_ip': '127.0.0.1',
        'upstream_port': str(free_port()),
        'timeout': '2',
        'upstream_timeout_sec': '2',
        'sinkhole_ip': '0.0.0.0',
        'proxy_ip': '192.0.2.10',
        'local_ttl': '60',
        'cache_enabled': 'true',
        'cache_max_entries': '2',
        'real_dns_enabled': 'false',
    })
    upstream = None
    lines = ['Phase 1 acceptance tests T1-T13', 'Actual test execution against local UDP simulator', '']
    passed = 0

    def check(tag, raw, expected, proxy, extra=None):
        nonlocal passed
        got = proxy.resolve(raw)
        ok = (got[1], got[2], str(got[3])) == expected and (extra(got) if extra else True)
        lines.append(
            f'{tag} | input={raw!r} | Domain : {got[0]} | Source : {got[1]} | '
            f'Status : {got[2]} | IP : {got[3]} | TTL : {got[4]} | {"PASS" if ok else "FAIL"}'
        )
        passed += bool(ok)
        return got

    try:
        config_path.write_text(render_config(cfg), encoding='utf-8')
        upstream = start_upstream(int(cfg['upstream_port']))
        proxy = mod.Proxy(mod.read_config())
        check('T1', 'ads.example.com', ('AD_BLOCK', 'OK', '0.0.0.0'), proxy, lambda r: r[4] == 60)
        check('T2', 'sub.ads.example.com', ('AD_BLOCK', 'OK', '0.0.0.0'), proxy)
        check('T3', 'ADS.Example.COM.', ('AD_BLOCK', 'OK', '0.0.0.0'), proxy, lambda r: r[0] == 'ads.example.com')
        check('T4', 'notads.example.com', ('UPSTREAM', 'OK', '198.51.100.7'), proxy, lambda r: r[4] == 5)
        check('T5', 'service.example.org', ('SANCTION', 'OK', '192.0.2.10'), proxy)
        check('T6', 'both.example.com', ('AD_BLOCK', 'OK', '0.0.0.0'), proxy)
        check('T7', 'normal.example.net', ('UPSTREAM', 'OK', '198.51.100.7'), proxy, lambda r: r[4] == 5)
        time.sleep(1)
        check('T8', 'normal.example.net', ('CACHE', 'OK', '198.51.100.7'), proxy, lambda r: 1 <= r[4] <= 5)
        time.sleep(5.2)
        check('T9', 'normal.example.net', ('UPSTREAM', 'OK', '198.51.100.7'), proxy, lambda r: r[4] == 5)
        check('T10a', 'missing.example.net', ('UPSTREAM', 'NOT_FOUND', '-'), proxy)
        check('T10b', 'missing.example.net', ('UPSTREAM', 'NOT_FOUND', '-'), proxy)
        passed -= 1  # T10 is one scenario with two independent requests.

        stop_upstream(upstream)
        upstream = None
        check('T11', 'other.example.net', ('UPSTREAM', 'SERVER_ERROR', '-'), proxy)
        check('T11-followup', 'ads.example.com', ('AD_BLOCK', 'OK', '0.0.0.0'), proxy)
        passed -= 1  # T11 is one scenario.

        check('T12a', '', ('NONE', 'INVALID_INPUT', '-'), proxy, lambda r: r[0] == '(empty)')
        check('T12b', 'bad domain.com', ('NONE', 'INVALID_INPUT', '-'), proxy)
        passed -= 1  # T12 is one scenario.

        cfg['sinkhole_ip'] = '10.0.0.1'
        cfg['cache_enabled'] = 'false'
        cfg['upstream_port'] = str(free_port())
        config_path.write_text(render_config(cfg), encoding='utf-8')
        upstream = start_upstream(int(cfg['upstream_port']))
        proxy2 = mod.Proxy(mod.read_config())
        check('T13a', 'ads.example.com', ('AD_BLOCK', 'OK', '10.0.0.1'), proxy2)
        check('T13b', 'normal.example.net', ('UPSTREAM', 'OK', '198.51.100.7'), proxy2)
        check('T13c', 'normal.example.net', ('UPSTREAM', 'OK', '198.51.100.7'), proxy2)
        passed -= 2  # T13 is one scenario with three checks.

        lines += ['', f'SCENARIOS PASSED: {passed}/13']
        sample = subprocess.run(
            [sys.executable, str(ROOT / 'dns_proxy.py')],
            cwd=ROOT, input='ads.example.com\nexit\n', text=True,
            capture_output=True, timeout=20
        )
        lines.extend(['', 'Actual console transcript:', sample.stdout])
        expected_transcript = (
            'Domain : ads.example.com\nSource : AD_BLOCK\nStatus : OK\n'
            'IP : 10.0.0.1\nTTL : 60'
        )
        if passed != 13 or sample.returncode or expected_transcript not in sample.stdout:
            raise AssertionError('acceptance test failure: passed='+str(passed)+'; sample_rc='+str(sample.returncode)+'; sample_stdout='+repr(sample.stdout)+'; lines='+repr(lines))
        return lines
    finally:
        stop_upstream(upstream)
        config_path.write_text(original, encoding='utf-8')

if __name__ == '__main__':
    output = run()
    report = '\n'.join(output) + '\n'
    (ROOT / 'test_results.txt').write_text(report, encoding='utf-8')
    print(report)
