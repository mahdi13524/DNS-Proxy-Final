import unittest
from unittest.mock import patch
from dns_control.domain import normalize, valid, matches
from dns_control.cache import TTLCache
from dns_control.resolver import Resolver

class CoreTests(unittest.TestCase):
    def test_normalize(self): self.assertEqual(normalize(' WWW.Example.COM. '),'www.example.com')
    def test_validation(self):
        self.assertTrue(valid('a.example.com'))
        for name in ('', '-bad.com', 'bad..com', 'bad_.com'): self.assertFalse(valid(name))
    def test_subdomain_match(self):
        self.assertTrue(matches('www.ads.example', {'ads.example'}))
        self.assertFalse(matches('notads.example', {'ads.example'}))
    def test_cache(self):
        c=TTLCache();c.put('a','1.2.3.4',60,1);self.assertEqual(c.get('a')[0],'1.2.3.4')
        c.put('b','1.2.3.5',60,1);self.assertIsNone(c.get('a'))
    @patch('dns_control.resolver.upstream.query',return_value=('OK','93.184.216.34',60))
    @patch('dns_control.resolver.lists.read',return_value=set())
    def test_resolver_cache(self,_lists,query):
        r=Resolver();self.assertEqual(r.resolve('example.com')['source'],'UPSTREAM');self.assertEqual(r.resolve('example.com')['source'],'CACHE');query.assert_called_once()
    @patch('dns_control.resolver.lists.read',side_effect=lambda name: {'ads.example'} if name=='ads' else set())
    def test_blocking(self,_lists):
        r=Resolver();result=r.resolve('sub.ads.example');self.assertEqual(result['source'],'AD_BLOCK');self.assertEqual(result['ip'],'0.0.0.0')
    def test_invalid_input(self):
        with self.assertRaises(ValueError): Resolver().resolve('bad..domain')

    @patch('dns_control.resolver.upstream.query', return_value=('OK', '93.184.216.34', 60))
    @patch('dns_control.resolver.lists.read', return_value=set())
    def test_upstream_telemetry(self, _lists, _query):
        r = Resolver()
        result = r.resolve('example.com')
        snap = r.snapshot()
        self.assertEqual(result['source'], 'UPSTREAM')
        self.assertEqual(snap['upstream']['requests'], 1)
        self.assertEqual(snap['upstream']['success'], 1)
        self.assertEqual(snap['upstream_events'][0]['domain'], 'example.com')
        self.assertEqual(snap['upstream_events'][0]['id'], 1)

    def test_csv(self): self.assertIn(b'domain',Resolver().csv())

    def test_cache_snapshot_reports_live_entries(self):
        c = TTLCache()
        c.put('inspect.example.net', '203.0.113.7', 30, 5)
        entries = c.snapshot()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['domain'], 'inspect.example.net')
        self.assertEqual(entries[0]['ip'], '203.0.113.7')
        self.assertGreaterEqual(entries[0]['ttl'], 1)

    def test_invalid_input_is_written_to_persistent_activity_log(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / 'activity.log'
            with patch('dns_control.resolver.ACTIVITY_LOG', log_path):
                with self.assertRaises(ValueError):
                    Resolver().resolve('bad domain', via='test')
            content = log_path.read_text(encoding='utf-8')
            self.assertIn('bad domain | NONE | INVALID_INPUT', content)
            self.assertIn('| test', content)


    def test_unlimited_cache_when_maximum_is_zero(self):
        c = TTLCache()
        c.put('one.example.net', '198.51.100.1', 60, 0)
        c.put('two.example.net', '198.51.100.2', 60, 0)
        c.put('three.example.net', '198.51.100.3', 60, 0)
        self.assertEqual(c.count(), 3)

    def test_bulk_policy_replace_skips_and_reports_invalid_lines(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from dns_control import lists
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'ads.txt'
            with patch.object(lists, 'list_path', return_value=target):
                result = lists.replace('ads', 'ads.example.com\nnot a domain\n# comment\n*.wild.example')
                self.assertEqual(result['domains'], ['ads.example.com'])
                self.assertEqual(result['invalid_count'], 2)
                self.assertEqual([x['line'] for x in result['warnings']], [2, 4])
                self.assertEqual(lists.read('ads'), {'ads.example.com'})

    def test_flexible_simulator_answers_unknown_domains_and_keeps_missing_fixture(self):
        from dns_control.simulator import _SimulatorUDPServer
        server = _SimulatorUDPServer(('127.0.0.1', 0))
        try:
            self.assertEqual(server.handle_query(b'QUERY github.com'), 'OK 198.51.100.7 5')
            self.assertEqual(server.handle_query(b'QUERY random-site.com'), 'OK 198.51.100.7 5')
            self.assertEqual(server.handle_query(b'QUERY example.com'), 'OK 93.184.216.34 60')
            self.assertEqual(server.handle_query(b'QUERY missing.example.net'), 'NOT_FOUND')
        finally:
            server.server_close()

    def test_console_unlimited_cache_when_maximum_is_zero(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import dns_proxy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ads.txt').write_text('', encoding='utf-8')
            (root / 'sanctions.txt').write_text('', encoding='utf-8')
            cfg = {
                'upstream_ip':'127.0.0.1', 'upstream_port':5354,
                'upstream_timeout_sec':1, 'local_ttl':60,
                'sinkhole_ip':'0.0.0.0', 'proxy_ip':'192.0.2.10',
                'ad_list_file':'ads.txt', 'sanction_list_file':'sanctions.txt',
                'cache_enabled':True, 'cache_max_entries':0, 'real_dns_enabled':False,
            }
            with patch.object(dns_proxy, 'ROOT', root):
                proxy = dns_proxy.Proxy(cfg)
                with patch.object(proxy, 'query', return_value=('OK','198.51.100.7',60)):
                    proxy.resolve('one.example.net')
                    proxy.resolve('two.example.net')
                    proxy.resolve('three.example.net')
                self.assertEqual(len(proxy.cache), 3)

if __name__=='__main__':unittest.main()
