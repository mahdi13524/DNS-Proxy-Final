"""Decision X-Ray: ensure traces reflect executed branches, not mock animation."""
import csv
import io
import unittest
from unittest.mock import patch
from dns_control.resolver import Resolver


class DecisionXRayTests(unittest.TestCase):
    @staticmethod
    def states(result):
        return {stage['key']: stage['state'] for stage in result['trace']}

    @patch('dns_control.resolver.upstream.query')
    @patch('dns_control.resolver.lists.read', side_effect=lambda kind: {'ads.example.com'} if kind == 'ads' else set())
    def test_ad_short_circuit_has_no_upstream_call(self, _lists, query):
        r = Resolver()
        result = r.resolve('sub.ads.example.com')
        states = self.states(result)
        self.assertEqual(states['advertising'], 'matched')
        self.assertEqual(states['sanctions'], 'skipped')
        self.assertEqual(states['cache'], 'skipped')
        self.assertEqual(states['upstream'], 'skipped')
        self.assertEqual(result['source'], 'AD_BLOCK')
        query.assert_not_called()

    @patch('dns_control.resolver.upstream.query')
    @patch('dns_control.resolver.lists.read', side_effect=lambda kind: {'service.example.org'} if kind == 'sanctions' else set())
    def test_sanction_trace(self, _lists, query):
        result = Resolver().resolve('service.example.org')
        states = self.states(result)
        self.assertEqual(states['advertising'], 'passed')
        self.assertEqual(states['sanctions'], 'matched')
        self.assertEqual(states['upstream'], 'skipped')
        query.assert_not_called()

    @patch('dns_control.resolver.upstream.query', return_value=('OK', '198.51.100.7', 60))
    @patch('dns_control.resolver.lists.read', return_value=set())
    def test_upstream_then_cache_and_csv(self, _lists, query):
        r = Resolver()
        first = r.resolve('normal.example.net')
        second = r.resolve('normal.example.net')
        self.assertEqual(self.states(first)['cache'], 'miss')
        self.assertEqual(self.states(first)['upstream'], 'matched')
        self.assertEqual(self.states(second)['cache'], 'matched')
        self.assertEqual(self.states(second)['upstream'], 'skipped')
        self.assertIsNotNone(first['upstream_id'])
        self.assertIsNone(second['upstream_id'])
        query.assert_called_once()
        rows = list(csv.DictReader(io.StringIO(r.csv().decode('utf-8-sig'))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['source'], 'CACHE')

    @patch('dns_control.resolver.config.load')
    @patch('dns_control.resolver.upstream.query', return_value=('SERVER_ERROR', '-', '-'))
    def test_filter_and_cache_disabled(self, query, load):
        from dns_control import config
        cfg = config.load()
        cfg['filter_enabled'] = 'false'
        cfg['cache_enabled'] = 'false'
        load.return_value = cfg
        result = Resolver().resolve('normal.example.net')
        states = self.states(result)
        self.assertEqual(states['advertising'], 'disabled')
        self.assertEqual(states['sanctions'], 'disabled')
        self.assertEqual(states['cache'], 'disabled')
        self.assertEqual(states['upstream'], 'error')
        self.assertEqual(result['status'], 'SERVER_ERROR')
        query.assert_called_once()


if __name__ == '__main__':
    unittest.main()
