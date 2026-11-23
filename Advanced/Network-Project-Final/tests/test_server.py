import json
import socket
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
import dns.message
import dns.rcode
from dns_control.server import API, DNSUDPServer, DNSHandler, ENGINE

class IntegrationTests(unittest.TestCase):
    def test_http_api(self):
        import urllib.request
        with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/api/stats') as r:
                    self.assertIn('stats',json.load(r))
            finally: server.shutdown();t.join()

    def test_batch_api_returns_per_domain_results_and_summary(self):
        import urllib.request
        def fake_resolve(domain, via='dashboard'):
            if domain == 'bad domain':
                raise ValueError('Invalid domain')
            return {
                'domain':domain.lower(),'source':'UPSTREAM','status':'OK',
                'ip':'203.0.113.10','ttl':60,'ms':1.2,
                'time':'2026-11-23T12:00:00','trace':[]
            }
        with patch.object(ENGINE,'resolve',side_effect=fake_resolve):
            with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                try:
                    body=json.dumps({'domains':['Example.com','bad domain','github.com']}).encode()
                    request=urllib.request.Request(
                        f'http://127.0.0.1:{server.server_port}/api/batch',
                        data=body,headers={'Content-Type':'application/json'},method='POST'
                    )
                    with urllib.request.urlopen(request) as response:
                        data=json.load(response)
                    self.assertEqual(len(data['results']),3)
                    self.assertEqual(data['results'][0]['status'],'OK')
                    self.assertEqual(data['results'][1]['status'],'INVALID_INPUT')
                    self.assertEqual(data['summary']['total'],3)
                    self.assertEqual(data['summary']['success'],2)
                    self.assertEqual(data['summary']['errors'],1)
                    self.assertEqual(data['results'][0]['trace'],[])
                finally:
                    server.shutdown();t.join()

    def test_batch_api_rejects_more_than_ten_domains(self):
        import urllib.request
        from urllib.error import HTTPError
        with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            try:
                body=json.dumps({'domains':['example.com']*11}).encode()
                request=urllib.request.Request(
                    f'http://127.0.0.1:{server.server_port}/api/batch',
                    data=body,headers={'Content-Type':'application/json'},method='POST'
                )
                with self.assertRaises(HTTPError) as context:
                    urllib.request.urlopen(request)
                self.assertEqual(context.exception.code,400)
            finally:
                server.shutdown();t.join()

    @patch.object(ENGINE,'resolve',return_value={'status':'OK','ip':'1.2.3.4','ttl':60})
    def test_udp_dns(self,_mock):
        with DNSUDPServer(('127.0.0.1',0),DNSHandler) as server:
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            try:
                request=dns.message.make_query('example.com','A')
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2);sock.sendto(request.to_wire(),server.server_address)
                    data,_=sock.recvfrom(2048)
                response=dns.message.from_wire(data)
                self.assertEqual(response.rcode(),dns.rcode.NOERROR)
                self.assertEqual(response.answer[0][0].address,'1.2.3.4')
            finally:server.shutdown();t.join()

    def test_persistent_activity_log_filters_legacy_and_dashboard_records(self):
        import tempfile
        from pathlib import Path
        import dns_control.server as server_module
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / 'log.txt'
            log_path.write_text(
                '2026-11-23 10:00:00 | ads.example.com | AD_BLOCK | OK | 0.0.0.0 | 60\n'
                '2026-11-23 10:01:00 | normal.example.net | UPSTREAM | OK | 198.51.100.7 | 5 | 3.2 | dashboard\n'
                '2026-11-23 10:02:00 | missing.example.net | UPSTREAM | NOT_FOUND | - | - | 2.1 | batch\n',
                encoding='utf-8'
            )
            with patch.object(server_module, 'ACTIVITY_LOG', log_path):
                all_rows = server_module.read_activity('limit=10')
                filtered = server_module.read_activity('source=UPSTREAM&status=OK&domain=normal')
            self.assertEqual(len(all_rows), 3)
            self.assertEqual(all_rows[0]['via'], 'batch')
            self.assertEqual(all_rows[2]['via'], 'console')
            self.assertEqual(len(filtered), 1)
            self.assertEqual(filtered[0]['domain'], 'normal.example.net')
            self.assertEqual(filtered[0]['ms'], '3.2')

    def test_local_simulator_control_starts_answers_and_stops(self):
        from dns_control.simulator import LocalSimulatorController
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        controller = LocalSimulatorController()
        cfg = {
            'upstream_ip': '127.0.0.1',
            'upstream_port': port,
            'real_dns_enabled': 'false',
        }
        try:
            state = controller.start(cfg)
            self.assertTrue(state['running'])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(b'QUERY normal.example.net', ('127.0.0.1', port))
                reply, _ = client.recvfrom(1024)
            self.assertEqual(reply.decode('ascii'), 'OK 198.51.100.7 5')
            state = controller.snapshot(cfg)
            self.assertEqual(state['requests'], 1)
            self.assertEqual(state['last_request']['domain'], 'normal.example.net')
        finally:
            controller.stop()
        self.assertFalse(controller.snapshot(cfg)['running'])


    def test_cache_and_activity_read_apis(self):
        import urllib.request
        import tempfile
        from pathlib import Path
        import dns_control.server as server_module
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / 'log.txt'
            log_path.write_text(
                '2026-11-23 12:00:00 | example.com | CACHE | OK | 93.184.216.34 | 45 | 0.5 | dashboard\n',
                encoding='utf-8'
            )
            with patch.object(server_module, 'ACTIVITY_LOG', log_path):
                with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                    t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/api/cache') as response:
                            cache_data=json.load(response)
                        with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/api/activity?source=CACHE') as response:
                            activity_data=json.load(response)
                        self.assertIn('entries',cache_data)
                        self.assertIn('max_entries',cache_data)
                        self.assertEqual(activity_data['entries'][0]['domain'],'example.com')
                        self.assertEqual(activity_data['entries'][0]['via'],'dashboard')
                    finally:
                        server.shutdown();t.join()


    def test_simulator_control_api_starts_and_stops_service(self):
        import urllib.request
        import dns_control.server as server_module
        from dns_control.simulator import LocalSimulatorController
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        controller = LocalSimulatorController()
        cfg = {'upstream_ip':'127.0.0.1','upstream_port':port,'real_dns_enabled':'false'}
        with patch.object(server_module, 'SIMULATOR', controller), patch.object(server_module.config, 'load', return_value=cfg):
            with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                try:
                    url=f'http://127.0.0.1:{server.server_port}/api/simulator'
                    request=urllib.request.Request(url,data=json.dumps({'running':True}).encode(),
                        headers={'Content-Type':'application/json'},method='POST')
                    with urllib.request.urlopen(request) as response:
                        started=json.load(response)
                    self.assertTrue(started['simulator']['running'])
                    request=urllib.request.Request(url,data=json.dumps({'running':False}).encode(),
                        headers={'Content-Type':'application/json'},method='POST')
                    with urllib.request.urlopen(request) as response:
                        stopped=json.load(response)
                    self.assertFalse(stopped['simulator']['running'])
                finally:
                    controller.stop();server.shutdown();t.join()


    def test_bulk_policy_list_api_returns_line_warnings(self):
        import urllib.request
        import dns_control.server as server_module
        expected = {
            'domains':['ads.example.com'],
            'warnings':[{'line':2,'value':'bad domain','reason':'Invalid domain'}],
            'invalid_count':1,
        }
        with patch.object(server_module.lists, 'replace', return_value=expected) as replace:
            with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                try:
                    body=json.dumps({'list':'ads','action':'replace','content':'ads.example.com\\nbad domain'}).encode()
                    request=urllib.request.Request(
                        f'http://127.0.0.1:{server.server_port}/api/lists',data=body,
                        headers={'Content-Type':'application/json'},method='POST'
                    )
                    with urllib.request.urlopen(request) as response:
                        data=json.load(response)
                    self.assertEqual(data['domains'],['ads.example.com'])
                    self.assertEqual(data['invalid_count'],1)
                    replace.assert_called_once()
                finally:server.shutdown();t.join()

    def test_config_api_accepts_policy_settings_and_unlimited_cache(self):
        import urllib.request
        import dns_control.server as server_module
        cfg = {
            'upstream_ip':'127.0.0.1','upstream_port':'5354','timeout':'2',
            'sinkhole_ip':'10.10.10.10','proxy_ip':'192.0.2.20','local_ttl':'0',
            'cache_max_entries':'0','real_dns_enabled':'false'
        }
        with (
            patch.object(server_module.config,'load',return_value=cfg),
            patch.object(server_module.config,'save') as save,
            patch.object(server_module.SIMULATOR,'reconcile'),
        ):
            with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                try:
                    body=json.dumps({'settings':{
                        'sinkhole_ip':'10.10.10.10','proxy_ip':'192.0.2.20',
                        'local_ttl':'0','cache_max_entries':'0'
                    }}).encode()
                    request=urllib.request.Request(
                        f'http://127.0.0.1:{server.server_port}/api/config',data=body,
                        headers={'Content-Type':'application/json'},method='POST'
                    )
                    with urllib.request.urlopen(request) as response:
                        data=json.load(response)
                    self.assertEqual(data['config']['cache_max_entries'],'0')
                    save.assert_called_once_with({
                        'sinkhole_ip':'10.10.10.10','proxy_ip':'192.0.2.20',
                        'local_ttl':'0','cache_max_entries':'0'
                    })
                finally:server.shutdown();t.join()

    def test_reload_api_reports_invalid_policy_lines(self):
        import urllib.request
        import dns_control.server as server_module
        with patch.object(server_module.lists,'inspect',side_effect=[
            {'domains':['ads.example.com'],'warnings':[{'line':3,'value':'bad','reason':'Invalid domain'}]},
            {'domains':[],'warnings':[]}
        ]):
            with ThreadingHTTPServer(('127.0.0.1',0),API) as server:
                t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
                try:
                    request=urllib.request.Request(
                        f'http://127.0.0.1:{server.server_port}/api/reload',data=b'{}',
                        headers={'Content-Type':'application/json'},method='POST'
                    )
                    with urllib.request.urlopen(request) as response:
                        data=json.load(response)
                    self.assertEqual(data['lists']['ads'],1)
                    self.assertEqual(data['warnings']['ads'][0]['line'],3)
                finally:server.shutdown();t.join()

if __name__=='__main__':unittest.main()
