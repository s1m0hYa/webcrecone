from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from test_diagnostics import collect, HTML
from webrecon.analyzer import analyze_report
from webrecon.cli import main
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.report import load_report, render_summary, save_report


BODY = Path(__file__).with_name('fixtures').joinpath('robots-response.html').read_text(encoding='utf-8')


class ResponseDocumentTests(unittest.TestCase):
    def test_received_html_produces_urls_without_any_additional_requests(self):
        data, requests = collect((200, HTML, BODY))
        self.assertEqual([item[0] for item in requests], ['/robots.txt'])
        self.assertEqual(data['pages'], [])
        self.assertEqual(data['scripts'], [])
        self.assertEqual(data['summary']['stop_reason'], 'robots_unexpected_content_type')
        self.assertEqual(data['summary']['response_documents_parsed'], 1)
        self.assertEqual(data['summary']['pages_parsed'], 0)
        document = data['response_documents'][0]
        self.assertEqual(document['purpose'], 'robots')
        self.assertTrue(document['url'].endswith('/robots.txt'))
        entries = {item['path']: item for item in data['url_list']}
        self.assertTrue({'/guide', '/contact', '/logout', '/assets/bundle.js', '/assets/site.css',
                         '/api/orders', '/api/items', '/api/metrics', '/help'} <= entries.keys())
        self.assertEqual(sum(item['path'] == '/guide' for item in data['url_list']), 1)
        self.assertEqual(entries['/guide']['observed_methods'], [])
        self.assertEqual(entries['/guide']['visit_status'], 'not_visited')
        self.assertEqual(entries['/guide']['sources'][0]['context'], 'response_document')
        self.assertEqual(data['summary']['script_queue_remaining'], 0)
        self.assertTrue(all(item.get('initial_disposition') != 'script_queued' for item in data['discoveries']))
        self.assertIn('별도 응답 HTML 분석: 1', render_summary(data))

    def test_methods_forms_and_dynamic_patterns_keep_the_response_source(self):
        data, _ = collect((200, HTML, BODY))
        apis = {item['path']: item for item in data['api_list']}
        self.assertEqual(apis['/api/orders']['declared_methods'], ['POST'])
        self.assertEqual(apis['/api/orders']['observed_methods'], [])
        self.assertEqual(apis['/api/orders']['parameter_names'], ['item', 'password'])
        self.assertIn('authentication', apis['/api/orders']['categories'])
        self.assertEqual(apis['/api/items']['declared_methods'], ['GET'])
        self.assertEqual(apis['/api/items']['parameter_names'], ['token'])
        self.assertEqual(apis['/api/metrics']['method_status'], 'unknown')
        pattern = data['endpoint_patterns'][0]
        self.assertEqual(pattern['pattern'], '/api/users/{userId}')
        self.assertTrue(pattern['source'].endswith('/robots.txt'))
        serialized = json.dumps(data)
        self.assertNotIn('_PRIVATE', serialized)
        self.assertNotIn('RAW_ONLY_MARKER', serialized)
        self.assertNotIn('<html', serialized)

    def test_scope_query_and_unsafe_paths_are_recorded_without_scheduling(self):
        data, requests = collect((200, HTML, BODY))
        refs = [item for item in data['discoveries'] if item.get('context') == 'response_document']
        dispositions = {item['disposition'] for item in refs}
        self.assertTrue({'response_reference_only', 'outside_scope', 'query_not_visited',
                         'suspected_state_change', 'api_not_visited', 'non_http_scheme'} <= dispositions)
        self.assertEqual(len(requests), 1)

    def test_already_received_error_html_is_parsed_while_access_remains_blocked(self):
        for status in (401, 403, 500):
            with self.subTest(status=status):
                data, requests = collect((status, HTML, '<a href="/support">Support</a>'))
                self.assertEqual(len(requests), 1)
                self.assertEqual(data['response_documents'][0]['status'], status)
                self.assertTrue(any(item['path'] == '/support' for item in data['url_list']))
                self.assertEqual(data['summary']['input_urls_response_received'], 0)
                self.assertEqual(data['robots_checks'][0]['decision'], 'blocked')

    def test_missing_robots_html_does_not_add_links_or_scripts_to_the_queue(self):
        for status in (404, 410):
            with self.subTest(status=status):
                data, requests = collect((status, HTML, BODY), seeds=())
                self.assertEqual([item[0] for item in requests], ['/robots.txt', '/'])
                self.assertIsNone(data['summary']['stop_reason'])
                self.assertEqual(data['summary']['pages_parsed'], 1)
                self.assertEqual(data['summary']['response_documents_parsed'], 1)
                self.assertEqual(data['summary']['queue_remaining'], 0)
                self.assertEqual(data['summary']['script_queue_remaining'], 0)

    def test_truncation_compression_and_backpressure_are_not_parsed(self):
        for response, options in [
            ((200, HTML, BODY), {'max_response_bytes': 40}),
            ((200, {**HTML, 'Content-Encoding': 'gzip'}, BODY), {}),
            ((429, HTML, BODY), {}),
            ((503, HTML, BODY), {}),
            ((200, {**HTML, 'Retry-After': '10'}, BODY), {}),
        ]:
            with self.subTest(status=response[0], options=options):
                data, requests = collect(response, **options)
                self.assertEqual(len(requests), 1)
                self.assertEqual(data['response_documents'], [])
                self.assertEqual(data['summary']['discovered_endpoints'], 0)

    def test_item_limits_and_plaintext_html_detection(self):
        body = '<html>' + ''.join(f'<a href="/guide/{n}">Guide</a>' for n in range(20)) + '</html>'
        data, requests = collect((200, {'Content-Type': 'text/plain'}, body),
                                 max_items_per_page=3, max_requests=1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(data['summary']['discovered_endpoints'], 3)
        self.assertEqual(data['response_documents'][0]['parse_basis'], 'html_markup')
        self.assertEqual(data['summary']['stop_reason'], 'robots_html_response')
        self.assertIn('response_document_item_limit', [item['code'] for item in data['issues']])

    def test_redirect_relative_links_use_final_response_url(self):
        routes = {'/robots.txt': (302, {'Location': '/legal/notice'}, ''),
                  '/legal/notice': (200, HTML, '<a href="help">Help</a>')}
        with simulated_server(routes) as (origin, requests):
            config = Config(origin, [origin], allowed_loopback_hosts=['127.0.0.1'])
            clock = FakeClock()
            crawler = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep)
            data = crawler.run()
            self.assertEqual(crawler.client.take_robots_html_responses(), [])
        self.assertEqual([item[0] for item in requests], ['/robots.txt', '/legal/notice'])
        self.assertEqual(clock.sleeps, [1])
        self.assertTrue(any(item['path'] == '/legal/help' for item in data['url_list']))
        document = data['response_documents'][0]
        self.assertEqual(document['requested_url'], origin + '/robots.txt')
        self.assertEqual(document['url'], origin + '/legal/notice')

    def test_offline_json_reanalysis_preserves_findings_and_legacy_has_no_invented_content(self):
        data, _ = collect((200, HTML, BODY))
        config = Config(target_url=data['target'], **data['limits'])
        with tempfile.TemporaryDirectory() as folder, patch('webrecon.report.REPOSITORY_ROOT', Path(folder)):
            path = save_report(data, config)
            original = path.read_bytes()
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
                loaded = load_report(path)
                self.assertEqual(loaded['url_list'], data['url_list'])
                self.assertEqual(loaded['api_list'], data['api_list'])
                self.assertEqual(loaded['endpoint_patterns'], data['endpoint_patterns'])
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(['report', '--input', str(path), '--list', 'apis', '--group-by', 'path']), 0)
                self.assertIn('/api/orders', json.loads(output.getvalue()))
            self.assertEqual(path.read_bytes(), original)
        legacy, _ = collect((200, HTML, '<html>No stored links</html>'))
        legacy.pop('response_documents')
        analyzed = analyze_report(copy.deepcopy(legacy))
        self.assertEqual(analyzed['summary']['response_documents_parsed'], 0)
        self.assertEqual(analyzed['summary']['discovered_endpoints'], 0)

    def test_scan_cli_saves_partial_findings_when_robots_stops_scan(self):
        with tempfile.TemporaryDirectory() as folder, simulated_server({'/robots.txt': (200, HTML, BODY)}) as (origin, requests):
            config_path = Path(folder) / 'config.json'
            config_path.write_text(json.dumps({'target_url': origin, 'allowed_origins': [origin],
                                              'allowed_loopback_hosts': ['127.0.0.1']}), encoding='utf-8')
            clock = FakeClock()
            def crawler(config, authorized):
                return Crawler(config, authorized=authorized, clock=clock.clock, sleep=clock.sleep)
            with patch('webrecon.report.REPOSITORY_ROOT', Path(folder)), patch('webrecon.cli.Crawler', side_effect=crawler), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['scan', '--config', str(config_path), '--ack-authorized']), 1)
            self.assertIn('별도 응답 HTML 분석: 1', output.getvalue())
            reports = list(Path(folder).joinpath('output').glob('webrecon-*.json'))
            self.assertEqual(len(reports), 1)
            saved = load_report(reports[0])
            self.assertTrue(any(item['path'] == '/api/orders' for item in saved['api_list']))
            self.assertEqual([item[0] for item in requests], ['/robots.txt'])
