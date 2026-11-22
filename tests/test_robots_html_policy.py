from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.cli import main
from webrecon.config import Config, ConfigError
from webrecon.crawler import Crawler
from webrecon.http_client import AuthorizationError
from webrecon.report import render_summary


HTML = {"Content-Type": "text/html"}
ROBOTS_HTML = '<!doctype html><html><body><a href="/robots-only">Home</a><script src="/robots-only.js"></script></body></html>'


def routes():
    return {
        '/robots.txt': (200, HTML, ROBOTS_HTML),
        '/': (200, HTML, '<a href="/one">One</a><script src="/assets/app.js"></script>'
              '<a href="/logout">Logout</a><a href="/search?token=PRIVATE">Query</a>'
              '<a href="https://outside.invalid/">Outside</a><form action="/submit" method="POST"></form>'),
        '/seed': (200, HTML, '<a href="/seed-child">Child</a><script src="/assets/app.js"></script>'),
        '/one': (200, HTML, '<a href="/two">Two</a>'),
        '/two': (200, HTML, '<a href="/three">Three</a>'),
        '/seed-child': (200, HTML, '<title>Seed child</title>'),
        '/assets/app.js': (200, {'Content-Type': 'application/javascript'},
                           'fetch("/api/items"); fetch("/api/orders", {method:"POST"});'),
    }


def collect(custom=None, *, policy='continue', **options):
    with simulated_server(custom or routes()) as (origin, requests):
        config = Config(origin, [origin], allowed_loopback_hosts=['127.0.0.1'],
                        seed_urls=[origin + '/seed'], robots_html_policy=policy, **options)
        clock = FakeClock()
        data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
    return data, config, requests, clock


class RobotsHtmlPolicyTests(unittest.TestCase):
    def test_continue_reaches_seeds_bfs_children_and_shared_script(self):
        data, _, requests, clock = collect()
        self.assertEqual([item[0] for item in requests],
                         ['/robots.txt', '/', '/seed', '/one', '/seed-child', '/two', '/assets/app.js'])
        self.assertEqual(clock.sleeps, [1] * 6)
        self.assertEqual([item['depth'] for item in data['pages']], [0, 0, 1, 1, 2])
        self.assertEqual(data['summary']['pages_parsed'], 5)
        self.assertEqual(data['summary']['scripts_observed'], 1)
        self.assertEqual(data['summary']['input_urls_response_received'], 2)
        self.assertIsNone(data['summary']['stop_reason'])
        self.assertEqual(data['limits']['robots_html_policy'], 'continue')
        check = data['robots_checks'][0]
        self.assertEqual(check['decision'], 'continued_unverified')
        self.assertEqual(check['reason'], 'robots_html_continued')
        self.assertFalse(check['policy_verified'])
        self.assertTrue(any('robots_html_policy=continue' in item for item in data['unverified']))
        self.assertIn('robots_html_continued', render_summary(data))
        apis = {item['path']: item for item in data['api_list']}
        self.assertEqual(apis['/api/orders']['declared_methods'], ['POST'])
        self.assertEqual(apis['/api/orders']['observed_methods'], [])
        self.assertEqual(data['summary']['response_documents_parsed'], 1)
        self.assertNotIn('PRIVATE', json.dumps(data))

    def test_default_and_stop_mode_still_stop_after_parsing_the_received_html(self):
        self.assertEqual(Config('https://example.invalid/', ['https://example.invalid']).robots_html_policy, 'stop')
        data, _, requests, _ = collect(policy='stop')
        self.assertEqual([item[0] for item in requests], ['/robots.txt'])
        self.assertEqual(data['summary']['stop_reason'], 'robots_unexpected_content_type')
        self.assertEqual(data['summary']['response_documents_parsed'], 1)

    def test_continue_keeps_depth_page_and_request_budgets(self):
        for options, expected_pages, expected_requests, stop in [
            ({'max_depth': 0}, 2, 4, None),
            ({'max_pages': 1}, 1, 3, 'page_limit'),
            ({'max_requests': 3}, 2, 3, 'request_budget_exhausted'),
        ]:
            with self.subTest(options=options):
                data, _, requests, clock = collect(**options)
                self.assertEqual(len(data['pages']), expected_pages)
                self.assertEqual(len(requests), expected_requests)
                self.assertEqual(data['summary']['stop_reason'], stop)
                self.assertTrue(all(delay >= 1 for delay in clock.sleeps))

    def test_access_failures_pressure_encoding_and_limits_are_not_exceptions(self):
        cases = [
            ((401, HTML, ROBOTS_HTML), {}, 'robots_access_denied'),
            ((403, HTML, ROBOTS_HTML), {}, 'robots_access_denied'),
            ((500, HTML, ROBOTS_HTML), {}, 'robots_http_status'),
            ((429, HTML, ROBOTS_HTML), {}, 'server_backpressure'),
            ((503, HTML, ROBOTS_HTML), {}, 'server_backpressure'),
            ((200, {**HTML, 'Retry-After': '30'}, ROBOTS_HTML), {}, 'server_backpressure'),
            ((200, {**HTML, 'Content-Encoding': 'gzip'}, ROBOTS_HTML), {}, 'robots_fetch_failed'),
            ((200, HTML, ROBOTS_HTML), {'max_response_bytes': 40}, 'robots_response_truncated'),
        ]
        for response, options, reason in cases:
            with self.subTest(status=response[0], reason=reason):
                custom = routes()
                custom['/robots.txt'] = response
                data, _, requests, _ = collect(custom, **options)
                self.assertEqual(len(requests), 1)
                self.assertEqual(data['summary']['stop_reason'], reason)
                self.assertEqual(data['robots_checks'][0]['decision'], 'blocked')

    def test_ambiguous_and_mixed_policies_do_not_become_html_exceptions(self):
        for headers, body in [
            (HTML, 'User-agent: *\nDisallow: /'),
            (HTML, '<html><pre>User-agent: *\nDisallow: /</pre></html>'),
            (HTML, '<html>Disallow: /private</html>'),
            (HTML, '<html>\x00</html>'),
            (HTML, 'not an HTML document'),
            ({'Content-Type': 'text/plain'}, ROBOTS_HTML),
        ]:
            with self.subTest(headers=headers, body=body):
                custom = routes()
                custom['/robots.txt'] = (200, headers, body)
                data, _, requests, _ = collect(custom)
                self.assertEqual(len(requests), 1)
                self.assertEqual(data['robots_checks'][0]['decision'], 'blocked')

    def test_valid_robots_disallow_and_delay_are_still_applied(self):
        custom = routes()
        custom['/robots.txt'] = (200, {'Content-Type': 'text/plain'},
                                'User-agent: *\nDisallow: /one\nCrawl-delay: 2\n')
        data, _, requests, clock = collect(custom)
        self.assertEqual(data['robots_checks'][0]['decision'], 'allowed')
        self.assertNotIn('/one', [item[0] for item in requests])
        self.assertNotIn('/two', [item[0] for item in requests])
        self.assertTrue(all(delay == 2 for delay in clock.sleeps))
        self.assertIn('robots_disallowed', [item['code'] for item in data['issues']])

    def test_redirects_still_check_scope_and_new_origins_check_robots(self):
        custom = routes()
        custom['/robots.txt'] = (302, {'Location': 'https://outside.invalid/robots.txt'}, '')
        data, _, requests, _ = collect(custom)
        self.assertEqual(len(requests), 1)
        self.assertEqual(data['robots_checks'][0]['decision'], 'blocked')
        self.assertEqual(data['robots_checks'][0]['error'], 'outside_scope')
        custom = {'/robots.txt': (200, HTML, ROBOTS_HTML), '/': (200, HTML, '<html>Home</html>')}
        with simulated_server(custom) as (origin, requests):
            second = origin.replace('127.0.0.1', '127.0.0.2')
            config = Config(origin, [origin, second], allowed_loopback_hosts=['127.0.0.1', '127.0.0.2'],
                            seed_urls=[second], robots_html_policy='continue')
            clock = FakeClock()
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        self.assertEqual([item[0] for item in requests], ['/robots.txt', '/', '/robots.txt', '/'])
        self.assertNotEqual(requests[0][2]['Host'], requests[2][2]['Host'])
        self.assertEqual(len(data['robots_checks']), 2)

    def test_configuration_and_approval_are_validated_before_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            for policy in ('ignore', '', True, None, [], {}):
                with self.subTest(policy=policy), self.assertRaises(ConfigError):
                    Config('https://example.invalid', ['https://example.invalid'], robots_html_policy=policy)
            config = Config('https://example.invalid', ['https://example.invalid'], robots_html_policy='continue')
            with self.assertRaises(AuthorizationError):
                Crawler(config)

    def test_cli_plan_and_scan_with_seeds_keep_the_selected_policy(self):
        with tempfile.TemporaryDirectory() as folder, simulated_server(routes()) as (origin, requests):
            config_path = Path(folder) / 'config.json'
            seeds_path = Path(folder) / 'seeds.txt'
            seeds_path.write_text(origin + '/seed\n', encoding='utf-8')
            config_path.write_text(json.dumps({'target_url': origin, 'allowed_origins': [origin],
                                              'allowed_loopback_hosts': ['127.0.0.1'],
                                              'robots_html_policy': 'continue'}), encoding='utf-8')
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['plan', '--config', str(config_path), '--seeds-file', str(seeds_path)]), 0)
                plan = json.loads(output.getvalue())
                self.assertEqual(plan['config']['robots_html_policy'], 'continue')
                self.assertEqual(len(plan['start_urls']), 2)
            clock = FakeClock()
            def crawler(config, authorized):
                return Crawler(config, authorized=authorized, clock=clock.clock, sleep=clock.sleep)
            with patch('webrecon.report.REPOSITORY_ROOT', Path(folder)), patch('webrecon.cli.Crawler', side_effect=crawler), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['scan', '--config', str(config_path), '--seeds-file', str(seeds_path), '--ack-authorized']), 0)
            self.assertIn('관찰 페이지: 5', output.getvalue())
            self.assertEqual(len(requests), 7)
            saved = json.loads(next(Path(folder).joinpath('output').glob('webrecon-*.json')).read_text(encoding='utf-8'))
            self.assertEqual(saved['limits']['robots_html_policy'], 'continue')
            self.assertEqual(saved['summary']['scripts_observed'], 1)
