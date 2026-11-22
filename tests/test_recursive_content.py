"""받은 HTML/JS의 재귀 분석과 새 참조 경로의 안전 제한을 검증한다. 외부 서버는 사용하지 않는다."""

import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.config import Config, ConfigError
from webrecon.cli import main
from webrecon.crawler import Crawler
from webrecon.js_patterns import parse_script
from webrecon.javascript import public_references
from webrecon.parser import parse_html
from webrecon.local_analysis import analyze_js_file


HTML = {"Content-Type": "text/html"}
JS = {"Content-Type": "application/javascript"}
BASE = "https://example.invalid/area/page"


def crawl(routes, **limits):
    with simulated_server({"/robots.txt": (404, {}, ""), **routes}) as (origin, requests):
        clock = FakeClock()
        config = Config(origin + "/", [origin], allowed_loopback_hosts=["127.0.0.1"], **limits)
        data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
    return data, [item[0] for item in requests], clock


class StructuralReferenceTests(unittest.TestCase):
    def parse(self, code, max_items=1000):
        return parse_script(code, BASE, max_items, script_url="https://example.invalid/assets/app.js")

    def test_import_forms_resolve_against_module_while_navigation_uses_document(self):
        code = '''import "./side.js"; import {a} from "./named.mjs";
        export {b} from "../shared.js"; export * from "./all.js";
        import("./lazy.js"); location.href = "next"; window.location.assign("../help");'''
        refs, _, limited = self.parse(code)
        self.assertFalse(limited)
        imports = [ref for ref in refs if ref["kind"] == "script_import"]
        self.assertEqual([ref['url'] for ref in imports], [
            "https://example.invalid/assets/side.js", "https://example.invalid/assets/named.mjs",
            "https://example.invalid/shared.js", "https://example.invalid/assets/all.js", "https://example.invalid/assets/lazy.js"])
        navigation = [ref for ref in refs if ref['kind'] == 'navigation']
        self.assertEqual([ref['url'] for ref in navigation], ["https://example.invalid/area/next", "https://example.invalid/help"])
        self.assertTrue(all(ref['source_location']['line'] >= 1 for ref in refs))
        self.assertTrue(all(ref['method'] is None for ref in refs))

    def test_navigation_constant_resolution_and_local_shadowing(self):
        code = 'const page="/help"; location.replace(page); function test(location) {location.href="/fake";} window.location="/other";'
        refs, _, _ = self.parse(code)
        actual = [ref['url'] for ref in refs if ref['kind'] == 'navigation']
        self.assertEqual(actual, ['https://example.invalid/help', 'https://example.invalid/other'])

    def test_no_guessing_bare_dynamic_imports_comments_strings_or_method_calls(self):
        code = '''import React from "react"; import(name); obj.import("./not-module.js");
        // import("./comment.js"); location.href="/comment";
        const example='location.href="/string"'; fetch("/endpoint",{method:"POST"});
        location.assign(makeUrl()); location.href = `/user/${id}`;'''
        refs, _, _ = self.parse(code)
        self.assertFalse(any(ref['kind'] in ('script_import', 'navigation') for ref in refs))
        self.assertTrue(any(ref['method'] == 'POST' for ref in refs))

    def test_structural_references_share_item_budget_and_mask_values(self):
        refs, patterns, limited = self.parse('import "./a.js";import "./b.js";location.href="/help";', 1)
        self.assertTrue(limited)
        self.assertEqual(len(refs) + len(patterns), 1)
        refs, _, _ = self.parse('import "./a.js?token=IMPORT_PRIVATE";location.href="/help?token=NAV_PRIVATE";')
        self.assertNotIn('_PRIVATE', json.dumps(public_references(refs)))
        refs, _, _ = self.parse(r'import "./a\n.js";location.href="/he\tlp";')
        self.assertFalse(any(ref['kind'] in ('script_import', 'navigation') for ref in refs))

    def test_inline_base_and_source_position_are_preserved(self):
        parsed = parse_html('<base href="/folder/"><script type="module">import "./app.js";location.href="next";</script>', BASE)
        refs = [ref for ref in parsed.references if ref['kind'] in ('script_import', 'navigation')]
        self.assertEqual([ref['url'] for ref in refs], ['https://example.invalid/folder/app.js','https://example.invalid/folder/next'])
        self.assertTrue(all(ref['inline_script']['index'] == 1 and ref['source_location']['line'] == 1 for ref in refs))

    def test_offline_imports_and_navigation_are_not_misclassified_as_api_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'module.js'
            path.write_text('import "./child.js";location.href="/help";')
            with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')), patch('socket.socket', side_effect=AssertionError('No network')):
                data = analyze_js_file(path, BASE)
        self.assertEqual(data['api_list'], [])
        self.assertEqual({item['kinds'][0] for item in data['endpoints']}, {'script_import','navigation'})
        self.assertEqual(data['requests'], [])


class RecursiveResponseTests(unittest.TestCase):
    def chain(self):
        return {
            '/': (200, HTML, '<script src="/assets/start.js"></script>'),
            '/assets/start.js': (200, JS, 'import "./chunk.mjs";'),
            '/assets/chunk.mjs': (200, JS, 'location.href="/details";fetch("/api/record-only");'),
            '/details': (200, HTML, '<script src="/after.js"></script>'),
            '/after.js': (200, HTML, '<a href="/leaf">Leaf</a>'),
            '/leaf': (200, JS, 'fetch("/api/final");location.href="/too-deep";'),
        }

    def test_html_js_html_chain_is_processed_until_queues_are_empty(self):
        data, requests, clock = crawl(self.chain())
        self.assertEqual(requests, ['/robots.txt','/','/assets/start.js','/assets/chunk.mjs','/details','/after.js','/leaf'])
        self.assertEqual(clock.sleeps, [1] * (len(requests)-1))
        self.assertEqual(data['summary']['queue_remaining'], 0)
        self.assertEqual(data['summary']['script_queue_remaining'], 0)
        self.assertEqual({item['path'] for item in data['api_list']}, {'/api/record-only', '/api/final'})
        self.assertEqual(data['summary']['pages_parsed'], 2)
        self.assertEqual(data['summary']['response_documents_parsed'], 1)
        self.assertTrue(any(item.get('initial_disposition') == 'depth_limit' or item['disposition'] == 'depth_limit'
                            for item in data['discoveries'] if item['url'].endswith('/too-deep')))
        self.assertTrue(any(item['url'].endswith('/leaf') and item['parsed'] for item in data['scripts']))
        self.assertTrue(all(not item['observed_methods'] for item in data['api_list']))

    def test_extensionless_script_and_page_url_returning_js_are_analyzed(self):
        data, requests, _ = crawl({'/': (200, HTML, '<a href="/loader">Loader</a><script src="/bundle"></script>'),
                                  '/loader': (200, JS, 'location.href="/next";'), '/bundle': (200, JS, 'fetch("/api/bundle");'),
                                  '/next': (200, HTML, '<a href="/deep">Deep</a>')})
        self.assertIn('/next', requests)
        self.assertIn('/bundle', requests)
        self.assertNotIn('/deep', requests)
        self.assertTrue(any(item['path'] == '/api/bundle' for item in data['api_list']))

    def test_import_redirect_uses_final_file_base_but_keeps_document_context(self):
        data, requests, _ = crawl({'/': (200, HTML, '<script src="/entry.js"></script>'),
                                  '/entry.js': (302, {'Location':'/assets/app.js'}, ''),
                                  '/assets/app.js': (200, JS, 'import "./child.js";'),
                                  '/assets/child.js': (200, JS, 'fetch("relative");location.href="help";'),
                                  '/help': (200, HTML, '<title>Help</title>')})
        self.assertIn('/assets/child.js', requests)
        self.assertIn('/help', requests)
        self.assertNotIn('/assets/help', requests)
        self.assertTrue(any(item['path'] == '/relative' for item in data['api_list']))
        candidate = next(item for item in data['discoveries'] if item['kind'] == 'script_import')
        self.assertTrue(candidate['source'].endswith('/assets/app.js'))
        self.assertEqual(candidate['script_depth'], 1)
        self.assertEqual(candidate['source_location']['line'], 1)

    def test_cycles_duplicates_and_separate_script_depth_are_bounded(self):
        routes = {'/': (200, HTML, '<script src="/a.js"></script>'),
                  '/a.js': (200, JS, 'import "./b.js";import "./b.js";'),
                  '/b.js': (200, JS, 'import "./a.js";import "./c.js";'),
                  '/c.js': (200, JS, 'import "./d.js";')}
        data, requests, _ = crawl(routes)
        self.assertEqual(requests, ['/robots.txt','/','/a.js','/b.js','/c.js'])
        self.assertTrue(any(item['disposition'] == 'script_depth_limit' for item in data['discoveries']))
        _, requests, _ = crawl(routes, max_script_depth=0)
        self.assertEqual(requests, ['/robots.txt','/','/a.js'])
        _, requests, _ = crawl(routes, read_scripts=False)
        self.assertEqual(requests, ['/robots.txt','/'])

    def test_script_html_switch_cannot_reset_dependency_depth(self):
        data, requests, _ = crawl({'/': (200, HTML, '<script src="/a.js"></script>'),
                                  '/a.js': (200, HTML, '<script src="/b.js"></script>'),
                                  '/b.js': (200, HTML, '<script src="/c.js"></script>')}, max_script_depth=1)
        self.assertEqual(requests, ['/robots.txt','/','/a.js','/b.js'])
        self.assertTrue(any(item['url'].endswith('/c.js') and item['disposition']=='script_depth_limit' for item in data['discoveries']))

    def test_navigation_respects_page_budget_and_scripts_share_request_budget(self):
        data, requests, _ = crawl(self.chain(), max_pages=1)
        self.assertEqual(requests, ['/robots.txt','/','/assets/start.js','/assets/chunk.mjs'])
        self.assertEqual(data['summary']['page_stop_reason'], 'page_limit')
        self.assertEqual(data['summary']['queue_remaining'], 1)
        data, requests, _ = crawl(self.chain(), max_requests=3)
        self.assertEqual(len(requests), 3)
        self.assertEqual(data['summary']['stop_reason'], 'request_budget_exhausted')

    def test_new_navigation_and_module_paths_obey_scope_query_action_and_robots(self):
        code = '''import "https://outside.invalid/a.js";import "/a.js?token=QUERY_PRIVATE";
        import "/logout.js";import "/private/a.js";import "/api/script.js";
        location.href="https://outside.invalid/page";location.href="/delete";location.href="/help?q=QUERY_PRIVATE";'''
        data, requests, _ = crawl({'/robots.txt':(200, {'Content-Type':'text/plain'},'User-agent: *\nDisallow: /private\n'),
                                  '/':(200, HTML, '<script src="/app.js"></script>'), '/app.js':(200, JS, code)})
        self.assertEqual(requests, ['/robots.txt','/','/app.js'])
        self.assertNotIn('QUERY_PRIVATE', json.dumps(data))
        reasons = {item['disposition'] for item in data['discoveries']}
        self.assertTrue({'outside_scope','query_not_visited','suspected_state_change','api_not_visited'} <= reasons)
        self.assertIn('robots_disallowed', {item.get('error') for item in data['requests']})

    def test_api_calls_forms_and_weak_literals_remain_record_only(self):
        data, requests, _ = crawl({'/': (200, HTML, '<script src="/app.js"></script><form action="/form" method="GET"></form>'),
                                  '/app.js':(200, JS, 'fetch("/looks-like-a-page");fetch("/post.js",{method:"POST"});const hint="/unused.js";')})
        self.assertEqual(requests, ['/robots.txt','/','/app.js'])
        self.assertTrue({'/looks-like-a-page','/post.js','/unused.js','/form'} <= {item['path'] for item in data['url_list']})

    def test_iframe_document_is_followed_without_running_js_or_forms(self):
        data, requests, _ = crawl({'/':(200, HTML, '<iframe src="/frame"></iframe>'),
                                  '/frame':(200, HTML, '<a href="/child">Child</a><form action="/form"></form>'),
                                  '/child':(200, HTML, '<title>Child</title>')})
        self.assertEqual(requests, ['/robots.txt','/','/frame','/child'])

    def test_error_html_is_extracted_but_cannot_add_requests(self):
        data, requests, _ = crawl({'/':(404, HTML, '<a href="/help">Help</a><script>fetch("/api/error");</script>')})
        self.assertEqual(requests, ['/robots.txt','/'])
        self.assertEqual(data['summary']['pages_parsed'], 0)
        self.assertEqual(data['summary']['response_documents_parsed'], 1)
        self.assertTrue(any(item['path']=='/api/error' for item in data['api_list']))
        self.assertTrue(any(item['url'].endswith('/help') and item['disposition']=='response_reference_only' for item in data['discoveries']))

    def test_error_javascript_is_extracted_without_following_its_imports(self):
        data, requests, _ = crawl({'/':(200, HTML, '<script src="/denied.js"></script>'),
                                  '/denied.js':(403, JS, 'import "./more.js";location.href="/login";fetch("/api/hint");')})
        self.assertEqual(requests, ['/robots.txt','/','/denied.js'])
        self.assertTrue(data['scripts'][0]['analysis_only'])
        self.assertTrue(any(item['path']=='/api/hint' for item in data['api_list']))
        self.assertTrue(any(item['url'].endswith('/more.js') and item['disposition']=='response_reference_only' for item in data['discoveries']))

    def test_module_import_redirect_cannot_escape_scope_or_robots(self):
        for destination, expected in (('https://outside.invalid/end.js', 'outside_scope'), ('/private/end.js', 'robots_disallowed')):
            with self.subTest(destination=destination):
                data, requests, _ = crawl({'/robots.txt':(200, {'Content-Type':'text/plain'}, 'User-agent: *\nDisallow: /private\n'),
                                          '/':(200, HTML, '<script src="/app.js"></script>'),
                                          '/app.js':(200, JS, 'import "./child.js";'),
                                          '/child.js':(302, {'Location':destination}, '')})
                self.assertEqual(requests, ['/robots.txt','/','/app.js','/child.js'])
                self.assertIn(expected, {item.get('error') for item in data['requests']})

    def test_limits_queue_backpressure_and_truncation_stop_new_routes(self):
        data, requests, _ = crawl({'/':(200, HTML, '<script src="/app.js"></script>'),
                                  '/app.js':(200, JS, 'import "./one.js";import "./two.js";'),
                                  '/one.js':(429, JS, 'location.href="/ignored";')}, max_queue_size=1)
        self.assertEqual(requests, ['/robots.txt','/','/app.js','/one.js'])
        self.assertEqual(data['summary']['stop_reason'], 'server_backpressure')
        self.assertTrue(any(item['disposition']=='queue_limit' for item in data['discoveries']))
        data, requests, _ = crawl({'/':(200, HTML,'<script src="/a.js"></script>'),
                                  '/a.js':(200, JS, 'import "./child.js";'+' ' * 120)}, max_response_bytes=100)
        self.assertEqual(requests, ['/robots.txt','/','/a.js'])
        self.assertFalse(any(item['url'].endswith('/child.js') for item in data['discoveries']))

    def test_script_depth_configuration_cannot_exceed_fixed_bound(self):
        for value in (-1, 3, True, '2'):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config(BASE, ['https://example.invalid'], max_script_depth=value)

    def test_js_only_start_url_saves_report_without_claiming_content_discovery(self):
        with simulated_server({'/robots.txt':(404, {}, ''), '/app.js':(200, JS, 'fetch("/api/hint");')}) as (origin, requests), tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / 'config.json'
            config.write_text(json.dumps({'target_url':origin+'/app.js', 'allowed_origins':[origin], 'allowed_loopback_hosts':['127.0.0.1']}))
            clock = FakeClock()
            from webrecon.http_client import SafeHttpClient
            def client(settings, authorized, **options):
                return SafeHttpClient(settings, authorized=authorized, clock=clock.clock, sleep=clock.sleep)
            with patch('webrecon.report.REPOSITORY_ROOT', root), patch('webrecon.crawler.SafeHttpClient', side_effect=client), redirect_stdout(io.StringIO()):
                self.assertEqual(main(['scan', '--config', str(config), '--ack-authorized']), 0)
            result = json.loads(next((root/'output').glob('*.json')).read_text())
            item = next(item for item in result['endpoints'] if item['url'].endswith('/app.js'))
            self.assertTrue(item['response_observed'])
            self.assertFalse(item['found_in_content'])
            self.assertEqual(len(result['pages']), 0)
            self.assertEqual(len(result['scripts']), 1)
            self.assertTrue(list((root/'output').glob('*.html')))
            self.assertEqual([item[0] for item in requests], ['/robots.txt','/app.js'])
