"""검출 범위, 누락 사유, 기록 상한과 변수의 선언 범위 분리를 검증한다."""

import json
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.analyzer import analyze_report
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.html_report import render_html
from webrecon.js_patterns import parse_script
from webrecon.parser import parse_html
from webrecon.report import render_summary


BASE = "https://example.invalid/"


class DiagnosticsTests(unittest.TestCase):
    def parse(self, code, limit=1000):
        audit = {}
        refs, patterns, limited = parse_script(code, BASE, limit, diagnostics=audit)
        return refs, patterns, limited, audit

    def test_detected_calls_reconcile_outcomes_and_duplicates(self):
        code = 'fetch("/api");fetch("/api");fetch(`/api/${id}`);fetch(url);fetch(makeUrl());fetch();'
        _, _, limited, audit = self.parse(code)
        self.assertFalse(limited)
        self.assertEqual(audit["detected_calls"], 6)
        self.assertEqual([audit[name + "_calls"] for name in ("resolved", "partial", "unresolved", "excluded")], [2, 1, 1, 2])
        self.assertEqual(audit["duplicate_calls"], 1)
        self.assertEqual(audit["excluded_reasons"], {"unsupported_expression": 2})
        self.assertEqual(audit["calls"][-1]["location"]["line"], 1)

    def test_tokenization_errors_are_distinct_from_empty_script(self):
        for code, reason in (('fetch("unterminated)', 'unterminated_string'), ('fetch("/a";', 'unbalanced_syntax'), ('/*', 'unterminated_comment')):
            with self.subTest(reason=reason):
                _, _, limited, audit = self.parse(code)
                self.assertTrue(limited)
                self.assertEqual(audit["analysis_issues"][0]["reason"], reason)
                self.assertEqual(audit["status"], "incomplete")
        self.assertEqual(self.parse('')[3]["analysis_issues"], [])
        with patch('webrecon.js_resolver.MAX_TOKENS', 2):
            self.assertEqual(self.parse('fetch("/a");')[3]["analysis_issues"][0]["reason"], 'token_limit')

    def test_result_limit_keeps_total_and_caps_detail(self):
        refs, patterns, limited, audit = self.parse('fetch("/a");fetch("/b");fetch(makeUrl());fetch("/c");', 1)
        self.assertTrue(limited)
        self.assertEqual(len(refs) + len(patterns), 1)
        self.assertEqual(audit["detected_calls"], 4)
        self.assertEqual(audit["excluded_reasons"], {"result_limit": 2, "unsupported_expression": 1})
        self.assertEqual((len(audit["calls"]), audit["omitted_call_details"]), (1, 3))

    def test_dynamic_host_and_non_http_reasons_are_preserved(self):
        _, _, _, audit = self.parse('fetch(`https://${host}/api`);fetch("file:///private");')
        self.assertEqual(audit["excluded_reasons"], {"unresolved_authority": 1, "invalid_url": 1})

    def test_opaque_syntax_and_trace_limits_are_visible(self):
        _, _, _, audit = self.parse('const re=/fetch("fake")/;fetch("/real");')
        self.assertEqual(audit["detected_calls"], 1)
        self.assertEqual(audit["analysis_issues"][0]["reason"], 'opaque_syntax_skipped')
        code = 'const x0="/api";' + ''.join(f'const x{i}=x{i-1};' for i in range(1, 20)) + 'fetch(x19);'
        self.assertIn('trace_limit', self.parse(code)[3]["limit_reasons"])

    def test_diagnostics_never_store_expressions_arguments_or_values(self):
        _, _, _, audit = self.parse('fetch(makeUrl("PASSWORD_PRIVATE"));fetch("/api?token=QUERY_PRIVATE");')
        saved = json.dumps(audit)
        self.assertNotIn('_PRIVATE', saved)
        self.assertNotIn('makeUrl', saved)
        self.assertNotIn('fetch(', saved)

    def test_inline_diagnostic_budget_is_shared_across_scripts(self):
        page = parse_html('<script>fetch(makeUrl());</script>' * 12, BASE, 5).data
        diagnostics = page["js_diagnostics"]
        self.assertLessEqual(sum(1 + len(item["calls"]) for item in diagnostics), 5)
        self.assertGreater(page["js_diagnostics_omitted"], 0)
        self.assertTrue(page["extraction_limited"])
        result = analyze_report({'pages': [{'url': BASE, **page}], 'endpoints': [], 'requests': [], 'issues': []})
        self.assertEqual(result['js_summary']['omitted_units'], page['js_diagnostics_omitted'])
        self.assertIn('생략한 스크립트 진단', render_summary(result))

    def test_crawler_records_inline_and_file_context_without_candidate_requests(self):
        routes = {'/robots.txt': (404, {}, ''), '/': (200, {'Content-Type': 'text/html'}, '<script>fetch(makeUrl());</script><script src="/app.js"></script>'),
                  '/app.js': (200, {'Content-Type': 'text/javascript'}, 'const url="/api";fetch((url));')}
        with simulated_server(routes) as (origin, requests):
            clock = FakeClock()
            result = Crawler(Config(origin, [origin], allowed_loopback_hosts=['127.0.0.1']), authorized=True,
                             clock=clock.clock, sleep=clock.sleep).run()
        self.assertEqual([request[0] for request in requests], ['/robots.txt', '/', '/app.js'])
        self.assertEqual(result['js_summary']['detected_calls'], 2)
        self.assertEqual(result['js_summary']['excluded_calls'], 1)
        self.assertEqual(result['js_diagnostics'][0]['inline_script']['index'], 1)
        self.assertTrue(result['js_diagnostics'][1]['source'].endswith('/app.js'))


class VariableInventoryTests(unittest.TestCase):
    def report(self, html):
        page = {'url': BASE, **parse_html(html, BASE).data}
        return analyze_report({'pages': [page], 'endpoints': [], 'requests': [], 'issues': []})

    def test_function_parameters_and_shadowed_constants_remain_separate(self):
        code = 'function a(id){fetch("/api/"+id);}function b(id){fetch("/api/"+id);} const base="/outer";{const base="/inner";fetch(base+"/a");}fetch(base+"/b");'
        data = self.report('<script>' + code + '</script>')
        ids = [item for item in data['variables'] if item['name'] == 'id']
        bases = [item for item in data['variables'] if item['name'] == 'base']
        self.assertEqual((len(ids), len(bases)), (2, 2))
        self.assertNotEqual(ids[0]['declaration'], ids[1]['declaration'])
        self.assertTrue(all(item['reasons'] == ['function_parameter'] for item in ids))

    def test_same_binding_aggregates_patterns_but_inline_units_do_not_merge(self):
        code = 'const base="/api";fetch(base+"/a");fetch(base+"/b");'
        data = self.report('<script>' + code + '</script><script>' + code + '</script>')
        self.assertEqual(len(data['variables']), 2)
        self.assertTrue(all(len(item['endpoints']) == 2 for item in data['variables']))
        html = render_html(data)
        self.assertIn('data-filter="resolution"', html)
        self.assertIn('data-filter="source"', html)
        self.assertIn('id="variables-table"', html)

    def test_legacy_reports_do_not_invent_diagnostics_or_variable_evidence(self):
        data = analyze_report({'pages': [], 'endpoints': [], 'requests': [], 'issues': []})
        self.assertEqual(data['variables'], [])
        self.assertFalse(data['js_summary']['available'])
        self.assertEqual(data['js_diagnostics'], [])

    def test_new_tables_escape_untrusted_source_names_and_patterns(self):
        data = self.report('<script>fetch("/api/"+id);</script>')
        data['variables'][0]['name'] = '<img src=x onerror=attack()>'
        data['variables'][0]['source'] = 'https://example.invalid/" onmouseover="attack'
        data['variables'][0]['endpoints'][0]['pattern'] = '</td><script>attack()</script>'
        html = render_html(data)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('<script>attack()', html)
        self.assertIn('&lt;img', html)
