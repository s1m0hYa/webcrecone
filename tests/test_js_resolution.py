"""Bounded const resolution, provenance, ambiguity, and record-only collection."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.analyzer import analyze_report
from webrecon.cli import main
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.html_report import render_html
from webrecon.javascript import parse_script, public_references
from webrecon.parser import parse_html
from webrecon.report import load_report, save_report


BASE = "https://example.invalid/folder/page"
FIXTURE = Path(__file__).parent / "fixtures" / "assets" / "const-routes.js"


class ConstantResolutionTests(unittest.TestCase):
    def parse(self, source, max_items=1000):
        return parse_script(source, BASE, max_items)

    def test_alias_chain_retains_unknown_id_and_declaration_locations(self):
        source = '\nconst baseUrl="/api";\nconst path=baseUrl+"/users";\nconst url=`${path}/${userId}`;\nfetch(url);'
        refs, patterns, limited = self.parse(source)
        self.assertFalse(limited)
        self.assertEqual(refs, [])  # Do not mistake /api or /users fragments for complete URLs.
        self.assertEqual(len(patterns), 1)
        item = patterns[0]
        self.assertEqual(item["pattern"], "/api/users/{userId}")
        self.assertEqual(item["resolution"], "partial")
        self.assertEqual(item["source_location"], {"line": 5, "column": 1})
        self.assertEqual([(entry["name"], entry["resolution"]) for entry in item["bindings"]],
                         [("baseUrl", "resolved"), ("path", "resolved"), ("url", "partial")])
        self.assertEqual(item["bindings"][0]["declaration"], {"line": 2, "column": 7})
        self.assertEqual(item["unresolved_variables"][0]["reason"], "definition_not_found")
        self.assertIsNone(item["resolved_url"])

    def test_complete_constants_become_candidates_with_declared_methods(self):
        refs, patterns, limited = self.parse('const base="/api", path=base+"/items"; const alias=path; axios.post(alias);')
        self.assertFalse(limited)
        self.assertEqual([(ref["url"], ref["method"]) for ref in refs], [("https://example.invalid/api/items", "POST")])
        self.assertEqual(patterns[0]["resolution"], "resolved")
        self.assertEqual(patterns[0]["observed_methods"], [])
        self.assertEqual(patterns[0]["resolved_url"], refs[0]["url"])

    def test_relative_urls_use_document_context_and_external_origins_are_not_guessed(self):
        refs, patterns, _ = self.parse('const route="./users"; fetch(route); const external="https://outside.invalid/api";fetch(external); fetch(baseUrl+"/users/"+userId);')
        self.assertEqual(refs[0]["url"], "https://example.invalid/folder/users")
        self.assertEqual(patterns[1]["origin"], "https://outside.invalid")
        self.assertIsNone(patterns[2]["origin"])
        self.assertTrue(patterns[2]["unresolved_base"])

    def test_function_block_and_arrow_bindings_do_not_leak(self):
        source = '''const base="/outer";
        function a(base) {fetch(base+"/a");}
        function b() {const base="/inner"; fetch(base+"/b");}
        const c = base => fetch(base+"/c");
        const d = (base) => {fetch(base+"/d");};
        {const base="/block"; fetch(base+"/e");}
        fetch(base+"/f");'''
        _, patterns, _ = self.parse(source)
        self.assertEqual([item["pattern"] for item in patterns], ["{base}/a", "/inner/b", "{base}/c", "{base}/d", "/block/e", "/outer/f"])
        for item in (patterns[0], patterns[2], patterns[3]):
            self.assertEqual(item["unresolved_variables"][0]["reason"], "function_parameter")

    def test_later_local_declaration_shadows_outer_constant(self):
        _, patterns, _ = self.parse('const base="/outer"; {fetch(base+"/x");const base="/later";}')
        self.assertEqual(patterns[0]["pattern"], "{base}/x")
        self.assertEqual(patterns[0]["unresolved_variables"][0]["reason"], "declaration_after_use")

    def test_loop_header_bindings_stay_in_loop_scope(self):
        for body in ('{fetch(base+"/inside");}', 'fetch(base+"/inside");'):
            with self.subTest(body=body):
                _, patterns, _ = self.parse('const base="/outer";for(const base="/loop"; condition;)'+body+'fetch(base+"/outside");')
                self.assertEqual([item["pattern"] for item in patterns], ["/loop/inside", "/outer/outside"])
        _, patterns, _ = self.parse('for(const base="/loop";condition;){fetch(base);}fetch(base);')
        self.assertEqual(patterns[-1]["unresolved_variables"][0]["reason"], "definition_not_found")

    def test_string_delimiters_are_not_scope_syntax(self):
        _, patterns, limited = self.parse('const example=")"\n{const url="/real";fetch(url);} const arrow="=>";')
        self.assertFalse(limited)
        self.assertEqual(patterns[0]["pattern"], "/real")

    def test_aliases_resolve_in_definition_scope_not_call_scope(self):
        _, patterns, _ = self.parse('const base="/outer";const endpoint=base+"/users"; {const base="/inner";fetch(endpoint);}')
        self.assertEqual(patterns[0]["pattern"], "/outer/users")

    def test_const_without_semicolons_and_literals_with_delimiters(self):
        refs, patterns, _ = self.parse('const base="/api"\nconst path=base+"/users"\nfetch(path)')
        self.assertEqual(patterns[0]["pattern"], "/api/users")
        self.assertEqual(refs[0]["url"], "https://example.invalid/api/users")
        _, patterns, _ = self.parse('const open="(";const url="/x/"+open;fetch(url);')
        self.assertEqual(patterns[0]["resolution"], "resolved")

    def test_mutable_duplicate_and_written_bindings_remain_unknown(self):
        for declaration, reason in (
            ('let base="/api";', "mutable_binding"), ('var base="/api";', "mutable_binding"),
            ('const base="/api";const base="/other";', "ambiguous_binding"),
            ('const base="/api";base="/other";', "write_detected"),
            ('const base="/api";base ||= "/other";', "write_detected"),
        ):
            with self.subTest(declaration=declaration):
                _, patterns, _ = self.parse(declaration + 'fetch(base+"/users");')
                self.assertEqual(patterns[0]["pattern"], "{base}/users")
                self.assertEqual(patterns[0]["unresolved_variables"][0]["reason"], reason)

    def test_unsupported_values_keep_reason_without_evaluating_them(self):
        for declaration, expected in (
            ('const url=getPath();', "unsupported_expression"),
            ('const url=1+2;', "unsupported_expression"),
            ('const url="/api/"+config.id;', "property_access"),
            ('const url="/api/"+token;', "sensitive_binding"),
        ):
            with self.subTest(declaration=declaration):
                _, patterns, _ = self.parse(declaration + "fetch(url);")
                self.assertEqual(patterns[0]["unresolved_variables"][0]["reason"], expected)
                self.assertNotEqual(patterns[0]["resolution"], "resolved")

    def test_cycle_depth_expansion_and_token_caps_terminate(self):
        _, patterns, _ = self.parse('const loop=loop; fetch(loop);')
        self.assertEqual(patterns[0]["unresolved_variables"][0]["reason"], "cyclic_reference")
        source = 'const x0="/api";' + ''.join(f'const x{i}=x{i-1};' for i in range(1, 30)) + 'fetch(x29);'
        _, patterns, limited = self.parse(source)
        self.assertTrue(limited)
        self.assertIn("trace_limit", [item["reason"] for item in patterns[0]["unresolved_variables"]])
        _, patterns, limited = self.parse('const url="/' + "a" * 8200 + '";fetch(url);')
        self.assertTrue(limited)
        self.assertEqual(patterns[0]["unresolved_variables"][0]["reason"], "expression_limit")
        with patch("webrecon.js_resolver.MAX_TOKENS", 10):
            refs, patterns, limited = self.parse('const url="/api";fetch(url);fetch(url);')
        self.assertTrue(limited)
        self.assertEqual((refs, patterns), ([], []))

    def test_comments_quoted_code_regex_and_nested_templates_do_not_create_calls(self):
        source = r'''/* const url="/bad";fetch('/comment'); */
        const example="fetch('/quoted')";
        const regex=/fetch\("\/regex"\)/;
        const template=`example ${`fetch('/nested-template')`}`;
        // fetch('/line-comment');
        const url="/real";fetch(url);'''
        refs, patterns, limited = self.parse(source)
        self.assertFalse(limited)
        self.assertEqual([ref["url"] for ref in refs], ["https://example.invalid/real"])
        self.assertEqual([item["pattern"] for item in patterns], ["/real"])

    def test_method_overrides_spreads_and_runtime_values_are_not_assumed(self):
        for options, expected in (('{method:"POST",body:JSON.stringify({id:1})}', ["POST"]),
                                  ('{method:"POST",...options}', []),
                                  ('{method:"POST",method:"DELETE"}', []),
                                  ('{method:"POST"+suffix}', []),
                                  ('{method:"POST",[key]:"DELETE"}', []),
                                  ('{method:method}', []), ('options', [])):
            with self.subTest(options=options):
                _, patterns, _ = self.parse('const url="/api";fetch(url,' + options + ');')
                self.assertEqual(patterns[0]["declared_methods"], expected)

    def test_sensitive_constants_queries_and_source_text_are_not_persisted(self):
        source = 'const token="/SECRET_PRIVATE";const base="/api";const url=base+"/"+token;fetch(url);const query="/api/items?token=QUERY_PRIVATE";fetch(query);'
        refs, patterns, _ = self.parse(source)
        saved = json.dumps([public_references(refs), patterns])
        self.assertNotIn("_PRIVATE", saved)
        self.assertNotIn("const ", saved)
        self.assertIn("sensitive_binding", saved)
        self.assertIn("token=REDACTED", saved)
        self.assertFalse(any("value" in binding for item in patterns for binding in item["bindings"]))

    def test_references_and_patterns_share_item_budget_and_deduplicate(self):
        for limit in range(5):
            refs, patterns, limited = self.parse('const url="/api";fetch(url);fetch(url);fetch(`/api/${id}`);', limit)
            self.assertLessEqual(len(refs) + len(patterns), limit)
        refs, patterns, limited = self.parse('const url="/api";fetch(url);fetch(url);', 2)
        self.assertEqual((len(refs), len(patterns), limited), (1, 1, False))

    def test_inline_scripts_are_separate_analysis_units(self):
        parsed = parse_html('<script>const base="/first";fetch(base+"/users");</script>\n<script>fetch(base+"/users");</script>', BASE)
        first, second = parsed.data["endpoint_patterns"]
        self.assertEqual(first["pattern"], "/first/users")
        self.assertEqual(second["pattern"], "{base}/users")
        self.assertEqual((first["inline_script"]["index"], second["inline_script"]["html_line"]), (1, 2))

    def test_local_crawl_never_visits_resolved_or_partial_js_candidates(self):
        routes = {"/robots.txt": (404, {}, ""),
                  "/": (200, {"Content-Type": "text/html"}, '<script src="/app.js"></script>'),
                  "/app.js": (200, {"Content-Type": "text/javascript"}, FIXTURE.read_text())}
        with simulated_server(routes) as (origin, requests):
            config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"])
            clock = FakeClock()
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/app.js"])
        self.assertEqual(clock.sleeps, [1, 1])
        candidates = {item["path"]: item for item in data["url_list"]}
        self.assertIn("/help-from-js", candidates)
        self.assertEqual(candidates["/api/users/list"]["declared_methods"], ["POST"])
        self.assertEqual(candidates["/api/users/list"]["observed_methods"], [])
        self.assertEqual(candidates["/help-from-js"]["visit_status"], "not_visited")
        self.assertNotIn("/api", candidates)
        self.assertNotIn("_PRIVATE", json.dumps(data))
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            path = save_report(data, config)
            before = path.read_bytes()
            with patch("socket.socket", side_effect=AssertionError("No network")), patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")):
                restored = load_report(path)
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["report", "--input", str(path), "--list", "patterns"]), 0)
            self.assertEqual(json.loads(output.getvalue()), restored["endpoint_patterns"])
            self.assertEqual(restored["endpoint_patterns"], data["endpoint_patterns"])
            self.assertEqual(path.read_bytes(), before)
        html = render_html(data)
        self.assertIn("정적 해석 완료", html)
        self.assertIn("상수 추적 · 미확인 이유", html)
        self.assertIn("지원 범위 내 정의를 찾지 못함", html)
        self.assertIn("호출 시 결정되는 함수 인자", html)
        self.assertNotIn("_PRIVATE", html)

    def test_legacy_patterns_remain_readable_without_invented_evidence(self):
        old = {"pattern": "/api/{id}", "origin": "https://example.invalid", "source": BASE,
               "domain": "example.invalid", "path": "/api/{id}", "declared_methods": ["GET"], "unresolved_base": False}
        data = analyze_report({"pages": [{"endpoint_patterns": [old]}], "endpoints": [], "requests": [], "issues": []})
        self.assertNotIn("bindings", data["endpoint_patterns"][0])
        self.assertIn("변수 값 미확인", render_html(data))
