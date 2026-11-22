import json
import unittest

from helpers import FakeClock, simulated_server
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.javascript import parse_javascript, public_references
from webrecon.parser import parse_html


class JavaScriptTests(unittest.TestCase):
    def test_static_calls_and_unknown_methods(self):
        code = '''fetch("/api/read"); fetch("/v1/write", {method: "POST"});
        fetch('/v1/nested', {method: 'POST', body: JSON.stringify({id: 1})});
        axios.put('/v1/item'); xhr.open("DELETE", "/v1/item");
        fetch('/api/options', options); fetch(`/api/${identifier}`);
        const hint = "/api/hint?token=QUERY_PRIVATE";
        fetch('api/relative'); fetch('/api/concatenated/' + identifier);'''
        refs, limited = parse_javascript(code, "https://example.invalid/folder/page")
        self.assertFalse(limited)
        methods = {(ref["url"], ref["method"]) for ref in refs}
        self.assertIn(("https://example.invalid/api/read", "GET"), methods)
        self.assertIn(("https://example.invalid/v1/write", "POST"), methods)
        self.assertIn(("https://example.invalid/v1/nested", "POST"), methods)
        self.assertIn(("https://example.invalid/v1/item", "PUT"), methods)
        self.assertIn(("https://example.invalid/v1/item", "DELETE"), methods)
        self.assertIn(("https://example.invalid/api/options", None), methods)
        self.assertIn(("https://example.invalid/folder/api/relative", "GET"), methods)
        self.assertFalse(any("${" in ref["url"] or "concatenated" in ref["url"] for ref in refs))
        self.assertNotIn("QUERY_PRIVATE", json.dumps(public_references(refs)))

    def test_inline_html_and_extraction_cap(self):
        html = '<script>fetch("/api/inline", {method:"POST"});</script><script type="application/json">"/api/not-code"</script>'
        page = parse_html(html, "https://example.invalid/")
        self.assertEqual(page.references[0]["method"], "POST")
        self.assertEqual(len(page.references), 1)
        refs, limited = parse_javascript('fetch("/one");fetch("/two");fetch("/three");', "https://example.invalid/", 1)
        self.assertTrue(limited)
        self.assertEqual(len(refs), 1)

    def _crawl(self, robots_status=404, robots_body="", **limits):
        routes = {
            "/robots.txt": (robots_status, {"Content-Type": "text/plain"}, robots_body),
            "/": (200, {"Content-Type": "text/html"}, '<a href="/about">About</a><script src="/assets/app.js"></script><script src="https://outside.invalid/app.js"></script><script>fetch("/api/inline");</script>'),
            "/about": (200, {"Content-Type": "text/html"}, "<title>About</title>"),
            "/assets/app.js": (200, {"Content-Type": "application/javascript"}, 'fetch("/api/orders", {method:"POST"}); const url="/api/key?token=SCRIPT_PRIVATE";'),
        }
        with simulated_server(routes) as (origin, requests):
            config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"], **limits)
            clock = FakeClock()
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        return data, requests, clock

    def test_missing_robots_continues_html_and_external_js_without_api_calls(self):
        for status in (404, 410):
            with self.subTest(status=status):
                data, requests, clock = self._crawl(status)
                self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/about", "/assets/app.js"])
                self.assertEqual(clock.sleeps, [1, 1, 1])
                self.assertEqual(len(data["scripts"]), 1)
                apis = {item["path"]: item for item in data["api_list"]}
                self.assertEqual(apis["/api/orders"]["declared_methods"], ["POST"])
                self.assertEqual(apis["/api/orders"]["observed_methods"], [])
                self.assertIn("/api/inline", apis)
                self.assertNotIn("SCRIPT_PRIVATE", json.dumps(data))
                self.assertEqual([issue["code"] for issue in data["issues"]], ["robots_missing"])

    def test_robots_access_failure_and_disallow_remain_enforced(self):
        for status in (401, 403, 500, 503):
            with self.subTest(status=status):
                data, requests, _ = self._crawl(status)
                self.assertEqual(len(requests), 1)
                self.assertFalse(data["pages"])
        data, requests, _ = self._crawl(200, "User-agent: *\nDisallow: /assets\n")
        self.assertNotIn("/assets/app.js", [item[0] for item in requests])
        self.assertFalse(data["scripts"])
        self.assertIn("robots_disallowed", [issue["code"] for issue in data["issues"]])

    def test_scripts_share_budget_and_can_be_disabled(self):
        data, requests, _ = self._crawl(max_requests=3)
        self.assertEqual(len(requests), 3)
        self.assertFalse(data["scripts"])
        data, requests, _ = self._crawl(read_scripts=False)
        self.assertEqual(len(requests), 3)
        self.assertTrue(any(item["path"] == "/api/inline" for item in data["api_list"]))

    def test_script_limits_and_redirect_scope(self):
        for extra, expected_error in (({"Location": "https://outside.invalid/evil.js"}, "outside_scope"), ({"Location": "/api/items"}, "api_not_visited")):
            with self.subTest(extra=extra), simulated_server({
                "/robots.txt": (404, {}, ""),
                "/": (200, {"Content-Type": "text/html"}, '<script src="/app.js"></script>'),
                "/app.js": (302, extra, ""),
            }) as (origin, requests):
                clock = FakeClock()
                config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"])
                data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
                self.assertEqual(len(requests), 3)
                self.assertIn(expected_error, [issue["code"] for issue in data["issues"]])

    def test_script_size_encoding_and_type_are_bounded(self):
        cases = [
            ({"Content-Type": "application/javascript"}, 'fetch("/api/private");' * 30, "script_size_limit"),
            ({"Content-Type": "application/javascript", "Content-Encoding": "gzip"}, "encoded", "unsupported_content_encoding"),
            ({"Content-Type": "text/plain"}, '<script>fetch("/api/private")</script>', "unsupported_response_content_type"),
        ]
        for headers, body, reason in cases:
            with self.subTest(reason=reason), simulated_server({
                "/robots.txt": (404, {}, ""),
                "/": (200, {"Content-Type": "text/html"}, '<script src="/app.js"></script>'),
                "/app.js": (200, headers, body),
            }) as (origin, requests):
                clock = FakeClock()
                config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"], max_response_bytes=100)
                data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
                self.assertEqual(len(requests), 3)
                self.assertEqual(data["api_list"], [])
                self.assertIn(reason, [issue["code"] for issue in data["issues"]])
