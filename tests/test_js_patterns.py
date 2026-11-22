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
from webrecon.javascript import parse_javascript
from webrecon.js_patterns import parse_endpoint_patterns
from webrecon.report import save_report


class DynamicPatternTests(unittest.TestCase):
    def test_user_examples_keep_unknown_base(self):
        text = 'fetch(baseUrl + "/users/" + userId); fetch(`/api/users/${userId}`);'
        patterns, limited = parse_endpoint_patterns(text, "https://example.invalid/")
        self.assertFalse(limited)
        self.assertEqual(len(patterns), 2)
        self.assertEqual(patterns[0]["pattern"], "{baseUrl}/users/{userId}")
        self.assertTrue(patterns[0]["unresolved_base"])
        self.assertIsNone(patterns[0]["domain"])
        self.assertEqual(patterns[1]["pattern"], "/api/users/{userId}")
        self.assertEqual(patterns[1]["domain"], "example.invalid")
        self.assertEqual(patterns[1]["declared_methods"], ["GET"])
        self.assertEqual(parse_javascript(text, "https://example.invalid/")[0], [])

    def test_methods_query_masking_relative_and_absolute_patterns(self):
        text = '''axios.post(`/api/users/${user.id}?token=TOKEN_PRIVATE`);
        fetch("./users/" + userId, {method: "DELETE"});
        fetch(`https://outside.invalid/users/${userId}`, options);'''
        patterns, _ = parse_endpoint_patterns(text, "https://example.invalid/folder/page")
        self.assertEqual(patterns[0]["declared_methods"], ["POST"])
        self.assertEqual(patterns[0]["parameter_names"], ["token"])
        self.assertNotIn("TOKEN_PRIVATE", json.dumps(patterns))
        self.assertEqual(patterns[1]["pattern"], "/folder/users/{userId}")
        self.assertEqual(patterns[1]["declared_methods"], ["DELETE"])
        self.assertEqual(patterns[2]["domain"], "outside.invalid")
        self.assertEqual(patterns[2]["declared_methods"], [])

    def test_unsupported_expressions_do_not_evaluate_or_create_patterns(self):
        for expression in ('`/api/${getId()}`', '`/api/${userId + 1}`', 'baseUrl + getPath()', '`https://${host}/api/user`', '`http://[/api/${id}`'):
            with self.subTest(expression=expression):
                patterns, _ = parse_endpoint_patterns('fetch(' + expression + ');', "https://example.invalid/")
                self.assertEqual(patterns, [])

    def test_dedup_and_cap(self):
        patterns, limited = parse_endpoint_patterns('fetch(`/api/${id}`);' * 3, "https://example.invalid/", 1)
        self.assertEqual(len(patterns), 1)
        self.assertFalse(limited)
        patterns, limited = parse_endpoint_patterns('fetch(`/a/${id}`);fetch(`/b/${id}`);', "https://example.invalid/", 1)
        self.assertEqual(len(patterns), 1)
        self.assertTrue(limited)

    def test_inline_external_json_and_cli_never_request_patterns(self):
        routes = {
            "/robots.txt": (404, {}, ""),
            "/": (200, {"Content-Type": "text/html"}, '<script>fetch(baseUrl + "/users/" + userId);</script><script src="/app.js"></script>'),
            "/app.js": (200, {"Content-Type": "text/javascript"}, 'fetch(`/api/users/${userId}`);'),
        }
        with simulated_server(routes) as (origin, requests):
            clock = FakeClock()
            config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"])
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/app.js"])
        self.assertEqual(len(data["endpoint_patterns"]), 2)
        self.assertEqual(data["api_list"], [])
        self.assertFalse(any("{" in item["url"] or "/users/" in item["url"] for item in data["url_list"]))
        self.assertEqual(data["endpoint_patterns"][1]["source"], origin + "/app.js")
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            path = save_report(data, config)
            with patch("socket.socket", side_effect=AssertionError("No network")), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["report", "--input", str(path), "--list", "patterns", "--group-by", "domain"]), 0)
            self.assertEqual(set(json.loads(output.getvalue())), {"unknown", "127.0.0.1"})

    def test_legacy_report_has_empty_patterns(self):
        data = analyze_report({"pages": [], "scripts": [], "endpoints": [], "requests": []})
        self.assertEqual(data["endpoint_patterns"], [])
