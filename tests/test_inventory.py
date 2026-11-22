"""Discovery inventories must not cause extra requests or imply verified methods."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.analyzer import analyze_report, group_urls
from webrecon.cli import main
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.parser import parse_robots_paths
from webrecon.report import load_report, save_report


def collect(robots, html="<title>Home</title>", **limits):
    routes = {"/robots.txt": (200, {"Content-Type": "text/plain"}, robots),
              "/": (200, {"Content-Type": "text/html"}, html)}
    with simulated_server(routes) as (origin, requests):
        config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"], **limits)
        clock = FakeClock()
        data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
    return data, config, requests


class RobotsInventoryTests(unittest.TestCase):
    def test_declarations_are_recorded_without_requests(self):
        data, config, requests = collect("User-agent: *\nDisallow: /private\nAllow: /public\nDisallow: /api/internal\n")
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/"])
        paths = data["robots_paths"]
        self.assertEqual([item["path_pattern"] for item in paths], ["/private", "/public", "/api/internal"])
        self.assertTrue(all(item["source"].endswith("/robots.txt") and item["observed_at"] for item in paths))
        self.assertEqual(paths[1]["directive"], "allow")
        self.assertEqual(paths[1]["line_number"], 3)
        api = data["api_list"][0]
        self.assertEqual(api["path"], "/api/internal")
        self.assertEqual(api["method_status"], "unknown")
        self.assertEqual(api["sources"][0]["kind"], "robots")

    def test_patterns_empty_rules_and_sensitive_values(self):
        text = ("User-agent: *\nDisallow:\nAllow: /\nDisallow: /private/*$\n"
                "Disallow: /search?token=QUERY_PRIVATE\nDisallow: /token/PATH_PRIVATE\n"
                "Disallow: https://user:AUTH_PRIVATE@example.invalid/\n"
                "Disallow: /private/*$ # COMMENT_PRIVATE\n")
        paths, limited = parse_robots_paths(text, "https://example.invalid")
        self.assertFalse(limited)
        self.assertEqual(len(paths), 5)
        pattern = next(item for item in paths if item["match_type"] == "pattern")
        self.assertEqual(pattern["path_pattern"], "/private/*$")
        self.assertIsNone(pattern["url"])
        self.assertNotIn("_PRIVATE", json.dumps(paths))
        data, _, _ = collect(text)
        self.assertFalse(any("*" in item["url"] for item in data["url_list"]))

    def test_observation_limit_does_not_weaken_robots(self):
        data, _, requests = collect("User-agent: *\nAllow: /first\nDisallow: /\n", max_items_per_page=1)
        self.assertEqual(len(data["robots_paths"]), 1)
        self.assertEqual([item[0] for item in requests], ["/robots.txt"])
        self.assertIn("robots_path_limit", [item["code"] for item in data["issues"]])
        self.assertIn("robots_disallowed", [item["code"] for item in data["issues"]])

    def test_failed_or_invalid_robots_produces_no_candidates(self):
        for body in ("<html>Disallow: /private</html>", "invalid\nDisallow: /private"):
            with self.subTest(body=body):
                data, _, requests = collect(body)
                self.assertEqual(data["robots_paths"], [])
                self.assertEqual(len(requests), 1)


class UrlInventoryTests(unittest.TestCase):
    def test_methods_distinguish_actual_get_and_declared_post(self):
        html = ('<form action="/api/orders" method="post"><input name="item"></form>'
                '<form action="/api/orders" method="get"></form>'
                '<a href="/api/users">Users</a><form action="/dialog" method="dialog"></form>')
        data, _, requests = collect("User-agent: *\nDisallow:\n", html)
        entries = {entry["path"]: entry for entry in data["url_list"]}
        self.assertEqual(entries["/"]["observed_methods"], ["GET"])
        self.assertEqual(entries["/"]["declared_methods"], [])
        self.assertEqual(entries["/api/orders"]["declared_methods"], ["GET", "POST"])
        self.assertEqual(entries["/api/orders"]["observed_methods"], [])
        self.assertEqual(entries["/api/users"]["method_status"], "unknown")
        self.assertEqual(entries["/dialog"]["method_status"], "unknown")
        self.assertEqual({item["path"] for item in data["api_list"]}, {"/api/orders", "/api/users"})
        self.assertTrue(all(item["method"] == "GET" for item in data["requests"] if item["network_attempted"]))
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/"])

    def test_domain_and_path_groups_preserve_origins_and_methods(self):
        html = ('<form action="https://one.invalid/api/items" method="post"></form>'
                '<a href="https://two.invalid/api/items">Two</a>'
                '<a href="https://one.invalid:8443/api/items">Other port</a>')
        data, _, requests = collect("User-agent: *\nDisallow:\n", html)
        domains = group_urls(data["api_list"], "domain")
        self.assertEqual(set(domains), {"one.invalid", "two.invalid"})
        self.assertEqual(len(domains["one.invalid"]), 2)
        self.assertEqual(len({item["origin"] for item in domains["one.invalid"]}), 2)
        paths = group_urls(data["api_list"], "path")
        self.assertEqual(len(paths["/api/items"]), 3)
        self.assertEqual(len(requests), 2)

    def test_saved_lists_and_offline_cli_grouping(self):
        data, config, _ = collect("User-agent: *\nDisallow: /api/private\n")
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            destination = save_report(data, config)
            with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                loaded = load_report(destination)
                self.assertEqual(loaded["robots_paths"], data["robots_paths"])
                self.assertEqual(loaded["api_list"], data["api_list"])
                for kind in ("urls", "apis"):
                    for grouping in ("domain", "path"):
                        with redirect_stdout(io.StringIO()) as output:
                            self.assertEqual(main(["report", "--input", str(destination), "--list", kind, "--group-by", grouping]), 0)
                        self.assertEqual(json.loads(output.getvalue()), group_urls(data["url_list" if kind == "urls" else "api_list"], grouping))

    def test_legacy_report_reanalysis_and_failed_requests(self):
        data, _, _ = collect("User-agent: *\nDisallow:\n", '<form action="/api/orders" method="post"></form>')
        data.pop("robots_paths")
        for request in data["requests"]:
            request.pop("method", None)
        data["requests"].append({"url": data["target"].rstrip("/") + "/api/orders",
                                 "network_attempted": True, "status": None, "error": "request_timeout"})
        updated = analyze_report(data)
        root = next(item for item in updated["url_list"] if item["path"] == "/")
        self.assertEqual(root["observed_methods"], ["GET"])
        self.assertEqual(updated["api_list"][0]["declared_methods"], ["POST"])
        self.assertEqual(updated["api_list"][0]["observed_methods"], [])
