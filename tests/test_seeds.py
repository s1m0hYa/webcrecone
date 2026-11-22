from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helpers import FakeClock, simulated_server
from webrecon.cli import main
from webrecon.config import Config, ConfigError, MAX_SEED_FILE_BYTES, with_seed_file
from webrecon.crawler import Crawler


class SeedConfigTests(unittest.TestCase):
    def test_file_normalization_comments_bom_and_merging(self):
        config = Config("https://example.invalid/", ["https://example.invalid"], seed_urls=["https://example.invalid/help"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "목록.txt"
            path.write_text("\ufeff# Comment\r\n\r\nhttps://EXAMPLE.INVALID:443/help#section\r\nhttps://example.invalid/products\r\n", encoding="utf-8")
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                config = with_seed_file(config, path)
        self.assertEqual(config.start_urls, ("https://example.invalid/", "https://example.invalid/help", "https://example.invalid/products"))

    def test_invalid_scope_and_non_http_fail_without_echoing_values(self):
        for url in ("https://outside.invalid/?token=PRIVATE", "https://sub.example.invalid", "https://example.invalid:8443", "http://127.0.0.1", "file:///tmp/PRIVATE", "https://user:PRIVATE@example.invalid", "/relative", None):
            with self.subTest(url=url), patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), self.assertRaises(ConfigError) as error:
                Config("https://example.invalid/", ["https://example.invalid"], seed_urls=[url])
            self.assertNotIn("PRIVATE", str(error.exception))

    def test_start_count_and_queue_limits(self):
        for options in ({"seed_urls": [f"https://example.invalid/{index}" for index in range(50)]},
                        {"seed_urls": ["https://example.invalid/help"], "max_queue_size": 1},
                        {"seed_urls": "https://example.invalid/help"}):
            with self.subTest(options=options), self.assertRaises(ConfigError):
                Config("https://example.invalid/", ["https://example.invalid"], **options)

    def test_file_size_and_encoding_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeds.txt"
            for content in (b"x" * (MAX_SEED_FILE_BYTES + 1), b"\xff\xff"):
                path.write_bytes(content)
                with self.assertRaises(ConfigError):
                    with_seed_file(Config("https://example.invalid/", ["https://example.invalid"]), path)

    def test_plan_and_authorization_with_seed_file_are_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps({"target_url": "https://example.invalid/", "allowed_origins": ["https://example.invalid"]}), encoding="utf-8")
            seed_path = Path(directory) / "seeds.txt"
            seed_path.write_text("https://example.invalid/help\nhttps://example.invalid/search?token=PRIVATE", encoding="utf-8")
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), patch("socket.socket", side_effect=AssertionError("socket forbidden")):
                for command in (["plan"], ["scan", "--dry-run"]):
                    with redirect_stdout(io.StringIO()) as output:
                        main(command + ["--config", str(config_path), "--seeds-file", str(seed_path)])
                    plan = json.loads(output.getvalue())
                    self.assertEqual(len(plan["start_urls"]), 3)
                    self.assertEqual(plan["start_urls"][2]["disposition"], "query_not_visited")
                    self.assertNotIn("PRIVATE", output.getvalue())
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(["scan", "--config", str(config_path), "--seeds-file", str(seed_path)])
                self.assertEqual(error.exception.code, 2)


class SeedCrawlerTests(unittest.TestCase):
    def crawl(self, extra_paths, **options):
        routes = {
            "/robots.txt": (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /private"),
            "/": (200, {"Content-Type": "text/html"}, "<title>No links</title>"),
            "/help": (200, {"Content-Type": "text/html"}, '<a href="/child">Child</a><script>fetch("/api/help");</script>'),
            "/products": (200, {"Content-Type": "text/html"}, '<a href="/child">Shared</a>'),
            "/child": (200, {"Content-Type": "text/html"}, '<a href="/grandchild">Deep</a>'),
        }
        with simulated_server(routes) as (origin, requests):
            config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"], seed_urls=[origin + path for path in extra_paths], **options)
            clock = FakeClock()
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        return data, requests, clock

    def test_disconnected_pages_are_depth_zero_then_bfs(self):
        data, requests, clock = self.crawl(["/help", "/products", "/help#duplicate"], max_depth=1)
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/help", "/products", "/child"])
        self.assertEqual([page["depth"] for page in data["pages"]], [0, 0, 0, 1])
        self.assertEqual(clock.sleeps, [1, 1, 1, 1])
        self.assertEqual(data["api_list"][0]["path"], "/api/help")
        self.assertEqual(data["api_list"][0]["declared_methods"], ["GET"])

    def test_seeds_share_global_request_and_page_budgets(self):
        for options in ({"max_requests": 3}, {"max_pages": 2}):
            with self.subTest(options=options):
                data, requests, _ = self.crawl(["/help", "/products"], **options)
                self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/help"])
                self.assertEqual(len(data["pages"]), 2)

    def test_query_actions_api_and_robots_seeds_never_requested(self):
        data, requests, _ = self.crawl(["/search?token=PRIVATE", "/logout", "/api/users", "/private", "/products"], max_depth=0)
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/products"])
        self.assertNotIn("PRIVATE", json.dumps(data))
        self.assertTrue(any(item["kind"] == "seed" and item["disposition"] == "query_not_visited" for item in data["discoveries"]))
        self.assertIn("robots_disallowed", [issue["code"] for issue in data["issues"]])

    def test_new_origin_checks_its_own_robots_and_does_not_reset_budget(self):
        with simulated_server({"/robots.txt": (404, {}, ""), "/": (200, {"Content-Type": "text/html"}, "<title>Home</title>")}) as (origin, requests):
            second = origin.replace("127.0.0.1", "127.0.0.2")
            config = Config(origin, [origin, second], allowed_loopback_hosts=["127.0.0.1", "127.0.0.2"], seed_urls=[second], max_requests=4)
            clock = FakeClock()
            data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/robots.txt", "/"])
        self.assertEqual(len(data["pages"]), 2)
        self.assertNotEqual(requests[0][2]["Host"], requests[2][2]["Host"])
        self.assertEqual(data["summary"]["network_attempts"], 4)
        self.assertEqual(clock.sleeps, [1, 1, 1])
