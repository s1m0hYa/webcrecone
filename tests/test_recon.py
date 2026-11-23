from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from webrecon.analyzer import analyze_report
from webrecon.cli import main
from webrecon.config import Config
from webrecon.crawler import Crawler
from webrecon.parser import parse_html
from webrecon.report import ReportError, load_report, output_directory, render_summary, save_report
from helpers import FakeClock, ROBOTS, local_server, simulated_server


FIXTURES = Path(__file__).parent / "fixtures"
HTML = FIXTURES.joinpath("index.html").read_text(encoding="utf-8")


def crawl(origin, **kwargs):
    config = Config(origin + "/", [origin], allowed_loopback_hosts=["127.0.0.1"], **kwargs)
    fake = FakeClock()
    return Crawler(config, authorized=True, clock=fake.clock, sleep=fake.sleep).run(), config, fake


def routes():
    return {
        "/robots.txt": ROBOTS,
        "/": (200, {"Content-Type": "text/html", "Set-Cookie": "session=COOKIE_PRIVATE", "Server": "FixtureServer/1.0"}, HTML),
        "/about.html": (200, {"Content-Type": "text/html"}, '<title>About</title><a href="/level2">Two</a>'),
        "/level2": (200, {"Content-Type": "text/html"}, '<a href="/level3">Three</a>'),
        "/assets/app.js": (200, {"Content-Type": "application/javascript"}, FIXTURES.joinpath("assets/app.js").read_text(encoding="utf-8")),
    }


class ParserTests(unittest.TestCase):
    def test_structures_and_fields(self):
        parsed = parse_html(HTML, "https://example.invalid/")
        self.assertEqual(parsed.data["title"], "WebRecon Local Fixture")
        self.assertEqual(parsed.data["comment_count"], 1)
        kinds = {reference["kind"] for reference in parsed.references}
        self.assertTrue({"link", "script", "stylesheet", "iframe", "form", "attribute"} <= kinds)
        form = parsed.data["forms"][0]
        self.assertEqual(form["method"], "POST")
        self.assertEqual([field["name"] for field in form["fields"]], ["username", "password", "csrf", "attachment", "message", "choice"])
        self.assertTrue(form["fields"][0]["required"])
        serialized = json.dumps(parsed.data)
        self.assertNotIn("_PRIVATE", serialized)
        self.assertNotIn("value", form["fields"][0])

    def test_base_and_empty_form_actions(self):
        parsed = parse_html('<base href="/folder/"><a href="page">Link</a><form></form>', "https://example.invalid/original")
        self.assertIn("https://example.invalid/folder/page", [ref["url"] for ref in parsed.references])
        self.assertEqual(parsed.data["forms"][0]["action"], "https://example.invalid/original")

    def test_bounded_extraction(self):
        parsed = parse_html('<a href="/page">Link</a>' * 20, "https://example.invalid/", 3)
        self.assertEqual(len(parsed.references), 3)
        self.assertTrue(parsed.data["extraction_limited"])


class CrawlTests(unittest.TestCase):
    def test_end_to_end_simulated_http(self):
        with simulated_server(routes()) as (origin, requests):
            data, config, fake = crawl(origin)
        self.assertEqual([request[0] for request in requests], ["/robots.txt", "/", "/about.html", "/embedded", "/level2", "/assets/app.js"])
        self.assertEqual(len(data["pages"]), 4)
        self.assertEqual(fake.sleeps, [1, 1, 1, 1, 1])
        self.assertNotIn("_PRIVATE", json.dumps(data))
        endpoints = {item["url"]: item for item in data["endpoints"]}
        self.assertEqual(endpoints[origin + "/search"]["parameter_names"], ["q", "token"])
        self.assertEqual(endpoints[origin + "/login"]["methods"], ["POST"])
        self.assertTrue({"authentication", "file_handling", "data_input"} <= set(endpoints[origin + "/login"]["classification"]["categories"]))
        self.assertIn("external_integration", endpoints["https://outside.invalid/integration"]["classification"]["categories"])
        self.assertEqual(sum(item["url"] == origin + "/about.html" for item in data["endpoints"]), 1)
        dispositions = {item["disposition"] for item in data["discoveries"]}
        self.assertTrue({"duplicate", "query_not_visited", "suspected_state_change", "api_not_visited", "outside_scope", "depth_limit", "reference_only"} <= dispositions)

    def test_budgets_depth_and_queue(self):
        for settings, expected_count, expected_pages in [
            ({"max_requests": 2}, 2, 1), ({"max_pages": 1}, 3, 1),
            ({"max_depth": 0}, 3, 1), ({"max_depth": 1}, 5, 3),
        ]:
            with self.subTest(settings=settings), simulated_server(routes()) as (origin, requests):
                data, _, _ = crawl(origin, **settings)
            self.assertEqual(len(requests), expected_count)
            self.assertEqual(len(data["pages"]), expected_pages)
        custom = routes()
        custom["/"] = (200, {"Content-Type": "text/html"}, '<a href="/one">1</a><a href="/two">2</a>')
        with simulated_server(custom) as (origin, requests):
            data, _, _ = crawl(origin, max_queue_size=1)
        self.assertIn("queue_limit", {item["disposition"] for item in data["discoveries"]})
        self.assertNotIn("/two", [item[0] for item in requests])

    def test_redirect_destinations_not_fetched_twice(self):
        custom = routes()
        custom["/"] = (302, {"Location": "/about.html"}, "")
        custom["/about.html"] = (200, {"Content-Type": "text/html"}, '<a href="/about.html#same">Self</a><a href="/alias">Alias</a>')
        custom["/alias"] = (302, {"Location": "/about.html"}, "")
        with simulated_server(custom) as (origin, requests):
            data, _, _ = crawl(origin)
        self.assertEqual([item[0] for item in requests].count("/about.html"), 1)
        self.assertEqual(data["pages"][0]["url"], origin + "/about.html")

    def test_sitemap_discovery_without_visiting_entries(self):
        custom = routes()
        with simulated_server(custom) as (origin, requests):
            custom["/sitemap.xml"] = (200, {"Content-Type": "application/xml"}, f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{origin}/listed?q=XML_PRIVATE</loc></url><url><loc>https://outside.invalid/extra</loc></url></urlset>')
            data, _, _ = crawl(origin, read_sitemap=True)
        self.assertIn("/sitemap.xml", [item[0] for item in requests])
        self.assertFalse(any("listed" in item[0] for item in requests))
        self.assertNotIn("XML_PRIVATE", json.dumps(data))
        self.assertTrue(any(item["kind"] == "sitemap" for item in data["discoveries"]))

    def test_xml_entities_rejected(self):
        custom = routes()
        custom["/sitemap.xml"] = (200, {"Content-Type": "application/xml"}, '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><urlset>&secret;</urlset>')
        with simulated_server(custom) as (origin, requests):
            data, _, _ = crawl(origin, read_sitemap=True)
        self.assertIn("sitemap_unsafe_xml", [item["code"] for item in data["issues"]])

    def test_robots_wildcard_delay_and_failure(self):
        custom = routes()
        custom["/robots.txt"] = (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /a*out*$\nDisallow: /private\nCrawl-delay: 2.5\n")
        with simulated_server(custom) as (origin, requests):
            data, _, fake = crawl(origin)
        self.assertNotIn("/about.html", [item[0] for item in requests])
        self.assertEqual(fake.sleeps, [2.5, 2.5, 2.5])
        for body in ("<html>soft404</html>", "this is not robots", "User-agent: *\nCrawl-delay: NaN"):
            custom["/robots.txt"] = (200, {"Content-Type": "text/plain"}, body)
            with self.subTest(body=body), simulated_server(custom) as (origin, requests):
                data, _, _ = crawl(origin)
            self.assertEqual(len(requests), 1)
            self.assertFalse(data["pages"])

    def test_robots_truncation_and_encoding_fail_closed(self):
        for body, headers in (("User-agent: *\n" * 100, {"Content-Type": "text/plain"}), ("compressed", {"Content-Type": "text/plain", "Content-Encoding": "gzip"})):
            custom = routes()
            custom["/robots.txt"] = (200, headers, body)
            with self.subTest(headers=headers), simulated_server(custom) as (origin, requests):
                data, _, _ = crawl(origin, max_response_bytes=40)
            self.assertEqual(len(requests), 1)
            self.assertFalse(data["pages"])


class ReportAndCliTests(unittest.TestCase):
    def test_json_round_trip_portable_unicode_path_and_reanalysis(self):
        with simulated_server(routes()) as (origin, requests):
            data, config, _ = crawl(origin, output_dir="output/한글 결과")
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            destination = save_report(data, config)
            self.assertEqual(destination.parent, Path(directory) / "output" / "한글 결과")
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), patch("socket.socket", side_effect=AssertionError("network forbidden")):
                loaded = load_report(destination)
            self.assertEqual(data["endpoints"], loaded["endpoints"])
            self.assertIn("엔드포인트", render_summary(loaded))
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(["report", "--input", str(destination)]), 0)
                self.assertIn("관찰 페이지: 4", stdout.getvalue())
            self.assertFalse(list(destination.parent.glob("*.tmp")))

    def test_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            try:
                (root / "output").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            config = Config("https://example.invalid", ["https://example.invalid"])
            with patch("webrecon.report.REPOSITORY_ROOT", root), self.assertRaises(ReportError):
                output_directory(config)

    def test_plan_dry_run_and_no_authorization_never_use_network(self):
        config_path = str(FIXTURES / "config.loopback.json")
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), patch("socket.socket", side_effect=AssertionError("network forbidden")):
            for args in (["plan", "--config", config_path], ["scan", "--config", config_path, "--dry-run"]):
                with redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(main(args), 0)
                self.assertFalse(json.loads(stdout.getvalue())["network_enabled"])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as context:
                main(["scan", "--config", config_path])
            self.assertEqual(context.exception.code, 2)

    def test_scan_cli_generates_json(self):
        with tempfile.TemporaryDirectory() as directory, simulated_server(routes()) as (origin, requests):
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"target_url": origin, "allowed_origins": [origin], "allowed_loopback_hosts": ["127.0.0.1"], "max_depth": 0}), encoding="utf-8")
            fake = FakeClock()
            real_crawler = Crawler
            def test_crawler(config, authorized):
                return real_crawler(config, authorized=authorized, clock=fake.clock, sleep=fake.sleep)
            with patch("webrecon.report.REPOSITORY_ROOT", Path(directory)), patch("webrecon.cli.Crawler", side_effect=test_crawler), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", "--config", str(config), "--ack-authorized"]), 0)
            reports = list(Path(directory).joinpath("output").glob("webrecon-*.json"))
            self.assertEqual(len(reports), 1)
            self.assertEqual(load_report(reports[0])["summary"]["pages_observed"], 1)
            self.assertTrue(reports[0].with_suffix(".html").is_file())
            self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/assets/app.js"])

    def test_invalid_report_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for data in ({}, {"schema_version": 1, "pages": [], "endpoints": [None], "requests": [], "issues": []}):
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ReportError):
                    load_report(path)


class RealLoopbackIntegrationTests(unittest.TestCase):
    def test_real_http_crawl(self):
        with local_server(routes()) as (origin, requests):
            data, _, _ = crawl(origin)
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/about.html", "/embedded", "/level2", "/assets/app.js"])
        self.assertEqual(len(data["pages"]), 3)

    def test_real_completion_interval(self):
        last_byte_times = []
        with local_server({"/robots.txt": ROBOTS, "/": (200, {"Content-Type": "text/html"}, "<title>Local</title>")},
                          last_byte_times=last_byte_times) as (origin, requests):
            config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"], max_depth=0)
            data = Crawler(config, authorized=True).run()
        self.assertEqual(len(data["pages"]), 1)
        self.assertGreaterEqual(requests[1][1] - last_byte_times[0], 1.0)


if __name__ == "__main__":
    unittest.main()
