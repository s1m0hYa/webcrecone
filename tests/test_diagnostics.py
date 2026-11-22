from contextlib import redirect_stdout
import copy
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
from webrecon.http_client import SafeHttpClient
from webrecon.report import load_report, render_summary


def collect(robots, *, seeds=("/help", "/products"), extra=None, **options):
    routes = {
        "/robots.txt": robots,
        "/": (200, {"Content-Type": "text/html"}, "<title>Home</title>"),
        "/help": (200, {"Content-Type": "text/html"}, "<title>Help</title>"),
        "/products": (200, {"Content-Type": "text/html"}, "<title>Products</title>"),
        **(extra or {}),
    }
    with simulated_server(routes) as (origin, requests):
        config = Config(origin, [origin], allowed_loopback_hosts=["127.0.0.1"],
                        seed_urls=[origin + path for path in seeds], **options)
        clock = FakeClock()
        data = Crawler(config, authorized=True, clock=clock.clock, sleep=clock.sleep).run()
    return data, requests


PLAIN = {"Content-Type": "text/plain"}
HTML = {"Content-Type": "text/html"}
VALID_ROBOTS = (200, PLAIN, "User-agent: *\nDisallow: /private\n")


class RobotsDiagnosticsTests(unittest.TestCase):
    def test_html_200_explains_stop_and_inputs_are_not_discoveries(self):
        body = '<html><form><input value="BODY_PRIVATE"></form><script>token="JS_PRIVATE";</script></html>'
        data, requests = collect((200, HTML, body))
        self.assertEqual([item[0] for item in requests], ["/robots.txt"])
        summary = data["summary"]
        self.assertEqual(summary["stop_reason"], "robots_unexpected_content_type")
        self.assertEqual(summary["input_urls"], 3)
        self.assertEqual(summary["input_urls_blocked"], 1)
        self.assertEqual(summary["input_urls_not_visited"], 2)
        self.assertEqual(summary["input_only_endpoints"], 3)
        # The empty form action belongs to the received /robots.txt document, not a seed page.
        self.assertEqual(summary["discovered_endpoints"], 1)
        self.assertEqual(summary["response_endpoints"], 1)
        self.assertEqual(summary["response_documents_parsed"], 1)
        self.assertEqual(summary["pages_parsed"], 0)
        self.assertEqual(summary["queue_remaining"], 2)
        self.assertEqual([item["disposition"] for item in data["start_urls"]], ["blocked", "not_visited", "not_visited"])
        self.assertFalse(any(item["disposition"] in ("queued", "script_queued") for item in data["discoveries"]))
        self.assertEqual(sum(item["input_only"] for item in data["url_list"]), 3)
        check = data["robots_checks"][0]
        self.assertEqual(check["decision"], "blocked")
        self.assertEqual(check["observed_bytes"], len(body.encode()))
        self.assertEqual(check["body_signals"], {"html_markup": True, "user_agent_directive": False, "empty": False})
        self.assertNotIn("_PRIVATE", json.dumps(data))
        text = render_summary(data)
        self.assertIn("HTTP 200 / Content-Type: text/html", text)
        self.assertIn("중단 사유: robots_unexpected_content_type", text)
        self.assertIn("원인: robots_unexpected_content_type", text)
        self.assertIn("입력만 있는 후보: 3", text)
        self.assertIn("수집 자료에서 발견한 경로: 1", text)

    def test_wrong_mime_text_is_distinguishable_but_not_automatically_allowed(self):
        data, requests = collect((200, HTML, "User-agent: *\nDisallow: /private\n"))
        check = data["robots_checks"][0]
        self.assertEqual(check["reason"], "robots_unexpected_content_type")
        self.assertEqual(check["body_signals"]["html_markup"], False)
        self.assertEqual(check["body_signals"]["user_agent_directive"], True)
        self.assertEqual(len(requests), 1)

    def test_failure_reasons_and_no_followup_requests(self):
        cases = [
            ((401, HTML, "denied"), {}, "robots_access_denied"),
            ((403, HTML, "denied"), {}, "robots_access_denied"),
            ((500, PLAIN, "error"), {}, "robots_http_status"),
            ((503, {"Retry-After": "30"}, "busy"), {}, "server_backpressure"),
            ((200, {**PLAIN, "Content-Encoding": "gzip"}, "opaque"), {}, "robots_fetch_failed"),
            ((200, PLAIN, "User-agent: *\n" * 20), {"max_response_bytes": 40}, "robots_response_truncated"),
            ((200, PLAIN, "<html>not robots</html>"), {}, "robots_html_response"),
            ((200, PLAIN, "invalid"), {}, "robots_invalid"),
            ((200, PLAIN, "User-agent: *\nCrawl-delay: NaN"), {}, "robots_unsupported_delay"),
        ]
        for response, options, reason in cases:
            with self.subTest(reason=reason, status=response[0]):
                data, requests = collect(response, **options)
                self.assertEqual(data["summary"]["stop_reason"], reason)
                self.assertEqual(data["robots_checks"][0]["reason"], reason)
                self.assertEqual(data["start_urls"][0]["visit_reason"], reason)
                self.assertEqual(len(requests), 1)
                self.assertIn("중단 사유: " + reason, render_summary(data))

    def test_transport_failure_keeps_specific_error_without_body_signals(self):
        with patch("webrecon.http_client.SafeHttpClient._exchange", side_effect=TimeoutError):
            data, requests = collect(VALID_ROBOTS)
        self.assertEqual(requests, [])
        check = data["robots_checks"][0]
        self.assertEqual(check["reason"], "robots_fetch_failed")
        self.assertEqual(check["error"], "request_timeout")
        self.assertIsNone(check["body_signals"])
        self.assertEqual(data["summary"]["network_attempts"], 1)
        self.assertIn("세부 오류: request_timeout", render_summary(data))

    def test_missing_and_valid_robots_allow_existing_page_flow(self):
        for response, decision in [((404, HTML, "missing"), "missing"),
                                   ((410, HTML, "gone"), "missing"), (VALID_ROBOTS, "allowed")]:
            with self.subTest(status=response[0]):
                data, requests = collect(response)
                self.assertEqual(len(requests), 4)
                self.assertEqual(data["robots_checks"][0]["decision"], decision)
                self.assertIsNone(data["summary"]["stop_reason"])
                self.assertEqual(data["summary"]["input_urls_response_received"], 3)
                self.assertEqual(data["summary"]["pages_parsed"], 3)
                self.assertEqual(data["summary"]["input_only_endpoints"], 0)

    def test_robots_redirect_failure_is_explained(self):
        for headers, error in [({"Location": "https://outside.invalid/robots.txt"}, "outside_scope"),
                               ({}, "redirect_missing_location"),
                               ({"Location": "/robots%bad%"}, "invalid_percent_encoding")]:
            with self.subTest(error=error):
                data, requests = collect((302, headers, ""))
                self.assertEqual(len(requests), 1)
                check = data["robots_checks"][0]
                self.assertEqual(check["reason"], "robots_fetch_failed")
                self.assertEqual(check["error"], error)
                self.assertIsNone(check["body_signals"])
                self.assertIn("세부 오류: " + error, render_summary(data))


class VisitSummaryTests(unittest.TestCase):
    def test_page_timeout_is_distinct_from_unvisited_input(self):
        exchange = SafeHttpClient._exchange
        def fail_root(client, url, address, record):
            if url.endswith("/"):
                raise TimeoutError
            return exchange(client, url, address, record)
        with patch.object(SafeHttpClient, "_exchange", fail_root):
            data, _ = collect(VALID_ROBOTS)
        self.assertEqual(data["summary"]["input_urls_request_failed"], 1)
        self.assertEqual(data["summary"]["input_urls_response_received"], 2)
        self.assertEqual(data["start_urls"][0]["visit_reason"], "request_timeout")
        self.assertIsNone(data["summary"]["stop_reason"])

    def test_interruption_is_reported_for_pending_inputs(self):
        exchange = SafeHttpClient._exchange
        def interrupt_root(client, url, address, record):
            if url.endswith("/"):
                raise KeyboardInterrupt
            return exchange(client, url, address, record)
        with patch.object(SafeHttpClient, "_exchange", interrupt_root):
            data, _ = collect(VALID_ROBOTS)
        self.assertEqual(data["summary"]["stop_reason"], "interrupted")
        self.assertEqual(data["start_urls"][0]["visit_status"], "request_failed")
        self.assertEqual(data["start_urls"][0]["visit_reason"], "interrupted")
        self.assertTrue(all(item["visit_reason"] == "interrupted" for item in data["start_urls"]))
        self.assertEqual(data["summary"]["input_urls_not_visited"], 2)

    def test_page_limit_leaves_pages_unvisited_but_collects_script(self):
        extra = {"/": (200, HTML, '<script src="/app.js"></script><a href="/help">Help</a>'),
                 "/app.js": (200, {"Content-Type": "application/javascript"}, "fetch('/api/items')")}
        data, requests = collect(VALID_ROBOTS, extra=extra, max_pages=1)
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/", "/app.js"])
        self.assertEqual(data["summary"]["stop_reason"], "page_limit")
        self.assertEqual(data["summary"]["input_urls_not_visited"], 2)
        self.assertEqual(data["start_urls"][1]["visit_reason"], "page_limit")
        script = next(item for item in data["discoveries"] if item["kind"] == "script")
        self.assertEqual(script["disposition"], "response_received")
        help_url = next(item for item in data["url_list"] if item["path"] == "/help")
        self.assertTrue(help_url["provided_as_input"])
        self.assertTrue(help_url["found_in_content"])
        self.assertFalse(help_url["input_only"])

    def test_budget_stop_marks_failed_candidate_and_remaining_script(self):
        extra = {"/": (200, HTML, '<script src="/app.js"></script>')}
        data, requests = collect(VALID_ROBOTS, extra=extra, max_requests=2)
        self.assertEqual(len(requests), 2)
        self.assertEqual(data["summary"]["stop_reason"], "request_budget_exhausted")
        self.assertEqual(data["start_urls"][1]["visit_status"], "blocked")
        self.assertEqual(data["start_urls"][2]["visit_status"], "not_visited")
        script = next(item for item in data["discoveries"] if item["kind"] == "script")
        self.assertEqual(script["disposition"], "not_visited")
        self.assertEqual(script["visit_reason"], "request_budget_exhausted")

    def test_redirect_and_duplicate_do_not_erase_observation(self):
        extra = {"/": (302, {"Location": "/help"}, ""),
                 "/help": (200, HTML, '<a href="/alias">Alias</a>'),
                 "/alias": (302, {"Location": "/help"}, "")}
        data, requests = collect(VALID_ROBOTS, seeds=("/help",), extra=extra)
        self.assertEqual([item[0] for item in requests].count("/help"), 1)
        self.assertEqual(data["summary"]["input_urls_response_received"], 2)
        self.assertTrue(all(item["visit_status"] == "response_received" for item in data["start_urls"]))
        self.assertEqual(data["summary"]["pages_parsed"], 1)

    def test_http_error_response_is_not_counted_as_parsed_html(self):
        data, _ = collect(VALID_ROBOTS, seeds=(), extra={"/": (404, HTML, "<title>Missing</title>")})
        self.assertEqual(data["summary"]["input_urls_response_received"], 1)
        self.assertEqual(data["start_urls"][0]["http_status"], 404)
        self.assertEqual(data["summary"]["pages_parsed"], 0)

    def test_legacy_report_is_reconciled_offline_without_rewriting_file(self):
        data, _ = collect((200, HTML, "<html>BODY_PRIVATE</html>"))
        data.pop("robots_checks")
        data["summary"]["stop_reason"] = "robots_unavailable"
        for item in data["discoveries"] + data["start_urls"]:
            item["disposition"] = item.pop("initial_disposition")
            for field in ("visit_status", "visit_reason", "http_status"):
                item.pop(field)
        data.pop("start_urls")  # Older results can recover inputs from their discovery records.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.json"
            original = json.dumps(data).encode()
            path.write_bytes(original)
            with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                loaded = load_report(path)
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["report", "--input", str(path)]), 0)
            self.assertEqual(path.read_bytes(), original)
        check = loaded["robots_checks"][0]
        self.assertEqual(check["reason"], "robots_unexpected_content_type")
        self.assertEqual(check["basis"], "saved_metadata")
        self.assertIsNone(check["body_signals"])
        self.assertEqual(loaded["summary"]["input_only_endpoints"], 3)
        self.assertEqual(loaded["summary"]["input_urls_not_visited"], 2)
        self.assertIn("Content-Type: text/html", output.getvalue())
        self.assertIn("본문 특징: 미확인", output.getvalue())
        self.assertEqual(analyze_report(copy.deepcopy(loaded)), loaded)
