import ipaddress
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

from webrecon.config import Config, ConfigError, load_config
from webrecon.http_client import AuthorizationError, SafeHttpClient, _PinnedConnection, _retry_after_seconds
from webrecon.safety import RequestLimiter, SafetyStop, redact_url, safe_headers
from webrecon.scope import ResolvedAddress, ScopeController, ScopeError, normalize_url, path_block_reason
from helpers import FakeClock, ROBOTS, simulated_server


class ConfigTests(unittest.TestCase):
    def test_defaults_and_no_dns(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            config = Config("https://example.invalid/", ["https://example.invalid:443"])
        self.assertEqual(config.max_requests, 100)
        self.assertEqual(config.allowed_origins, ("https://example.invalid",))

    def test_limits_cannot_be_relaxed(self):
        for key, value in {
            "request_interval": 0.999, "max_requests": 101, "max_pages": 51,
            "max_depth": 3, "timeout": 11, "max_redirects": 4,
            "max_response_bytes": 1048577, "max_queue_size": 1001,
            "max_items_per_page": 1001, "read_sitemap": "true",
        }.items():
            with self.subTest(key=key), self.assertRaises(ConfigError):
                Config("https://example.invalid/", ["https://example.invalid"], **{key: value})
        for value in (True, float("nan"), float("inf"), "1"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config("https://example.invalid", ["https://example.invalid"], request_interval=value)

    def test_scope_and_output_validation(self):
        for target, origins in [
            ("https://example.invalid/?token=x", ["https://example.invalid"]),
            ("https://example.invalid/logout", ["https://example.invalid"]),
            ("https://example.invalid", []),
            ("https://example.invalid", ["https://example.invalid/path"]),
            ("http://127.0.0.1", ["http://127.0.0.1"]),
        ]:
            with self.subTest(target=target, origins=origins), self.assertRaises(ConfigError):
                Config(target, origins)
        for output in ("/tmp/data", "../output", "output/../../data", "C:\\temp", "output\\test"):
            with self.subTest(output=output), self.assertRaises(ConfigError):
                Config("https://example.invalid", ["https://example.invalid"], output_dir=output)

    def test_json_errors_do_not_echo_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps({"unknown_secret": "PRIVATE"}), encoding="utf-8")
            with self.assertRaises(ConfigError) as context:
                load_config(path)
            self.assertNotIn("PRIVATE", str(context.exception))


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeController(["https://example.invalid:443"])

    def test_exact_origin(self):
        self.assertEqual(self.scope.validate_url("HTTPS://EXAMPLE.INVALID:443/a#frag"), "https://example.invalid/a")
        for url in ("https://example.invalid.evil.test/", "https://sub.example.invalid", "http://example.invalid", "https://example.invalid:444/"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                self.scope.validate_url(url)

    def test_non_http_and_invalid(self):
        for url in ("file:///etc/passwd", "ftp://example.invalid", "data:text/plain,x", "javascript:alert(1)", "https://user:pass@example.invalid", "https://example.invalid\\evil", "https://example.invalid:bad", "https://example.invalid/%QQ", "https://example.invalid/%2e%2e/admin", "https://example.invalid/\n"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_url(url)

    def test_normalization_dedup(self):
        self.assertEqual(normalize_url("HTTPS://EXAMPLE.INVALID:443/%7euser#one"), normalize_url("https://example.invalid/~user#two"))
        self.assertEqual(normalize_url("https://example.invalid"), "https://example.invalid/")
        self.assertEqual(normalize_url("http://[::1]:8080/"), "http://[::1]:8080/")

    def test_non_public_addresses(self):
        for host in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "[::1]", "[fe80::1]", "[::ffff:127.0.0.1]", "[64:ff9b::7f00:1]"):
            url = f"http://{host}/"
            with self.subTest(host=host), self.assertRaises(ScopeError):
                ScopeController([url]).validate_url(url)

    def test_loopback_exception_is_exact(self):
        scope = ScopeController(["http://127.0.0.1:8000", "http://127.0.0.2:8000"], ["127.0.0.1"])
        self.assertEqual(scope.validate_url("http://127.0.0.1:8000/"), "http://127.0.0.1:8000/")
        with self.assertRaises(ScopeError):
            scope.validate_url("http://127.0.0.2:8000/")

    def test_dns_rejects_mixed_answers(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("8.8.8.8", "127.0.0.1")]
        with patch("socket.getaddrinfo", return_value=records), self.assertRaises(ScopeError):
            self.scope.resolve("https://example.invalid/")

    def test_pinned_connect_does_not_resolve_again(self):
        address = ResolvedAddress(socket.AF_INET, ("8.8.8.8", 443))
        with patch("socket.getaddrinfo", side_effect=AssertionError("second DNS lookup")), patch("socket.socket") as factory, patch("ssl.create_default_context") as context:
            connection = _PinnedConnection("example.invalid", 443, 10, address, True)
            connection.connect()
            factory.return_value.connect.assert_called_once_with(("8.8.8.8", 443))
            context.return_value.wrap_socket.assert_called_once_with(factory.return_value, server_hostname="example.invalid")
            connection.close()

    def test_query_and_state_change_paths(self):
        for path in ("/?x=1", "/?", "/logout", "/delete-account", "/%64elete", "/%2564elete", "/run", "/api/users", "/x;session=secret"):
            self.assertIsNotNone(path_block_reason("https://example.invalid" + path))
        self.assertIsNone(path_block_reason("https://example.invalid/about"))


class RateTests(unittest.TestCase):
    def test_completion_not_start_controls_gap(self):
        fake = FakeClock()
        limiter = RequestLimiter(1, 2, fake.clock, fake.sleep)
        limiter.start()
        fake.now += 8
        limiter.complete()
        fake.now += 0.2
        limiter.start()
        self.assertAlmostEqual(fake.sleeps[0], 0.8)
        self.assertGreaterEqual(fake.now, 9)
        limiter.complete()
        with self.assertRaises(SafetyStop):
            limiter.start()

    def test_early_wakeup_waits_again(self):
        fake = FakeClock()
        def sleep(seconds):
            fake.now += min(seconds, 0.25)
        limiter = RequestLimiter(1, 2, fake.clock, sleep)
        limiter.start()
        limiter.complete()
        limiter.start()
        self.assertEqual(fake.now, 1)


class SimulatedClientTests(unittest.TestCase):
    def client(self, origin, **kwargs):
        fake = FakeClock()
        config = Config(origin + "/", [origin], allowed_loopback_hosts=["127.0.0.1"], **kwargs)
        return SafeHttpClient(config, authorized=True, clock=fake.clock, sleep=fake.sleep), fake

    def test_authorization_before_dns(self):
        config = Config("https://example.invalid", ["https://example.invalid"])
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), self.assertRaises(AuthorizationError):
            SafeHttpClient(config)

    def test_invalid_and_outside_url_blocked_before_dns(self):
        config = Config("https://example.invalid", ["https://example.invalid"])
        client = SafeHttpClient(config, authorized=True)
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), patch("socket.socket", side_effect=AssertionError("socket forbidden")):
            for url in ("https://[", "https://outside.invalid", "javascript:x", "https://user:PRIVATE@example.invalid/", "https://example.invalid/?token=PRIVATE"):
                self.assertIsNotNone(client.fetch(url).error)
        self.assertEqual(client.limiter.count, 0)
        self.assertNotIn("PRIVATE", json.dumps(client.records))

    def test_concurrent_use_rejected_before_network(self):
        config = Config("https://example.invalid", ["https://example.invalid"])
        client = SafeHttpClient(config, authorized=True)
        with client._lock, self.assertRaises(SafetyStop):
            client.fetch(config.target_url)
        self.assertEqual(client.limiter.count, 0)

    def test_dns_rebinding_answer_blocks_socket_creation(self):
        config = Config("https://example.invalid", ["https://example.invalid"])
        client = SafeHttpClient(config, authorized=True)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        with patch("socket.getaddrinfo", return_value=addresses), patch("socket.socket", side_effect=AssertionError("socket forbidden")):
            result = client.fetch(config.target_url)
        self.assertEqual(result.error, "robots_fetch_failed")
        self.assertEqual(client.records[0]["error"], "dns_non_public_address")

    def test_redirect_chain_budget_and_completion_gaps(self):
        routes = {"/robots.txt": ROBOTS, "/": (302, {"Location": "/one"}, ""), "/one": (302, {"Location": "/two"}, ""), "/two": (302, {"Location": "/three"}, ""), "/three": (302, {"Location": "/four"}, "")}
        with simulated_server(routes) as (origin, requests):
            client, fake = self.client(origin)
            self.assertEqual(client.fetch(origin + "/").error, "redirect_limit")
        self.assertEqual(len(requests), 5)
        self.assertEqual(fake.sleeps, [1, 1, 1, 1])
        self.assertNotIn("/four", [request[0] for request in requests])

    def test_retry_after_date_or_malformed_stops_without_retry(self):
        self.assertEqual(_retry_after_seconds("120"), 120)
        self.assertIsNone(_retry_after_seconds("not a date"))
        self.assertGreater(_retry_after_seconds("Wed, 01 Jan 2098 00:00:00 GMT"), 0)
        with simulated_server({"/robots.txt": (503, {"Retry-After": "not a date"}, "")}) as (origin, requests):
            client, _ = self.client(origin)
            client.fetch(origin + "/")
            client.fetch(origin + "/next")
        self.assertEqual(client.limiter.stop_reason, "server_backpressure")
        self.assertEqual(len(requests), 1)

    def test_redirect_outside_scope_never_connects(self):
        with simulated_server({"/robots.txt": ROBOTS, "/": (302, {"Location": "https://outside.invalid/"}, "")}) as (origin, requests):
            client, fake = self.client(origin)
            result = client.fetch(origin + "/")
        self.assertEqual(result.error, "outside_scope")
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/"])
        self.assertEqual(fake.sleeps, [1.0])

    def test_redirect_rechecks_robots_and_sensitive_path(self):
        for target, reason in (("/private/data", "robots_disallowed"), ("/logout", "suspected_state_change"), ("/?token=SECRET", "query_not_visited"), ("file:///etc/passwd", "non_http_scheme")):
            with self.subTest(target=target), simulated_server({"/robots.txt": ROBOTS, "/": (302, {"Location": target}, "")}) as (origin, requests):
                client, _ = self.client(origin)
                self.assertEqual(client.fetch(origin + "/").error, reason)
                self.assertEqual(len(requests), 2)
                self.assertNotIn("SECRET", json.dumps(client.records))

    def test_errors_preserve_interval_and_budget(self):
        with simulated_server({"/robots.txt": ROBOTS}) as (origin, requests):
            client, fake = self.client(origin, max_requests=3)
            client.fetch(origin + "/missing")
            with patch.object(client, "_exchange", side_effect=TimeoutError):
                self.assertEqual(client.fetch(origin + "/another").error, "request_timeout")
            self.assertEqual(client.fetch(origin + "/last").error, "request_budget_exhausted")
        self.assertEqual(fake.sleeps, [1, 1])
        self.assertEqual(client.limiter.count, 3)

    def test_failure_then_next_request_waits(self):
        with simulated_server({"/robots.txt": ROBOTS}) as (origin, requests):
            client, fake = self.client(origin)
            client.fetch(origin + "/missing")
            with patch.object(client, "_exchange", side_effect=OSError):
                client.fetch(origin + "/error")
            client.fetch(origin + "/next")
        self.assertEqual(fake.sleeps, [1, 1, 1])

    def test_backpressure_blocks_all_later_requests(self):
        for status, headers in ((429, {"Retry-After": "120"}), (503, {}), (200, {"Retry-After": "10"})):
            with self.subTest(status=status), simulated_server({"/robots.txt": ROBOTS, "/": (status, headers, "")}) as (origin, requests):
                client, _ = self.client(origin)
                self.assertEqual(client.fetch(origin + "/").error, "server_backpressure")
                self.assertEqual(client.fetch(origin + "/next").error, "server_backpressure")
                self.assertEqual(len(requests), 2)

    def test_missing_robots_allows_page_collection(self):
        with simulated_server({"/": (200, {"Content-Type": "text/html"}, "<title>Home</title>")}) as (origin, requests):
            client, _ = self.client(origin)
            self.assertEqual(client.fetch(origin + "/").status, 200)
            self.assertEqual(client.robots_observation_issues[0]["code"], "robots_missing")
        self.assertEqual([item[0] for item in requests], ["/robots.txt", "/"])

    def test_response_cap_and_redirect_cap(self):
        routes = {"/robots.txt": (200, {"Content-Type": "text/plain"}, ""), "/": (200, {"Content-Type": "text/html"}, "x" * 60)}
        with simulated_server(routes) as (origin, requests):
            client, _ = self.client(origin, max_response_bytes=40)
            response = client.fetch(origin + "/")
            self.assertTrue(response.truncated)
            self.assertEqual(len(response.body), 40)
        routes["/"] = (302, {"Location": "/next"}, "")
        with simulated_server(routes) as (origin, requests):
            client, _ = self.client(origin, max_redirects=0)
            self.assertEqual(client.fetch(origin + "/").error, "redirect_limit")
            self.assertEqual(len(requests), 2)

    def test_no_cookie_or_authorization_replay(self):
        routes = {"/robots.txt": ROBOTS, "/": (302, {"Location": "/next", "Set-Cookie": "session=SECRET"}, ""), "/next": (200, {}, "ok")}
        with simulated_server(routes) as (origin, requests):
            client, fake = self.client(origin)
            self.assertEqual(client.fetch(origin + "/").status, 200)
        self.assertEqual(fake.sleeps, [1, 1])
        for _, _, headers in requests:
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("Authorization", headers)
        self.assertNotIn("SECRET", json.dumps(client.records))

    def test_browser_header_preserves_tool_robots_rules(self):
        expected_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
        )
        robots = "User-agent: WebRecon\nDisallow: /private\nRequest-rate: 1/6\n"
        routes = {
            "/robots.txt": (200, {"Content-Type": "text/plain"}, robots),
            "/": (302, {"Location": "/next"}, ""),
            "/next": (200, {"Content-Type": "text/html"}, "<title>Home</title>"),
        }
        with simulated_server(routes) as (origin, requests):
            client, fake = self.client(origin)
            self.assertEqual(client.fetch(origin + "/").status, 200)
            self.assertEqual(client.fetch(origin + "/private").error, "robots_disallowed")
        self.assertEqual([path for path, _, _ in requests], ["/robots.txt", "/", "/next"])
        self.assertEqual(fake.sleeps, [6, 6])
        for _, _, headers in requests:
            self.assertEqual(headers["User-Agent"], expected_agent)

    def test_tls_failure_is_recorded(self):
        with simulated_server({"/robots.txt": ROBOTS}) as (origin, requests):
            client, _ = self.client(origin)
            client.fetch(origin + "/missing")
            with patch.object(client, "_exchange", side_effect=ssl.SSLCertVerificationError):
                self.assertEqual(client.fetch(origin + "/next").error, "tls_certificate_verification_failed")
        self.assertEqual(client.records[-1]["tls_verification"], "failed")


class RedactionTests(unittest.TestCase):
    def test_all_query_values_and_auth_headers_removed(self):
        clean = redact_url("https://example.invalid/path?q=PRIVATE&token=SECRET#hidden")
        self.assertIn("q=REDACTED", clean)
        self.assertNotIn("PRIVATE", clean)
        self.assertNotIn("SECRET", clean)
        headers = safe_headers({"Set-Cookie": "session=SECRET", "Authorization": "Bearer PRIVATE", "X-Debug": "PRIVATE", "Content-Type": "text/html; charset=utf-8"})
        self.assertNotIn("PRIVATE", json.dumps(headers))
        self.assertNotIn("SECRET", json.dumps(headers))
        self.assertEqual(headers["content-type"], "text/html")


if __name__ == "__main__":
    unittest.main()
