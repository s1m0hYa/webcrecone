"""전체 검토에서 재현한 요청 정책 경계. 외부 DNS/서버 없이 실제 HTTP 파서를 거친다."""

import unittest

from helpers import FakeClock, ROBOTS, simulated_server
from webrecon.analyzer import analyze_report
from webrecon.config import Config, ConfigError
from webrecon.crawler import Crawler
from webrecon.http_client import SafeHttpClient
from webrecon.parser import parse_html
from webrecon.scope import normalize_url


ORIGIN = "http://127.0.0.1:8123"
HTML = {"Content-Type": "text/html"}
JS = {"Content-Type": "application/javascript"}


def settings(**options):
    return Config(ORIGIN + "/", [ORIGIN], allowed_loopback_hosts=["127.0.0.1"], **options)


def crawl(routes, **options):
    clock = FakeClock()
    with simulated_server({"/robots.txt": ROBOTS, **routes}) as (_, requests):
        data = Crawler(settings(**options), authorized=True, clock=clock.clock, sleep=clock.sleep).run()
    return data, [row[0] for row in requests], clock


class ReviewRegressionTests(unittest.TestCase):
    def test_empty_query_survives_normalization_and_is_never_queued(self):
        self.assertEqual(normalize_url(ORIGIN + "/x?#fragment"), ORIGIN + "/x?")
        html = '<a href="/link?">query</a><script src="/script.js?"></script><script>location.href="/nav?";import "./module.js?";</script>'
        data, requests, _ = crawl({"/": (200, HTML, html)}, seed_urls=[ORIGIN + "/seed?"])
        self.assertEqual(requests, ["/robots.txt", "/"])
        blocked = [item for item in data["discoveries"] if item["disposition"] == "query_not_visited"]
        self.assertEqual(len(blocked), 5)

    def test_empty_query_does_not_inherit_old_query_values(self):
        page = parse_html('<a href="?">empty</a><a href="?#part">fragment</a>', ORIGIN + "/page?secret=PRIVATE")
        self.assertEqual([ref["url"] for ref in page.references], [ORIGIN + "/page?", ORIGIN + "/page?#part"])

    def test_control_characters_in_html_references_are_not_silently_deleted(self):
        html = '<a href="/ta&#9;b">tab</a><a href="/li&#10;ne">newline</a><script src="/sc&#13;ript.js"></script><a href="/ok">ok</a>'
        data, requests, _ = crawl({"/": (200, HTML, html)})
        self.assertEqual(requests, ["/robots.txt", "/", "/ok"])
        self.assertFalse(any(item["url"].endswith(("/tab", "/line", "/script.js")) for item in data["endpoints"]))

    def test_redirect_empty_query_and_controls_are_blocked_before_second_request(self):
        for destination, reason in (("/next?", "query_not_visited"), ("/ne\txt", "invalid_redirect")):
            with self.subTest(destination=destination), simulated_server({"/robots.txt": ROBOTS, "/": (302, {"Location": destination}, "")}) as (_, requests):
                clock = FakeClock()
                client = SafeHttpClient(settings(), authorized=True, clock=clock.clock, sleep=clock.sleep)
                self.assertEqual(client.fetch(ORIGIN).error, reason)
                self.assertEqual([row[0] for row in requests], ["/robots.txt", "/"])

    def test_short_robots_body_cannot_grant_permission(self):
        routes = {"/robots.txt": (200, {"Content-Type": "text/plain", "Content-Length": "100"}, "User-agent: *\nDisallow:\n")}
        data, requests, _ = crawl(routes)
        self.assertEqual(requests, ["/robots.txt"])
        self.assertEqual(data["summary"]["stop_reason"], "robots_fetch_failed")
        self.assertEqual(data["requests"][0]["error"], "incomplete_response_body")
        self.assertFalse(data["response_documents"])

    def test_short_html_and_js_bodies_do_not_produce_followup_requests(self):
        routes = {"/": (200, HTML, '<a href="/short">page</a><a href="/ok">ok</a><script src="/short.js"></script>'),
                  "/short": (200, {**HTML, "Content-Length": "999"}, '<a href="/must-not-follow">x</a>'),
                  "/ok": (200, HTML, '<title>Complete</title>'),
                  "/short.js": (200, {**JS, "Content-Length": "999"}, 'location.href="/must-not-follow";')}
        data, requests, clock = crawl(routes)
        self.assertEqual(requests, ["/robots.txt", "/", "/short", "/ok", "/short.js"])
        self.assertEqual(clock.sleeps, [1] * 4)
        self.assertFalse(any(item["url"].endswith("/must-not-follow") for item in data["endpoints"]))
        self.assertEqual(sum(item.get("error") == "incomplete_response_body" for item in data["requests"]), 2)
        self.assertEqual(data["summary"]["pages_parsed"], 2)

    def test_complete_and_incomplete_chunked_bodies(self):
        body = b'<title>ok</title>'
        chunk = f'{len(body):x}\r\n'.encode() + body + b'\r\n'
        for complete in (True, False):
            with self.subTest(complete=complete):
                payload = chunk + (b'0\r\n\r\n' if complete else b'')
                data, requests, _ = crawl({"/": (200, {**HTML, "Transfer-Encoding": "chunked"}, payload)})
                self.assertEqual(requests, ["/robots.txt", "/"])
                self.assertEqual(data["summary"]["pages_parsed"], int(complete))
                if not complete:
                    self.assertTrue(data["requests"][-1]["error"])

    def test_malformed_retry_after_still_stops_every_later_request(self):
        for status in (200, 429, 503):
            with self.subTest(status=status), simulated_server({"/robots.txt": ROBOTS, "/": (status, {"Retry-After": "²"}, "")}) as (_, requests):
                clock = FakeClock()
                client = SafeHttpClient(settings(), authorized=True, clock=clock.clock, sleep=clock.sleep)
                self.assertEqual(client.fetch(ORIGIN).error, "server_backpressure")
                self.assertEqual(client.fetch(ORIGIN + "/next").error, "server_backpressure")
                self.assertEqual(len(requests), 2)
                self.assertIsNone(client.records[1]["retry_after_seconds"])

    def test_huge_interval_is_a_config_error_not_an_overflow(self):
        with self.assertRaises(ConfigError):
            settings(request_interval=10 ** 500)

    def test_external_script_uses_html_base_without_changing_provenance(self):
        routes = {"/": (200, HTML, '<base href="/folder/"><script src="/app.js"></script><script>const p="api/inline";fetch(p);</script>'),
                  "/app.js": (200, JS, 'import "./child.js";'),
                  "/child.js": (200, JS, 'fetch("api/users");location.href="next";'),
                  "/folder/next": (200, HTML, '<title>Next</title>')}
        data, requests, _ = crawl(routes)
        self.assertIn("/folder/next", requests)
        self.assertNotIn("/next", requests)
        self.assertEqual({item["path"] for item in data["api_list"]}, {"/folder/api/users", "/folder/api/inline"})
        inline = data["endpoint_patterns"][0]
        self.assertEqual(inline["source"], ORIGIN + "/")
        self.assertEqual(data["scripts"][1]["document"], ORIGIN + "/")
        self.assertEqual(data["scripts"][1]["base_url"], ORIGIN + "/folder/")

    def test_api_classification_survives_endpoint_source_display_cap(self):
        routes = {"/": (200, HTML, ''.join(f'<a href="/p{i}">p</a>' for i in range(20)) + '<script src="/app.js"></script>'),
                  "/app.js": (200, JS, 'fetch("/service", {method:"POST"});'),
                  "/service": (200, HTML, '<title>Service</title>')}
        routes.update({f'/p{i}': (200, HTML, '<a href="/service">service</a>') for i in range(20)})
        data, requests, _ = crawl(routes)
        self.assertEqual(requests.count('/service'), 1)
        item = next(item for item in data['endpoints'] if item['url'].endswith('/service'))
        self.assertEqual(len(item['sources']), 20)
        self.assertIn('api', item['classification']['categories'])
        # report의 오프라인 재분석도 표시용 출처 상한 때문에 API 근거를 잃으면 안 된다.
        again = analyze_report(data)
        item = next(item for item in again['api_list'] if item['path'] == '/service')
        self.assertEqual(item['declared_methods'], ['POST'])
        self.assertEqual(item['observed_methods'], ['GET'])

    def test_script_depth_also_counts_links_and_navigation_to_js_files(self):
        for mime, body in ((HTML, '<a href="/b.js">next</a>'), (JS, 'location.href="/b.js";')):
            with self.subTest(mime=mime):
                data, requests, _ = crawl({'/': (200, HTML, '<script src="/a.js"></script>'),
                                          '/a.js': (200, mime, body)}, max_script_depth=0)
                self.assertEqual(requests, ['/robots.txt', '/', '/a.js'])
                blocked = next(item for item in data['discoveries'] if item['url'].endswith('/b.js'))
                self.assertEqual(blocked['disposition'], 'script_depth_limit')
                self.assertEqual(blocked['script_depth'], 1)
