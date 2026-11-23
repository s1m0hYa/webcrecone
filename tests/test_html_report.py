"""Offline report semantics, hostile content, and persistence boundaries."""

from base64 import b64encode
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_recon import crawl, routes
from helpers import simulated_server
from webrecon.analyzer import analyze_report
from webrecon.cli import main
from webrecon.html_report import render_html, resource_type
from webrecon.report import ReportError, load_report, save_html_report, save_report


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.tables = {}
        self.scripts = []
        self.table = None
        self.cell = None
        self.row = None
        self.in_script = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "table":
            self.table = attrs["id"]
            self.tables[self.table] = []
        elif tag == "tr":
            self.row = []
        elif tag == "td":
            self.cell = ""
        elif tag == "script":
            self.in_script = True
            self.scripts.append("")

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data
        if self.in_script:
            self.scripts[-1] += data

    def handle_endtag(self, tag):
        if tag == "td":
            self.row.append(self.cell)
            self.cell = None
        elif tag == "tr" and self.row:
            self.tables[self.table].append(self.row)
        elif tag == "table":
            self.table = None
        elif tag == "script":
            self.in_script = False


class HtmlReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with simulated_server(routes()) as (origin, requests):
            cls.data, cls.config, _ = crawl(origin, output_dir="output/한글 결과")

    def test_response_methods_and_declarations_are_separate(self):
        before = deepcopy(self.data)
        doc = Document(render_html(self.data))
        rows = doc.tables["endpoints-table"]
        self.assertEqual(len(rows), len(self.data["url_list"]))
        login = next(row for row in rows if row[0].startswith("/login"))
        self.assertEqual(login[2], "미확인")
        self.assertEqual(login[3], "POST")
        self.assertNotIn("200", login[4])
        self.assertIn("미방문", login[4])
        about = next(row for row in rows if row[0].startswith("/about.html"))
        self.assertEqual(about[2], "GET")
        self.assertIn("200", about[4])
        self.assertIn("응답 수신", about[4])
        self.assertIn("password", login[0])  # name only, no field values
        self.assertEqual(before, self.data)

    def test_resource_reference_does_not_claim_a_response(self):
        data = deepcopy(self.data)
        data["url_list"].append({"url": "https://outside.invalid/asset.png", "categories": ["unknown"],
                                 "sources": [], "outside_scope": True, "visit_status": "not_visited"})
        rows = Document(render_html(data)).tables["resources-table"]
        image = next(row for row in rows if row[0].startswith("/asset.png"))
        self.assertEqual(image[1], "이미지")
        self.assertIn("미방문", image[2])
        self.assertEqual(image[3:], ["—", "—"])
        script = next(row for row in rows if row[0].startswith("/assets/app.js"))
        self.assertEqual(script[1], "JavaScript")
        self.assertIn("200", script[2])
        self.assertIsNone(resource_type({"url": "https://example.invalid/login"}))
        self.assertEqual(resource_type({"url": "https://example.invalid/~redacted~", "sources": [{"kind": "script"}]}), "JavaScript")

    def test_tabs_and_pagination_preserve_all_rows_without_javascript(self):
        data = deepcopy(self.data)
        sample = data['url_list'][0]
        data['url_list'] = [{**sample, 'url': f'https://example.invalid/page/{index}'} for index in range(123)]
        document = Document(render_html(data))
        tabs = [attrs for tag, attrs in document.tags if 'data-report-tab' in attrs]
        panels = [attrs for tag, attrs in document.tags if 'data-report-panel' in attrs]
        self.assertEqual(len(tabs), 8)
        self.assertEqual(tabs[0]['href'], '#document-section')
        self.assertEqual({tab['href'][1:] for tab in tabs}, {panel['id'] for panel in panels})
        self.assertTrue(all('hidden' not in panel for panel in panels))
        self.assertEqual(len(document.tables['endpoints-table']), 123)
        self.assertEqual(sum('data-pagination' in attrs for _, attrs in document.tags), 7)
        self.assertTrue(any(attrs.get('data-filter') == 'resource' for _, attrs in document.tags))

    def test_javascript_response_is_not_shown_as_total_analysis_failure(self):
        data = deepcopy(self.data)
        data['pages'] = [{'url':'https://example.invalid/loader', 'status':200, 'parsed':False,
                          'analysis_type':'javascript', 'depth':0}]
        row = Document(render_html(data)).tables['documents-table'][0]
        self.assertIn('JS 분석됨', row[1])
        self.assertNotIn('파싱 안 됨', row[1])

    def test_initial_tab_uses_available_observations(self):
        for pages, patterns, expected in (([], [], 'endpoint-section'), ([], [{'pattern':'/x', 'source':'local:input.js'}], 'pattern-section')):
            data = deepcopy(self.data)
            data['pages'], data['response_documents'], data['endpoint_patterns'] = pages, [], patterns
            if patterns:
                data['url_list'] = []
            doc = Document(render_html(data))
            nav = next(attrs for _, attrs in doc.tags if 'data-report-tabs' in attrs)
            self.assertEqual(nav['data-default-tab'], expected)

    def test_hostile_strings_remain_text_and_script_has_exact_csp_hash(self):
        data = deepcopy(self.data)
        attack = '</script><img src="https://attacker.invalid/x" onerror="alert(1)"><script>alert(2)</script>'
        data["pages"][0]["title"] = attack
        data["summary"]["pages_parsed"] = attack
        data["issues"].append({"code": attack})
        data["url_list"][0]["parameter_names"] = [attack]
        data["endpoint_patterns"] = [{"pattern": attack, "source": "javascript:alert(3)", "declared_methods": [attack]}]
        html = render_html(data)
        doc = Document(html)
        self.assertNotIn(attack, html)
        self.assertIn("&lt;/script&gt;", html)
        self.assertEqual(len(doc.scripts), 1)
        self.assertNotIn("alert(", doc.scripts[0])
        self.assertFalse(any(tag in {"img", "iframe", "object", "embed", "form", "base"} for tag, _ in doc.tags))
        for tag, attrs in doc.tags:
            self.assertFalse(any(key.startswith("on") for key in attrs))
            self.assertNotIn("src", attrs)
            if "href" in attrs:
                self.assertTrue(attrs["href"].startswith("#"))
        policy = next(attrs["content"] for tag, attrs in doc.tags if attrs.get("http-equiv") == "Content-Security-Policy")
        digest = b64encode(hashlib.sha256(doc.scripts[0].encode()).digest()).decode()
        self.assertIn("script-src 'sha256-" + digest + "'", policy)
        self.assertIn("connect-src 'none'", policy)
        self.assertIn("form-action 'none'", policy)

    def test_masks_values_and_omits_raw_headers_and_bodies(self):
        data = deepcopy(self.data)
        data["target"] = "https://example.invalid/?token=QUERY_PRIVATE"
        data["pages"][0]["title"] = "password=TITLE_PRIVATE"
        data["pages"][0]["html"] = "BODY_PRIVATE"
        data["requests"][0]["headers"]["set-cookie"] = "COOKIE_PRIVATE"
        data["requests"][0]["headers"]["authorization"] = "Bearer AUTH_PRIVATE"
        html = render_html(data)
        self.assertNotIn("_PRIVATE", html)
        self.assertIn("token=REDACTED", html)

    def test_old_empty_report_and_unverified_robots_remain_honest(self):
        old = analyze_report({"schema_version": 1, "pages": [], "endpoints": [], "requests": [], "issues": []})
        html = render_html(old)
        self.assertTrue(all(not rows for rows in Document(html).tables.values()))
        data = deepcopy(self.data)
        data["robots_checks"] = [{"url": "https://example.invalid/robots.txt", "status": 200,
                                  "decision": "continued_unverified", "reason": "robots_html_continued"}]
        data["response_documents"] = [{"url": "https://example.invalid/robots.txt", "status": 200,
                                       "parsed": True, "title": "Robots HTML"}]
        html = render_html(data)
        self.assertIn("robots 정책 미확인", html)
        self.assertIn("별도 응답 HTML", html)
        self.assertEqual(len(Document(html).tables["documents-table"]), len(data["pages"]) + 1)

    def test_export_cli_offline_portable_and_preserves_input(self):
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            source = save_report(self.data, self.config)
            original = source.read_bytes()
            with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), patch("socket.socket", side_effect=AssertionError("No network")):
                with redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(main(["report", "--input", str(source), "--format", "html"]), 0)
                html_path = Path(directory).resolve() / "output" / (source.stem + ".html")
                self.assertTrue(html_path.is_file())
                self.assertIn(str(html_path), stdout.getvalue())
                self.assertEqual(len(Document(html_path.read_text(encoding="utf-8")).tables["endpoints-table"]), len(self.data["url_list"]))
                nested = save_html_report(load_report(source), self.config)
                self.assertEqual(nested.parent.name, "한글 결과")
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(list(Path(directory).rglob("*.tmp")))

    def test_atomic_html_write_failure_keeps_prior_report_and_json(self):
        with tempfile.TemporaryDirectory() as directory, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            source = save_report(self.data, self.config)
            source_bytes = source.read_bytes()
            output = save_html_report(self.data, self.config)
            previous = output.read_bytes()
            with patch("webrecon.report.os.replace", side_effect=OSError("read only")), self.assertRaises(ReportError):
                save_html_report(self.data, self.config)
            self.assertEqual(output.read_bytes(), previous)
            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertFalse(list(output.parent.glob("*.tmp")))

    def test_export_rejects_invalid_identifier_and_output_symlink(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside, patch("webrecon.report.REPOSITORY_ROOT", Path(directory)):
            data = deepcopy(self.data)
            data["scan_id"] = "../escape"
            with self.assertRaises(ReportError):
                save_html_report(data)
            self.assertFalse(list(Path(directory).iterdir()))
            try:
                (Path(directory) / "output").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(ReportError):
                save_html_report(self.data)
            self.assertFalse(list(Path(outside).iterdir()))

    def test_cli_rejects_conflicting_presentation_flags(self):
        for extra in (["--format", "html", "--list", "urls"], ["--format", "html", "--group-by", "domain"]):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(["report", "--input", "unused.json", *extra])
            self.assertEqual(exc.exception.code, 2)
