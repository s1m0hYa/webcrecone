"""설치·DNS·HTTP 없는 로컬 파일 분석과 보고서 보존을 검증한다."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from webrecon.analyzer import analyze_report
from webrecon.cli import main
from webrecon.html_report import render_html
from webrecon.local_analysis import LocalAnalysisError, MAX_LOCAL_BYTES, analyze_js_file
from webrecon.report import load_report


BASE = 'https://example.invalid/folder/page'


class LocalAnalysisTests(unittest.TestCase):
    def test_offline_cli_creates_reusable_json_html_and_lists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / '한글-PASSWORD_PRIVATE.js'
            source.write_text('const base="/api";const url=(base+"/users/"+userId);fetch(url);axios.post("/api/items?token=QUERY_PRIVATE");fetch(makeUrl());', encoding='utf-8')
            before = source.read_bytes()
            with patch('socket.socket', side_effect=AssertionError('No network')), patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')), patch('webrecon.report.REPOSITORY_ROOT', root):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(['analyze-js', '--input', str(source), '--base-url', BASE]), 0)
                files = list((root / 'output').glob('*.json'))
                self.assertEqual(len(files), 1)
                raw = files[0].read_bytes()
                data = load_report(files[0])
                self.assertEqual(data['analysis_mode'], 'local_js')
                self.assertFalse(data['network_enabled'])
                self.assertEqual((data['requests'], data['pages'], data['start_urls']), ([], [], []))
                self.assertEqual(data['js_summary']['detected_calls'], 3)
                self.assertEqual(data['js_summary']['excluded_calls'], 1)
                self.assertTrue(all(item['outside_scope'] is None for item in data['url_list']))
                self.assertEqual(data['api_list'][0]['observed_methods'], [])
                self.assertEqual(data['api_list'][0]['declared_methods'], ['POST'])
                self.assertNotIn('_PRIVATE', json.dumps(data))
                self.assertNotIn(str(source), json.dumps(data))
                html = files[0].with_suffix('.html').read_text(encoding='utf-8')
                self.assertIn('범위 미평가', html)
                self.assertIn('로컬 JS 입력', html)
                self.assertIn('id="variables-table"', html)
                self.assertIn('id="js-diagnostics-table"', html)
                self.assertNotIn('_PRIVATE', html)
                for kind, key in (('variables', 'variables'), ('diagnostics', 'js_diagnostics'), ('patterns', 'endpoint_patterns')):
                    with redirect_stdout(io.StringIO()) as listed:
                        self.assertEqual(main(['report', '--input', str(files[0]), '--list', kind]), 0)
                    self.assertEqual(json.loads(listed.getvalue()), data[key])
                self.assertEqual(files[0].read_bytes(), raw)
                self.assertIn('DNS·HTTP 요청 없음', output.getvalue())
            self.assertEqual(source.read_bytes(), before)

    def test_bom_crlf_and_relative_document_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'code.js'
            source.write_bytes(b'\xef\xbb\xbfconst url="./users";\r\nfetch(url);')
            data = analyze_js_file(source, BASE)
        self.assertEqual(data['url_list'][0]['url'], 'https://example.invalid/folder/users')
        self.assertEqual(data['endpoint_patterns'][0]['source_location']['line'], 2)

    def test_oversize_invalid_utf8_missing_and_directory_inputs_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for content in (b'\xff', b' ' * (MAX_LOCAL_BYTES + 1)):
                source = root / 'SECRET_PRIVATE.js'
                source.write_bytes(content)
                with self.assertRaises(LocalAnalysisError) as error:
                    analyze_js_file(source, BASE)
                self.assertNotIn('_PRIVATE', str(error.exception))
            for source in (root, root / 'missing.js'):
                with self.assertRaises(LocalAnalysisError):
                    analyze_js_file(source, BASE)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO API 미지원 환경')
    def test_fifo_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'pipe.js'
            os.mkfifo(fifo)
            with patch('webrecon.local_analysis.os.open', side_effect=AssertionError('Do not open FIFO')):
                with self.assertRaises(LocalAnalysisError):
                    analyze_js_file(fifo, BASE)

    def test_invalid_base_never_reads_file_or_uses_network(self):
        with patch('socket.socket', side_effect=AssertionError('No network')), patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')), patch('webrecon.local_analysis.os.open', side_effect=AssertionError('No file read')):
            for url in ('file:///private', 'https://user:password@example.invalid/', 'not-a-url'):
                with self.assertRaises(LocalAnalysisError):
                    analyze_js_file('unused.js', url)

    def test_cli_rejects_unsupported_grouping_and_missing_arguments(self):
        for args in (['analyze-js', '--input', 'missing.js'], ['report', '--input', 'missing.json', '--list', 'variables', '--group-by', 'domain']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(args)
            self.assertEqual(error.exception.code, 2)

    def test_results_and_diagnostics_survive_offline_reanalysis(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'code.js'
            source.write_text('function first(id){fetch("/api/"+id);}function second(id){fetch("/api/"+id);}', encoding='utf-8')
            data = analyze_js_file(source, BASE)
        restored = analyze_report(json.loads(json.dumps(data)))
        self.assertEqual(len(restored['variables']), 2)
        self.assertEqual(restored['variables'], data['variables'])
        self.assertEqual(restored['js_diagnostics'], data['js_diagnostics'])
        self.assertIn('function_parameter', json.dumps(restored['variables']))
