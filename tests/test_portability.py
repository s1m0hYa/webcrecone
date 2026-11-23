"""다른 폴더로 복사한 패키지의 설치 없는 실행. 현재 OS 검증이며 Windows 실기를 대신하지 않는다."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class CopyExecutionTests(unittest.TestCase):
    def test_fresh_copy_without_site_packages_creates_offline_reports(self):
        package = Path(__file__).resolve().parent.parent / "webrecon"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "다른 폴더 with spaces"
            root.mkdir()
            shutil.copytree(package, root / "webrecon", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (root / "config.json").write_text(json.dumps({"target_url": "https://example.invalid/", "allowed_origins": ["https://example.invalid"]}), encoding="utf-8")
            (root / "input.js").write_text('fetch("/api/items", {method:"POST"});', encoding="utf-8")

            def invoke(*args):
                # -S로 site-packages 및 site 초기화를 제외한다. 모든 명령은 오프라인이다.
                return subprocess.run([sys.executable, "-X", "utf8", "-S", "-m", "webrecon", *args], cwd=root,
                                      capture_output=True, encoding="utf-8", timeout=20)

            help_result = invoke("--help")
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            plan = invoke("plan", "--config", "config.json")
            self.assertEqual(plan.returncode, 0, plan.stderr)
            self.assertFalse(json.loads(plan.stdout)["network_enabled"])
            local = invoke("analyze-js", "--input", "input.js", "--base-url", "https://example.invalid/")
            self.assertEqual(local.returncode, 0, local.stderr)
            report = next((root / "output").glob("*.json"))
            data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(data["requests"], [])
            self.assertEqual(data["api_list"][0]["declared_methods"], ["POST"])
            html = report.with_suffix(".html").read_text(encoding="utf-8")
            self.assertIn("data-report-tabs", html)
            self.assertIn("data-pagination", html)
            self.assertNotIn('${script}', html)
            self.assertNotIn('${styles}', html)
            exported = invoke("report", "--input", str(report.relative_to(root)), "--format", "html")
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertTrue(report.with_suffix(".html").is_file())

