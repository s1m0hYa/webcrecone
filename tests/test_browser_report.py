"""설치된 Chromium 계열 브라우저에서 로컬 HTML과 실제 레이아웃을 점검한다."""
from base64 import b64encode
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from helpers import simulated_server
from test_recon import crawl
from test_script_contexts import fixture
from webrecon.html_report import render_html


def installed_browser():
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        if path := shutil.which(name):
            return path
    for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        if folder := os.environ.get(var):
            for exe in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe"):
                path = Path(folder) / exe
                if path.is_file():
                    return str(path)
    return None


# 제품 스크립트 해시는 그대로 두고 임시 테스트 HTML에 고정된 점검 코드 하나만 허용한다.
PROBE = """
(() => {
  const check = (ok, message) => { if (!ok) throw Error(message); };
  const byId = id => document.getElementById(id);
  const change = (id, value, event) => {
    const el = byId(id); el.value = value; el.dispatchEvent(new Event(event));
  };
  try {
    check(!byId("document-section").hidden && !byId("explorer").hidden, "initial tab");
    check(byId("ex-tree").innerText.includes("start()"), "page to function");
    change("ex-kind","function","change");
    check(byId("ex-list").children.length === 40 && !byId("ex-more").hidden, "first 40");
    byId("ex-more").click();
    check(byId("ex-list").children.length > 40, "more");
    change("ex-filter","start()","input"); byId("ex-list").firstElementChild.click();
    check(byId("ex-detail").innerText.includes("모듈 직접 호출"), "import link");
    byId("ex-detail").querySelector(".ex-ref").click();
    check(byId("ex-detail").innerText.includes("이 함수를 호출한 곳"), "reverse caller");
    check(byId("ex-tree").innerText.includes("fetch"), "function to API");
    change("ex-direction","in","change");
    check(byId("ex-tree").innerText.includes("start()"), "reverse tree");
    const panes = [...document.querySelectorAll(".ex-pane")].map(el => el.getBoundingClientRect());
    const narrow = matchMedia("(max-width:620px)").matches;
    check(narrow ? panes[1].top >= panes[0].bottom - 1 : panes[1].left >= panes[0].right - 1, "layout");
    check(document.documentElement.scrollWidth <= innerWidth + 1, "horizontal overflow");
    document.body.dataset.check = narrow ? "narrow-ok" : "wide-ok";
  } catch (err) { document.body.dataset.check = "error-" + err.message; }
})();
"""


class BrowserReportTests(unittest.TestCase):
    @unittest.skipUnless(installed_browser(), "실행 가능한 로컬 Chromium 계열 브라우저 없음")
    def test_real_offline_report_at_two_widths(self):
        main = ('import {read} from "./lib.js"; function start(){read();}\n' +
                "\n".join(f"function sample{i}(){{}}" for i in range(65)))
        with simulated_server(fixture(main)) as (origin, _):
            data, _, _ = crawl(origin)
        digest = b64encode(hashlib.sha256(PROBE.encode()).digest()).decode("ascii")
        html = render_html(data).replace("script-src ", f"script-src 'sha256-{digest}' ", 1)
        html = html.replace("</body>", "<script>" + PROBE + "</script></body>")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "offline report.html")
            path.write_text(html, encoding="utf-8")
            for width, mode in ((1280, "wide"), (580, "narrow")):
                with self.subTest(width=width):
                    result = subprocess.run([installed_browser(), "--headless", "--disable-gpu",
                                             "--disable-background-networking", "--no-first-run",
                                             "--disable-component-update", "--no-default-browser-check",
                                             "--user-data-dir=" + str(Path(folder, str(width))),
                                             f"--window-size={width},900", "--dump-dom", path.as_uri()],
                                            capture_output=True, timeout=45)
                    self.assertEqual(result.returncode, 0, result.stderr[-800:])
                    # Chrome의 DOM 직렬화만 읽는다. 테스트 페이지는 새 창 버튼을 작동시키지 않는다.
                    dom = result.stdout.decode("utf-8", errors="replace")
                    start = dom.find("<body")
                    self.assertIn('data-check="' + mode + '-ok"', dom[start:dom.find(">", start)])
