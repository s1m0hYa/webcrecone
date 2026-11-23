"""공유 모듈은 한 번만 받으며 각 문서의 참조·가져온 함수 호출 근거를 분리한다."""
import json
from unittest import TestCase
from unittest.mock import patch

from helpers import ROBOTS, simulated_server
from test_recon import crawl
from webrecon.analyzer import analyze_report
from webrecon.report_explorer import build_explorer
from webrecon.script_contexts import ScriptContexts


def fixture(main=None, library=None):
    def page(body):
        return 200, {"Content-Type": "text/html"}, body

    def js(body):
        return 200, {"Content-Type": "application/javascript"}, body

    return {
        "/robots.txt": ROBOTS,
        "/": page('<a href="/second/">next</a><script src="/app.js"></script>'),
        "/second/": page('<base href="/other/"><script src="/app.js"></script>'),
        "/app.js": js(main if main is not None else 'import {read as lookup} from "./lib.js"\nfunction start(){lookup();}'),
        "/lib.js": js(library if library is not None else
                      'import "./app.js"; export function read(id){fetch("./items?x=PRIVATE"); fetch(`./parts/${id}`);}'),
    }


class ContextTests(TestCase):
    def test_shared_nested_cycle_keeps_base_calls_and_requests_separate(self):
        with simulated_server(fixture()) as (origin, requests):
            data, _, _ = crawl(origin)
        self.assertCountEqual([r[0] for r in requests], ["/robots.txt", "/", "/second/", "/app.js", "/lib.js"])
        self.assertEqual(len(data["scripts"]), 2)
        self.assertEqual(len(data["js_diagnostics"]), 2)
        self.assertEqual({p["path"] for p in data["endpoint_patterns"]}, {"/parts/{id}", "/other/parts/{id}"})
        self.assertEqual({p["path"] for p in data["api_list"]}, {"/items", "/other/items"})
        self.assertTrue(all(p["observed_methods"] == [] for p in data["api_list"]))
        self.assertNotIn("PRIVATE", json.dumps(data))
        # JSON만 읽은 새 세션에서도 각 페이지가 올바른 함수·API로만 연결되어야 한다.
        nodes = build_explorer(analyze_report(json.loads(json.dumps(data))))
        def dest(source, via):
            return [nodes[e["to"]] for e in source["edges"] if e["via"] == via]
        for page in (node for node in nodes if node["kind"] == "page"):
            app, = dest(page, "script.src")
            caller, = dest(app, "선언")
            callee, = dest(caller, "모듈 직접 호출")
            self.assertEqual(callee["label"], "read()")
            self.assertEqual(nodes[callee["unit"]]["document"], page["address"])
            url, = [n["address"] for n in dest(callee, "fetch") if n["kind"] == "api"]
            path = "/items" if page["address"] == origin + "/" else "/other/items"
            self.assertEqual(url.partition("?")[0], origin + path)

    def test_shadow_missing_export_and_member_are_not_calls(self):
        main = ('import {read as fn, missing} from "./lib.js"; '
                'function shadow(fn){ fn(); } function other(){obj.fn(); missing(); }')
        with simulated_server(fixture(main)) as (origin, _):
            data, _, _ = crawl(origin)
        self.assertFalse(any(e["via"] == "모듈 직접 호출" for n in build_explorer(data) for e in n["edges"]))

    def test_separate_imports_of_same_file_and_unobserved_module(self):
        main = ('import {read} from "./lib.js"; import {other as b} from "./lib.js"; '
                'import {lost} from "./lost.js?x=hidden"; function run(){read();b();lost();}')
        with simulated_server(fixture(main, 'export const read=()=>1; export function other(){}')) as (origin, req):
            data, _, _ = crawl(origin)
        self.assertFalse(any("lost" in r[0] for r in req))
        nodes = build_explorer(data)
        for run in (n for n in nodes if n["label"] == "run()"):
            self.assertCountEqual([nodes[e["to"]]["label"] for e in run["edges"] if e["via"] == "모듈 직접 호출"],
                                  ["read()", "other()"])

    def test_exhausted_replay_budget_does_not_borrow_first_document(self):
        with patch.object(ScriptContexts, "MAX_VIEWS", 0), simulated_server(fixture()) as (origin, requests):
            data, _, _ = crawl(origin)
        self.assertEqual(len(requests), 5)
        self.assertIn("script_context_limit", [issue["code"] for issue in data["issues"]])
        nodes = build_explorer(data)
        page = next(n for n in nodes if n["address"] == origin + "/second/" and n["kind"] == "page")
        ref = next(nodes[e["to"]] for e in page["edges"] if e["via"] == "script.src")
        self.assertEqual(ref["edges"], [])
