"""콜 그래프가 선언 범위와 저장된 근거만 사용하는지 검사한다."""
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch

from webrecon.js_patterns import parse_script
from webrecon.local_analysis import analyze_js_file
from webrecon.report import load_report, save_html_report, save_report
from webrecon.parser import parse_html
from webrecon.report_explorer import build_explorer


def analyzed(text, **limits):
    diagnostic = {}
    refs, patterns, _ = parse_script(text, "https://example.invalid/", diagnostics=diagnostic, **limits)
    return {"url":"local:input.js", "parsed":True, "references":refs, "endpoint_patterns":patterns,
            "js_diagnostics":[diagnostic]}


def connections(nodes, kind):
    return [(n["label"], nodes[e["to"]]["label"], e["at"]) for n in nodes for e in n["edges"] if e["via"] == kind]


class SymbolTests(TestCase):
    def test_chain_recursion_and_scoped_template_uses(self):
        source = ('const read = id => `item ${ id }`;\n'
                  'function list(id) { return read(id); }\n'
                  'function start(id) { list(id); start(id); }\nstart(1);')
        nodes = build_explorer({"scripts":[analyzed(source)]})
        self.assertCountEqual(connections(nodes, "직접 호출"), [
            ("list()", "read()", [2,28]), ("start()", "list()", [3,22]), ("start()", "start()", [3,32]),
            ("local:input.js", "start()", [4,1])])
        variables = [n for n in nodes if n["kind"] == "variable"]
        self.assertEqual([n["at"] for n in variables], [[1,14],[2,15],[3,16]])
        self.assertIn(("read()", "id", [1,29]), connections(nodes, "변수 사용"))
        for n in nodes:
            if n["kind"] == "function":
                for e in n["edges"]:
                    if e["via"] == "변수 사용":
                        self.assertEqual(nodes[e["to"]]["at"][0], n["at"][0])

    def test_shadows_members_anonymous_and_reassignment(self):
        source = ('function oldFn() {} oldFn = replacement; oldFn();\n'
                  'function work() {} function test(work) { work(); }\n'
                  'function start(){ obj.work(); const alias = work; alias(); (()=>work())(); }')
        nodes = build_explorer({"scripts":[analyzed(source)]})
        self.assertEqual(connections(nodes, "직접 호출"), [])

    def test_variable_reads_omit_properties_declarations_comments_and_strings(self):
        source = ('const title = "PRIVATE_VALUE"; function format(){\n'
                  'const box = {title: 1}; /* title */ box.title; "title";\n'
                  'return `\\${title} ${title}`; }')
        record = analyzed(source)
        nodes = build_explorer({"scripts":[record]})
        self.assertEqual([(a,b) for a,b,_ in connections(nodes, "변수 사용")], [("format()", "box"), ("format()", "title")])
        self.assertNotIn("PRIVATE_VALUE", json.dumps(record))

    def test_separate_inline_units_and_graph_budget(self):
        code = 'function openList(x) { return x; } openList(1);'
        page = parse_html(('<script>'+code+'</script>')*2, 'https://example.invalid/').data
        nodes = build_explorer({"pages":[{**page, "url":"https://example.invalid/", "parsed":True}]})
        funcs = [n for n in nodes if n["kind"]=="function"]
        self.assertEqual(len(funcs),2)
        self.assertNotEqual(funcs[0]["unit"],funcs[1]["unit"])
        limited_page = parse_html(('<script>'+code+'</script>')*5,'https://example.invalid/',max_items=6).data
        graphs = [d["symbol_graph"] for d in limited_page["js_diagnostics"]]
        self.assertLessEqual(sum(len(g["symbols"])+len(g["relations"]) for g in graphs),6)
        self.assertTrue(any(g["limited"] for g in graphs))

    def test_old_resolved_pattern_keeps_variable_dependency_without_invented_caller(self):
        record = analyzed('const route = "/api/users"; function load(){ fetch(route); } load();')
        record.pop("js_diagnostics")
        nodes = build_explorer({"scripts":[record]})
        self.assertEqual(connections(nodes, "직접 호출"), [])
        [(owner,variable,_)] = connections(nodes,"주소식 의존")
        self.assertEqual(variable, "route")
        self.assertTrue(owner.endswith("/api/users"))
        self.assertEqual(next(n["uses"] for n in nodes if n["kind"]=="function"),[[1,62]])

    def test_local_file_report_roundtrip_and_no_viewer(self):
        source = Path(__file__).parent / "fixtures" / "assets" / "callgraph-demo.js"
        with tempfile.TemporaryDirectory() as work, patch("webrecon.report.REPOSITORY_ROOT", Path(work)), \
                patch("socket.getaddrinfo", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError):
            data = analyze_js_file(source, "https://example.invalid/")
            result = save_report(data, None)
            nodes = build_explorer(load_report(result))
            self.assertEqual(connections(nodes, "직접 호출"), [
                ("local:input.js", "renderSummary()", [13,1]),
                ("summarize()", "formatCount()", [6,12]), ("renderSummary()", "summarize()", [10,12])])
            html = save_html_report(load_report(result)).read_text(encoding="utf-8")
            self.assertIn("변수 사용",html)
            for old in ('type="file"', "ex-code", "arrayBuffer()", "source_sha256"):
                self.assertNotIn(old,html)

    def test_eight_sites_limit_and_arrow_on_separate_statements(self):
        source = "const initial = 1\nfunction render() {}\nconst draw = () => render()\n" + "draw();"*12
        graph = analyzed(source)["js_diagnostics"][0]["symbol_graph"]
        self.assertTrue(graph["limited"])
        self.assertEqual(len([r for r in graph["relations"] if r["kind"]=="call"]),9)
