"""오프라인 양방향 탐색기의 식별·출처·원본 열기 경계."""
import json
from unittest import TestCase
from unittest.mock import patch

from helpers import ROBOTS, simulated_server
from test_recon import crawl
from webrecon.js_patterns import parse_script
from webrecon.report_explorer import build_explorer


class ExplorerTests(TestCase):
    def test_page_script_function_and_api_with_actual_capture(self):
        code = 'function loadUsers() {\n  fetch("/api/users", {method:"POST"});\n}\nloadUsers();'
        routes = {
            "/robots.txt": ROBOTS,
            "/": (200, {"Content-Type":"text/html"}, '<script src="/app.js"></script><link rel="stylesheet" href="/app.css">'),
            "/app.js": (200, {"Content-Type":"application/javascript"}, code),
        }
        with simulated_server(routes) as (origin, requests):
            data, _, _ = crawl(origin)
        with patch("socket.socket", side_effect=AssertionError), patch("socket.getaddrinfo", side_effect=AssertionError):
            nodes = build_explorer(data)
        by_kind = {node["kind"]:node for node in nodes}
        self.assertEqual([r[0] for r in requests], ["/robots.txt", "/", "/app.js"])
        page, script, fn, api = [by_kind[k] for k in ("page","js","function","api")]
        self.assertIn(script["id"], [edge["to"] for edge in page["edges"]])
        self.assertEqual(script["edges"][0]["to"], fn["id"])
        self.assertEqual(fn["label"], "loadUsers()")
        self.assertEqual(fn["uses"], [[4,1]])
        self.assertEqual(fn["edges"], [{"to":api["id"], "via":"fetch", "method":"POST", "at":[2,3]}])
        self.assertTrue(all(n.get("open") for n in (page, script, by_kind["asset"])))
        self.assertNotIn("open",api)
        self.assertNotIn("source_sha256", data["scripts"][0])
        self.assertNotIn(code, json.dumps(data))

    def test_masked_unsafe_and_unproven_addresses_are_inert(self):
        origin = "https://example.invalid"
        addresses = ["/good.css", "/old.css", "/logout/icon.css", "/api/x.css", "/x.css?", "/x.css?k=hidden",
                     "/token/abc.css", "https://external.invalid/style.css", "/blocked.css", "javascript:alert(1)"]
        refs = [{"url": v if ":" in v else origin+v, "kind":"stylesheet","attribute":"link.href",
                 "exact_address":i!=1} for i,v in enumerate(addresses)]
        data = {"limits":{"allowed_origins":[origin]}, "pages":[{"url":origin+"/", "status":200,
                "parsed":True, "references":refs}], "requests":[{"url":origin+"/blocked.css","error":"robots_disallowed"}]}
        nodes = build_explorer(data)
        self.assertEqual([n["address"] for n in nodes if n.get("open")], [origin+"/good.css"])
        self.assertNotIn("hidden", json.dumps(nodes))
        data["analysis_mode"] = "local_js"
        self.assertFalse(any(n.get("open") for n in build_explorer(data)))

    def test_shared_redirected_module_preserves_document_context_and_sources(self):
        origin = "https://example.invalid"
        refs = [{"url":origin+"/app", "kind":"script","attribute":"script.src"}]
        data = {"pages":[{"url":origin+p, "parsed":True, "references":refs} for p in ("/a","/b")],
                "scripts":[{"url":origin+"/module.js","requested_url":origin+"/app","parsed":True,
                            "document":origin+"/a","references":[{"url":origin+"/a/users","kind":"javascript","attribute":"fetch"}]}]}
        nodes = build_explorer(data)
        js, = [n for n in nodes if n["kind"]=="js"]
        self.assertEqual(js["document"], origin+"/a")
        self.assertEqual(sum(any(e["to"]==js["id"] for e in n["edges"]) for n in nodes),2)
        self.assertNotIn(origin+"/b/users",json.dumps(nodes))
        self.assertFalse(any(n.get("open") for n in nodes))

    def test_inline_scopes_and_weak_strings_stay_distinct(self):
        origin = "https://example.invalid"
        refs = [{"url":origin+"/x", "kind":"javascript", "attribute":"string_literal", "inline_script":{"index":1}},
                {"url":origin+"/x", "kind":"javascript", "attribute":"fetch", "inline_script":{"index":2}}]
        nodes = build_explorer({"response_documents":[{"url":origin+"/robots.txt","parsed":True,"references":refs}]})
        units = [n for n in nodes if n["kind"]=="inline"]
        self.assertEqual(len(units), 2)
        self.assertEqual([nodes[n["edges"][0]["to"]]["kind"] for n in units], ["hint","api"])

    def test_named_declarations_exclude_shadowed_member_and_nested_anonymous_uses(self):
        code = ('function load() { fetch("/a"); (() => {fetch("/b");})(); }\n'
                'function other(load) { load(); }\nobj.load();\nload();\n'
                'const f = function hidden() { fetch("/c"); };\n')
        refs, _, _ = parse_script(code,"https://example.invalid")
        direct = {r["url"].split("/")[-1]:r for r in refs}
        self.assertEqual(direct["a"]["function"]["uses"], [{"line":4,"column":1}])
        self.assertNotIn("function",direct["b"])
        self.assertNotIn("function",direct["c"])

    def test_same_endpoint_in_two_functions_keeps_both_sites_and_one_candidate(self):
        code = 'function one() {fetch("/users");} function two() {fetch("/users");}'
        refs, _, limited = parse_script(code, "https://example.invalid", max_items=1)
        self.assertFalse(limited)
        self.assertEqual(len(refs), 1)
        nodes = build_explorer({"scripts":[{"url":"local:input.js","parsed":True,"references":refs}]})
        api, = [node for node in nodes if node["kind"]=="api"]
        self.assertEqual({fn["label"] for fn in nodes if fn["kind"]=="function"
                          and fn["edges"][0]["to"]==api["id"]}, {"one()","two()"})

    def test_script_reference_to_html_uses_actual_document_but_does_not_join_robots_html(self):
        origin = "https://example.invalid"
        page = {"url":origin+"/", "parsed":True, "references":[{"kind":"script","url":origin+"/loader"},
                                                                {"kind":"link","url":origin+"/robots.txt"}]}
        separate = [{"url":origin+"/loader","purpose":"script","parsed":True},
                    {"url":origin+"/robots.txt","purpose":"robots","parsed":True}]
        nodes = build_explorer({"pages":[page], "response_documents":separate})
        self.assertEqual([nodes[e["to"]]["kind"] for e in nodes[0]["edges"]], ["response","asset"])

    def test_ambiguous_redirect_stays_a_reference_without_borrowing_either_response(self):
        origin = "https://example.invalid"
        page = {"url":origin+"/", "parsed":True, "references":[{"kind":"script","url":origin+"/loader"}]}
        scripts = [{"url":origin+path,"requested_url":origin+"/loader","parsed":True} for path in ("/a.js","/b.js")]
        nodes = build_explorer({"pages":[page],"scripts":scripts})
        target = nodes[nodes[0]["edges"][0]["to"]]
        self.assertEqual(target["address"], origin+"/loader")
        self.assertFalse(target.get("captured"))
