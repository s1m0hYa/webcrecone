"""제한된 escape/괄호 해석을 검증하며 JS 실행이나 동적 계산을 허용하지 않는다."""

import json
import unittest

from webrecon.js_patterns import parse_script
from webrecon.javascript import public_references


BASE = "https://example.invalid/folder/page"


class ExpressionExtensionTests(unittest.TestCase):
    def test_hex_unicode_slashes_and_grouped_alias(self):
        code = r'const base="\x2fapi"; const url=(base + ("\u002fusers/" + userId));fetch((url));'
        refs, patterns, limited = parse_script(code, BASE)
        self.assertFalse(limited)
        self.assertEqual(refs, [])
        self.assertEqual(patterns[0]["pattern"], "/api/users/{userId}")
        refs, _, _ = parse_script(r'fetch("\/api/\u{75}sers");', BASE)
        self.assertEqual(refs[0]["url"], "https://example.invalid/api/users")

    def test_unicode_surrogate_pairs_and_line_continuations(self):
        refs, _, limited = parse_script('fetch("/api/\\\nusers");fetch("/api/\\\r\nitems");', BASE)
        self.assertFalse(limited)
        self.assertEqual([ref["url"].split("/")[-1] for ref in refs], ["users", "items"])
        refs, _, _ = parse_script(r'fetch("/api/\uD83D\uDE00");', BASE)
        self.assertIn("%F0%9F%98%80", public_references(refs)[0]["url"])

    def test_escaped_template_interpolation_stays_literal(self):
        refs, patterns, _ = parse_script(r'fetch(`\x2fapi/\${notVariable}`);fetch(`\u002fapi/${id}`);', BASE)
        self.assertEqual(len(refs), 1)
        self.assertIn("${notVariable}", refs[0]["url"])
        self.assertEqual(patterns[0]["variables"], ["id"])
        self.assertNotIn("notVariable", json.dumps(patterns))

    def test_invalid_escapes_controls_and_legacy_octal_are_excluded(self):
        for literal, reason in ((r'"/api/\xGG"', "invalid_string_escape"),
                                (r'"/api/\u{110000}"', "invalid_string_escape"),
                                (r'"/api/\uD800"', "invalid_string_escape"),
                                (r'"/api/\1"', "unsupported_string_escape"),
                                (r'"/api/\q"', "unsupported_string_escape"),
                                (r'"/api/\nusers"', "invalid_url")):
            with self.subTest(literal=literal):
                audit = {}
                refs, patterns, _ = parse_script("fetch(" + literal + ");", BASE, diagnostics=audit)
                self.assertEqual((refs, patterns), ([], []))
                self.assertEqual(audit["excluded_reasons"], {reason: 1})

    def test_parentheses_do_not_enable_functions_arithmetic_or_comma(self):
        for expression in ('(getUrl())', '(1+2)', '("/api", "/other")', '(id ? "/a" : "/b")'):
            with self.subTest(expression=expression):
                audit = {}
                refs, patterns, _ = parse_script('fetch(' + expression + ');', BASE, diagnostics=audit)
                self.assertFalse(refs or patterns)
                self.assertEqual(audit["excluded_calls"], 1)

    def test_parenthesis_depth_and_expansion_remain_bounded(self):
        audit = {}
        refs, patterns, limited = parse_script('fetch(' + '(' * 40 + '"/api"' + ')' * 40 + ');', BASE, diagnostics=audit)
        self.assertTrue(limited)
        self.assertFalse(refs or patterns)
        self.assertEqual(audit["excluded_reasons"], {"group_depth_limit": 1})

    def test_decoded_query_values_are_masked(self):
        refs, patterns, _ = parse_script(r'const url=("\x2fapi/items?token=SECRET_PRIVATE");fetch((url));', BASE)
        saved = json.dumps([public_references(refs), patterns])
        self.assertNotIn("SECRET_PRIVATE", saved)
        self.assertIn("token=REDACTED", saved)
