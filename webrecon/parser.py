"""Pure, bounded HTML extraction. Raw URLs are transient; field values are discarded."""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .javascript import parse_script, public_references
from .safety import REDACTED, product_hint, redact_url, safe_name, safe_text
from .scope import resolve_reference


@dataclass
class ParsedPage:
    """data는 저장용 마스킹 자료, references/base_url은 정책·해석용 일시적 원래 주소다."""
    data: dict
    references: list = field(default_factory=list)
    base_url: str | None = None


class _PageParser(HTMLParser):
    def __init__(self, url, max_items):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base_url = url
        self.base_seen = False
        self.max_items = max_items
        self.item_count = 0
        self.limited = False
        self.title_parts = []
        self.in_title = False
        self.references = []
        self.forms = []
        self.current_form = None
        self.meta = []
        self.comment_count = 0
        self.script_parts = None
        self.endpoint_patterns = []
        self.js_diagnostics = []
        self.symbol_items = 0
        self.js_diagnostic_details = 0
        self.js_diagnostics_omitted = 0
        self.script_index = 0
        self.script_location = None

    def _reserve(self):
        """링크·폼·필드·메타·인라인 JS가 페이지 하나의 추출 예산을 나눠 쓴다."""
        if self.item_count >= self.max_items:
            self.limited = True
            return False
        self.item_count += 1
        return True

    def _reference(self, value, kind, attribute, method=None):
        if value is not None and len(value) <= 8192 and self._reserve():
            line, column = self.getpos()
            self.references.append({"raw": value.strip(), "kind": kind, "attribute": attribute, "method": method,
                                    "source_location": {"line": line, "column": column + 1}})

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.script_index += 1
            line, column = self.getpos()
            self.script_location = {"index": self.script_index, "html_line": line, "html_column": column + 1}
            script_type = (attrs.get("type") or "").lower()
            self.script_parts = [] if not attrs.get("src") and script_type in ("", "module", "text/javascript", "application/javascript") else None
        if tag == "title":
            self.in_title = True
        if tag == "base" and not self.base_seen and attrs.get("href") is not None:
            self.base_seen = True
            try:
                self.base_url = resolve_reference(self.url, attrs["href"].strip())
            except ValueError:
                self.base_url = self.url
            self._reference(attrs["href"], "base", "href")
        if tag == "form":
            self.current_form = None
            if self._reserve():
                declared = (attrs.get("method") or "get").upper()
                method = declared if declared in ("GET", "POST", "PUT", "PATCH", "DELETE", "DIALOG") else "UNKNOWN"
                form = {"raw_action": attrs.get("action") or "", "method": method, "fields": []}
                self.forms.append(form)
                self.current_form = form
                self._reference(form["raw_action"], "form", "action", method)
        if tag in ("input", "textarea", "select", "button") and self.current_form is not None and self._reserve():
            # 입력 구조만 남긴다. value, textarea 본문, option 값은 결과에 복사하지 않는다.
            field_type = (attrs.get("type") or ("text" if tag == "input" else tag)).lower()
            if field_type not in {"text", "password", "email", "number", "hidden", "file", "checkbox", "radio", "submit", "button", "search", "tel", "url", "date", "time", "range", "color", "reset", "textarea", "select"}:
                field_type = "unknown"
            self.current_form["fields"].append({
                "tag": tag, "name": safe_name(attrs["name"]) if attrs.get("name") else None,
                "type": field_type, "required": "required" in attrs,
            })
        if tag == "meta" and self._reserve():
            name = attrs.get("name") or attrs.get("http-equiv") or attrs.get("property") or "unknown"
            self.meta.append({"name": safe_name(name), "content": product_hint(attrs.get("content", "")) if name.lower() == "generator" else REDACTED})
        # 새 속성을 추가할 때 kind를 주의한다. link/script로 바꾸면 crawler의 자동 탐색 대상이 될 수 있다.
        for attribute in ("href", "src", "action", "formaction", "data-url", "data-href", "data-endpoint", "poster", "cite"):
            if attribute not in attrs or (tag == "form" and attribute == "action") or tag == "base":
                continue
            kind = "attribute"
            if tag in ("a", "area") and attribute == "href":
                kind = "link"
            elif tag == "script" and attribute == "src":
                kind = "script"
            elif tag == "link" and "stylesheet" in (attrs.get("rel") or "").lower().split():
                kind = "stylesheet"
            elif tag == "iframe":
                kind = "iframe"
            self._reference(attrs[attribute], kind, f"{tag}.{attribute}")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "script" and self.script_parts is not None:
            script = "".join(self.script_parts)
            # script마다 독립적인 선언 범위를 만든다. 다른 script의 상수를 합쳐 추정하지 않는다.
            diagnostic = {}
            refs, patterns, limited = parse_script(script, self.base_url, max(0, self.max_items - self.item_count), diagnostics=diagnostic,
                                                   symbol_limit=self.max_items - self.symbol_items,
                                                   diagnostic_limit=max(0, self.max_items - self.js_diagnostic_details - 1))
            diagnostic["inline_script"] = dict(self.script_location)
            diagnostic.update(source=redact_url(self.url), base_url=redact_url(self.base_url))
            # 빈 script를 반복해서 넣어도 진단 목록 자체가 페이지 상한을 넘지 않게 한다.
            if self.js_diagnostic_details < self.max_items:
                self.js_diagnostics.append(diagnostic)
                graph = diagnostic["symbol_graph"]
                self.symbol_items += len(graph["symbols"]) + len(graph["relations"])
                self.js_diagnostic_details += 1 + len(diagnostic["calls"])
            else:
                self.limited = True
                self.js_diagnostics_omitted += 1
            self.limited = self.limited or limited
            for ref in refs:
                if self._reserve():
                    self.references.append({**ref, "raw": ref["url"], "inline_script": dict(self.script_location)})
            for pattern in patterns:
                pattern["inline_script"] = dict(self.script_location)
                pattern.update(source=redact_url(self.url), base_url=redact_url(self.base_url))
            self.endpoint_patterns.extend(patterns)
            self.item_count += len(patterns)
            self.script_parts = None
        if tag == "title":
            self.in_title = False
        if tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if self.script_parts is not None:
            self.script_parts.append(data)
        if self.in_title and sum(map(len, self.title_parts)) < 1000:
            self.title_parts.append(data[:1000])

    def handle_comment(self, data):
        self.comment_count += 1

    def _resolve(self, value, *, empty_is_document=False):
        try:
            return self.url if empty_is_document and not value else resolve_reference(self.base_url, value)
        except ValueError:
            return "[invalid-url]"

    def result(self):
        """같은 참조를 일시적 정책 입력과 마스킹된 저장 자료로 분리해 반환한다."""
        references = []
        for ref in self.references:
            references.append({
                "url": self._resolve(ref["raw"], empty_is_document=ref["kind"] == "form"),
                "kind": ref["kind"], "attribute": ref["attribute"], "method": ref["method"],
                **{key: ref[key] for key in ("source_location", "inline_script", "function", "additional_sites") if key in ref},
            })
        forms = [{
            "action": redact_url(self._resolve(form["raw_action"], empty_is_document=True)),
            "method": form["method"], "fields": form["fields"],
        } for form in self.forms]
        return ParsedPage(data={
            "title": safe_text("".join(self.title_parts)), "forms": forms, "base_url": redact_url(self.base_url),
            "references": public_references(references), "meta": self.meta,
            "endpoint_patterns": self.endpoint_patterns,
            "js_diagnostics": self.js_diagnostics,
            "js_diagnostics_omitted": self.js_diagnostics_omitted,
            "comment_count": self.comment_count, "extraction_limited": self.limited,
        }, references=references, base_url=self.base_url)


def parse_html(text: str, url: str, max_items=1000) -> ParsedPage:
    """네트워크 없이 HTML 구조를 추출한다. 응답 MIME/크기/잘림 검사는 수집기 책임이다."""
    parser = _PageParser(url, max_items)
    parser.feed(text)
    parser.close()
    return parser.result()


def parse_robots_paths(text: str, origin: str, max_items=1000):
    """Extract declarations only; these observations never grant permission to fetch."""
    paths = []
    seen = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        name, separator, value = line.split("#", 1)[0].partition(":")
        directive = name.strip().lower()
        value = value.strip()
        if not separator or directive not in ("allow", "disallow") or not value:
            continue
        is_pattern = "*" in value or value.endswith("$")
        # Direct concatenation keeps // paths on the original origin; never urljoin rules.
        address = redact_url(origin + ("" if value.startswith("/") else "/") + value)
        valid = value.startswith(("/", "*")) and address.startswith(origin + "/")
        if valid:
            parts = urlsplit(address)
            pattern = parts.path + ("?" + parts.query if parts.query else "")
            if value.startswith("*"):
                pattern = pattern[1:]
        else:
            pattern = "[invalid-pattern]"
        key = (directive, pattern, is_pattern)
        if key in seen:
            continue
        if len(paths) >= max_items:
            return paths, True
        seen.add(key)
        paths.append({
            "directive": directive, "path_pattern": pattern, "line_number": line_number,
            "url": address if valid and not is_pattern else None,
            "match_type": ("pattern" if is_pattern else "prefix") if valid else "invalid",
            "disposition": "recorded_only", "confidence": "low",
            "unverified": "robots 선언이며 경로의 존재·접근 가능 여부·HTTP 메서드를 확인하지 않았습니다.",
        })
    return paths, False
