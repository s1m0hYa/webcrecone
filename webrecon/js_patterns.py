"""Sanitized URL candidates and partial constant resolution, without JS execution."""

import re
from urllib.parse import urlsplit

from .js_resolver import Resolution, Script, Unknown, Unsupported, decode_string
from .js_symbols import enclosing_function, symbol_graph
from .js_references import structural_references
from .safety import parameter_names, redact_url, safe_name
from .scope import resolve_reference


REASON_LABELS = {
    "definition_not_found": "지원 범위 내 정의를 찾지 못함",
    "function_parameter": "호출 시 결정되는 함수 인자",
    "mutable_binding": "let/var 값은 추적하지 않음",
    "property_access": "객체 속성 값은 미확인",
    "unsupported_binding": "지원하지 않는 선언 형태",
    "unsupported_expression": "지원하지 않는 표현식",
    "unsupported_string_escape": "이스케이프 문자열 해석 미지원",
    "declaration_after_use": "참조보다 뒤에 선언됨",
    "ambiguous_binding": "같은 범위의 선언이 모호함",
    "write_detected": "재할당·변경 구문 관찰",
    "cyclic_reference": "순환 참조",
    "sensitive_binding": "민감한 이름의 값 추적 제외",
    "trace_limit": "상수 추적 깊이·횟수 상한",
    "expression_limit": "표현식 조합 크기 상한",
    "invalid_string_escape": "잘못된 문자열 이스케이프",
    "group_depth_limit": "괄호 표현식 깊이 상한",
    "source_size_limit": "JS 입력 크기 상한",
    "token_limit": "토큰 개수 상한",
    "syntax_depth_limit": "구문 중첩 상한",
    "unbalanced_syntax": "괄호 구문 불일치",
    "unterminated_string": "닫히지 않은 문자열",
    "unterminated_template": "닫히지 않은 템플릿",
    "unterminated_comment": "닫히지 않은 주석",
    "lexical_depth": "인용 구문 중첩 상한",
    "escaped_identifier_unsupported": "이스케이프 식별자 미지원",
    "opaque_syntax_skipped": "정규식·나눗셈 모호 구간 제외",
    "unresolved_authority": "호스트에 미확인 변수가 있음",
    "not_url_pattern": "주소 형태로 표현할 수 없음",
    "marker_collision": "내부 자리표시자와 충돌",
    "invalid_url": "잘못된 또는 비HTTP 주소",
    "result_limit": "참조·패턴 추출 개수 상한",
}


def _finding(parts, resolution, script, call, expression, attribute, method, document_url):
    """str/Unknown 조각을 마스킹된 패턴과 출처로 바꾼다. 제외 사유는 고정 코드로 전달한다."""
    unknowns = [part for part in parts if isinstance(part, Unknown)]
    fragments, replacements = [], []
    for part in parts:
        if isinstance(part, Unknown):
            # 공통 URL 마스킹이 변수 이름을 경로 값으로 오인하지 않도록 임시 표식을 사용한다.
            marker = f"~wr{len(replacements)}~"
            replacements.append((marker, safe_name(part.name)))
            fragments.append(marker)
        else:
            if "~wr" in part:
                raise Unsupported("marker_collision")
            fragments.append(part)
    shape = "".join(fragments)
    if re.search(r"[\x00-\x20\x7f\\]", shape):
        raise Unsupported("invalid_url")
    unresolved_base = shape.startswith("~wr")
    if unknowns and "/" not in shape and not any(token.kind == "identifier" for token in expression):
        raise Unsupported("not_url_pattern")
    try:
        if not unresolved_base and "~wr" in urlsplit(shape).netloc:
            raise Unsupported("unresolved_authority")
        # 가짜 origin은 마스킹을 위한 내부 자리일 뿐이다. 미확인 base의 저장 origin은 항상 None이다.
        address = "https://pattern.invalid/" + shape if unresolved_base else resolve_reference(document_url, shape)
        cleaned = redact_url(address)
        if cleaned.startswith("["):
            raise Unsupported("invalid_url")
        parsed = urlsplit(cleaned)
    except Unsupported:
        raise
    except ValueError:
        raise Unsupported("invalid_url") from None
    display = parsed.path + ("?" + parsed.query if parsed.query else "")
    if unresolved_base:
        display = display[1:]
    for marker, name in replacements:
        display = display.replace(marker, "{" + name + "}")
    known_text = any(isinstance(part, str) and part for part in parts)
    status = "resolved" if not unknowns else "partial" if known_text else "unresolved"
    bindings = [{**binding, "name": safe_name(binding["name"])} for _, binding in sorted(resolution.bindings.items())]
    unresolved = []
    for part in unknowns:
        entry = {"name": safe_name(part.name), "reason": part.reason, "location": script.location(part.position),
                 "declaration": script.location(part.declaration) if part.declaration is not None else None,
                 "scope": script.location(part.scope_position) if part.scope_position is not None else None}
        if entry not in unresolved:
            unresolved.append(entry)
    return {
        "pattern": display, "path": display.split("?", 1)[0],
        "domain": None if unresolved_base else parsed.hostname,
        "origin": None if unresolved_base else f"{parsed.scheme}://{parsed.netloc}",
        "unresolved_base": unresolved_base, "variables": sorted({safe_name(part.name) for part in unknowns}),
        "parameter_names": parameter_names(address),
        "expression_kind": "alias" if len(expression) == 1 and expression[0].kind == "identifier" else "template" if len(expression) == 1 and expression[0].kind == "template" else "concatenation",
        "declared_methods": [method] if method else [], "observed_methods": [],
        "source": redact_url(document_url), "attribute": attribute,
        "source_location": script.location(call.start), "bindings": bindings,
        "resolution": status, "unresolved_variables": unresolved,
        "resolved_url": cleaned if status == "resolved" else None,
        "confidence": "low", "disposition": "static_candidate" if status == "resolved" else "pattern_only",
        "unverified": "정적 문자열 해석 결과입니다. 코드 실행·변수 값 추측·API 존재 확인·추가 요청을 수행하지 않았습니다.",
    }


def parse_script(text, document_url, max_items=1000, *, diagnostics=None, diagnostic_limit=1000, symbol_limit=1000, script_url=None):
    """네트워크 없이 (references, patterns, limited)를 반환한다. 두 목록은 추출 예산을 공유한다.

    document_url은 상대 호출 URL의 기준 문서다. refs는 저장 전 public_references로 마스킹해야 한다.
    diagnostics dict를 주면 검출/제외 집계와 제한된 호출 위치를 채운다. 원문은 기록하지 않는다.
    script_url은 모듈 상대 경로의 기준이다. 생략하면 인라인 스크립트처럼 document_url을 사용한다.
    patterns는 이미 마스킹됐으며 resolved도 정적 후보다. limited=False는 완전한 분석을 뜻하지 않는다.
    """
    script = Script(text)
    references, patterns, seen_references, seen_patterns = [], [], {}, {}
    remaining_sites = min(1000, max_items)
    limited = script.limited
    detail_limit = min(1000, max(0, max_items), max(0, diagnostic_limit))
    limit_reasons = set()
    audit = {"coverage": "recognized_call_shapes_only", "detected_calls": 0,
             "resolved_calls": 0, "partial_calls": 0, "unresolved_calls": 0, "excluded_calls": 0,
             "duplicate_calls": 0, "excluded_reasons": {}, "calls": [], "omitted_call_details": 0,
             "analysis_issues": [{"reason": item["reason"], "location": script.location(item["position"])}
                                 for item in script.problems], "source": redact_url(document_url)}
    opaque = [token for token in script.tokens if token.kind == "opaque"]
    if opaque:
        audit["analysis_issues"].append({"reason": "opaque_syntax_skipped", "location": script.location(opaque[0].start), "count": len(opaque)})

    def note(call, attribute, method, outcome, reason=None, duplicate=False):
        audit["detected_calls"] += 1
        audit[outcome + "_calls"] += 1
        audit["duplicate_calls"] += int(duplicate)
        if reason:
            audit["excluded_reasons"][reason] = audit["excluded_reasons"].get(reason, 0) + 1
        if len(audit["calls"]) < detail_limit:
            audit["calls"].append({"location": script.location(call.start), "attribute": attribute,
                                   "declared_methods": [method] if method else [], "outcome": outcome,
                                   "reason": reason, "duplicate": duplicate})
        else:
            audit["omitted_call_details"] += 1

    def remember_site(item, location, function):
        # 반복 호출의 추가 근거는 URL·탐색 예산과 분리한다. 같은 파일에서도 저장량을 제한한다.
        nonlocal remaining_sites
        if not location or remaining_sites <= 0 or item.get("source_location") == location:
            return
        sites = item.setdefault("additional_sites", [])
        if len(sites) < 8:
            sites.append({"source_location": location, "function": function})
            remaining_sites -= 1

    def add_reference(value, attribute, method=None, *, kind="javascript", location=None, function=None):
        nonlocal limited
        try:
            if re.search(r"[\x00-\x20\x7f\\]", value):
                raise ValueError
            url = resolve_reference(document_url, value)
            if redact_url(url).startswith("["):
                raise ValueError
        except ValueError:
            return "invalid_url"
        key = (url, kind, attribute, method)
        if key in seen_references:
            if kind in ("javascript", "script_import"):
                remember_site(seen_references[key], location, function)
            return "duplicate"
        if len(references) + len(patterns) >= max_items:
            limited = True
            limit_reasons.add("result_limit")
            return "result_limit"
        item = {"url": url, "kind": kind, "attribute": attribute, "method": method}
        if location:
            item["source_location"] = location
        if function:
            item["function"] = function
        seen_references[key] = item
        references.append(item)
        return "added"

    owners = script.named_function_sites()
    for call, scope, expression, attribute, method in script.calls():
        function = owners.get(id(enclosing_function(scope)))
        resolution = Resolution(script)
        try:
            parts = resolution.expression(expression, scope)
        except Unsupported as exc:
            limited = limited or resolution.limited
            if resolution.limited:
                limit_reasons.add(str(exc))
            note(call, attribute, method, "excluded", str(exc))
            continue
        limited = limited or resolution.limited
        if resolution.limited:
            limit_reasons.update(part.reason for part in parts if isinstance(part, Unknown) and part.reason.endswith("limit"))
        literal = len(expression) == 1 and expression[0].kind in {"string", "template"} and not resolution.bindings and not any(isinstance(part, Unknown) for part in parts)
        if literal:
            outcome = add_reference("".join(parts), attribute, method, location=script.location(call.start), function=function)
            note(call, attribute, method, "resolved" if outcome in ("added", "duplicate") else "excluded",
                 None if outcome in ("added", "duplicate") else outcome, outcome == "duplicate")
            continue
        try:
            finding = _finding(parts, resolution, script, call, expression, attribute, method, document_url)
        except Unsupported as exc:
            note(call, attribute, method, "excluded", str(exc))
            continue
        # 같은 선언·이유는 후보 하나로 집계하고 반복 위치는 별도 상한 안에서만 보존한다.
        key = (finding["pattern"], finding["origin"], method,
               tuple((item["name"], item["declaration"]["line"], item["declaration"]["column"]) for item in finding["bindings"]),
               tuple((item["name"], item["reason"],
                      tuple((item.get("declaration") or {}).values()), tuple((item.get("scope") or {}).values()))
                     for item in finding["unresolved_variables"]))
        if function:
            finding["function"] = function
        duplicate = key in seen_patterns
        if duplicate:
            remember_site(seen_patterns[key], finding["source_location"], function)
        else:
            if len(references) + len(patterns) >= max_items:
                limited = True
                limit_reasons.add("result_limit")
                note(call, attribute, method, "excluded", "result_limit")
                continue
            patterns.append(finding)
            seen_patterns[key] = finding
        if finding["resolution"] == "resolved":
            # 완성 주소 참조도 예산 한 항목을 소비한다. kind=javascript라 크롤러에서 기록 전용이다.
            add_reference(finding["resolved_url"], attribute, method, location=finding["source_location"], function=function)
        note(call, attribute, method, finding["resolution"], duplicate=duplicate)
    for ref in structural_references(script, document_url, script_url or document_url):
        add_reference(ref["url"], ref["attribute"], kind=ref["kind"], location=ref["source_location"])
    if not limited:
        # 호출에 연결되지 않은 URL 모양 문자열은 약한 단서다. 실제 요청 메서드는 추정하지 않는다.
        for token in script.tokens:
            if token.kind not in {"string", "template"} or token.start in script.excluded_strings:
                continue
            if token.kind == "template" and "${" in token.value:
                continue
            try:
                value = decode_string(token.value)
            except Unsupported:
                continue
            if not value.startswith(("/", "./", "../", "http://", "https://")):
                continue
            add_reference(value, "string_literal")
            if limited:
                break
    audit["limited"] = limited
    audit["limit_reasons"] = sorted(limit_reasons)
    audit["status"] = "incomplete" if limited or audit["analysis_issues"] else "bounded_static_analysis"
    audit["references"] = len(references)
    audit["patterns"] = len(patterns)
    if diagnostics is not None:
        audit["symbol_graph"] = symbol_graph(script, owners, min(1000, max_items, symbol_limit))
        diagnostics.clear()
        diagnostics.update(audit)
    return references, patterns, limited


def parse_endpoint_patterns(text, document_url, max_items=1000):
    _, patterns, limited = parse_script(text, document_url, max_items)
    return patterns, limited
