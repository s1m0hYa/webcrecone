"""Render saved, sanitized observations without fetching or embedding target resources."""

from base64 import b64encode
from collections import Counter
import hashlib
import json
from html import escape
from pathlib import Path
from string import Template
from urllib.parse import urlsplit

from .report_explorer import RESOURCE_EXTENSIONS, build_explorer, resource_type
from .safety import redact_url, safe_text
from .js_patterns import REASON_LABELS


CATEGORIES = {
    "authentication": "인증", "administration": "관리", "file_handling": "파일 처리",
    "data_input": "데이터 입력", "api": "API", "external_integration": "외부 연동",
    "configuration": "설정", "unknown": "미분류",
}
VISITS = {"response_received": "응답 수신", "request_failed": "요청 실패",
          "blocked": "차단", "not_visited": "미방문"}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}
RESOLUTIONS = {"resolved": "정적 해석 완료", "partial": "부분 해석", "unresolved": "값 미확인", "legacy": "근거 미기록"}


def _escape(value):
    """HTML 문맥용 이스케이프다. 민감값 마스킹과는 별개이므로 입력 종류에 맞는 헬퍼를 쓴다."""
    return escape(str(value if value is not None else "—"), quote=True)


def _text(value):
    return _escape(safe_text(value, 500)) if value is not None else "—"


def _code(value):
    # Internal diagnostic codes may exceed the generic free-text masking length.
    return f"<code>{_escape(value)}</code>"


def _address(value):
    # URLs are inert text: opening a report must never contact a discovered host.
    return f'<code class="address">{_escape(redact_url(value or ""))}</code>'


def _source(value):
    return '<code>로컬 JS 입력</code>' if value == "local:input.js" else _address(value)


def _location(value):
    return f'{_text(value.get("line"))}행 · {_text(value.get("column"))}열' if value else "위치 미기록"


def _badge(label, tone="neutral"):
    return f'<span class="badge {tone}">{_escape(label)}</span>'


def _methods(values):
    return " ".join(_badge(value, "method") for value in values if value in METHODS) or '<span class="muted">미확인</span>'


def _status(status):
    if not isinstance(status, int) or isinstance(status, bool):
        return '<span class="muted">—</span>'
    tone = "good" if 200 <= status < 300 else "warn" if status < 400 else "bad"
    return _badge(str(status), tone)


def _visit(entry):
    value = entry.get("visit_status", "not_visited")
    return _badge(VISITS.get(value, "미확인"), "good" if value == "response_received" else "neutral")


def _sources(entry):
    sources = entry.get("sources", [])
    parameters = entry.get("parameter_names", [])
    items = "".join(
        f'<li>{_source(source.get("page"))}<small>{_text(source.get("kind"))} · '
        f'{_text(source.get("attribute"))}</small></li>' for source in sources
    )
    params = ", ".join(_text(value) for value in parameters) or "없음"
    flags = []
    if entry.get("provided_as_input"):
        flags.append("입력 시작점")
    if entry.get("found_in_content"):
        flags.append("콘텐츠에서 발견")
    if entry.get("input_only"):
        flags.append("입력 근거만 있음")
    confidence = {"low": "낮음", "medium": "중간", "high": "높음"}.get(entry.get("confidence"), "미확인")
    return (
        f'<details><summary>출처 {len(sources)} · 입력 이름 {len(parameters)}</summary>'
        f'<div class="detail"><p>{" · ".join(flags) or "근거 미기록"} · 분류 신뢰도 {confidence}</p>'
        f'<p>파라미터 이름: {params}</p><ul class="sources">{items}</ul>'
        f'<p>방문 사유: {_code(entry.get("visit_reason"))}</p>'
        '<p class="muted">분류와 메서드 선언은 정적 단서입니다. 기능 존재·지원 여부를 검증하지 않았습니다.</p>'
        '</div></details>'
    )


def _url_cell(entry):
    url = redact_url(entry["url"])
    parts = urlsplit(url)
    return (f'<strong class="path">{_escape(parts.path or "/")}</strong>'
            f'<small>{_escape(parts.netloc)}</small>{_address(url)}')


def _endpoint_rows(entries):
    """정적 표와 data-* 필터 근거를 함께 만든다. 브라우저 코드는 이 DOM만 검색한다."""
    rows = []
    for entry in entries:
        categories = [key for key in entry.get("categories", []) if key in CATEGORIES] or ["unknown"]
        domain = urlsplit(redact_url(entry["url"])).hostname or "미확인"
        methods = [f"{kind}:{method}" for kind in ("observed", "declared")
                   for method in entry.get(f"{kind}_methods", []) if method in METHODS]
        attrs = {"domain": domain, "category": " ".join(categories), "method": " ".join(methods),
                 "visit": entry.get("visit_status", "not_visited"),
                 "scope": "unknown" if entry.get("outside_scope", False) is None else "outside" if entry.get("outside_scope") else "inside"}
        attributes = " ".join(f'data-{key}="{_escape(value)}"' for key, value in attrs.items())
        categories_html = " ".join(_badge(CATEGORIES[key], "api" if key == "api" else "neutral") for key in categories)
        scope = '<small>범위 미평가</small>' if attrs["scope"] == "unknown" else _badge("범위 밖", "warn") if entry.get("outside_scope") else '<small>승인 범위 안</small>'
        rows.append(
            f'<tr {attributes}><td>{_url_cell(entry)}{_sources(entry)}</td><td>{categories_html}{scope}</td>'
            f'<td>{_methods(entry.get("observed_methods", []))}</td>'
            f'<td>{_methods(entry.get("declared_methods", []))}</td>'
            f'<td>{_status(entry.get("http_status"))}<small>{_visit(entry)}</small></td></tr>'
        )
    return "".join(rows)


def _resource_rows(entries, requests):
    rows = []
    for entry in entries:
        records = [record for record in requests if record.get("url") == entry["url"] and record.get("status") is not None]
        record = records[-1] if records else {}
        size = record.get("observed_bytes")
        rows.append(
            f'<tr data-resource="{_escape(resource_type(entry))}"><td>{_url_cell(entry)}{_sources(entry)}</td><td>{_badge(resource_type(entry))}</td>'
            f'<td>{_status(entry.get("http_status"))}<small>{_visit(entry)}</small></td>'
            f'<td>{_text(record.get("content_type"))}</td><td>{_text(size)}{ " B" if size is not None else ""}</td></tr>'
        )
    return "".join(rows)


def _document_rows(data):
    rows = []
    for kind, documents in (("페이지", data["pages"]), ("별도 응답 HTML", data.get("response_documents", []))):
        for document in documents:
            parsed = "HTML 분석됨" if document.get("parsed") else "HTML 파싱 안 됨"
            if document.get("analysis_type") == "javascript":
                parsed = "JS 분석됨 · HTML 아님"
            if document.get("analysis_only"):
                parsed += " · 오류 응답 후보만 기록"
            forms = []
            for form in document.get("forms", []):
                fields = ", ".join(f'{_text(field.get("name"))} ({_text(field.get("type"))})'
                                   for field in form.get("fields", [])) or "입력 없음"
                forms.append(f'<li>{_methods([form.get("method")])} {_address(form.get("action"))}<small>{fields}</small></li>')
            forms_html = f'<details><summary>폼 {len(forms)}개 · 선언만 기록</summary><ul class="sources">{"".join(forms)}</ul></details>' if forms else "폼 없음"
            rows.append(
                f'<tr><td><strong>{_text(document.get("title") or "제목 미기록")}</strong>'
                f'{_address(document.get("url"))}<small>{_escape(kind)} · 깊이 {_text(document.get("depth"))}</small></td>'
                f'<td>{_status(document.get("status"))}<small>{parsed}</small></td>'
                f'<td>{len(document.get("references", []))}개</td><td>{forms_html}</td></tr>'
            )
    return "".join(rows)


def _pattern_rows(data):
    """추적 근거를 표시하되 옛 결과에 없는 선언 위치/상태를 만들어 채우지 않는다."""
    rows = []
    states = {"resolved": "정적 해석 완료", "partial": "부분 해석", "unresolved": "값 미확인"}
    for item in data.get("endpoint_patterns", []):
        location = item.get("source_location", {})
        source = _source(item.get("source"))
        if location:
            source += f'<small>스크립트 {_text(location.get("line"))}행 · {_text(location.get("column"))}열</small>'
        inline = item.get("inline_script", {})
        if inline:
            source += f'<small>인라인 #{_text(inline.get("index"))} · HTML script 태그 {_text(inline.get("html_line"))}행</small>'
        evidence = []
        for binding in item.get("bindings", []):
            position = binding.get("declaration", {})
            evidence.append(f'<li>{_code(binding.get("name"))}: {_escape(states.get(binding.get("resolution"), "미확인"))}'
                            f'<small>선언 {_text(position.get("line"))}행 · {_text(position.get("column"))}열</small></li>')
        for variable in item.get("unresolved_variables", []):
            reason = REASON_LABELS.get(variable.get("reason"), "미확인")
            evidence.append(f'<li>{_code(variable.get("name"))}: {_escape(reason)}</li>')
        details = ('<details><summary>상수 추적 · 미확인 이유</summary><ul class="sources">'
                   + "".join(evidence) + '</ul></details>') if evidence else ""
        status = states.get(item.get("resolution"), "기준 주소 미확인" if item.get("unresolved_base") else "변수 값 미확인")
        resolution = item.get("resolution") if item.get("resolution") in RESOLUTIONS else "legacy"
        rows.append(f'<tr data-resolution="{resolution}"><td><code class="address">{_escape(item.get("pattern"))}</code>{details}</td>'
                    f'<td>{_methods(item.get("declared_methods", []))}</td><td>{source}</td>'
                    f'<td>{_badge(status)}<small>실제 요청·기능 존재 미검증</small></td></tr>')
    return "".join(rows)


def _variable_rows(data):
    rows = []
    for item in data.get("variables", []):
        state = item.get("resolution") if item.get("resolution") in RESOLUTIONS else "legacy"
        endpoints = "".join(f'<li>{_escape(entry["pattern"])}<small>{_text(entry.get("origin"))}</small>{_methods(entry.get("declared_methods", []))}</li>'
                            for entry in item.get("endpoints", []))
        reasons = " · ".join(REASON_LABELS.get(reason, reason) for reason in item.get("reasons", [])) or "—"
        inline = item.get("inline_script", {})
        identity = "선언" if item.get("declaration") else "참조 범위" if item.get("scope") else "참조 위치"
        position = item.get("declaration") or item.get("scope") or next(iter(item.get("references", [])), None)
        rows.append(f'<tr data-resolution="{state}" data-source="{_escape(item.get("source"))}">'
                    f'<td>{_code(item.get("name"))}<small>{identity} {_location(position)}</small></td>'
                    f'<td>{_source(item.get("source"))}<small>인라인 #{_text(inline.get("index"))}</small></td>'
                    f'<td>{_badge(RESOLUTIONS[state])}<small>{_escape(reasons)}</small></td>'
                    f'<td><ul class="sources">{endpoints}</ul></td></tr>')
    return "".join(rows)


def _js_diagnostic_rows(data):
    rows = []
    for item in data.get("js_diagnostics", []):
        calls = "".join(f'<li>{_location(call.get("location"))} · {_text(call.get("attribute"))} · '
                        f'{_text(call.get("outcome"))}<small>{_escape(REASON_LABELS.get(call.get("reason"), call.get("reason") or "—"))}'
                        f'{" · 중복 근거" if call.get("duplicate") else ""}</small></li>' for call in item.get("calls", []))
        reasons = "".join(f'<li>{_escape(REASON_LABELS.get(code, code))}: {_text(count)}</li>'
                          for code, count in item.get("excluded_reasons", {}).items())
        problems = "".join(f'<li>{_escape(REASON_LABELS.get(problem.get("reason"), problem.get("reason")))} · '
                            f'{_location(problem.get("location"))}</li>' for problem in item.get("analysis_issues", []))
        problems += "".join(f'<li>{_escape(REASON_LABELS.get(reason, reason))}</li>' for reason in item.get("limit_reasons", []))
        rows.append(f'<tr><td>{_source(item.get("source"))}<small>인라인 #{_text(item.get("inline_script", {}).get("index"))}</small>'
                    f'<details><summary>호출 위치 · 제외 이유</summary><ul class="sources">{calls}</ul>'
                    f'<small>상세 생략 {_text(item.get("omitted_call_details", 0))}개</small></details></td>'
                    f'<td>검출 {_text(item.get("detected_calls", 0))}<small>완료 {_text(item.get("resolved_calls", 0))} / '
                    f'부분 {_text(item.get("partial_calls", 0))} / 미확인 {_text(item.get("unresolved_calls", 0))}</small></td>'
                    f'<td>제외 {_text(item.get("excluded_calls", 0))}<ul>{reasons}</ul></td>'
                    f'<td>{_text(item.get("status"))}<ul>{problems}</ul>'
                    f'<small>근거 중복 {_text(item.get("duplicate_calls", 0))}개 · 지원하는 호출 형태의 집계</small></td></tr>')
    return "".join(rows)


def _request_rows(data):
    rows = []
    for number, item in enumerate(data["requests"], 1):
        rows.append(
            f'<tr><td>{number}</td><td>{_address(item.get("url"))}'
            f'<small>{_text(item.get("purpose"))} · {_text(item.get("observed_at"))}</small>'
            f'{"<small>리다이렉트 → " + _address(item["redirect_to"]) + "</small>" if item.get("redirect_to") else ""}</td>'
            f'<td>{_methods([item.get("method", "GET")])}<small>{"전송 시도" if item.get("network_attempted") else "전송 전 차단"}</small></td>'
            f'<td>{_status(item.get("status"))}<small>{_escape(item.get("error"))}</small></td>'
            f'<td>{_text(item.get("content_type"))}<small>{_text(item.get("observed_bytes"))} B'
            f'{" · 잘림" if item.get("truncated") else ""}</small></td>'
            f'<td>{_text(item.get("tls_verification"))}</td></tr>'
        )
    return "".join(rows)


def _table(headers, rows, identifier, *, filters="", description=""):
    headings = "".join(f'<th scope="col">{_escape(label)}</th>' for label in headers)
    return (
        f'<div class="inventory" data-inventory="{identifier}"><div class="tools">'
        f'<label class="search-label">검색<input type="search" data-search placeholder="경로, 도메인, 출처 검색" aria-controls="{identifier}-table"></label>'
        f'{filters}<button type="button" data-reset>초기화</button></div>'
        f'<div class="table-info"><span data-count aria-live="polite"></span><span>{description}</span></div>'
        f'<div class="table-scroll" tabindex="0" role="region" aria-label="{identifier} 목록">'
        f'<table id="{identifier}-table"><thead><tr>{headings}</tr></thead><tbody>{rows}</tbody></table></div>'
        f'<p class="empty" data-empty{ " hidden" if rows else ""}>표시할 항목이 없습니다.</p>'
        '<div class="pagination" data-pagination hidden>'
        '<label>페이지당 <select data-page-size aria-label="페이지당 항목 수">'
        '<option value="50">50개</option><option value="100">100개</option><option value="250">250개</option></select></label>'
        '<button type="button" data-previous>이전</button><span data-page-position aria-live="polite"></span>'
        '<button type="button" data-next>다음</button></div></div>'
    )


def _select(label, key, options):
    choices = '<option value="">전체</option>' + "".join(
        f'<option value="{_escape(value)}">{_escape(text)}</option>' for value, text in options
    )
    return f'<label>{label}<select data-filter="{key}">{choices}</select></label>'


def render_html(data):
    """Return a standalone document; local filtering scripts contain no report data."""
    # analyze_report 이후의 자료를 받는다. 새 표를 추가해도 수집/분류나 대상 자산 로딩은 하지 않는다.
    entries = data.get("url_list", [])
    resources = [entry for entry in entries if resource_type(entry)]
    summary = data.get("summary", {})
    counts = Counter(key for entry in entries for key in entry.get("categories", []) if key in CATEGORIES)
    cards = "".join(
        f'<div class="metric"><span>{label}</span><strong>{_escape(value)}</strong><small>{description}</small></div>'
        for label, value, description in (
            ("엔드포인트 후보", len(entries), "입력·콘텐츠에서 모은 고유 경로"),
            ("API 후보", len(data.get("api_list", [])), "정적 단서 · 호출 미검증"),
            ("파일 참조", len(resources), "확장자·HTML 참조 기준"),
            ("응답 받은 경로", summary.get("response_endpoints", 0), "HTTP 상태가 기록된 후보"),
            ("파싱한 페이지", summary.get("pages_parsed", 0), "별도 응답 HTML 제외"),
            ("네트워크 시도", sum(bool(item.get("network_attempted")) for item in data["requests"]), "robots·리다이렉트 포함"),
        )
    )
    categories = "".join(f'<button type="button" class="category-chip" data-category="{key}">{label}<b>{counts[key]}</b></button>'
                         for key, label in CATEGORIES.items() if counts[key])
    domains = sorted({urlsplit(redact_url(entry["url"])).hostname or "미확인" for entry in entries})
    method_options = sorted({(f"{kind}:{method}", f"{label} {method}")
                             for entry in entries for kind, label in (("observed", "응답"), ("declared", "선언"))
                             for method in entry.get(f"{kind}_methods", []) if method in METHODS})
    filters = (
        _select("도메인", "domain", [(value, value) for value in domains])
        + _select("분류", "category", CATEGORIES.items())
        + _select("메서드 근거", "method", method_options)
        + _select("방문 상태", "visit", VISITS.items())
        + _select("범위", "scope", [("inside", "승인 범위 안"), ("outside", "범위 밖"), ("unknown", "범위 미평가")])
    )
    robots = "".join(
        f'<li>{_address(check.get("url"))} {_status(check.get("status"))}'
        f'<small>{_text(check.get("decision"))} · {_escape(check.get("reason") or "—")}</small></li>'
        for check in data.get("robots_checks", [])
    ) or '<li class="muted">검사 기록 없음</li>'
    issues = "".join(f'<li>{_escape(item.get("code"))}<small>{_address(item["url"]) if item.get("url") else ""}</small></li>'
                     for item in data["issues"]) or '<li class="muted">기록 없음</li>'
    notice = "robots 정책 미확인 상태에서 탐색했습니다." if any(
        check.get("decision") == "continued_unverified" for check in data.get("robots_checks", [])
    ) else "저장된 관찰 결과입니다."
    if data.get("analysis_mode") == "local_js":
        notice = "로컬 JS 파일만 분석했습니다. 표시된 기준 URL에는 접속하지 않았으며 승인 범위·robots·응답은 미확인입니다."
    if data.get("js_summary", {}).get("omitted_units"):
        notice += " 페이지 진단 상한으로 일부 인라인 JS 진단을 생략했습니다."
    if summary.get("stop_reason") or summary.get("page_stop_reason"):
        notice += " 수집 중단 또는 탐색 제한이 기록되어 있습니다."
    context = {
        "explorer": escape(json.dumps(build_explorer(data), ensure_ascii=False, separators=(",", ":")), quote=False),
        "default_tab": ("document-section" if data["pages"] or data.get("response_documents") or data.get("analysis_mode") == "local_js" else
                        "endpoint-section" if entries else "pattern-section" if data.get("endpoint_patterns") else
                        "request-section" if data["requests"] else "diagnostic-section"),
        "target": _address(data.get("target")), "scan_id": _escape(data.get("scan_id")),
        "started_at": _text(data.get("started_at")), "finished_at": _text(data.get("finished_at")),
        "cards": cards, "categories": categories, "notice": notice,
        "endpoints": _table(["경로 · 발견 근거", "유형 · 범위", "응답 메서드", "선언 메서드", "HTTP · 방문"],
                            _endpoint_rows(entries), "endpoints", filters=filters,
                            description="분류는 중복될 수 있습니다. 출처를 펼치면 발견 위치와 입력 이름을 볼 수 있습니다."),
        "resources": _table(["웹 파일 위치 · 출처", "참조 유형", "HTTP · 방문", "관찰 MIME", "읽은 크기"],
                            _resource_rows(resources, data["requests"]), "resources",
                            filters=_select("리소스 유형", "resource", [(value, value) for value in RESOURCE_EXTENSIONS])),
        "documents": _table(["문서 · 위치", "응답 · 파싱", "참조", "폼 · 입력 구조"], _document_rows(data), "documents"),
        "patterns": _table(["주소 패턴 · 상수 추적", "선언 메서드", "출처 · 위치", "해석 상태"], _pattern_rows(data), "patterns",
                           filters=_select("해석 상태", "resolution", RESOLUTIONS.items())),
        "variables": _table(["변수 · 식별 근거", "출처", "해석 상태 · 이유", "연결된 엔드포인트 패턴"], _variable_rows(data), "variables",
                            filters=_select("해석 상태", "resolution", RESOLUTIONS.items()) + _select("출처", "source", [
                                (source, "로컬 JS 입력" if source == "local:input.js" else redact_url(source))
                                for source in sorted({item["source"] for item in data.get("variables", [])})])),
        "js_diagnostics": _table(["출처 · 호출 위치", "정적 해석", "제외", "분석 범위 · 제한"], _js_diagnostic_rows(data), "js-diagnostics"),
        "requests": _table(["#", "요청 URL · 시각", "메서드 · 전송", "HTTP · 오류", "응답 타입 · 크기", "TLS 검증"],
                           _request_rows(data), "requests"),
        "robots": robots, "issues": issues,
        "stop_reason": _escape(summary.get("stop_reason") or "없음"),
        "page_stop_reason": _escape(summary.get("page_stop_reason") or "없음"),
        "queue": _text(summary.get("queue_remaining", 0)), "script_queue": _text(summary.get("script_queue_remaining", 0)),
        "unverified": "".join(f'<li>{_text(item)}</li>' for item in data.get("unverified", [])),
    }
    template = Path(__file__).with_name("report_template.html").read_text(encoding="utf-8")
    context["styles"] = Path(__file__).with_name("report_style.css").read_text(encoding="utf-8")
    script = Path(__file__).with_name("report_ui.js").read_text(encoding="utf-8")
    script += "\n" + Path(__file__).with_name("report_explorer.js").read_text(encoding="utf-8")
    context["script"] = script
    # 관찰 값을 <script> 안에 삽입하지 않는다. 해시는 고정 UI 코드만 대상으로 생성한다.
    # Authorize only our fixed local UI script, even when a report contains hostile strings.
    context["script_hash"] = b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    return Template(template).substitute(context)
