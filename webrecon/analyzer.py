"""Heuristic analysis of sanitized observations; this module never performs I/O."""

import re
from urllib.parse import urlsplit, urlunsplit

from .diagnostics import legacy_robots_checks
from .js_inventory import build_variables, summarize_diagnostics
from .safety import REDACTED


def _html_documents(data):
    return data.get("pages", []) + data.get("response_documents", [])


def classify_endpoint(endpoint, *, javascript_call=False):
    """저장된 이름/폼/호출 단서로 후보를 분류한다. 이 분류는 크롤링 허용 규칙이 아니다."""
    path = urlsplit(endpoint["url"]).path.lower()
    categories = []
    evidence = []
    rules = {
        "authentication": r"login|signin|sign-in|auth|password|register|logout",
        "administration": r"admin|manage|console|dashboard",
        "file_handling": r"upload|download|attachment|file|export",
        "api": r"(?:^|/)(?:api|graphql|rpc|rest)(?:/|$|[.])",
        "configuration": r"config|settings|preferences|\.well-known",
    }
    for category, pattern in rules.items():
        if re.search(pattern, path):
            categories.append(category)
            evidence.append({"kind": "url_name_hint", "category": category})
    if javascript_call or any(source.get("kind") == "javascript" and source.get("attribute") != "string_literal" for source in endpoint.get("sources", [])):
        categories.append("api")
        evidence.append({"kind": "javascript_call_hint", "category": "api"})
    if endpoint.get("parameter_names") or "form" in endpoint.get("kinds", []):
        categories.append("data_input")
        evidence.append({"kind": "declared_input", "category": "data_input"})
    if "password" in endpoint.get("field_types", []):
        categories.append("authentication")
        evidence.append({"kind": "password_field", "category": "authentication"})
    if "file" in endpoint.get("field_types", []):
        categories.append("file_handling")
        evidence.append({"kind": "file_field", "category": "file_handling"})
    if endpoint.get("outside_scope"):
        categories.append("external_integration")
        evidence.append({"kind": "outside_approved_origin", "category": "external_integration"})
    return {
        "categories": sorted(set(categories)) or ["unknown"],
        "confidence": "medium" if any(item["kind"] in ("password_field", "file_field", "declared_input") for item in evidence) else "low",
        "evidence": evidence,
        "unverified": "정적 단서에 따른 후보 분류이며 기능·취약점의 존재를 검증하지 않았습니다.",
    }


def analyze_report(data):
    """JSON 호환 dict를 제자리 갱신하고 반환한다. 파일 저장·DNS·HTTP는 수행하지 않는다.

    수집 직후와 report 재분석이 함께 쓰므로 새 선택 필드는 구버전의 누락도 처리해야 한다.
    파생 목록은 저장된 pages/scripts/endpoints/requests에서 재생성하며 원문 JS를 복원하지 않는다.
    """
    if "robots_checks" not in data:
        data["robots_checks"] = legacy_robots_checks(data)
    annotate_collection(data)
    # 표시용 endpoint.sources는 20개로 잘린다. 분류 근거는 저장된 파서 참조도 함께 확인한다.
    call_urls = {_path_url(ref["url"]) for resource in _html_documents(data) + data.get("scripts", [])
                 for ref in resource.get("references", [])
                 if ref.get("kind") == "javascript" and ref.get("attribute") != "string_literal"}
    for endpoint in data.get("endpoints", []):
        endpoint["classification"] = classify_endpoint(endpoint, javascript_call=endpoint["url"] in call_urls)
    technologies = []
    seen = set()
    for request in data.get("requests", []):
        for header in ("server", "x-powered-by"):
            hint = request.get("headers", {}).get(header)
            key = (hint, request["url"], header)
            if hint and hint != REDACTED and key not in seen:
                seen.add(key)
                technologies.append({"hint": hint, "source": request["url"], "evidence": header, "confidence": "low", "unverified": "헤더는 생략되거나 위장될 수 있습니다."})
    for page in _html_documents(data):
        for meta in page.get("meta", []):
            if meta["name"].lower() == "generator" and meta["content"] != REDACTED:
                technologies.append({"hint": meta["content"], "source": page["url"], "evidence": "meta.generator", "confidence": "low", "unverified": "선언된 값이며 실제 기술을 검증하지 않았습니다."})
    data["technologies"] = technologies
    data["url_list"] = build_url_list(data)
    data["api_list"] = [item for item in data["url_list"] if "api" in item["categories"]]
    patterns = []
    seen_patterns = set()
    for resource in _html_documents(data) + data.get("scripts", []):
        for item in resource.get("endpoint_patterns", []):
            location = item.get("source_location", {})
            # 같은 패턴이어도 파일/인라인 script/호출 위치가 다르면 별도 근거로 유지한다.
            key = (item["pattern"], item["origin"], item["source"], tuple(item["declared_methods"]),
                   location.get("line"), location.get("column"), item.get("inline_script", {}).get("index"))
            if key not in seen_patterns:
                seen_patterns.add(key)
                patterns.append(item)
    data["endpoint_patterns"] = patterns
    data["variables"] = build_variables(patterns)
    data["js_diagnostics"] = [item for resource in _html_documents(data) + data.get("scripts", [])
                              for item in resource.get("js_diagnostics", [])]
    data["js_summary"] = summarize_diagnostics(data["js_diagnostics"])
    data["js_summary"]["omitted_units"] = sum(item.get("js_diagnostics_omitted", 0) for item in _html_documents(data))
    return data


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


def _path_url(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _request_rank(record):
    # A later duplicate/block record must not erase an earlier HTTP observation.
    if record.get("network_attempted"):
        return 3 if record.get("status") is not None else 2
    return 1


def _visit_outcome(record, fallback):
    if record is None:
        return {"visit_status": "not_visited", "visit_reason": fallback, "http_status": None}
    if record.get("network_attempted"):
        status = "response_received" if record.get("status") is not None else "request_failed"
    else:
        status = "blocked"
    reason = record.get("error") or (fallback if status == "request_failed" else None)
    return {"visit_status": status, "visit_reason": reason, "http_status": record.get("status")}


def annotate_collection(data):
    """큐 등록 당시 자료를 실제 요청 기록과 대조한다. 원래 사유는 initial_disposition에 남긴다.

    입력됨·콘텐츠에서 발견됨·HTTP 응답 수신은 서로 독립된 사실이며 합이 전체 수와 같을 필요가 없다.
    """
    summary = data.setdefault("summary", {})
    if not summary.get("stop_reason"):
        for code in ("interrupted", "page_limit"):
            if any(issue.get("code") == code for issue in data.get("issues", [])):
                summary["stop_reason"] = code
                break
    exact, paths = {}, {}
    # 시작점/발견 기록은 URL별, 엔드포인트는 경로별로 대조한다. 마스킹에 따른 병합 한계가 있다.
    for record in data.get("requests", []):
        for index, key in ((exact, record["url"]), (paths, _path_url(record["url"]))):
            if key not in index or _request_rank(record) > _request_rank(index[key]):
                index[key] = record
    if "start_urls" not in data:
        inputs = list(dict.fromkeys(item["url"] for item in data.get("discoveries", [])
                                    if item.get("kind") in ("target", "seed")))
        if not inputs and data.get("target"):
            inputs = [data["target"]]
        data["start_urls"] = [{"url": url, "depth": 0, "disposition": "candidate"} for url in inputs]
    for item in data.get("discoveries", []) + data["start_urls"]:
        initial = item.get("initial_disposition", item.get("disposition", "recorded_only"))
        if initial in ("queued", "script_queued", "candidate"):
            fallback = summary.get("stop_reason") or "not_processed"
            if initial != "script_queued" and summary.get("page_stop_reason"):
                fallback = summary["page_stop_reason"]
            item.setdefault("initial_disposition", initial)
            item.update(_visit_outcome(exact.get(item["url"]), fallback))
            item["disposition"] = item["visit_status"]
        else:
            item.update(_visit_outcome(exact.get(item["url"]), initial))
    for endpoint in data.get("endpoints", []):
        kinds = set(endpoint.get("kinds", []))
        endpoint["provided_as_input"] = bool(kinds & {"target", "seed"})
        endpoint["found_in_content"] = bool(kinds - {"target", "seed", "page", "script_response"})
        endpoint.update(_visit_outcome(paths.get(endpoint["url"]), summary.get("stop_reason") or "not_requested"))
        endpoint["response_observed"] = endpoint["visit_status"] == "response_received"
        endpoint["input_only"] = (endpoint["provided_as_input"] and not endpoint["found_in_content"]
                                  and not endpoint["response_observed"])
    endpoints = data.get("endpoints", [])
    summary.update({
        "input_urls": len(data["start_urls"]),
        "endpoint_candidates": len(endpoints),
        "input_only_endpoints": sum(item["input_only"] for item in endpoints),
        "discovered_endpoints": sum(item["found_in_content"] for item in endpoints),
        "response_endpoints": sum(item["response_observed"] for item in endpoints),
        "pages_parsed": sum(bool(page.get("parsed")) for page in data.get("pages", [])),
        "response_documents_parsed": sum(bool(item.get("parsed")) for item in data.get("response_documents", [])),
    })
    for status in ("response_received", "request_failed", "blocked", "not_visited"):
        summary["input_urls_" + status] = sum(item["visit_status"] == status for item in data["start_urls"])


def build_url_list(data):
    """Separate response evidence from HTML declarations; never guess a URL's method."""
    # endpoint.methods에는 서로 다른 근거가 섞일 수 있으므로 관찰/선언의 원자료에서 다시 만든다.
    observed = {}
    declared = {}
    for request in data.get("requests", []):
        if request.get("network_attempted") and request.get("status") is not None:
            # schema v1 predates the explicit method field; its client was GET-only.
            method = request.get("method", "GET")
            if method in HTTP_METHODS:
                observed.setdefault(_path_url(request["url"]), set()).add(method)
    for page in _html_documents(data):
        for form in page.get("forms", []):
            if form.get("method") in HTTP_METHODS:
                declared.setdefault(_path_url(form["action"]), set()).add(form["method"])
    for resource in _html_documents(data) + data.get("scripts", []):
        for reference in resource.get("references", []):
            if reference.get("kind") == "javascript" and reference.get("method") in HTTP_METHODS:
                declared.setdefault(_path_url(reference["url"]), set()).add(reference["method"])
    entries = []
    for endpoint in data.get("endpoints", []):
        url = endpoint["url"]
        parts = urlsplit(url)
        observed_methods = sorted(observed.get(url, set()))
        declared_methods = sorted(declared.get(url, set()))
        entries.append({
            "url": url, "domain": parts.hostname, "origin": f"{parts.scheme}://{parts.netloc}",
            "path": parts.path, "parameter_names": endpoint.get("parameter_names", []),
            "observed_methods": observed_methods, "declared_methods": declared_methods,
            "method_status": "known" if observed_methods or declared_methods else "unknown",
            "outside_scope": endpoint.get("outside_scope", False),
            "categories": endpoint["classification"]["categories"],
            "confidence": endpoint["classification"]["confidence"],
            "sources": endpoint.get("sources", []),
            **{key: endpoint[key] for key in ("provided_as_input", "found_in_content", "response_observed",
                                            "input_only", "visit_status", "visit_reason", "http_status")},
            "unverified": "선언된 메서드는 전송·지원 여부를 검증하지 않았습니다. API 분류는 정적 후보입니다.",
        })
    return sorted(entries, key=lambda item: item["url"])


def group_urls(entries, group_by):
    """저장된 목록을 묶는 표현 단계다. domain 그룹에서도 실제 스킴·포트는 각 origin에 보존된다."""
    if group_by not in ("domain", "path"):
        raise ValueError("unsupported_url_group")
    groups = {}
    for entry in entries:
        groups.setdefault(entry[group_by] or "unknown", []).append(entry)
    return dict(sorted(groups.items()))
