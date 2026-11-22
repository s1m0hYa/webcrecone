"""Pure robots diagnostics. Preserve structural signals, never response text."""

import re


def robots_body_signals(text):
    """원문 대신 불리언 특징만 남긴다. HTML 형태라는 이유로 SPA/정책 부재를 확정하지 않는다."""
    return {
        "html_markup": bool(re.search(r"<(?:!doctype\s+html|html|head|body|script|form)\b", text, re.I)),
        "user_agent_directive": bool(re.search(r"^\s*user-agent\s*:", text, re.I | re.M)),
        "empty": not text.strip(),
    }


def robots_response_failure(check):
    """Diagnose transport/metadata failures; this does not grant robots permission."""
    error = check.get("error")
    if error:
        if error in ("server_backpressure", "request_budget_exhausted"):
            return error
        return "robots_fetch_failed"
    if check.get("status") in (404, 410):
        return None
    if check.get("status") in (401, 403):
        return "robots_access_denied"
    if check.get("status") != 200:
        return "robots_http_status"
    if check.get("truncated"):
        return "robots_response_truncated"
    if check.get("content_type", "") not in ("text/plain", ""):
        return "robots_unexpected_content_type"
    if (check.get("body_signals") or {}).get("html_markup"):
        return "robots_html_response"
    return None


def eligible_for_html_fallback(check, text):
    """Recognize a complete 200 HTML document, not missing/valid robots permission."""
    # 조건 판정만 한다. continue 설정 확인과 실제 진행 결정은 SafeHttpClient에 남겨 둔다.
    return (
        check.get("status") == 200 and not check.get("error") and not check.get("truncated")
        and check.get("content_type") in ("text/html", "application/xhtml+xml")
        and bool((check.get("body_signals") or {}).get("html_markup"))
        and "\x00" not in text
        and not re.search(r"\b(?:user-agent|allow|disallow|crawl-delay|request-rate|sitemap)\s*:", text, re.I)
    )


def legacy_robots_checks(data):
    """Recover only saved metadata; absent bodies cannot prove policy validity."""
    groups = []
    current = []
    for record in data.get("requests", []):
        if record.get("purpose") == "robots":
            current.append(record)
        elif current:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    checks = []
    for records in groups:
        last = records[-1]
        check = {key: last.get(key) for key in (
            "status", "error", "observed_bytes", "truncated", "observed_at",
        )}
        check.update({
            "url": records[0]["url"], "final_url": last["url"],
            "content_type": last.get("content_type", last.get("headers", {}).get("content-type", "")),
            "body_signals": None, "basis": "saved_metadata",
        })
        reason = robots_response_failure(check)
        check["reason"] = reason
        check["decision"] = "blocked" if reason else "missing" if check["status"] in (404, 410) else "unknown"
        checks.append(check)
    return checks
