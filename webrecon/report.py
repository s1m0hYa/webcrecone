"""Atomic JSON/HTML persistence and offline report views."""

from collections import Counter
import json
import os
from pathlib import Path
import tempfile
from uuid import UUID

from .analyzer import analyze_report
from .config import REPOSITORY_ROOT
from .html_report import render_html
from .safety import redact_url, safe_text


REASON_MESSAGES = {
    "robots_unexpected_content_type": "robots 정책으로 지원하지 않는 응답 타입입니다. 서버의 robots 경로와 MIME 설정을 확인하세요.",
    "robots_html_response": "본문에서 HTML 형태를 관찰했습니다. robots 부재인지 접근 안내인지 확정할 수 없습니다.",
    "robots_access_denied": "robots 접근이 거부되어 탐색을 중단했습니다.",
    "robots_http_status": "robots 정책을 확인할 수 없는 HTTP 상태입니다.",
    "robots_fetch_failed": "robots 요청·전송이 실패하거나 차단됐습니다. 아래 세부 오류를 확인하세요.",
    "robots_response_truncated": "robots 응답이 읽기 상한을 초과해 완전한 정책을 확인할 수 없습니다.",
    "robots_invalid": "robots 본문이 지원하는 정책 형식이 아닙니다.",
    "robots_missing": "robots가 404/410으로 응답해 부재로 기록하고 탐색을 계속했습니다.",
    "robots_html_continued": "robots가 200 HTML로 응답했습니다. 정책 미확인 상태에서 continue 설정에 따라 탐색을 계속했습니다.",
    "robots_invalid_request_rate": "robots의 Request-rate 선언이 올바르지 않습니다.",
    "robots_unsupported_delay": "robots의 Crawl-delay 선언을 지원하지 않습니다.",
    "robots_delay_exceeds_limit": "robots가 요구하는 간격이 지원 상한을 초과했습니다.",
    "server_backpressure": "서버가 부하·요청 제한 신호를 보내 추가 요청을 중단했습니다.",
    "request_budget_exhausted": "실행 전체의 요청 예산을 소진했습니다.",
    "unsupported_content_encoding": "지원하지 않는 응답 압축입니다.",
    "incomplete_response_body": "선언된 Content-Length보다 적은 본문을 받아 응답을 분석하지 않았습니다.",
    "tls_certificate_verification_failed": "TLS 인증서 검증에 실패했습니다.",
    "robots_cross_origin_redirect": "robots가 다른 origin으로 리다이렉트되어 중단했습니다.",
    "redirect_missing_location": "리다이렉트 응답에 목적지 헤더가 없습니다.",
    "invalid_percent_encoding": "URL의 퍼센트 인코딩이 올바르지 않습니다.",
}


def _display_code(value):
    # Known internal codes are not secrets, even when longer than the text mask's limit.
    return value if isinstance(value, str) and value in REASON_MESSAGES else safe_text(value)


class ReportError(ValueError):
    pass


def output_directory(config=None):
    """설정 경로를 저장소 output 경계 안으로 해석한다. 디렉터리 생성이나 네트워크 작업은 없다."""
    output_dir = config.output_dir if config is not None else "output"
    directory = REPOSITORY_ROOT.joinpath(*output_dir.split("/")).resolve()
    # Compare against the literal repository/output boundary, including symlink resolution.
    boundary = REPOSITORY_ROOT / "output"
    if not directory.is_relative_to(boundary):
        raise ReportError("출력 경로가 저장소 output 폴더 밖을 가리킵니다.")
    return directory


def _save_artifact(data, config, extension, writer):
    """같은 디렉터리의 임시 파일을 완성한 뒤 교체한다. 실패 시 기존 결과와 임시 파일을 구별한다."""
    directory = output_directory(config)
    try:
        identifier = str(UUID(data["scan_id"]))
        # 입력 JSON의 scan_id를 경로 문자열로 직접 쓰지 않는다.
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"webrecon-{identifier}.{extension}"
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                writer(handle)
                handle.write("\n")
            os.replace(temporary, destination)
        finally:
            if temporary and temporary.exists():
                temporary.unlink()
        return destination
    except (OSError, ValueError, KeyError, TypeError):
        raise ReportError(f"결과 {extension.upper()}을 저장할 수 없습니다.") from None


def save_report(data, config):
    """이미 마스킹한 결과를 저장한다. 이 함수가 중첩 필드의 민감값을 자동 정제하지는 않는다."""
    return _save_artifact(data, config, "json", lambda handle: json.dump(
        data, handle, ensure_ascii=False, indent=2, allow_nan=False))


def save_html_report(data, config=None):
    # Offline exports always remain inside repository/output, even for input elsewhere.
    return _save_artifact(data, config, "html", lambda handle: handle.write(render_html(data)))


def load_report(path):
    """로컬 결과를 검증하고 메모리에서 파생 목록을 다시 만든다. 입력 파일을 덮어쓰지 않는다."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, UnicodeError):
        raise ReportError("결과 JSON 파일을 읽을 수 없습니다.") from None
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ReportError("지원하지 않는 보고서 형식입니다.")
    if not all(isinstance(data.get(key), list) for key in ("pages", "endpoints", "requests", "issues")):
        raise ReportError("보고서에 필수 관찰 데이터가 없습니다.")
    if "robots_paths" in data and not isinstance(data["robots_paths"], list):
        raise ReportError("robots_paths는 목록이어야 합니다.")
    if "response_documents" in data and not isinstance(data["response_documents"], list):
        raise ReportError("response_documents는 목록이어야 합니다.")
    if "robots_checks" in data and not isinstance(data["robots_checks"], list):
        raise ReportError("robots_checks는 목록이어야 합니다.")
    if any(not isinstance(check, dict) or (check.get("body_signals") is not None
           and not isinstance(check["body_signals"], dict))
           or any(check.get(key) is not None and not isinstance(check[key], str)
                  for key in ("reason", "error", "url", "final_url"))
           for check in data.get("robots_checks", [])):
        raise ReportError("robots 검사 기록의 구조가 올바르지 않습니다.")
    try:
        return analyze_report(data)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ReportError("보고서 관찰 데이터의 구조가 올바르지 않습니다.") from None


def render_summary(data):
    """이미 분석된 결과의 요약만 만든다. 후보 수·응답 수·파싱 수를 서로 바꿔 표시하지 않는다."""
    counts = Counter(category for endpoint in data["endpoints"] for category in endpoint["classification"]["categories"])
    attempts = sum(bool(item.get("network_attempted")) for item in data["requests"])
    summary = data.get("summary", {})
    lines = [
        f"중단 사유: {_display_code(summary.get('stop_reason') or '없음')}",
        f"입력 시작 URL: {summary.get('input_urls', 0)} "
        f"(응답 {summary.get('input_urls_response_received', 0)}, "
        f"요청 실패 {summary.get('input_urls_request_failed', 0)}, "
        f"차단 {summary.get('input_urls_blocked', 0)}, 미방문 {summary.get('input_urls_not_visited', 0)})",
        f"관찰 페이지: {len(data['pages'])} (HTML 파싱: {summary.get('pages_parsed', 0)})",
        f"별도 응답 HTML 분석: {summary.get('response_documents_parsed', 0)} (robots 등 이미 받은 응답)",
        f"엔드포인트 후보 전체: {len(data['endpoints'])} (입력만 있는 후보: {summary.get('input_only_endpoints', 0)})",
        f"수집 자료에서 발견한 경로: {summary.get('discovered_endpoints', 0)} / HTTP 응답을 받은 경로: {summary.get('response_endpoints', 0)}",
        f"미처리 큐: 페이지 {summary.get('queue_remaining', 0)}, JS {summary.get('script_queue_remaining', 0)}",
        f"robots 경로 선언: {len(data.get('robots_paths', []))}",
        f"관찰 JS 파일: {len(data.get('scripts', []))}",
        f"API 후보: {len(data.get('api_list', []))}",
        f"주소 패턴·정적 해석: {len(data.get('endpoint_patterns', []))} "
        f"(해석 완료 {sum(item.get('resolution') == 'resolved' for item in data.get('endpoint_patterns', []))})",
        f"네트워크 시도: {attempts}", f"제한·실패 기록: {len(data['issues'])}",
        "후보 분류(입력 포함): " + (", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "없음"),
        "분류는 정적 단서이며 실제 기능이나 취약점 검증 결과가 아닙니다.",
    ]
    for check in data.get("robots_checks", []):
        reason = check.get("reason")
        lines.append(f"robots URL: {redact_url(check.get('url', ''))}")
        lines.append(
            f"robots 검사: {safe_text(check.get('decision'))} / "
            f"HTTP {safe_text(check.get('status'))} / Content-Type: {safe_text(check.get('content_type') or '(미지정)')} / "
            f"읽은 바이트: {safe_text(check.get('observed_bytes'))}"
        )
        if reason:
            lines.append(f"  원인: {_display_code(reason)} — {REASON_MESSAGES.get(reason, 'JSON의 검사 기록을 확인하세요.')}")
        if check.get("error"):
            lines.append(f"  세부 오류: {_display_code(check['error'])}")
        signals = check.get("body_signals")
        if signals is None:
            lines.append("  본문 특징: 미확인 (기록 없음 또는 전송 실패)")
        else:
            lines.append(f"  본문 특징: HTML 형태={bool(signals.get('html_markup'))}, User-agent 지시문={bool(signals.get('user_agent_directive'))}")
    js = data.get("js_summary", {})
    lines.append(f"추적 변수: {len(data.get('variables', []))}")
    if js.get("available"):
        lines.append(f"JS 호출 진단: 검출 {js['detected_calls']} / 완료 {js['resolved_calls']} / 부분 {js['partial_calls']} / "
                     f"미확인 {js['unresolved_calls']} / 제외 {js['excluded_calls']} (지원하는 호출 형태만 집계)")
        if js.get("excluded_reasons"):
            lines.append("JS 제외 이유: " + ", ".join(f"{key}={value}" for key, value in sorted(js["excluded_reasons"].items())))
        if js.get("incomplete_units") or js.get("omitted_call_details") or js.get("omitted_units"):
            lines.append(f"JS 진단 한계: 불완전 분석 {js.get('incomplete_units', 0)}개 / "
                         f"생략한 호출 상세 {js.get('omitted_call_details', 0)}개 / "
                         f"생략한 스크립트 진단 {js.get('omitted_units', 0)}개 (저장된 진단만 집계)")
    else:
        lines.append("JS 호출 진단: 미기록 (호출이 없다는 뜻이 아닙니다.)")
    if data.get("analysis_mode") == "local_js":
        lines.insert(0, "분석 모드: 로컬 JS / DNS·HTTP 요청 없음 / 기준 URL은 접속 대상이 아닙니다.")
    lines.append("응답 수신은 HTTP 상태 관찰이며 페이지 파싱 성공이나 엔드포인트 존재 확인과 다릅니다.")
    return "\n".join(lines)
