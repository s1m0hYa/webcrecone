"""명시한 로컬 JS 파일을 오프라인으로 분석한다. 네트워크 클라이언트를 만들지 않는다."""

from dataclasses import asdict
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit, urlunsplit

from .analyzer import analyze_report
from .javascript import public_references
from .js_patterns import parse_script
from .models import ScanResult, utc_now
from .safety import parameter_names, redact_url
from .scope import ScopeError, normalize_url


MAX_LOCAL_BYTES = 1048576
MAX_LOCAL_ITEMS = 1000
LOCAL_SOURCE = "local:input.js"


class LocalAnalysisError(ValueError):
    pass


def analyze_js_file(path, base_url):
    """UTF-8 일반 파일 하나를 기존 JSON 스키마로 변환한다. 파일 경로·원문은 저장하지 않는다."""
    try:
        document = normalize_url(base_url)
    except ScopeError:
        raise LocalAnalysisError("--base-url에는 사용자 정보 없는 HTTP(S) 문서 URL이 필요합니다.") from None
    descriptor = None
    try:
        # FIFO/장치 입력으로 무한 대기하지 않는다. 열고 난 뒤에도 일반 파일인지 확인한다.
        if not Path(path).is_file():
            raise LocalAnalysisError("입력은 읽을 수 있는 로컬 일반 JS 파일이어야 합니다.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise LocalAnalysisError("일반 파일 외의 입력은 지원하지 않습니다.")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            content = handle.read(MAX_LOCAL_BYTES + 1)
        if len(content) > MAX_LOCAL_BYTES:
            raise LocalAnalysisError("로컬 JS 파일은 최대 1MiB입니다.")
        text = content.decode("utf-8-sig")
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, LocalAnalysisError):
            raise
        raise LocalAnalysisError("로컬 JS 파일을 UTF-8로 읽을 수 없습니다.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)

    diagnostic = {}
    references, patterns, limited = parse_script(text, document, MAX_LOCAL_ITEMS, diagnostics=diagnostic)
    result = ScanResult(target=redact_url(document), limits={"mode": "local_js", "max_response_bytes": MAX_LOCAL_BYTES,
                                                          "max_items_per_page": MAX_LOCAL_ITEMS})
    for item in patterns:
        item.update(source=LOCAL_SOURCE, document=redact_url(document))
    diagnostic.update(source=LOCAL_SOURCE, document=redact_url(document))
    result.scripts.append({"url": LOCAL_SOURCE, "source": redact_url(document), "source_kind": "local_file",
                           "status": None, "observed_at": utc_now(), "parsed": True,
                           "references": public_references(references), "endpoint_patterns": patterns,
                           "js_diagnostics": [diagnostic]})
    endpoints = {}
    for ref in references:
        address = redact_url(ref["url"])
        if address.startswith("["):
            continue
        parts = urlsplit(address)
        key = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        entry = endpoints.setdefault(key, {"url": key, "first_seen": utc_now(), "kinds": [],
                                           "sources": [], "parameter_names": [], "methods": [], "field_types": [],
                                           "outside_scope": None})
        entry["parameter_names"] = sorted(set(entry["parameter_names"]) | set(parameter_names(ref["url"])))
        entry["kinds"] = sorted(set(entry["kinds"]) | {ref["kind"]})
        evidence = {"page": LOCAL_SOURCE, "kind": ref["kind"], "attribute": ref["attribute"]}
        if evidence not in entry["sources"] and len(entry["sources"]) < 20:
            entry["sources"].append(evidence)
    result.endpoints = list(endpoints.values())
    if limited:
        result.issues.append({"code": "local_js_analysis_limited", "observed_at": utc_now()})
    result.unverified.append("로컬 JS 파일만 분석했습니다. base URL은 상대 주소 해석 기준이며 승인 범위·DNS·robots·HTTP는 확인하지 않았습니다.")
    result.unverified.append("원본 JS의 웹 URL이 없으므로 로컬 분석의 모듈 상대 주소도 --base-url을 기준으로 해석한 후보입니다.")
    result.finished_at = utc_now()
    data = asdict(result)
    data.update(analysis_mode="local_js", network_enabled=False, start_urls=[],
                summary={"network_attempts": 0, "page_attempts": 0, "pages_observed": 0, "scripts_observed": 1,
                         "queue_remaining": 0, "script_queue_remaining": 0, "stop_reason": None})
    return analyze_report(data)
