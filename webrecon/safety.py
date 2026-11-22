"""Central request budget/rate policy and deliberately lossy output sanitization."""

import re
import time
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

from .scope import ScopeError, normalize_url


REDACTED = "[redacted]"
_SECRET = re.compile(
    r"(?i)(?:password|passwd|secret|token|session(?:id)?|api[-_]?key|authorization)"
    r"\s*[:=]\s*[^\s<>,;]+|\bBearer\s+\S+|\bBasic\s+\S+"
)


class SafetyStop(RuntimeError):
    pass


class RequestLimiter:
    """한 실행의 시도 예산과 완료 후 간격을 공유한다. clock/sleep 주입은 테스트용이다."""
    def __init__(self, interval, max_requests, clock=time.monotonic, sleep=time.sleep):
        if interval < 1 or not 1 <= max_requests <= 100:
            raise ValueError("invalid_request_limits")
        self.interval = interval
        self.max_requests = max_requests
        self.clock = clock
        self.sleep = sleep
        self.count = 0
        self.last_completed = None
        self.stop_reason = None

    def start(self):
        """이전 완료 시각에서 충분히 지난 후 시도 1회를 소비한다. 실패해도 환불하지 않는다."""
        if self.stop_reason:
            raise SafetyStop(self.stop_reason)
        if self.count >= self.max_requests:
            self.stop_reason = "request_budget_exhausted"
            raise SafetyStop(self.stop_reason)
        if self.last_completed is not None:
            remaining = self.interval - (self.clock() - self.last_completed)
            # sleep이 일찍 깨어나도 최소 간격을 지키도록 monotonic 경과 시간을 다시 확인한다.
            while remaining > 0:
                self.sleep(remaining)
                remaining = self.interval - (self.clock() - self.last_completed)
        self.count += 1

    def complete(self):
        """전송의 finally에서 호출한다. 시작 시각 기준으로 바꾸면 느린 요청 뒤 대기가 사라진다."""
        self.last_completed = self.clock()

    def stop(self, reason):
        self.stop_reason = self.stop_reason or reason


def safe_text(value: str, limit=200) -> str:
    value = _SECRET.sub(REDACTED, str(value))
    value = re.sub(r"https?://\S+", "[url]", value, flags=re.IGNORECASE)
    value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", REDACTED, value, flags=re.IGNORECASE)
    value = re.sub(r"[A-Za-z0-9_+./=-]{24,}", REDACTED, value)
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    return " ".join(value.split())[:limit]


def safe_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:\[\]-]{0,63}", value or ""):
        return "[redacted-name]"
    if len(value) >= 24 and not re.search(r"[_:.[\]-]", value):
        return "[redacted-name]"
    return value


def parameter_names(url: str) -> list[str]:
    """쿼리 값은 버리고 이름만 남긴다. 필드 수 초과도 원문 없이 고정 표시로 반환한다."""
    try:
        query = urlsplit(url).query
        return sorted({safe_name(name) for name, value in parse_qsl(query, keep_blank_values=True, max_num_fields=200)})
    except ValueError:
        return ["[parameter-limit]"]


def redact_url(url: str) -> str:
    """저장·표시용으로 값을 지우는 손실 변환이다. 반환 URL을 재요청 대상으로 쓰지 않는다.

    다른 실제 URL이 같은 표시로 합쳐질 수 있고, 모든 민감정보를 검출하는 보장은 없다.
    """
    try:
        parts = urlsplit(normalize_url(url))
    except ScopeError:
        return "[invalid-or-non-http-url]"
    segments = parts.path.split("/")
    redact_next = False
    for index, segment in enumerate(segments):
        decoded = unquote(segment)
        if redact_next or re.search(r"(?i)(?:token|secret|session|password|api[-_]?key)[=:;]", decoded):
            segments[index] = "~redacted~"
        elif len(decoded) >= 24 and re.search(r"[0-9]", decoded):
            segments[index] = "~redacted~"
        else:
            segments[index] = quote(safe_text(decoded, 160), safe="@!$&'()*+,;=:-._~")
        redact_next = bool(re.fullmatch(r"(?i)token|secret|session|password|reset|api[-_]?key", decoded))
    query = "&".join(f"{quote(name, safe='')}=REDACTED" for name in parameter_names(url))
    cleaned = urlunsplit((parts.scheme, parts.netloc, "/".join(segments), query, ""))
    return cleaned + ("?" if not query and "?" in url.split("#", 1)[0] else "")


def product_hint(value: str) -> str:
    match = re.match(r"([A-Za-z][A-Za-z0-9_.+-]{0,30})(?:/([0-9][0-9.]{0,15}))?(?:\s|$)", value)
    return match.group(0).strip() if match else REDACTED


def safe_headers(headers) -> dict:
    """헤더 이름과 허용한 최소 제품/MIME 단서만 보존한다. 새 값 보존은 명시적으로 검토한다."""
    result = {}
    for name, value in headers.items():
        key = name.lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", key):
            continue
        cleaned = REDACTED
        if key == "content-type":
            mime = value.split(";", 1)[0].strip().lower()
            if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime):
                cleaned = mime[:100]
        elif key == "content-length" and re.fullmatch(r"[0-9]{1,18}", value):
            cleaned = value
        elif key in ("server", "x-powered-by"):
            cleaned = product_hint(value)
        result[key] = cleaned
    return result
