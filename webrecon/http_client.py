"""Only network entry point: authorized sequential GETs with pinned DNS and robots."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import logging
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit
from urllib.robotparser import RobotFileParser

from .config import Config, HTTP_USER_AGENT
from .diagnostics import eligible_for_html_fallback, robots_body_signals, robots_response_failure
from .models import FetchResult, utc_now
from .parser import parse_robots_paths
from .safety import RequestLimiter, SafetyStop, redact_url, safe_headers
from .scope import ScopeController, ScopeError, origin_of, path_block_reason, resolve_reference


LOGGER = logging.getLogger(__name__)
# Keep the tool's robots identity independent of the requested HTTP header.
ROBOTS_AGENT = "WebRecon/0.1"
REDIRECTS = {301, 302, 303, 307, 308}


class _RobotsPolicy:
    """stdlib parsing plus conservative wildcard Disallow support across all groups."""

    def __init__(self, parser, disallows):
        self.parser = parser
        self.disallows = disallows

    def can_fetch(self, agent, url):
        if not self.parser.can_fetch(agent, url):
            return False
        path = unquote(urlsplit(url).path)
        for pattern in self.disallows:
            pattern = unquote(pattern)
            anchored = pattern.endswith("$")
            pieces = (pattern[:-1] if anchored else pattern).split("*")
            if not path.startswith(pieces[0]):
                continue
            cursor = len(pieces[0])
            matches = True
            for index, piece in enumerate(pieces[1:], 1):
                if anchored and index == len(pieces) - 1:
                    position = len(path) - len(piece) if path.endswith(piece) else -1
                else:
                    position = path.find(piece, cursor)
                if position < cursor:
                    matches = False
                    break
                cursor = position + len(piece)
            if matches and (not anchored or cursor == len(path)):
                return False
        return True


class AuthorizationError(ValueError):
    pass


class _PinnedConnection(http.client.HTTPConnection):
    """ScopeController가 검증한 주소로 연결하되 Host와 TLS 검증에는 원래 호스트를 쓴다."""
    def __init__(self, host, port, timeout, address, use_tls):
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._tls_context = ssl.create_default_context() if use_tls else None

    def connect(self):
        raw = socket.socket(self._address.family, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect(self._address.address)
            # Keep the original hostname for certificate verification and SNI.
            self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host) if self._tls_context else raw
        except BaseException:
            raw.close()
            raise


def _retry_after_seconds(value):
    if value is None:
        return None
    if value.strip().isascii() and value.strip().isdigit():
        return int(value.strip()[:12])
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, int((date - datetime.now(timezone.utc)).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return None


class SafeHttpClient:
    """수집기의 유일한 네트워크 진입점은 fetch다. _follow/_one/_exchange를 직접 쓰지 않는다.

    robots·리다이렉트도 같은 limiter와 전송 경로를 공유한다. 생성 시 승인을 먼저 검사한다.
    """
    def __init__(self, config: Config, *, authorized=False, clock=time.monotonic, sleep=time.sleep):
        if authorized is not True:
            raise AuthorizationError("네트워크 실행에는 --ack-authorized 승인이 필요합니다.")
        self.config = config
        self.scope = ScopeController(config.allowed_origins, config.allowed_loopback_hosts)
        self.limiter = RequestLimiter(config.request_interval, config.max_requests, clock, sleep)
        self.records = []
        self.robots_paths = []
        self.robots_checks = []
        self._robots_html_responses = []
        self.robots_observation_issues = []
        self._robots = {}
        self._visited_urls = set()
        # Reject concurrent/reentrant use; the crawler itself is entirely synchronous.
        self._lock = threading.Lock()

    @property
    def visited_urls(self):
        return frozenset(self._visited_urls)

    def take_robots_html_responses(self):
        """Transfer bounded, already received bodies for offline parsing; performs no I/O."""
        responses = self._robots_html_responses
        self._robots_html_responses = []
        return responses

    def fetch(self, url: str) -> FetchResult:
        """승인 범위·robots를 적용한 순차 GET. 예상된 차단/실패는 FetchResult.error로 반환한다.

        동시/재진입 호출만 SafetyStop으로 거부한다. 잠금은 병렬 요청을 허용하기 위한 것이 아니다.
        """
        if not self._lock.acquire(blocking=False):
            raise SafetyStop("concurrent_request_forbidden")
        try:
            return self._follow(url, purpose="page")
        finally:
            self._lock.release()

    def _blocked(self, url, reason, purpose):
        """전송 전 차단도 근거로 남긴다. _one을 거치지 않아 요청 예산은 소비하지 않는다."""
        self.records.append({
            "url": redact_url(url), "purpose": purpose, "observed_at": utc_now(),
            "status": None, "error": reason, "network_attempted": False,
        })
        return FetchResult(url=url, error=reason)

    def _follow(self, url, purpose, robots_origin=None):
        """각 hop을 새 요청처럼 검사한다. robots 수집만 자기 정책 검사를 생략하는 내부 예외다."""
        seen = set()
        for hop in range(self.config.max_redirects + 1):
            try:
                original = url
                url = self.scope.validate_url(url)
                reason = path_block_reason(original) or path_block_reason(url)
                if reason:
                    return self._blocked(url, reason, purpose)
                if url in seen:
                    return self._blocked(url, "redirect_loop", purpose)
                seen.add(url)
                if robots_origin and origin_of(url) != robots_origin:
                    return self._blocked(url, "robots_cross_origin_redirect", purpose)
                if purpose != "robots":
                    # 새 origin으로 이동하면 그 origin의 robots부터 확인한다. URL 승인만으로 부족하다.
                    robots = self._ensure_robots(url)
                    if robots is None:
                        return self._blocked(url, self.limiter.stop_reason or "robots_unavailable", purpose)
                    if not robots.can_fetch(ROBOTS_AGENT, url):
                        return self._blocked(url, "robots_disallowed", purpose)
                if url in self._visited_urls:
                    return self._blocked(url, "already_requested", purpose)
                self._visited_urls.add(url)
                # 실패한 시도도 재요청하지 않도록 연결 전에 방문 집합에 넣는다.
                result, location = self._one(url, purpose, hop)
            except (ScopeError, SafetyStop) as exc:
                return self._blocked(url, str(exc), purpose)
            if result.error or result.status not in REDIRECTS:
                return result
            if not location:
                return self._blocked(url, "redirect_missing_location", purpose)
            try:
                destination = resolve_reference(url, location)
            except ValueError:
                return self._blocked(url, "invalid_redirect", purpose)
            self.records[-1]["redirect_to"] = redact_url(destination)
            if hop == self.config.max_redirects:
                return self._blocked(destination, "redirect_limit", purpose)
            # Revalidation, robots, DNS and rate limiting also apply to every hop.
            url = destination
        raise AssertionError("unreachable")

    def _reject_robots(self, check, reason):
        """robots 실패는 해당 페이지뿐 아니라 실행 전체의 추가 요청을 중단한다."""
        check.update(decision="blocked", reason=reason)
        self.limiter.stop(reason)
        return None

    def _ensure_robots(self, url):
        """origin별 정책을 한 번 확인한다. 부재/예외 허용/정상 정책/실패를 따로 기록한다."""
        origin = origin_of(url)
        if origin in self._robots:
            return self._robots[origin]
        # None은 아직 유효 정책이 없다는 뜻이다. 실패를 재시도로 바꾸지 않는다.
        self._robots[origin] = None
        result = self._follow(origin + "/robots.txt", "robots", robots_origin=origin)
        record = self.records[-1]
        text = result.text()
        check = {key: record.get(key) for key in (
            "status", "error", "observed_bytes", "truncated", "observed_at",
        )}
        check.update({
            "url": redact_url(origin + "/robots.txt"), "final_url": redact_url(result.url),
            "content_type": record.get("content_type", ""),
            "body_signals": robots_body_signals(text) if not result.error else None,
            "basis": "response", "decision": "pending", "reason": None,
        })
        self.robots_checks.append(check)
        if (not result.error and not result.truncated and result.body
                and (result.content_type in ("text/html", "application/xhtml+xml")
                     or check["body_signals"]["html_markup"])):
            # A rejected policy can still contain useful static references. Never persist the body.
            self._robots_html_responses.append((origin + "/robots.txt", result))
        missing = not result.error and result.status in (404, 410)
        continue_html = self.config.robots_html_policy == "continue" and eligible_for_html_fallback(check, text)
        if missing or continue_html:
            # Only the configured HTML exception permits proceeding with an unverified policy.
            parser = RobotFileParser()
            parser.parse(["User-agent: *", "Disallow:"])
            policy = _RobotsPolicy(parser, [])
            self._robots[origin] = policy
            reason = "robots_missing" if missing else "robots_html_continued"
            check.update(decision="missing" if missing else "continued_unverified", reason=reason)
            if continue_html:
                check["policy_verified"] = False
            self.robots_observation_issues.append({"code": reason, "status": result.status,
                                                  "url": redact_url(result.url), "observed_at": utc_now()})
            return policy
        failure = robots_response_failure(check)
        if failure:
            return self._reject_robots(check, failure)
        # Other malformed policies still stop; the explicit HTML exception was handled above.
        if "<" in text or "\x00" in text:
            return self._reject_robots(check, "robots_invalid")
        lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        lines = [line for line in lines if line]
        if any(":" not in line for line in lines) or (lines and not any(line.lower().startswith("user-agent:") for line in lines)):
            return self._reject_robots(check, "robots_invalid")
        paths, limited = parse_robots_paths(text, origin, self.config.max_items_per_page)
        # 관찰 목록의 상한과 실제 robots 적용은 별개다. 아래 정책 파서는 전체 본문을 읽는다.
        observed_at = utc_now()
        self.robots_paths.extend({**item, "origin": origin, "source": redact_url(result.url),
                                  "observed_at": observed_at} for item in paths)
        if limited:
            self.robots_observation_issues.append({"code": "robots_path_limit",
                                                  "url": redact_url(result.url), "observed_at": observed_at})
        parser = RobotFileParser()
        parser.parse(text.splitlines())
        delay = parser.crawl_delay(ROBOTS_AGENT)
        rate = parser.request_rate(ROBOTS_AGENT)
        intervals = [self.config.request_interval]
        if delay is not None:
            intervals.append(delay)
        if rate is not None:
            if rate.requests <= 0:
                return self._reject_robots(check, "robots_invalid_request_rate")
            intervals.append(rate.seconds / rate.requests)
        # robotparser ignores fractional Crawl-delay; conservatively honor all valid declarations.
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip().lower() == "crawl-delay":
                try:
                    declared = float(value.split("#", 1)[0].strip())
                    if not 0 <= declared <= 60:
                        raise ValueError
                    intervals.append(declared)
                except ValueError:
                    return self._reject_robots(check, "robots_unsupported_delay")
        interval = max(intervals)
        if interval > 60:
            return self._reject_robots(check, "robots_delay_exceeds_limit")
        self.limiter.interval = max(self.limiter.interval, interval)
        disallows = []
        for line in lines:
            key, _, value = line.partition(":")
            if key.strip().lower() == "disallow" and value.strip():
                disallows.append(value.strip())
        policy = _RobotsPolicy(parser, disallows)
        self._robots[origin] = policy
        check.update(decision="allowed", reason=None)
        return policy

    def _one(self, url, purpose, hop):
        """DNS를 포함한 시도 1회의 예산·오류 기록·완료 시각을 한 곳에서 관리한다."""
        url = self.scope.validate_url(url)
        self.limiter.start()
        # network_attempted는 DNS 단계부터 센다. HTTP 응답 성공 수로 해석하면 안 된다.
        record = {
            "url": redact_url(url), "purpose": purpose, "redirect_hop": hop,
            "method": "GET",
            "observed_at": utc_now(), "network_attempted": True,
            "status": None, "error": None, "headers": {}, "observed_bytes": 0,
            "truncated": False, "tls_verification": "not_attempted",
        }
        result = FetchResult(url=url)
        location = None
        try:
            address = self.scope.resolve(url)
            result, location = self._exchange(url, address, record)
        except ssl.SSLCertVerificationError:
            result.error = "tls_certificate_verification_failed"
            record["tls_verification"] = "failed"
        except ScopeError as exc:
            result.error = str(exc)
        except (TimeoutError, socket.timeout):
            result.error = "request_timeout"
        except (OSError, http.client.HTTPException, ValueError):
            # Exception messages may include URLs, header contents, or server data.
            result.error = "transport_error"
        finally:
            # DNS 실패·타임아웃도 다음 요청까지의 간격을 유지해야 한다.
            self.limiter.complete()
            record["error"] = result.error
            self.records.append(record)
            LOGGER.info("HTTP attempt %d: status=%s error=%s", self.limiter.count, record["status"], result.error)
        return result, location

    def _exchange(self, url, address, record):
        """검증된 주소에 한 번 연결해 제한된 본문을 읽고 반드시 닫는다. 자동 재시도는 없다."""
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        connection = _PinnedConnection(parts.hostname, port, self.config.timeout, address, parts.scheme == "https")
        result = FetchResult(url=url)
        response = None
        try:
            deadline = time.monotonic() + self.config.timeout
            # 쿼리는 _follow에서 차단했다. 새 수집기도 이 계층을 직접 호출해서는 안 된다.
            connection.request("GET", parts.path or "/", headers={
                "User-Agent": HTTP_USER_AGENT, "Accept": "text/html, application/xhtml+xml, text/plain, application/xml;q=0.8",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            transport_socket = connection.sock
            response = connection.getresponse()
            record["tls_verification"] = "verified" if parts.scheme == "https" else "not_applicable"
            result.status = response.status
            record["status"] = response.status
            record["headers"] = safe_headers(response.headers)
            result.content_type = (response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower())
            result.charset = response.headers.get_content_charset() or "utf-8"
            record["content_type"] = record["headers"].get("content-type", "")
            retry_after = response.headers.get("Retry-After")
            if response.status in (429, 503) or retry_after is not None:
                # 날짜/초 해석보다 중단 결정을 먼저 한다. 잘못된 헤더도 제한 신호다.
                result.error = "server_backpressure"
                self.limiter.stop("server_backpressure")
                if retry_after is not None:
                    record["retry_after_seconds"] = _retry_after_seconds(retry_after)
                return result, None
            if response.status in REDIRECTS:
                return result, response.headers.get("Location")
            if response.headers.get("Content-Encoding", "identity").lower() not in ("identity", ""):
                result.error = "unsupported_content_encoding"
                return result, None
            chunks = []
            # 상한보다 1바이트 더 읽어 잘림을 감지하지만 보관하는 body는 상한 이하로 자른다.
            remaining = self.config.max_response_bytes + 1
            while remaining:
                if response.isclosed():
                    break
                seconds_left = deadline - time.monotonic()
                if seconds_left <= 0:
                    raise TimeoutError
                # HTTPResponse may own the socket after a Connection: close header.
                transport_socket.settimeout(seconds_left)
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                record["observed_bytes"] += len(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            result.truncated = len(body) > self.config.max_response_bytes
            if not result.truncated and response.length not in (None, 0):
                # read1은 Content-Length 전에 EOF여도 예외를 내지 않는다. 부분 정책/문서를 파싱하지 않는다.
                result.error = "incomplete_response_body"
                return result, None
            result.body = body[:self.config.max_response_bytes]
            record["observed_bytes"] = len(body)
            record["truncated"] = result.truncated
            return result, None
        finally:
            if response is not None:
                response.close()
            connection.close()
