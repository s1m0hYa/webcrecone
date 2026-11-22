"""Pure URL validation and explicit DNS address validation; no implicit scope."""

from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


class ScopeError(ValueError):
    """A stable reason code, never an untrusted URL or resolver error."""


def normalize_url(url: str) -> str:
    """HTTP(S) URL의 표기를 통일한다. 정규화 성공은 승인·방문 허용을 뜻하지 않는다."""
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ScopeError("invalid_url")
    if re.search(r"[\x00-\x20\x7f\\]", url):
        raise ScopeError("unsafe_url_characters")
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            raise ScopeError("non_http_scheme")
        if parts.username is not None or parts.password is not None:
            raise ScopeError("userinfo_forbidden")
        host = parts.hostname
        if not host or "%" in host or host.endswith("."):
            raise ScopeError("invalid_host")
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise ScopeError("invalid_host")
        scheme = parts.scheme.lower()
        port = parts.port
        if parts.netloc.endswith(":") or port == 0:
            raise ScopeError("invalid_port")
        port = port if port is not None else (443 if scheme == "https" else 80)
        authority = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            authority += f":{port}"
        path = parts.path or "/"
        if re.search(r"%(?![0-9a-fA-F]{2})", path + parts.query):
            raise ScopeError("invalid_percent_encoding")
        # Decode only unreserved characters; encoded separators remain encoded.
        def canonical_escape(match):
            char = chr(int(match.group(0)[1:], 16))
            return char if re.fullmatch(r"[A-Za-z0-9._~-]", char) else match.group(0).upper()
        path = re.sub(r"%[0-9a-fA-F]{2}", canonical_escape, path)
        if any(segment in (".", "..") for segment in path.split("/")):
            raise ScopeError("ambiguous_dot_path")
        path = quote(path, safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="%=&/:?@!$'()*+,;~-._")
        normalized = urlunsplit((scheme, authority, path, query, ""))
        # 빈 쿼리 구분자도 방문 차단 근거다. 정규화가 /path?를 /path로 바꾸면 안 된다.
        return normalized + ("?" if not query and "?" in url.split("#", 1)[0] else "")
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ScopeError):
            raise
        raise ScopeError("invalid_url") from None


def resolve_reference(base: str, reference: str) -> str:
    """urljoin의 제어 문자 제거·빈 쿼리 생략 전에 검사한다. 범위 승인은 별도다."""
    if not isinstance(reference, str) or len(reference) > 8192:
        raise ScopeError("invalid_url")
    if re.search(r"[\x00-\x20\x7f\\]", reference):
        raise ScopeError("unsafe_url_characters")
    try:
        parts = urlsplit(reference)
        explicit_query = "?" in reference.split("#", 1)[0]
        inherits_query = not (parts.scheme or parts.netloc or parts.path or explicit_query)
        empty_query = (explicit_query and not parts.query) or (
            inherits_query and "?" in base.split("#", 1)[0] and not urlsplit(base).query)
        resolved = urljoin(base, reference)
        if empty_query:
            joined = urlsplit(resolved)
            resolved = urlunsplit((joined.scheme, joined.netloc, joined.path, "", "")) + "?"
            if joined.fragment:
                resolved += "#" + joined.fragment
        return resolved
    except ValueError:
        raise ScopeError("invalid_url") from None


def origin_of(url: str) -> str:
    parts = urlsplit(normalize_url(url))
    return f"{parts.scheme}://{parts.netloc}"


def path_block_reason(url: str) -> str | None:
    """자동 방문 제외 사유를 반환한다. None이어도 GET의 무해성을 보장하지 않는다.

    발견 기록은 남길 수 있으며, 공격표면 분류(analyzer)와 독립된 요청 정책이다.
    """
    parts = urlsplit(url)
    if parts.query or "?" in url.split("#", 1)[0]:
        return "query_not_visited"
    path = parts.path
    # Repeated decoding catches common encoded action paths without rewriting requests.
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if re.search(r"[\x00-\x20\x7f\\%]", path):
        return "ambiguous_path"
    if ";" in path:
        return "path_parameters_not_visited"
    if re.search(
        r"logout|log[-_]?off|sign[-_]?out|delete|remove|destroy|reset|execute|"
        r"(?:^|[/_.-])(?:run|exec|purge|clear|drop|kill|shutdown|reboot|"
        r"unsubscribe|activate|deactivate|confirm|approve|reject|submit|"
        r"save|update|create|add|edit|upload|checkout|purchase|pay)(?:$|[/_.-])",
        path, re.IGNORECASE,
    ):
        return "suspected_state_change"
    if re.search(r"(?:^|/)(?:api|graphql|rpc|rest)(?:/|$|[.])", path, re.IGNORECASE):
        return "api_not_visited"
    return None


@dataclass(frozen=True)
class ResolvedAddress:
    family: int
    address: tuple


class ScopeController:
    """URL/origin 검사와 DNS 주소 검사를 분리해 오프라인 plan에서도 재사용한다."""
    def __init__(self, allowed_origins, allowed_loopback_hosts=()):
        self.allowed_origins = frozenset(origin_of(url) for url in allowed_origins)
        self.allowed_loopback_hosts = frozenset(allowed_loopback_hosts)

    def validate_url(self, url: str) -> str:
        """DNS 없이 origin과 숫자형 IP를 검사하고 정규화된 URL을 반환한다."""
        normalized = normalize_url(url)
        if origin_of(normalized) not in self.allowed_origins:
            raise ScopeError("outside_scope")
        host = urlsplit(normalized).hostname
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return normalized
        if not self._address_allowed(host, address):
            raise ScopeError("non_public_address")
        return normalized

    def _address_allowed(self, host, address):
        if address.is_loopback and host in self.allowed_loopback_hosts:
            return True
        # Transition/mapped addresses can hide a second routing destination.
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped or address.sixtofour or address.teredo:
                return False
            if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
                return False
            if address not in ipaddress.ip_network("2000::/3") or address in ipaddress.ip_network("2001::/23") or address in ipaddress.ip_network("3fff::/20"):
                return False
        elif address in ipaddress.ip_network("192.0.0.0/24"):
            return False
        return address.is_global and not (
            address.is_multicast or address.is_reserved or address.is_unspecified
            or address.is_loopback or address.is_link_local or address.is_private
        )

    def resolve(self, url: str) -> ResolvedAddress:
        """실제 DNS를 조회한다. 승인된 클라이언트의 요청 경로에서만 호출해야 한다.

        모든 응답 주소가 허용되어야 하나를 선택한다. 연결 시 호스트를 다시 조회하지 않는다.
        """
        normalized = self.validate_url(url)
        parts = urlsplit(normalized)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            records = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
        except OSError:
            raise ScopeError("dns_failed") from None
        if not records:
            raise ScopeError("dns_empty")
        addresses = []
        for family, socktype, protocol, canonname, sockaddr in records:
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                raise ScopeError("invalid_dns_address") from None
            if family not in (socket.AF_INET, socket.AF_INET6) or not self._address_allowed(parts.hostname, address):
                raise ScopeError("dns_non_public_address")
            addresses.append(ResolvedAddress(family, sockaddr))
        # Exactly one checked address is used. No hidden connection retries or new DNS lookup.
        return addresses[0]
