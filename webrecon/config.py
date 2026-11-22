"""Single source of defaults and hard safety ceilings."""

from dataclasses import asdict, dataclass, fields, replace
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath

from .scope import ScopeController, ScopeError, normalize_url, origin_of, path_block_reason
from .safety import redact_url


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
HTTP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
)
MAX_START_URLS = 50
MAX_SEED_ENTRIES = 1000
MAX_SEED_FILE_BYTES = 1048576


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    """설정의 기본값·상한·정규화를 관리한다. 생성/검증 과정에는 DNS 조회가 없다.

    frozen은 검증 후 값을 바꾸는 실수를 막는다. seed 추가도 replace로 다시 검증한다.
    """
    target_url: str
    allowed_origins: tuple[str, ...]
    allowed_loopback_hosts: tuple[str, ...] = ()
    request_interval: float = 1.0
    max_requests: int = 100
    max_pages: int = 50
    max_depth: int = 2
    max_script_depth: int = 2
    timeout: float = 10.0
    max_redirects: int = 3
    max_response_bytes: int = 1048576
    max_queue_size: int = 1000
    max_items_per_page: int = 1000
    read_sitemap: bool = False
    read_scripts: bool = True
    robots_html_policy: str = "stop"
    output_dir: str = "output"
    seed_urls: tuple[str, ...] = ()

    def __post_init__(self):
        # bool도 int의 하위 타입이므로 isinstance 대신 정확한 타입으로 상한 입력을 검사한다.
        integer_limits = {
            "max_requests": (1, 100), "max_pages": (1, 50), "max_depth": (0, 2), "max_script_depth": (0, 2),
            "max_redirects": (0, 3), "max_response_bytes": (1, 1048576),
            "max_queue_size": (1, 1000), "max_items_per_page": (1, 1000),
        }
        for name, (minimum, maximum) in integer_limits.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ConfigError(f"{name}: 정수 {minimum}..{maximum} 범위가 필요합니다.")
        for name, minimum, maximum in (("request_interval", 1, 60), ("timeout", 0.1, 10)):
            value = getattr(self, name)
            if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
                raise ConfigError(f"{name}: {minimum}..{maximum} 범위가 필요합니다.")
        for name in ("read_sitemap", "read_scripts"):
            if type(getattr(self, name)) is not bool:
                raise ConfigError(f"{name}: true 또는 false가 필요합니다.")
        if not isinstance(self.robots_html_policy, str) or self.robots_html_policy not in ("stop", "continue"):
            raise ConfigError("robots_html_policy: stop 또는 continue가 필요합니다.")
        if not isinstance(self.allowed_origins, (list, tuple)) or not 1 <= len(self.allowed_origins) <= 20:
            raise ConfigError("allowed_origins: 명시적인 HTTP(S) origin 목록(1..20)이 필요합니다.")
        if not isinstance(self.allowed_loopback_hosts, (list, tuple)):
            raise ConfigError("allowed_loopback_hosts: 숫자형 루프백 주소 목록이 필요합니다.")
        loopbacks = []
        try:
            for host in self.allowed_loopback_hosts:
                if not isinstance(host, str) or not ipaddress.ip_address(host).is_loopback:
                    raise ValueError
                loopbacks.append(ipaddress.ip_address(host).compressed)
        except ValueError:
            raise ConfigError("테스트 예외는 명시적인 숫자형 루프백 IP만 허용합니다.") from None
        try:
            origins = []
            for entry in self.allowed_origins:
                normalized = normalize_url(entry)
                if normalized != origin_of(normalized) + "/" or "#" in entry or "?" in entry:
                    raise ConfigError("allowed_origins에는 경로·쿼리·fragment 없이 origin만 지정하세요.")
                origins.append(origin_of(normalized))
            scope = ScopeController(origins, loopbacks)
            for origin in origins:
                scope.validate_url(origin)
            target = scope.validate_url(self.target_url)
            # 필수 target은 방문 가능한 형태여야 한다. 추가 seed의 위험 경로는 발견만 기록한다.
            reason = path_block_reason(self.target_url) or path_block_reason(target)
            if reason:
                raise ConfigError(f"대상 URL은 자동 방문할 수 없습니다: {reason}")
        except ScopeError as exc:
            raise ConfigError(f"범위 설정 오류: {exc}") from None
        object.__setattr__(self, "target_url", target)
        object.__setattr__(self, "allowed_origins", tuple(dict.fromkeys(origins)))
        object.__setattr__(self, "allowed_loopback_hosts", tuple(loopbacks))
        if not isinstance(self.seed_urls, (list, tuple)) or len(self.seed_urls) > MAX_SEED_ENTRIES:
            raise ConfigError(f"seed_urls: URL 목록({MAX_SEED_ENTRIES}개 이하)이 필요합니다.")
        seeds = []
        seen = {target}
        for index, url in enumerate(self.seed_urls, 1):
            try:
                normalized = scope.validate_url(url)
            except ScopeError as exc:
                raise ConfigError(f"시작 URL {index}번 오류: {exc}") from None
            if normalized not in seen:
                seen.add(normalized)
                seeds.append(normalized)
        if len(seen) > MAX_START_URLS:
            raise ConfigError(f"target_url을 포함한 고유 시작 URL은 최대 {MAX_START_URLS}개입니다.")
        if len(seen) > self.max_queue_size:
            raise ConfigError("시작 URL 수가 max_queue_size를 초과합니다.")
        object.__setattr__(self, "seed_urls", tuple(seeds))
        if not isinstance(self.output_dir, str) or "\\" in self.output_dir or ":" in self.output_dir:
            raise ConfigError("output_dir: output 아래의 상대 경로를 /로 구분하세요.")
        path = PurePosixPath(self.output_dir)
        if path.is_absolute() or not path.parts or path.parts[0] != "output" or ".." in path.parts:
            raise ConfigError("output_dir은 저장소의 output 폴더 내부여야 합니다.")

    def to_dict(self):
        """설정을 dict로 만든다. target_url 마스킹/제거는 출력하는 호출자 책임이다."""
        data = asdict(self)
        # Used for plans/reports: caller-provided seeds may contain sensitive query values.
        data["seed_urls"] = [redact_url(url) for url in self.seed_urls]
        return data

    @property
    def start_urls(self):
        return (self.target_url,) + self.seed_urls

    def start_plan(self):
        return [{"url": redact_url(url), "depth": 0,
                 "disposition": path_block_reason(url) or "candidate"} for url in self.start_urls]


def load_config(path: Path) -> Config:
    """로컬 JSON을 읽어 Config로 검증한다. 오타 난 키를 무시하면 제한 설정이 오해될 수 있다."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("설정 JSON 파일을 읽을 수 없습니다.") from None
    if not isinstance(data, dict):
        raise ConfigError("설정은 JSON 객체여야 합니다.")
    names = {field.name for field in fields(Config)}
    if set(data) - names:
        raise ConfigError("설정에 알 수 없는 키가 있습니다. README.md의 설정 항목을 확인하세요.")
    if not {"target_url", "allowed_origins"} <= data.keys():
        raise ConfigError("target_url과 allowed_origins가 필요합니다.")
    return Config(**data)


def with_seed_file(config: Config, path: Path) -> Config:
    """Read a bounded local UTF-8 list; configuration validation never resolves DNS."""
    try:
        with Path(path).open("rb") as handle:
            content = handle.read(MAX_SEED_FILE_BYTES + 1)
        if len(content) > MAX_SEED_FILE_BYTES:
            raise ConfigError("시작 URL 파일은 최대 1MiB입니다.")
        lines = content.decode("utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        raise ConfigError("시작 URL 파일을 UTF-8 텍스트로 읽을 수 없습니다.") from None
    seeds = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    # Config를 다시 생성하므로 파일 seed에도 origin·중복·전체 시작점 상한을 동일하게 적용한다.
    return replace(config, seed_urls=config.seed_urls + tuple(seeds))
