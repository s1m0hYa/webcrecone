"""Small transport and report models. Response bodies never enter persisted models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class FetchResult:
    """파싱 전의 일시적 전송 결과. body와 마스킹 전 URL이 있으므로 통째로 저장하지 않는다."""
    url: str
    status: int | None = None
    body: bytes = b""
    content_type: str = ""
    charset: str = "utf-8"
    error: str | None = None
    truncated: bool = False

    def text(self):
        try:
            return self.body.decode(self.charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


@dataclass
class ScanResult:
    """저장 가능한 관찰 자료의 뼈대. 각 생산자는 문자열을 마스킹하고 본문은 제외해야 한다.

    asdict가 자동으로 민감값을 제거하지는 않는다. 파생 목록/방문 상태는 analyzer에서 보완한다.
    """
    target: str
    limits: dict
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    schema_version: int = 1
    pages: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    response_documents: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    requests: list = field(default_factory=list)
    discoveries: list = field(default_factory=list)
    robots_paths: list = field(default_factory=list)
    robots_checks: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    unverified: list = field(default_factory=lambda: [
        "분류는 정적 단서이며 실제 기능·취약점·접근권한을 확인하지 않았습니다.",
        "JavaScript 실행, 인증, 폼 제출, API 호출을 수행하지 않았습니다. JS URL·메서드는 정적 후보입니다.",
        "GET 부작용 및 임의 경로·페이지 텍스트에 포함된 민감정보를 완전히 배제할 수 없습니다.",
    ])
