"""이미 받은 외부 JS를 참조 문서별로 해석한다. 전송·큐 등록은 이 모듈의 역할이 아니다."""

from collections import deque

from .javascript import parse_script, public_references
from .safety import redact_url
from .scope import ScopeError, normalize_url


class ScriptContexts:
    # 페이지 수와 별도로 CPU·메모리 예산을 둔다. 원문 캐시는 한 실행 안에서만 살아 있다.
    CACHE_BYTES = 4 * 1024 * 1024
    REPLAY_BYTES = 8 * 1024 * 1024
    MAX_VIEWS = 64
    MAX_FINDINGS = 4096

    def __init__(self):
        self.roots = {}
        self.aliases = {}
        self.content = {}
        self.cache_bytes = 0

    def document(self, refs, document, base):
        # HTML src와 인라인 모듈의 명시적 import만 문서의 실행 문맥으로 삼는다.
        for ref in refs:
            if ref["kind"] in ("script", "script_import"):
                self.roots[ref["url"], document, base] = None

    def observed(self, requested, final, record, text, byte_count):
        for url in (requested, final):
            self.aliases[url] = final if self.aliases.get(url, final) == final else None
        # 식별자가 마스킹된 파일·문서는 저장 후 구별할 수 없어 다른 문맥과 결합하지 않는다.
        if any(redact_url(url) != url for url in (requested, final)):
            return
        stored = None
        if self.cache_bytes + byte_count <= self.CACHE_BYTES:
            stored = text
            self.cache_bytes += byte_count
        self.content[final] = (record, stored, byte_count)
        record["document_contexts"] = []
        self.roots[final, record["document"], record["base_url"]] = None

    def analyze(self, item_limit, record_reference, issue):
        """중복·순환 import를 (파일, 문서, base) 단위로 끊고 추가 결과는 관찰 근거로만 전달한다."""
        queue = deque(self.roots)
        visited = set()
        views = work = findings = 0
        try:
            while queue:
                url, document, base = queue.popleft()
                try:
                    final = self.aliases.get(normalize_url(url))
                except ScopeError:
                    continue
                key = (final, document, base)
                if final not in self.content or key in visited:
                    continue
                visited.add(key)
                record, source, size = self.content[final]
                if document != redact_url(document) or base != redact_url(base):
                    continue
                if (document, base) == (record["document"], record["base_url"]):
                    refs = record["references"]
                else:
                    if source is None or views >= self.MAX_VIEWS or work + size > self.REPLAY_BYTES or findings >= self.MAX_FINDINGS:
                        if not record.get("contexts_limited"):
                            issue("script_context_limit", final)
                        record["contexts_limited"] = True
                        continue
                    refs, patterns, limited = parse_script(source, base, min(item_limit, self.MAX_FINDINGS - findings), script_url=final)
                    views += 1
                    work += size
                    findings += len(refs) + len(patterns)
                    context = {"document": document, "base_url": base, "references": public_references(refs),
                               "endpoint_patterns": [{**p, "source": final, "document": document, "base_url": base} for p in patterns],
                               "extraction_limited": limited}
                    record["document_contexts"].append(context)
                    for ref in refs:
                        record_reference(ref, final, record["depth"], document_url=document, base_url=base,
                                         record_only=True, context="shared_script")
                    refs = context["references"]
                for ref in refs:
                    if ref["kind"] == "script_import" and ref.get("exact_address"):
                        queue.append((ref["url"], document, base))
        finally:
            self.content.clear()
            self.roots.clear()
            self.aliases.clear()
