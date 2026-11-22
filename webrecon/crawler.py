"""Bounded traversal of explicit document/module references, dispatching by response MIME."""

from collections import deque
from dataclasses import asdict
import logging
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from .analyzer import analyze_report
from .http_client import SafeHttpClient
from .javascript import parse_script, public_references
from .models import ScanResult, utc_now
from .parser import parse_html
from .safety import parameter_names, redact_url
from .scope import ScopeError, normalize_url, origin_of, path_block_reason


LOGGER = logging.getLogger(__name__)
HTML_TYPES = {"text/html", "application/xhtml+xml"}
SCRIPT_TYPES = {"text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript"}
ASSET_SUFFIXES = (".js", ".css", ".json", ".xml", ".txt", ".pdf", ".zip", ".gz", ".tar", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".mp4", ".mp3", ".woff", ".woff2", ".exe", ".csv")


class Crawler:
    """실행 하나의 큐·발견 자료를 소유한다. 새 scan마다 새 인스턴스를 생성한다."""
    def __init__(self, config, *, authorized=False, clock=None, sleep=None):
        options = {}
        if clock is not None:
            options["clock"] = clock
        if sleep is not None:
            options["sleep"] = sleep
        self.config = config
        self.client = SafeHttpClient(config, authorized=authorized, **options)
        limits = config.to_dict()
        limits.pop("target_url")
        self.result = ScanResult(target=redact_url(config.target_url), limits=limits)
        self.queue = deque()
        self.script_queue = deque()
        # scheduled는 큐 중복, client.visited_urls는 리다이렉트까지 포함한 요청 중복을 막는다.
        self.scheduled = set()
        self.endpoints = {}
        self.page_attempts = 0

    def _issue(self, code, url=None):
        issue = {"code": code, "observed_at": utc_now()}
        if url:
            issue["url"] = redact_url(url)
        self.result.issues.append(issue)

    def _discover(self, reference, source, depth, *, script_depth=None, document_url=None, base_url=None, record_only=False):
        """후보를 먼저 기록한 뒤 방문 여부를 결정한다. 큐 등록 자체는 요청 승인이 아니다.

        reference.url은 정책 검사용 원래 주소이며 저장 필드는 별도로 마스킹한다.
        record_only=True는 이미 받은 응답 문서의 참조로서 두 큐 모두 등록하지 않는다.
        """
        raw_url = reference["url"]
        kind = reference["kind"]
        now = utc_now()
        discovery = {
            "url": redact_url(raw_url), "source": redact_url(source),
            "kind": kind, "attribute": reference.get("attribute"),
            "method": reference.get("method"), "observed_at": now,
            "depth": depth, "disposition": "recorded_only",
        }
        if script_depth is not None:
            discovery["script_depth"] = script_depth
        if document_url:
            discovery["document"] = redact_url(document_url)
        if base_url:
            discovery["base_url"] = redact_url(base_url)
        discovery.update({key: reference[key] for key in ("source_location", "inline_script") if key in reference})
        self.result.discoveries.append(discovery)
        if record_only:
            discovery["context"] = "response_document"
        try:
            normalized = normalize_url(raw_url)
        except ScopeError as exc:
            discovery["disposition"] = str(exc)
            return
        parts = urlsplit(normalized)
        # 엔드포인트는 경로 단위로 합친다. 쿼리 값은 버리고 parameter_names만 병합한다.
        path_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        key = redact_url(path_url)
        endpoint = self.endpoints.setdefault(key, {
            "url": key, "first_seen": now, "parameter_names": [], "methods": [],
            "kinds": [], "field_types": [], "sources": [], "outside_scope": False,
        })
        endpoint["parameter_names"] = sorted(set(endpoint["parameter_names"]) | set(parameter_names(raw_url)))
        endpoint["kinds"] = sorted(set(endpoint["kinds"]) | {kind})
        if reference.get("method"):
            endpoint["methods"] = sorted(set(endpoint["methods"]) | {reference["method"]})
        evidence = {"page": redact_url(source), "kind": kind, "attribute": reference.get("attribute")}
        evidence.update({key: reference[key] for key in ("source_location", "inline_script") if key in reference})
        if record_only:
            evidence["context"] = "response_document"
        if kind == "robots":
            evidence.update({"directive": reference["directive"], "line_number": reference["line_number"]})
        if evidence not in endpoint["sources"] and len(endpoint["sources"]) < 20:
            endpoint["sources"].append(evidence)
        try:
            self.client.scope.validate_url(normalized)
        except ScopeError as exc:
            endpoint["outside_scope"] = str(exc) == "outside_scope"
            discovery["disposition"] = str(exc)
            return
        reason = path_block_reason(raw_url) or path_block_reason(normalized)
        if reason:
            discovery["disposition"] = reason
        elif record_only:
            discovery["disposition"] = "response_reference_only"
        elif (kind in ("script", "script_import", "link", "target", "seed", "navigation")
              and (parts.path.lower().endswith((".js", ".mjs"))
                   or (kind in ("script", "script_import") and "." not in parts.path.rsplit("/", 1)[-1]))):
            # 명시적 문서/모듈 참조만 수집한다. fetch·일반 문자열·폼을 스크립트 요청으로 승격하지 않는다.
            # 참조 종류가 link/navigation이어도 새 JS 큐 간선은 한 단계를 소비한다.
            level = 0 if script_depth is None else script_depth + 1
            discovery["script_depth"] = level
            if not self.config.read_scripts:
                discovery["disposition"] = "scripts_disabled"
            elif depth > self.config.max_depth:
                discovery["disposition"] = "depth_limit"
            elif level > self.config.max_script_depth:
                discovery["disposition"] = "script_depth_limit"
            elif normalized in self.scheduled or normalized in self.client.visited_urls:
                discovery["disposition"] = "duplicate"
            elif len(self.queue) + len(self.script_queue) >= self.config.max_queue_size:
                discovery["disposition"] = "queue_limit"
            else:
                self.script_queue.append((normalized, source, document_url or source,
                                          base_url or document_url or source, depth, level))
                self.scheduled.add(normalized)
                discovery["disposition"] = "script_queued"
        elif kind not in ("link", "target", "seed", "navigation") and not (kind == "iframe" and reference.get("attribute") == "iframe.src"):
            discovery["disposition"] = "reference_only"
        elif parts.path.lower().endswith(ASSET_SUFFIXES):
            discovery["disposition"] = "asset_not_visited"
        elif depth > self.config.max_depth:
            discovery["disposition"] = "depth_limit"
        elif normalized in self.scheduled or normalized in self.client.visited_urls:
            discovery["disposition"] = "duplicate"
        elif len(self.queue) + len(self.script_queue) >= self.config.max_queue_size:
            discovery["disposition"] = "queue_limit"
        else:
            self.queue.append((normalized, depth, script_depth))
            self.scheduled.add(normalized)
            discovery["disposition"] = "queued"

    def _discover_html(self, parsed, source, depth, *, script_depth=None, record_only=False):
        for reference in parsed.references:
            # HTML의 직접 script 참조는 문서 깊이를 늘리지 않는다. JS 체인은 별도 상한으로 제한한다.
            is_script = reference["kind"] in ("script", "script_import")
            self._discover(reference, source, depth if is_script else depth + 1,
                           script_depth=script_depth, document_url=source, base_url=parsed.base_url or source,
                           record_only=record_only)
        for form in parsed.data["forms"]:
            parts = urlsplit(form["action"])
            key = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            if key in self.endpoints:
                endpoint = self.endpoints[key]
                endpoint["field_types"] = sorted(set(endpoint["field_types"]) | {field["type"] for field in form["fields"]})
                endpoint["parameter_names"] = sorted(set(endpoint["parameter_names"]) | {field["name"] for field in form["fields"] if field["name"]})

    def _collect_response_documents(self):
        """robots 정책 실패와 별개로 이미 받은 HTML의 정적 후보만 활용한다."""
        # Analyze only bytes already received. These references must never populate either queue.
        for requested_url, response in self.client.take_robots_html_responses():
            parsed = parse_html(response.text(), response.url, self.config.max_items_per_page)
            document = {
                "requested_url": redact_url(requested_url), "url": redact_url(response.url),
                "purpose": "robots", "status": response.status, "observed_at": utc_now(),
                "content_type": response.content_type if response.content_type in HTML_TYPES else "other",
                "parse_basis": "content_type" if response.content_type in HTML_TYPES else "html_markup",
                "parsed": True, **parsed.data,
            }
            self.result.response_documents.append(document)
            self._discover_html(parsed, response.url, 0, record_only=True)
            if parsed.data["extraction_limited"]:
                self._issue("response_document_item_limit", response.url)

    def _analyze_response(self, response, requested_url, source, document_url, base_url, depth, script_depth, *, collection):
        """요청 당시 예상 종류가 아닌 실제 MIME으로 분석한다. 본문/원래 URL은 저장하지 않는다.

        오류 상태의 완전한 HTML/JS도 발견만 기록한다. 정상 응답에서만 새 탐색 큐를 채운다.
        script 요청의 HTML은 별도 응답 문서로 남겨 페이지 시도 예산과 실제 파싱 종류를 구분한다.
        """
        record = {"requested_url": redact_url(requested_url), "url": redact_url(response.url),
                  "status": response.status, "observed_at": utc_now(), "depth": depth,
                  "script_depth": script_depth, "content_type": response.content_type if response.content_type in HTML_TYPES | SCRIPT_TYPES else "other",
                  "truncated": response.truncated, "parsed": False}
        record["exact_address"] = response.url == record["url"]
        if collection == "page":
            self.result.pages.append(record)
        if response.truncated:
            self._issue("script_size_limit" if collection == "script" else "response_size_limit", requested_url)
            return
        record_only = response.status != 200
        if response.content_type in HTML_TYPES:
            if collection == "script" or record_only:
                if collection == "page":
                    # 실패 응답의 후보 추출을 정상 페이지 파싱 성공으로 집계하지 않는다.
                    record = dict(record)
                record.update(purpose=collection, parse_basis="content_type")
                self.result.response_documents.append(record)
            parsed = parse_html(response.text(), response.url, self.config.max_items_per_page)
            record.update(parsed.data, parsed=True, analysis_type="html", analysis_only=record_only)
            self._discover({"url": response.url, "kind": "page", "method": "GET"}, requested_url, depth)
            self._discover_html(parsed, response.url, depth, script_depth=script_depth, record_only=record_only)
            if parsed.data["extraction_limited"]:
                self._issue("html_item_limit", response.url)
        elif response.content_type in SCRIPT_TYPES:
            # import는 최종 파일, fetch/location은 문서 base 기준이다. 실제 출처와 해석 기준을 분리한다.
            level = 0 if script_depth is None else script_depth
            script = {**record, "source": redact_url(source), "document": redact_url(document_url), "base_url": redact_url(base_url),
                      "script_depth": level, "analysis_type": "javascript", "analysis_only": record_only}
            self.result.scripts.append(script)
            self._discover({"url": response.url, "kind": "script_response", "method": "GET"}, requested_url, depth)
            diagnostic = {}
            refs, patterns, limited = parse_script(response.text(), base_url, self.config.max_items_per_page,
                                                    script_url=response.url, diagnostics=diagnostic)
            script["js_diagnostics"] = [{**diagnostic, "source": redact_url(response.url), "document": redact_url(document_url),
                                         "base_url": redact_url(base_url)}]
            script["references"] = public_references(refs)
            script["endpoint_patterns"] = [{**item, "source": redact_url(response.url), "document": redact_url(document_url),
                                            "base_url": redact_url(base_url)} for item in patterns]
            script["parsed"] = True
            if collection == "page":
                record["analysis_type"] = "javascript"
            if limited:
                self._issue("script_item_limit", response.url)
            for ref in refs:
                self._discover(ref, response.url, depth + (ref["kind"] == "navigation"),
                               script_depth=level,
                               document_url=document_url, base_url=base_url, record_only=record_only)
        else:
            self._issue("unsupported_response_content_type", response.url)
        if record_only:
            self._issue("unsuccessful_response_recorded_only", response.url)

    def _sitemap(self):
        """최초 origin의 sitemap 한 개만 관찰한다. loc와 sitemap index를 따라가지 않는다."""
        url = origin_of(self.config.target_url) + "/sitemap.xml"
        response = self.client.fetch(url)
        if response.error or response.status != 200 or response.truncated:
            self._issue(response.error or "sitemap_unavailable", url)
            return
        if response.content_type not in ("application/xml", "text/xml"):
            self._issue("sitemap_unsupported_content_type", url)
            return
        text = response.text()
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper() or "\x00" in text:
            self._issue("sitemap_unsafe_xml", url)
            return
        try:
            root = ET.fromstring(text)
        except (ET.ParseError, ValueError):
            self._issue("sitemap_invalid_xml", url)
            return
        if root.tag.rsplit("}", 1)[-1] != "urlset":
            self._issue("sitemap_index_not_followed", url)
            return
        count = 0
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] != "loc" or not element.text:
                continue
            if count >= self.config.max_items_per_page:
                self._issue("sitemap_item_limit", url)
                break
            count += 1
            self._discover({"url": element.text.strip(), "kind": "sitemap", "attribute": "loc"}, url, 1)

    def run(self):
        """페이지 BFS와 JS 큐를 함께 소진한다. JS 분석에서 생긴 페이지도 같은 실행 중 처리한다.

        본문은 파싱 중에만 사용한다. 파일 저장은 CLI가 report 모듈에 맡긴다.
        """
        for index, url in enumerate(self.config.start_urls):
            self._discover({"url": url, "kind": "target" if index == 0 else "seed"}, url, 0)
        sitemap_pending = self.config.read_sitemap
        traversal_stop = None
        try:
            while self.queue or self.script_queue:
                if self.client.limiter.stop_reason:
                    self._issue(self.client.limiter.stop_reason)
                    break
                if self.queue and self.page_attempts >= self.config.max_pages and traversal_stop != "page_limit":
                    self._issue("page_limit")
                    traversal_stop = "page_limit"
                if self.queue and self.page_attempts < self.config.max_pages:
                    url, depth, script_depth = self.queue.popleft()
                    source = document_url = base_url = url
                    collection = "page"
                elif self.script_queue:
                    url, source, document_url, base_url, depth, script_depth = self.script_queue.popleft()
                    collection = "script"
                else:
                    break
                if url in self.client.visited_urls:
                    continue
                if collection == "page":
                    self.page_attempts += 1
                # 실패한 페이지도 페이지 예산을 소비한다. robots/redirect는 클라이언트의 요청 예산만 쓴다.
                response = self.client.fetch(url)
                if response.error:
                    self._issue(response.error, url)
                    continue
                if collection == "page":
                    document_url = base_url = response.url
                self._analyze_response(response, url, source, document_url, base_url, depth, script_depth, collection=collection)
                if sitemap_pending and not self.client.limiter.stop_reason:
                    sitemap_pending = False
                    self._sitemap()
                LOGGER.info("Pages observed: %d; queued: %d", len(self.result.pages), len(self.queue))
            self._collect_response_documents()
        except KeyboardInterrupt:
            self._issue("interrupted")
            traversal_stop = "interrupted"
        # Record robots candidates after traversal, without adding them to the crawl queue.
        self.result.robots_paths = self.client.robots_paths
        self.result.robots_checks = self.client.robots_checks
        self.result.issues.extend(self.client.robots_observation_issues)
        if any(check["decision"] == "continued_unverified" for check in self.result.robots_checks):
            self.result.unverified.append("robots가 200 HTML로 응답해 정책을 확인하지 못했으며 robots_html_policy=continue 설정으로 탐색을 계속했습니다.")
        for item in self.result.robots_paths:
            if item["url"]:
                self._discover({"url": item["url"], "kind": "robots", "attribute": item["directive"],
                                "directive": item["directive"], "line_number": item["line_number"]},
                               item["source"], 0)
        self.result.requests = self.client.records
        self.result.endpoints = list(self.endpoints.values())
        self.result.finished_at = utc_now()
        data = asdict(self.result)
        # 큐 등록 당시 상태는 실제 요청 기록과 대조해 analyzer가 최종 방문 상태로 갱신한다.
        data["start_urls"] = self.config.start_plan()
        data["summary"] = {
            "network_attempts": self.client.limiter.count, "page_attempts": self.page_attempts,
            "pages_observed": len(data["pages"]), "endpoints": len(data["endpoints"]),
            "queue_remaining": len(self.queue), "effective_interval": self.client.limiter.interval,
            "scripts_observed": len(data["scripts"]), "script_queue_remaining": len(self.script_queue),
            "stop_reason": "interrupted" if traversal_stop == "interrupted" else self.client.limiter.stop_reason or traversal_stop,
            "page_stop_reason": traversal_stop,
        }
        return analyze_report(data)
