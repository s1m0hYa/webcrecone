"""저장된 참조를 오프라인 탐색용 그래프로 변환한다. 수집 큐와 독립적이다."""

from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .safety import redact_url, safe_name, safe_text
from .scope import ScopeController, ScopeError, path_block_reason


METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE", "DIALOG"}
RESOURCE_EXTENSIONS = {
    "JavaScript": {".js", ".mjs", ".cjs"}, "CSS": {".css"},
    "이미지": {".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".avif"},
    "글꼴": {".woff", ".woff2", ".ttf", ".otf", ".eot"},
    "문서·데이터": {".pdf", ".csv", ".json", ".xml", ".txt", ".zip", ".map"},
    "미디어": {".mp4", ".webm", ".mp3", ".ogg", ".wav"},
}


def resource_type(entry):
    """A file reference hint, never a claim that the file exists on the server."""
    kinds = {source.get("kind") for source in entry.get("sources", [])}
    if kinds & {"script", "script_import", "script_response"}:
        return "JavaScript"
    if "stylesheet" in kinds:
        return "CSS"
    suffix = PurePosixPath(urlsplit(entry["url"]).path).suffix.lower()
    return next((label for label, extensions in RESOURCE_EXTENSIONS.items() if suffix in extensions), None)


def _point(value):
    if isinstance(value, dict) and all(type(value.get(k)) is int and value[k] > 0 for k in ("line", "column")):
        return [value["line"], value["column"]]
    return None


def _masked(url):
    path = unquote(url).lower()
    return "?" in url or "[redacted" in path or "~redacted~" in path or url.startswith("[")


def _address(value):
    return value if value == "local:input.js" else redact_url(value or "")


def _sites(findings):
    """구형 자료는 처음 위치만 있다. 반복 호출의 위치는 같은 파일·인라인 단위 안에서만 확장한다."""
    for item in findings:
        yield item
        for extra in item.get("additional_sites", [])[:8]:
            yield {**item, "function": extra.get("function"), "source_location": extra.get("source_location")}


def build_explorer(data):
    """참조를 기록한 파일을 부모로 삼는다. URL 인벤토리의 경로 단위 집계로 관계를 추측하지 않는다."""
    nodes, keys, edges = [], {}, set()
    aliases, observations = {}, []
    # 같은 파일을 가리켜도 페이지별 상대 주소가 달라지므로 문서 문맥을 그래프 키에 포함한다.
    contexts, contextual_files = {}, set()
    exports, pending_calls, import_targets = {}, [], {}
    limits = data.get("limits") or {}
    api_paths = {row.get("url") for row in data.get("api_list", [])}
    try:
        scope = ScopeController(limits.get("allowed_origins", []), limits.get("allowed_loopback_hosts", []))
    except (ValueError, TypeError):
        scope = ScopeController([])
    blocked = {r.get("url") for r in data.get("requests", []) if r.get("error") or r.get("status") in (401, 403, 429, 503)}

    def node(key, kind, label, address=""):
        if key not in keys:
            keys[key] = len(nodes)
            nodes.append({"id": len(nodes), "kind": kind, "label": label, "address": address, "edges": []})
        return nodes[keys[key]]

    def connect(parent, child, evidence, method="", point=None):
        key = (parent["id"], child["id"], evidence, method, tuple(point or []))
        if key not in edges:
            edges.add(key)
            parent["edges"].append({"to": child["id"], "via": evidence, "method": method, "at": point})

    def allow_open(item, observation):
        addr = item["address"]
        if data.get("analysis_mode") == "local_js" or observation.get("exact_address") is not True or addr in blocked or _masked(addr):
            return
        try:
            if (observation.get("url") == addr and addr not in api_paths
                    and scope.validate_url(addr) == addr and not path_block_reason(addr)):
                item["open"] = True
        except ScopeError:
            pass

    # MIME·최종 URL이 있는 관찰부터 등록한다. redirect 이전 참조도 같은 최종 자료를 가리킨다.
    for field, kind in (("pages", "page"), ("scripts", "js"), ("response_documents", "response")):
        for index, record in enumerate(data.get(field, [])):
            if not record.get("parsed"):
                continue
            addr = _address(record.get("url"))
            title = safe_text(record.get("title") or "")
            item = node(("observed", field, index), kind, title or addr, addr)
            item["captured"] = True
            if isinstance(record.get("status"), int):
                item["status"] = record["status"]
            if record.get("document"):
                item["document"] = _address(record["document"])
            if kind != "response" and record.get("status") == 200:
                allow_open(item, record)
            observations.append((field, record, item))
            if kind == "js" and "document_contexts" in record:
                contextual_files.add(item["id"])
                contexts[item["id"], item.get("document"), record.get("base_url")] = item
                for view in record["document_contexts"]:
                    doc, base = view["document"], view["base_url"]
                    unit = node(("context", index, doc, base), "js", addr, addr)
                    unit.update({key: item[key] for key in ("captured", "open", "status") if key in item})
                    unit.update(document=doc, base=base)
                    contexts[item["id"], doc, base] = unit
                    observations.append((field, {**record, **view}, unit))
                item["base"] = record.get("base_url")
                if record.get("contexts_limited"):
                    item["contextsLimited"] = True
            if kind != "response" or record.get("purpose") in ("page", "script"):
                for alias in (addr, _address(record.get("requested_url"))):
                    if _masked(alias):
                        continue
                    # 둘 이상의 응답이 같은 표기를 쓰면 어느 본문인지 선택할 수 없다.
                    if alias in aliases and aliases[alias] is not item:
                        aliases[alias] = None
                    else:
                        aliases[alias] = item

    def script_unit(parent, finding):
        inline = finding.get("inline_script") or {}
        if type(inline.get("index")) is not int:
            return parent
        index = inline["index"]
        unit = node(("inline", parent["id"], index), "inline", f"인라인 JS #{index}")
        unit["file"] = parent["id"]
        connect(parent, unit, "script", point=_point({"line": inline.get("html_line"), "column": inline.get("html_column")}))
        return unit

    def symbol(unit, kind, name, at, fallback=()):
        # 같은 이름이라도 파일·인라인 단위·선언 위치가 다르면 별개의 심볼이다.
        name = safe_name(name)
        key = (kind, unit["id"], name, tuple(at or ()), fallback)
        item = node(key, kind, name + "()" if kind == "function" else name)
        item.update(unit=unit["id"], at=at)
        if at:
            connect(unit, item, "선언", point=at)
        return item

    def source_for(parent, finding):
        unit = script_unit(parent, finding)
        function = finding.get("function") or {}
        at = _point(function.get("declaration"))
        if not at:
            return unit
        fn = symbol(unit, "function", function.get("name") or "", at)
        fn["uses"] = [p for use in function.get("uses", [])[:8] if (p := _point(use))]
        return fn

    def add_symbol_graph(parent, diagnostic):
        graph = diagnostic.get("symbol_graph")
        if not isinstance(graph, dict) or not all(isinstance(graph.get(k), list) for k in ("symbols", "relations")):
            return
        unit = script_unit(parent, diagnostic)
        unit["symbolsRecorded"] = True
        if graph.get("limited"):
            unit["graphLimited"] = True
        by_id = {}
        for index, record in enumerate(graph.get("symbols", [])):
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                continue
            kind = record.get("kind")
            at = _point(record.get("declaration"))
            if kind in ("function", "variable") and at:
                by_id[index] = symbol(unit, kind, record["name"], at)
        # 내보내기와 호출 근거는 선언 ID로만 연결한다. 파일 이름이 비슷한 후보는 선택하지 않는다.
        if parent["kind"] == "js" and parent.get("status") == 200 and parent.get("captured"):
            for exp in graph.get("exports", []):
                target = by_id.get(exp.get("symbol"))
                if target and target["kind"] == "function":
                    exports[unit["id"], exp["name"]] = target
            for call in graph.get("imported_calls", []):
                caller = unit if call["source"] is None else by_id.get(call["source"])
                point = _point(call.get("import_at"))
                at = _point(call.get("location"))
                if caller and point and at:
                    pending_calls.append((unit["id"], tuple(point), call["name"], caller, at))
        for relation in graph.get("relations", []):
            if not isinstance(relation, dict):
                continue
            source_id, target_id = relation.get("source"), relation.get("target")
            if (source_id is not None and type(source_id) is not int) or type(target_id) is not int:
                continue
            source = unit if source_id is None else by_id.get(source_id)
            target = by_id.get(target_id)
            kind = relation.get("kind")
            if kind not in ("call", "use"):
                continue
            via = "직접 호출" if kind == "call" else "변수 사용"
            at = _point(relation.get("location"))
            target_kind = "function" if via == "직접 호출" else "variable"
            if source and (source is unit or source["kind"] == "function") and target and target["kind"] == target_kind and via and at:
                connect(source, target, via, point=at)

    for field, record, parent in observations:
        for diagnostic in record.get("js_diagnostics", []):
            add_symbol_graph(parent, diagnostic)
        resolved_sites = {}
        for ref in _sites(record.get("references", [])):
            addr = _address(ref.get("url"))
            basis = safe_text(ref.get("attribute") or ref.get("kind") or "")
            kind = ref.get("kind")
            source = source_for(parent, ref)
            asset = resource_type({"url": addr, "sources": [ref]})
            method = ref.get("method") if ref.get("method") in METHODS else ""
            if kind == "javascript" and basis != "string_literal":
                target_kind = "api"
            elif kind == "form":
                target_kind = "form"
            elif basis == "string_literal":
                target_kind = "hint"
            else:
                if asset == "JavaScript":
                    target_kind = "js"
                elif asset or basis in ("img.src", "video.src", "audio.src", "source.src", "video.poster"):
                    target_kind = "asset"
                else:
                    target_kind = "link"
            target = aliases.get(addr) if target_kind in ("js", "link", "asset") else None
            observed_script = target if target and target["id"] in contextual_files and kind in ("script", "script_import") else None
            if observed_script:
                doc = record.get("document") if field == "scripts" else record.get("url")
                target = contexts.get((target["id"], doc, record.get("base_url") or doc))
            if target is None:
                key = (target_kind, addr, source["id"] if _masked(addr) or observed_script else None)
                target = node(key, target_kind, addr, addr)
                if observed_script:
                    target["contextMissing"] = True
                if asset and target_kind in ("asset", "js"):
                    target["format"] = asset
                    # 수집·재생을 유도하지 않고, 실제 원본과 같은 정적 리소스에만 수동 열기를 제공한다.
                    if field != "response_documents" and parent.get("status") == 200 and kind in ("script", "script_import", "stylesheet", "attribute"):
                        allow_open(target, ref)
            if target_kind in {"link", "hint", "asset"} and addr in api_paths and not _masked(addr):
                target["api_hint"] = True
            if target_kind == "api":
                site = (ref.get("url"), basis, tuple(_point(ref.get("source_location")) or ()),
                        (ref.get("inline_script") or {}).get("index"))
                resolved_sites[site] = target
            at = _point(ref.get("source_location"))
            if (kind == "script_import" and basis == "import" and ref.get("exact_address") and at
                    and target["kind"] == "js" and target.get("captured") and target.get("status") == 200):
                import_targets[source["id"], tuple(at)] = target["id"]
            connect(source, target, basis, method, at)

        for item in _sites(record.get("endpoint_patterns", [])):
            site = (item.get("resolved_url"), item.get("attribute"), tuple(_point(item.get("source_location")) or ()),
                    (item.get("inline_script") or {}).get("index"))
            target = resolved_sites.get(site) if item.get("resolution") == "resolved" else None
            if target is None:
                source = source_for(parent, item)
                display = str(item.get("pattern") or "미확인").partition("?")[0]
                # 템플릿은 저장된 경로와 변수 자리만 표시한다. 미확인 host에 origin을 붙이지 않는다.
                target = node(("pattern", source["id"], display, item.get("origin")), "pattern", display)
                if item.get("origin"):
                    target["origin"] = _address(item["origin"])
                if item.get("resolution") in ("resolved", "partial", "unresolved"):
                    target["resolution"] = item["resolution"]
                method = next((m for m in item.get("declared_methods", []) if m in METHODS), "")
                connect(source, target, safe_text(item.get("attribute", "")), method, _point(item.get("source_location")))
            unit = script_unit(parent, item)
            for binding in (*item.get("bindings", []), *item.get("unresolved_variables", [])):
                at = _point(binding.get("declaration"))
                scope_at = _point(binding.get("scope")) or _point(binding.get("location")) or _point(item.get("source_location"))
                if not at and not scope_at:
                    continue
                variable = symbol(unit, "variable", binding["name"], at, () if at else tuple(scope_at))
                connect(target, variable, "주소식 의존", point=_point(item.get("source_location")))
    # 모든 파일의 선언이 모인 뒤 해석해야 모듈 순서나 순환 import에 의존하지 않는다.
    for unit_id, import_at, name, caller, at in pending_calls:
        target = exports.get((import_targets.get((unit_id, import_at)), name))
        if target:
            connect(caller, target, "모듈 직접 호출", point=at)
    return nodes
