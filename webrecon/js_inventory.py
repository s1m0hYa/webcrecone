"""저장된 정적 근거에서 변수 목록과 JS 진단을 재구성한다. I/O는 수행하지 않는다."""

from urllib.parse import urlsplit


STATES = {"resolved": 0, "partial": 1, "unresolved": 2}


def _position(value):
    return (value or {}).get("line"), (value or {}).get("column")


def build_variables(patterns):
    """파일·인라인 script·선언(또는 참조 범위)을 구별한다. 모든 JS 심볼의 목록은 아니다."""
    entries = {}
    for pattern in patterns:
        source = pattern.get("source", "")
        inline = pattern.get("inline_script", {})
        for kind, records in (("binding", pattern.get("bindings", [])), ("unknown", pattern.get("unresolved_variables", []))):
            for record in records:
                declaration = record.get("declaration")
                scope = record.get("scope")
                # 옛 자료에 범위 근거가 없으면 호출 위치까지 포함해 동명 변수를 섣불리 합치지 않는다.
                basis = "declaration" if declaration else "scope" if scope else "reference"
                position = declaration or scope or record.get("location") or pattern.get("source_location")
                key = source, inline.get("index"), record["name"], basis, _position(position)
                if record["name"].startswith("["):
                    key += (_position(record.get("location") or pattern.get("source_location")),)
                item = entries.setdefault(key, {
                    "name": record["name"], "source": source, "document": pattern.get("document"),
                    "inline_script": inline, "declaration": declaration, "scope": scope,
                    "identity_basis": basis, "resolution": "resolved", "reasons": [], "endpoints": [],
                    "references": [], "domain": urlsplit(source).hostname,
                })
                state = record.get("resolution", "unresolved") if kind == "binding" else "unresolved"
                if STATES.get(state, 2) > STATES[item["resolution"]]:
                    item["resolution"] = state if state in STATES else "unresolved"
                reason = record.get("reason")
                if reason and reason not in item["reasons"]:
                    item["reasons"].append(reason)
                endpoint = {"pattern": pattern["pattern"], "origin": pattern.get("origin"),
                            "declared_methods": pattern.get("declared_methods", [])}
                if endpoint not in item["endpoints"]:
                    item["endpoints"].append(endpoint)
                location = record.get("location") or pattern.get("source_location")
                if location and location not in item["references"]:
                    item["references"].append(location)
    return list(entries.values())


def summarize_diagnostics(diagnostics):
    """검출한 호출 내 합계를 계산한다. 미기록 자료를 호출 0개로 확인했다고 취급하지 않는다."""
    result = {"analyzed_units": len(diagnostics), "coverage": "recognized_call_shapes_only",
              "available": bool(diagnostics), "incomplete_units": 0, "excluded_reasons": {}}
    for name in ("detected_calls", "resolved_calls", "partial_calls", "unresolved_calls", "excluded_calls", "duplicate_calls", "omitted_call_details"):
        result[name] = sum(item.get(name, 0) for item in diagnostics)
    result["incomplete_units"] = sum(item.get("status") == "incomplete" for item in diagnostics)
    for item in diagnostics:
        for code, count in item.get("excluded_reasons", {}).items():
            result["excluded_reasons"][code] = result["excluded_reasons"].get(code, 0) + count
    return result
