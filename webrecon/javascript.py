"""Public JS parsing adapters. Parsing is static and performs no network requests."""

from .js_patterns import parse_script
from .safety import parameter_names, redact_url


def parse_javascript(text, base_url, max_items=1000):
    """참조만 필요한 기존 호출자를 위한 진입점. 전체 결과는 parse_script를 한 번만 호출해 받는다."""
    references, _, limited = parse_script(text, base_url, max_items)
    return references, limited


def public_references(references):
    """참조를 저장 직전에 마스킹한다. 원래 URL의 쿼리 값은 결과에 남기지 않는다."""
    records = []
    for item in references:
        address = redact_url(item["url"])
        records.append({**item, "url": address, "parameter_names": parameter_names(item["url"]),
                        "exact_address": item["url"] == address})
    return records
