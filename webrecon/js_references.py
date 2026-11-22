"""명시적 모듈 참조와 페이지 이동 구문만 관찰한다. 함수·모듈을 실행하지 않는다."""

import re

from .js_resolver import Resolution, Unknown, Unsupported, decode_string
from .scope import resolve_reference


def structural_references(script, document_url, script_url):
    """토큰을 재사용해 (주소, 종류, 속성, 위치) 후보를 생성한다.

    import 상대 경로는 JS 파일 기준, location 이동은 문서 기준이다. 일반 URL 문자열이나
    fetch/XHR 호출을 탐색 근거로 바꾸지 않는다. bare import와 동적 module 식은 따라가지 않는다.
    """
    tokens = script.tokens
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or (index and tokens[index - 1].value in (".", "?.")):
            continue
        if token.value in ("import", "export"):
            cursor = index + 1
            specifier = None
            attribute = "import" if token.value == "import" else "export_from"
            if cursor < len(tokens) and token.value == "import":
                if tokens[cursor].kind == "string":
                    specifier = tokens[cursor]
                elif tokens[cursor].value == "(" and script.pairs.get(cursor) == cursor + 2 and tokens[cursor + 1].kind == "string":
                    specifier, attribute = tokens[cursor + 1], "import_literal"
            # from 앞의 {name}은 건너뛴다. 긴 문서에서 각 export가 끝까지 순회하지 않게 제한한다.
            if specifier is None and cursor < len(tokens) and tokens[cursor].value not in ("(", "."):
                end = min(len(tokens), cursor + 256)
                while cursor < end:
                    current = tokens[cursor]
                    if current.value in (";", "const", "let", "var", "function", "class", "default", "import", "export"):
                        break
                    if current.kind == "identifier" and current.value == "from":
                        if cursor + 1 < len(tokens) and tokens[cursor + 1].kind == "string":
                            specifier = tokens[cursor + 1]
                        break
                    cursor = script.pairs[cursor] + 1 if current.value == "{" and cursor in script.pairs else cursor + 1
            if specifier is not None:
                script.excluded_strings.add(specifier.start)
                try:
                    value = decode_string(specifier.value)
                    # npm 패키지 등의 bare specifier를 URL로 추측하지 않는다.
                    if value.startswith(("/", "./", "../", "http://", "https://")) and not re.search(r"[\x00-\x20\x7f\\]", value):
                        yield {"url": resolve_reference(script_url, value), "kind": "script_import", "attribute": attribute,
                               "method": None, "source_location": script.location(token.start)}
                except (Unsupported, ValueError):
                    pass
            continue
        if token.value not in ("location", "window", "document"):
            continue
        cursor = index
        if token.value in ("window", "document"):
            if cursor + 2 >= len(tokens) or tokens[cursor + 1].value != "." or tokens[cursor + 2].value != "location":
                continue
            cursor += 2
        cursor += 1
        attribute = "location"
        if cursor + 1 < len(tokens) and tokens[cursor].value == ".":
            attribute += "." + tokens[cursor + 1].value
            cursor += 2
        if cursor >= len(tokens):
            continue
        if attribute in ("location", "location.href") and tokens[cursor].value == "=":
            start = cursor + 1
            end = script._end_expression(start)
        elif attribute in ("location.assign", "location.replace") and tokens[cursor].value == "(":
            start = cursor + 1
            end = script.pairs.get(cursor, start)
        else:
            continue
        expression = tokens[start:end]
        script.excluded_strings.update(part.start for part in expression)
        # 같은 이름의 지역 변수·인자라면 브라우저 location 객체라고 해석하지 않는다.
        scope = script.token_scopes[index]
        if script._lookup(scope, token.value) is not None:
            continue
        try:
            parts = Resolution(script).expression(expression, scope)
            if any(isinstance(part, Unknown) for part in parts):
                continue
            value = "".join(parts)
            if not value or re.search(r"[\x00-\x20\x7f\\]", value):
                continue
            yield {"url": resolve_reference(document_url, value), "kind": "navigation", "attribute": attribute,
                   "method": None, "source_location": script.location(token.start)}
        except (Unsupported, ValueError):
            continue
