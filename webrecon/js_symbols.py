"""정적 함수 호출·변수 사용 근거. 스크립트마다 독립적으로 처리하며 값이나 원문을 보존하지 않는다."""

from .js_resolver import IDENTIFIER, interpolations
from .safety import safe_name


def enclosing_function(scope):
    while scope and scope.kind == "block":
        scope = scope.parent
    return scope


def _uses(script, headers):
    tokens = script.tokens
    for i, token in enumerate(tokens):
        if token.start in headers:
            continue
        if token.kind == "template":
            for first, end in interpolations(token.value):
                expression = token.value[first + 2:end - 1]
                name = expression.strip()
                if IDENTIFIER.fullmatch(name):
                    spaces = len(expression) - len(expression.lstrip())
                    yield i, name, token.start + 3 + first + spaces
        if token.kind != "identifier":
            continue
        previous = tokens[i - 1].value if i else ""
        after = tokens[i + 1].value if i + 1 < len(tokens) else ""
        if previous in (".", "?.", "#", "break", "continue") or after == ":":
            continue
        if after == "(" and i + 1 in script.pairs:
            close = script.pairs[i + 1]
            if close + 1 < len(tokens) and tokens[close + 1].value == "{":
                continue
        yield i, token.value, token.start


def symbol_graph(script, owners, limit):
    """선언 위치로 심볼을 식별하고 직접 호출/바인딩 사용의 양 끝을 같은 단위의 ID로 기록한다."""
    symbols, relations, identifiers = [], [], {}
    graph = {"symbols": symbols, "relations": relations, "limited": any(info.get("uses_limited") for info in owners.values())}
    functions = {}
    # 기존 호출 추출기가 배제한 재할당·동명 선언을 그래프에서 다시 추정하지 않는다.
    calls = {}
    for info in owners.values():
        at = info["declaration"]
        offset = script.lines[at["line"] - 1] + at["column"] - 1
        functions[offset] = info
        for use in info["uses"]:
            calls[script.lines[use["line"] - 1] + use["column"] - 1] = offset

    def append_symbol(kind, name, location):
        point = (location["line"], location["column"])
        if point not in identifiers:
            if len(symbols) + len(relations) >= limit:
                graph["limited"] = True
                return None
            identifiers[point] = len(symbols)
            symbols.append({"kind": kind, "name": name, "declaration": location})
        return identifiers[point]

    for info in functions.values():
        if append_symbol("function", info["name"], info["declaration"]) is None:
            break

    # 매개변수 선언부는 본문과 별도 범위다. 복합 기본값·구조 분해를 단순 식별자로 해석하지 않는다.
    headers = set()
    simple_parameters = set()
    for scope in script.scopes:
        params = scope.parameters
        headers.update(t.start for t in params)
        if all((t.kind == "identifier" if i % 2 == 0 else t.value == ",") for i, t in enumerate(params)):
            simple_parameters.update(t.start for t in params if t.kind == "identifier")

    for i, name, position in _uses(script, headers):
        scope = script.token_scopes[i]
        owner = enclosing_function(scope)
        info = owners.get(id(owner))
        # 익명 함수 내부 사용을 파일 최상위나 바깥 함수에 잘못 귀속시키지 않는다.
        if not info and owner is not script.scopes[0]:
            continue
        if position in calls:
            callee = functions[calls[position]]
            target = append_symbol("function", callee["name"], callee["declaration"])
            kind = "call"
        else:
            binding = script._lookup(scope, name)
            if not binding or binding.position == position or binding.position in functions:
                continue
            if binding.reason not in (None, "mutable_binding", "write_detected", "function_parameter"):
                continue
            if binding.reason == "function_parameter" and binding.position not in simple_parameters:
                continue
            kind = "use"
            target = append_symbol("variable", safe_name(binding.name), script.location(binding.position))
        if target is None or len(symbols) + len(relations) >= limit:
            graph["limited"] = True
            break
        caller = identifiers[(info["declaration"]["line"], info["declaration"]["column"])] if info else None
        relations.append({"source": caller, "target": target, "kind": kind, "location": script.location(position)})
    # 외부 이름은 아직 함수로 단정하지 않는다. 보고서가 관찰된 import/선언 양 끝을 대조한다.
    exports, imported_calls = [], []
    if script.limited or not any(t.value in ("import", "export") for t in script.tokens):
        return graph
    tokens = script.tokens
    for i, token in enumerate(tokens[:-1]):
        if len(symbols) + len(relations) + len(exports) + len(imported_calls) >= limit:
            graph["limited"] = True
            break
        if token.kind != "identifier":
            continue
        scope = script.token_scopes[i]
        if token.value == "export" and scope is script.scopes[0]:
            pos = i + 1
            if tokens[pos].value == "async":
                pos += 1
            if pos + 1 < len(tokens) and tokens[pos].value in ("function", "const"):
                name = tokens[pos + 1]
                info = functions.get(name.start)
                if info and safe_name(name.value) == name.value and name.start not in script.written_positions:
                    point = info["declaration"]
                    symbol_id = identifiers.get((point["line"], point["column"]))
                    if symbol_id is not None:
                        exports.append({"name": name.value, "symbol": symbol_id})
            continue
        if not script.named_imports or tokens[i + 1].value != "(":
            continue
        if i and tokens[i - 1].value in (".", "?.", "new", "#"):
            continue
        end = script.pairs.get(i + 1)
        if end is None or (end + 1 < len(tokens) and tokens[end + 1].value == "{"):
            continue
        binding = script._lookup(scope, token.value)
        if not binding or binding.reason != "unsupported_binding" or binding.position in script.written_positions:
            continue
        imported = script.named_imports.get(binding.position)
        if not imported or safe_name(imported[0]) != imported[0]:
            continue
        owner = enclosing_function(scope)
        info = owners.get(id(owner))
        at = info["declaration"] if info else {}
        caller = identifiers.get((at.get("line"), at.get("column")))
        if owner is not script.scopes[0] and caller is None:
            continue
        imported_calls.append({"name": imported[0], "source": caller, "import_at": script.location(imported[1]),
                               "location": script.location(token.start)})
    if exports or imported_calls:
        graph.update(exports=exports, imported_calls=imported_calls)
    return graph
