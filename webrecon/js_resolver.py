"""Bounded lexical observations of simple JS constants. Never executes source code."""

from bisect import bisect_right
from dataclasses import dataclass, field
import re

from .safety import safe_name


# 네트워크 응답 상한과 별도로 순수 분석의 작업량을 제한한다. 서로 다른 예산을 한 값으로 합치지 않는다.
MAX_TOKENS = 250000
MAX_DEPTH = 12
MAX_STEPS = 128
MAX_PARTS = 64
MAX_LENGTH = 8192
MAX_GROUP_DEPTH = 32
IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
MEMBER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*")
SENSITIVE = re.compile(r"password|passwd|secret|token|session|cookie|authorization|api_?key", re.I)
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


@dataclass
class Token:
    """start/end는 원문 문자열의 0 기반 문자 오프셋이며 end는 포함하지 않는다."""
    kind: str
    value: str
    start: int
    end: int


def _quoted_end(text, start, depth=0):
    """인용 구간의 끝만 찾는다. 이스케이프를 건너뛰지만 문자열 값을 디코딩하지는 않는다."""
    if depth > 24:
        raise ValueError("lexical_depth")
    quote, index = text[start], start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 3 if text[index + 1:index + 3] == "\r\n" else 2
        elif char == quote:
            return index + 1
        elif quote == "`" and text.startswith("${", index):
            index = _interpolation_end(text, index + 2, depth + 1)
        elif char in "\r\n" and quote != "`":
            raise ValueError("unterminated_string")
        else:
            index += 1
    raise ValueError("unterminated_string")


def _regex_end(text, start):
    # Ambiguous division/regex syntax is opaque, rather than parsed as call text.
    index, in_class = start + 1, False
    while index < len(text) and text[index] not in "\r\n":
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(text) and text[index].isalpha():
                index += 1
            return index
        index += 1
    return index


def _interpolation_end(text, start, depth):
    level, index = 1, start
    while index < len(text):
        char = text[index]
        if char in "\"'`":
            index = _quoted_end(text, index, depth)
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = end if end >= 0 else len(text)
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated_comment")
            index = end + 2
        elif char == "/":
            index = _regex_end(text, index)
        else:
            level += (char == "{") - (char == "}")
            index += 1
            if level == 0:
                return index
    raise ValueError("unterminated_template")


def interpolations(value):
    """이스케이프된 달러 기호를 건너뛰고 템플릿 본문의 보간 구간만 반환한다."""
    index = 0
    while index < len(value):
        if value[index] == "\\":
            index += 2
        elif value.startswith("${", index):
            try:
                end = _interpolation_end(value, index + 2, 0)
            except ValueError:
                raise Unsupported("unsupported_expression") from None
            yield index, end
            index = end
        else:
            index += 1


def tokenize(text, problems=None):
    """주석과 인용 문자열을 구별해 (tokens, limited)를 반환하는 제한된 어휘 분석기다.

    원문/토큰은 일시적으로만 보관한다. 오류·상한에서는 불완전한 토큰을 사용하지 않고 비운다.
    problems에는 원문 없이 고정 코드와 문자 위치를 남긴다.
    """
    tokens, index = [], 0
    def fail(reason):
        if problems is not None:
            problems.append({"reason": reason, "position": index})
        return [], True
    try:
        if len(text) > 1048576:
            return fail("source_size_limit")
        while index < len(text):
            start, char = index, text[index]
            if char.isspace():
                index += 1
                continue
            if text.startswith("//", index):
                end = text.find("\n", index)
                index = end if end >= 0 else len(text)
                continue
            if text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0:
                    raise ValueError("unterminated_comment")
                index = end + 2
                continue
            if len(tokens) >= MAX_TOKENS:
                return fail("token_limit")
            if char in "\"'`":
                index = _quoted_end(text, index)
                tokens.append(Token("template" if char == "`" else "string", text[start + 1:index - 1], start, index))
            elif char == "/":
                index = _regex_end(text, index)
                tokens.append(Token("opaque", "regex_or_division", start, index))
            elif match := IDENTIFIER.match(text, index):
                index = match.end()
                tokens.append(Token("identifier", match.group(), start, index))
            else:
                operator = next((value for value in ("===", "!==", "...", "||=", "&&=", "??=", "**=", "=>", "==", "!=", "++", "--", "+=", "-=", "*=", "%=", "??", "?.", "&&", "||", "<=", ">=") if text.startswith(value, index)), char)
                index += len(operator)
                if char == "\\":
                    return fail("escaped_identifier_unsupported")
                tokens.append(Token("punctuation", operator, start, index))
        return tokens, False
    except ValueError as exc:
        return fail(str(exc))


@dataclass
class Scope:
    """start/end는 Token의 문자 위치가 아닌 토큰 배열 인덱스다. 부모를 따라 이름을 검색한다."""
    start: int
    end: int
    kind: str = "block"
    parameters: list = field(default_factory=list)
    parent: object = None
    bindings: dict = field(default_factory=dict)


@dataclass
class Binding:
    """선언 하나와 초기화식 토큰. position은 원문의 선언 이름 위치이며 실행된 값이 아니다."""
    name: str
    position: int
    scope: Scope
    expression: list
    reason: str | None = None


@dataclass
class Unknown:
    """미확인 값을 이름·사유·원문 위치로 보존한다. 빈 문자열로 대체하면 거짓 URL이 만들어진다."""
    name: str
    reason: str
    position: int
    declaration: int | None = None
    scope_position: int | None = None


class Unsupported(ValueError):
    """문자열 조각으로 표현할 수 없는 식. 호출자가 제외하거나 별칭의 Unknown으로 바꾼다."""
    pass


def decode_string(value):
    """허용한 JS 문자열 이스케이프만 복호화한다. Python의 unicode_escape는 사용하지 않는다."""
    # 문자열을 JS로 실행하지 않고 허용한 escape만 해석한다. 미지원/잘못된 값은 추측하지 않는다.
    output, index = [], 0
    simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v",
              "\\": "\\", "/": "/", "'": "'", '"': '"', "`": "`", "$": "$"}
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        index += 1
        if index == len(value):
            raise Unsupported("invalid_string_escape")
        char = value[index]
        index += 1
        if char in simple:
            output.append(simple[char])
        elif char in "\r\n":
            if char == "\r" and index < len(value) and value[index] == "\n":
                index += 1
        elif char == "0" and (index == len(value) or not value[index].isdigit()):
            output.append("\0")
        elif char in ("x", "u"):
            if char == "u" and index < len(value) and value[index] == "{":
                end = value.find("}", index + 1)
                digits = value[index + 1:end] if end >= 0 else ""
                index = end + 1
                valid = 1 <= len(digits) <= 6
            else:
                width = 2 if char == "x" else 4
                digits = value[index:index + width]
                index += width
                valid = len(digits) == width
            if not valid or not re.fullmatch(r"[0-9a-fA-F]+", digits) or int(digits, 16) > 0x10ffff:
                raise Unsupported("invalid_string_escape")
            output.append(chr(int(digits, 16)))
        else:
            raise Unsupported("unsupported_string_escape")
    try:
        # 인접한 UTF-16 surrogate pair만 합치고 고립 surrogate는 거부한다.
        return "".join(output).encode("utf-16-le", errors="surrogatepass").decode("utf-16-le")
    except UnicodeError:
        raise Unsupported("invalid_string_escape") from None


class Script:
    """한 JS 본문의 토큰·괄호 쌍·선언 범위 인덱스. 다른 파일이나 script와 공유하지 않는다."""
    def __init__(self, text):
        self.text = text
        self.lines = [0] + [match.end() for match in re.finditer("\n", text)]
        self.problems = []
        self.tokens, self.limited = tokenize(text, self.problems)
        self.pairs = {}
        self.scopes = [Scope(0, len(self.tokens), "root")]
        self.token_scopes = []
        self.excluded_strings = set()
        # 먼저 전체 선언을 등록해야 뒤에 선언된 지역 변수도 바깥쪽 상수를 가린다는 사실을 안다.
        self._build_scopes()
        self._bindings()

    def location(self, position):
        """문자 오프셋을 본문 기준 1 기반 행/열로 바꾼다. 바이트나 브라우저 UTF-16 오프셋이 아니다."""
        line = bisect_right(self.lines, position)
        return {"line": line, "column": position - self.lines[line - 1] + 1}

    def _end_expression(self, start, stop=None):
        """최상위 구분자까지의 토큰 구간을 찾는다. 중첩 괄호는 건너뛰며 완전한 JS ASI 파서는 아니다."""
        index, end = start, len(self.tokens) if stop is None else stop
        while index < end:
            token = self.tokens[index]
            if token.kind == "punctuation" and token.value in (",", ";", ")", "]", "}"):
                break
            if index > start and token.kind == "identifier" and "\n" in self.text[self.tokens[index - 1].end:token.start]:
                if token.value in {"const", "let", "var", "fetch", "axios", "return", "function", "export"}:
                    break
            index = self.pairs.get(index, index) + 1 if token.kind == "punctuation" and token.value in ("(", "[", "{") else index + 1
        return index

    def _build_scopes(self):
        """괄호를 검증한 뒤 중괄호/함수/for/짧은 화살표 본문의 범위와 부모 관계를 만든다.

        문법 전체를 재현하지 않는 휴리스틱이다. 문자열의 괄호 글자를 구문으로 취급하면 안 된다.
        """
        stack = []
        for index, token in enumerate(self.tokens):
            if token.kind != "punctuation":
                continue
            if token.value in ("(", "[", "{"):
                stack.append(index)
                if len(stack) > 128:
                    self.problems.append({"reason": "syntax_depth_limit", "position": token.start})
                    self.tokens, self.limited = [], True
                    return
            elif token.value in (")", "]", "}"):
                if not stack or self.tokens[stack[-1]].value != {")": "(", "]": "[", "}": "{"}[token.value]:
                    self.problems.append({"reason": "unbalanced_syntax", "position": token.start})
                    self.tokens, self.limited = [], True
                    return
                opening = stack.pop()
                self.pairs[opening] = index
                self.pairs[index] = opening
        if stack:
            self.problems.append({"reason": "unbalanced_syntax", "position": self.tokens[stack[-1]].start})
            self.tokens, self.limited = [], True
            return
        for index, token in enumerate(self.tokens):
            if token.value != "{" or token.kind != "punctuation":
                continue
            previous = self.tokens[index - 1].value if index else ""
            kind, parameters = "block", []
            end_parameter = index - 2 if previous == "=>" else index - 1
            if end_parameter >= 0 and self.tokens[end_parameter].kind == "punctuation" and self.tokens[end_parameter].value == ")":
                opening = self.pairs[end_parameter]
                before = self.tokens[opening - 1].value if opening else ""
                if before not in {"if", "while", "for", "switch", "with"}:
                    kind = "function" if before != "catch" else "block"
                    parameters = self.tokens[opening + 1:end_parameter]
            elif previous == "=>" and self.tokens[index - 1].kind == "punctuation" and end_parameter >= 0:
                kind, parameters = "function", [self.tokens[end_parameter]]
            self.scopes.append(Scope(index + 1, self.pairs[index], kind, parameters))
        for index, token in enumerate(self.tokens):
            if token.kind == "identifier" and token.value == "for":
                opening = index + 2 if index + 1 < len(self.tokens) and self.tokens[index + 1].value == "await" else index + 1
                if opening in self.pairs and self.tokens[opening].value == "(":
                    body = self.pairs[opening] + 1
                    end = self.pairs[body] + 1 if body in self.pairs and self.tokens[body].value == "{" else self._end_expression(body)
                    self.scopes.append(Scope(opening + 1, end))
            if token.kind == "punctuation" and token.value == "=>" and index > 0 and index + 1 < len(self.tokens) and self.tokens[index + 1].value != "{":
                previous = index - 1
                parameters = self.tokens[self.pairs[previous] + 1:previous] if previous in self.pairs and self.tokens[previous].value == ")" else [self.tokens[previous]]
                self.scopes.append(Scope(index + 1, self._end_expression(index + 1), "function", parameters))
        # 같은 시작점이면 넓은 범위를 먼저 쌓아 가장 안쪽 선언부터 검색할 수 있게 한다.
        starts = {}
        for scope in sorted(self.scopes[1:], key=lambda item: (item.start, -item.end)):
            starts.setdefault(scope.start, []).append(scope)
        active = [self.scopes[0]]
        for index in range(len(self.tokens)):
            while len(active) > 1 and index >= active[-1].end:
                active.pop()
            for scope in starts.get(index, []):
                scope.parent = active[-1]
                active.append(scope)
            self.token_scopes.append(active[-1])

    def _bind(self, scope, token, expression, reason=None):
        if token.value in scope.bindings:
            scope.bindings[token.value].reason = "ambiguous_binding"
        else:
            scope.bindings[token.value] = Binding(token.value, token.start, scope, expression, reason)

    def _lookup(self, scope, name):
        """가장 가까운 선언을 반환한다. 그 선언이 미지원이어도 바깥의 같은 이름으로 대체하지 않는다."""
        while scope is not None:
            if name in scope.bindings:
                return scope.bindings[name]
            scope = scope.parent
        return None

    def _bindings(self):
        """매개변수/선언을 먼저 등록하고, 감지한 쓰기 구문이 있으면 상수 추적을 무효화한다."""
        declaration_positions = set()
        for scope in self.scopes:
            for token in scope.parameters:
                if token.kind == "identifier":
                    self._bind(scope, token, [], "function_parameter")
        for index, token in enumerate(self.tokens):
            if token.value not in {"const", "let", "var", "function", "class", "import"} or token.kind != "identifier":
                continue
            if index and self.tokens[index - 1].value in (".", "?."):
                continue
            scope, cursor = self.token_scopes[index], index + 1
            if token.value == "var":
                while scope.parent and scope.kind not in {"root", "function"}:
                    scope = scope.parent
            if cursor >= len(self.tokens):
                continue
            if token.value in {"function", "class", "import"}:
                end = self._end_expression(cursor) if token.value == "import" else cursor + 1
                for name in self.tokens[cursor:end]:
                    if name.kind == "identifier":
                        self._bind(scope, name, [], "unsupported_binding")
                continue
            while cursor < len(self.tokens):
                name = self.tokens[cursor]
                if name.kind == "punctuation" and name.value in ("{", "["):
                    end = self.pairs[cursor]
                    for part in self.tokens[cursor + 1:end]:
                        if part.kind == "identifier":
                            self._bind(scope, part, [], "unsupported_binding")
                    break
                if name.kind != "identifier":
                    break
                declaration_positions.add(name.start)
                start = cursor + 2
                end = self._end_expression(start) if cursor + 1 < len(self.tokens) and self.tokens[cursor + 1].value == "=" else cursor + 1
                expression = self.tokens[start:end] if end >= start else []
                reason = None if token.value == "const" else "mutable_binding"
                self._bind(scope, name, expression, reason)
                if SENSITIVE.search(name.value):
                    # 사용되지 않은 민감 변수도 초기화 문자열이 일반 URL 후보로 새지 않도록 제외한다.
                    self.excluded_strings.update(part.start for part in expression)
                if end < len(self.tokens) and self.tokens[end].value == ",":
                    cursor = end + 1
                else:
                    break
        # 실행 순서를 해석하지 않는다. 호출 뒤의 쓰기라도 발견하면 보수적으로 미확인 처리한다.
        for index, token in enumerate(self.tokens):
            if token.kind != "identifier" or token.start in declaration_positions:
                continue
            if index and self.tokens[index - 1].value in (".", "?."):
                continue
            next_value = self.tokens[index + 1].value if index + 1 < len(self.tokens) else ""
            previous = self.tokens[index - 1].value if index else ""
            if next_value in {"=", "+=", "-=", "*=", "%=", "||=", "&&=", "??=", "**=", "++", "--"} or previous in {"++", "--"}:
                binding = self._lookup(self.token_scopes[index], token.value)
                if binding and not binding.reason:
                    binding.reason = "write_detected"

    def named_function_sites(self):
        """이름 있는 함수 선언과 같은 바인딩의 직접 호출 위치만 연결한다."""
        functions, owners, names = {}, {}, set()
        tokens = self.tokens
        for scope in self.scopes:
            if scope.kind != "function":
                continue
            body = scope.start - 1
            before_body = body - 1 if tokens[body].value == "{" else body
            if before_body < 0:
                continue
            arrow = tokens[before_body].value == "=>"
            last_param = before_body - 1 if arrow else before_body
            if last_param < 0:
                continue
            opening = self.pairs.get(last_param, last_param)
            prefix = opening - 1
            if arrow:
                if prefix >= 0 and tokens[prefix].value == "async":
                    prefix -= 1
                if prefix < 2 or tokens[prefix].value != "=" or tokens[prefix - 2].value != "const":
                    continue
                name_index = prefix - 1
            else:
                if opening < 2 or tokens[opening - 2].value != "function":
                    continue
                name_index = opening - 1
                # 이름 있는 함수 표현식의 이름을 바깥 범위의 선언으로 취급하지 않는다.
                previous = opening - 3
                if previous >= 0 and tokens[previous].value == "async":
                    previous -= 1
                if previous >= 0 and tokens[previous].value not in (";", "{", "}", "export", "default"):
                    prev = tokens[previous]
                    # 세미콜론을 생략한 문장 끝은 허용하되 대입식의 function 이름은 계속 제외한다.
                    newline = "\n" in self.text[prev.end:tokens[previous + 1].start]
                    ends_statement = prev.kind in ("string", "template", "identifier") or prev.value in (")", "]") or prev.value.isdecimal()
                    if not newline or not ends_statement or prev.value in ("new", "typeof", "void", "delete", "await"):
                        continue
            name = tokens[name_index]
            binding = self._lookup(self.token_scopes[name_index], name.value)
            expected = None if arrow else "unsupported_binding"
            if not binding or binding.position != name.start or binding.reason != expected:
                continue
            info = {"name": safe_name(name.value), "declaration": self.location(name.start), "uses": []}
            functions[name.start] = owners[id(scope)] = info
            names.add(name.value)
        reassigned = set()
        for index, token in enumerate(tokens[:-1]):
            if token.kind != "identifier" or token.value not in names:
                continue
            if index and tokens[index - 1].value in (".", "?.", "function", "new"):
                continue
            binding = self._lookup(self.token_scopes[index], token.value)
            if not binding or binding.position not in functions or binding.position == token.start:
                continue
            after = tokens[index + 1].value
            if after in {"=", "+=", "-=", "*=", "%=", "**=", "||=", "&&=", "??=", "++", "--"} or (
                    index and tokens[index - 1].value in ("++", "--")):
                reassigned.add(binding.position)
            if after != "(":
                continue
            # 메서드 정의의 이름 뒤에도 괄호가 온다. 호출로 표시하지 않는다.
            closing = self.pairs.get(index + 1)
            if closing is None or (closing + 1 < len(tokens) and tokens[closing + 1].value == "{"):
                continue
            info = functions[binding.position]
            if len(info["uses"]) < 8:
                info["uses"].append(self.location(token.start))
            else:
                info["uses_limited"] = True
        for position in reassigned:
            functions[position]["uses"].clear()
            functions[position].pop("uses_limited", None)
        return owners

    def calls(self):
        """(호출 토큰, 범위, URL식 토큰, 호출 형태, 선언 메서드)를 순서대로 생성한다.

        fetch/axios/open이라는 구문 모양을 관찰할 뿐 실제 함수 정체나 실행 여부를 확인하지 않는다.
        URL식의 문자열 조각은 별도의 완성 URL로 다시 수집하지 않도록 제외 집합에 넣는다.
        """
        for index, token in enumerate(self.tokens):
            if token.kind != "identifier":
                continue
            start, attribute, method = None, None, None
            if token.value == "fetch" and (index == 0 or self.tokens[index - 1].value not in (".", "?.")):
                if index + 1 < len(self.tokens) and self.tokens[index + 1].value == "(":
                    start, attribute = index + 2, "fetch"
            elif token.value == "axios" and index + 3 < len(self.tokens):
                if self.tokens[index + 1].value == "." and self.tokens[index + 2].value.upper() in METHODS and self.tokens[index + 3].value == "(":
                    start, method = index + 4, self.tokens[index + 2].value.upper()
                    attribute = "axios." + method.lower()
            elif token.value == "open" and index > 0 and index + 4 < len(self.tokens):
                if self.tokens[index - 1].value == "." and self.tokens[index + 1].value == "(" and self.tokens[index + 2].kind == "string" and self.tokens[index + 2].value.upper() in METHODS and self.tokens[index + 3].value == ",":
                    start, attribute, method = index + 4, "xhr.open", self.tokens[index + 2].value.upper()
            if start is None:
                continue
            end = self._end_expression(start)
            if end >= len(self.tokens):
                continue
            expression = self.tokens[start:end]
            self.excluded_strings.update(part.start for part in expression)
            if attribute == "fetch":
                if self.tokens[end].value == ")":
                    method = "GET"
                elif self.tokens[end].value == "," and end + 1 in self.pairs and self.tokens[end + 1].value == "{":
                    # Only a single literal method with no spread/computed override is evidence.
                    close = self.pairs[end + 1]
                    option_tokens = self.tokens[end + 2:close]
                    declared, invalid, cursor = [], False, 0
                    while cursor < len(option_tokens):
                        part = option_tokens[cursor]
                        if part.value in {"...", "["}:
                            invalid = True
                        if part.value == "method" and cursor + 2 < len(option_tokens) and option_tokens[cursor + 1].value == ":":
                            value = option_tokens[cursor + 2]
                            complete = cursor + 3 == len(option_tokens) or (option_tokens[cursor + 3].kind == "punctuation" and option_tokens[cursor + 3].value == ",")
                            declared.append(value.value.upper() if complete and value.kind == "string" and value.value.upper() in METHODS else None)
                        if part.value in ("{", "[", "(") and part.kind == "punctuation":
                            position = end + 2 + cursor
                            cursor = self.pairs[position] - (end + 2) + 1
                        else:
                            cursor += 1
                    method = declared[0] if len(declared) == 1 and not invalid else None
            yield token, self.token_scopes[index], expression, attribute, method


class Resolution:
    """호출 한 개의 추적 예산과 선언 근거. expression 결과는 str/Unknown 조각의 목록이다."""
    def __init__(self, script):
        self.script = script
        self.bindings = {}
        self.steps = 0
        self.limited = False

    def name(self, name, scope, position, stack):
        """이름을 선행 const로 따라간다. stack에는 이름 대신 선언 위치를 넣어 범위별로 구별한다."""
        self.steps += 1
        binding = self.script._lookup(scope, name) if "." not in name else None
        owner = binding.scope if binding else scope
        scope_position = self.script.tokens[owner.start].start if owner.start < len(self.script.tokens) else 0
        def unknown(reason):
            return [Unknown(name, reason, position, binding.position if binding else None, scope_position)]
        if self.steps > MAX_STEPS or len(stack) >= MAX_DEPTH:
            self.limited = True
            return unknown("trace_limit")
        if SENSITIVE.search(name):
            return unknown("sensitive_binding")
        if "." in name:
            return unknown("property_access")
        if binding is None:
            return unknown("definition_not_found")
        self.script.excluded_strings.update(token.start for token in binding.expression)
        reason = binding.reason
        if binding.position in stack:
            reason = "cyclic_reference"
        elif binding.position >= position:
            reason = "declaration_after_use"
        if reason:
            result = unknown(reason)
        else:
            try:
                # 별칭은 사용하는 곳이 아닌 선언된 범위에서 해석한다. 호출 쪽의 동명 변수가 끼면 안 된다.
                result = self.expression(binding.expression, binding.scope, stack + (binding.position,))
            except Unsupported as exc:
                result = unknown(str(exc))
        # 근거에는 선언 이름·위치·상태만 저장하고 원래 상수 값 목록은 만들지 않는다.
        self.bindings[binding.position] = {"name": name, "declaration": self.script.location(binding.position),
                                           "scope": self.script.location(self.script.tokens[binding.scope.start].start) if binding.scope.start < len(self.script.tokens) else {"line": 1, "column": 1},
                                           "resolution": "resolved" if not any(isinstance(part, Unknown) for part in result)
                                           else "partial" if any(isinstance(part, str) and part for part in result) else "unresolved"}
        return result

    def expression(self, tokens, scope, stack=(), group_depth=0):
        """문자열/이름/단순 템플릿을 +로 이은 작은 문법만 조합한다. JS 평가기는 아니다.

        미지원 식은 Unsupported, 추적 불가 이름은 Unknown이다. 숫자 연산·함수 호출은 실행하지 않는다.
        """
        if not tokens:
            raise Unsupported("unsupported_expression")
        if group_depth >= MAX_GROUP_DEPTH:
            self.limited = True
            raise Unsupported("group_depth_limit")
        parts, cursor, expect_atom = [], 0, True
        while cursor < len(tokens):
            token = tokens[cursor]
            if not expect_atom:
                if token.kind != "punctuation" or token.value != "+":
                    raise Unsupported("unsupported_expression")
                expect_atom, cursor = True, cursor + 1
                continue
            if token.kind in ("string", "template"):
                if token.kind == "template":
                    offset = 0
                    for index, end in interpolations(token.value):
                        name = token.value[index + 2:end - 1].strip()
                        if not MEMBER.fullmatch(name):
                            raise Unsupported("unsupported_expression")
                        parts.append(decode_string(token.value[offset:index]))
                        parts.extend(self.name(name, scope, token.start + 1 + index, stack))
                        offset = end
                    parts.append(decode_string(token.value[offset:]))
                else:
                    parts.append(decode_string(token.value))
                cursor += 1
            elif token.kind == "punctuation" and token.value == "(":
                level, end = 1, cursor + 1
                while end < len(tokens) and level:
                    if tokens[end].kind == "punctuation":
                        level += (tokens[end].value == "(") - (tokens[end].value == ")")
                    end += 1
                if level:
                    raise Unsupported("unsupported_expression")
                parts.extend(self.expression(tokens[cursor + 1:end - 1], scope, stack, group_depth + 1))
                cursor = end
            elif token.kind == "identifier":
                name, cursor = token.value, cursor + 1
                while cursor + 1 < len(tokens) and tokens[cursor].value == "." and tokens[cursor + 1].kind == "identifier":
                    name += "." + tokens[cursor + 1].value
                    cursor += 2
                parts.extend(self.name(name, scope, token.start, stack))
            else:
                raise Unsupported("unsupported_expression")
            expect_atom = False
            if len(parts) > MAX_PARTS or sum(len(part) for part in parts if isinstance(part, str)) > MAX_LENGTH:
                self.limited = True
                raise Unsupported("expression_limit")
        if expect_atom:
            raise Unsupported("unsupported_expression")
        return parts
