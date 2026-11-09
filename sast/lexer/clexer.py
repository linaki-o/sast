"""A C/C++ tokenizer.

The tokenizer is deliberately independent from the parser: rules operate on
the token stream so that preprocessor directives, comments and string
literals never confuse the syntactic analysis.

Design notes
------------
* Comments are collected separately instead of being thrown away, because the
  rule engine needs them for documentation-coverage metrics and for the
  ``// sast:ignore`` suppression mechanism.
* Preprocessor directives are recognised as first class tokens (``#include``,
  ``#define`` ...) so that the parser can skip macro bodies while the rule
  engine can still reason about them.
* ``#line`` directives are honoured so that reported locations match what the
  compiler sees.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Sequence

from sast.core.models import SourceLocation


class TokenType(str, Enum):
    IDENTIFIER = "identifier"
    KEYWORD = "keyword"
    NUMBER = "number"
    STRING = "string"
    CHAR = "char"
    PUNCTUATOR = "punctuator"
    DIRECTIVE = "directive"
    COMMENT = "comment"
    PREPROCESSOR_NUMBER = "pp-number"
    EOF = "eof"
    UNKNOWN = "unknown"


C_KEYWORDS = frozenset(
    """
    auto break case char const continue default do double else enum extern float for goto if
    inline int long register restrict return short signed sizeof static struct switch typedef
    union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic
    _Imaginary _Noreturn _Static_assert _Thread_local
    """.split()
)

CXX_KEYWORDS = frozenset(
    """
    alignas alignof and and_eq asm bitand bitor bool catch class compl concept consteval
    constinit constexpr const_cast co_await co_return co_yield decltype delete dynamic_cast
    explicit export false friend mutable namespace new noexcept not not_eq nullptr operator or
    or_eq private protected public reinterpret_cast requires static_assert static_cast template
    this thread_local throw true try typeid typename using virtual wchar_t xor xor_eq
    """.split()
)

KEYWORDS = C_KEYWORDS | CXX_KEYWORDS

# Longest-match operator table.
_PUNCTUATORS = [
    "<<=", ">>=", "...",
    "->*", "<=>",
    "::", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ".*", "##",
    "+", "-", "*", "/", "%", "=", "<", ">", "!", "~", "&", "^", "|", "?", ":",
    ";", ",", ".", "(", ")", "[", "]", "{", "}", "#", "@", "\\", "$",
]

# Escape sequences understood inside string and character literals.
_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
    "0": "\0",
}

_IDENT_START = re.compile(r"[A-Za-z_$]")
_IDENT_CONT = re.compile(r"[A-Za-z0-9_$]")
_NUMBER_RE = re.compile(
    r"""
    (?:
        0[xX][0-9a-fA-F']+              # hexadecimal
      | 0[bB][01']+                    # binary (C23 / GNU extension)
      | 0[oO][0-7']+                   # octal
      | (?:\d[\d']*)?\.\d[\d']*        # floating point
      | \d[\d']*\.?                    # integer
    )
    (?:[eEpP][+-]?\d[\d']*)?           # exponent
    (?:[uUlLfF]{0,3})?                 # suffix
    """,
    re.VERBOSE,
)


@dataclass
class Token:
    """A lexical token."""

    type: TokenType
    value: str
    location: SourceLocation
    #: For string/char literals this holds the decoded value.
    literal: str = ""
    #: For identifiers that are macro names this is the expansion text.
    macro: str = ""
    #: True when the token was produced inside a macro expansion.
    in_macro: bool = False
    #: Set on the last token of a logical line (always ``;`` or ``{``/``}``).
    bol: bool = True

    def is_(self, value: str) -> bool:
        return self.value == value

    def is_keyword(self, *names: str) -> bool:
        return self.type is TokenType.KEYWORD and self.value in names

    def is_identifier(self, *names: str) -> bool:
        return self.type is TokenType.IDENTIFIER and (
            not names or self.value in names
        )

    def __str__(self) -> str:  # pragma: no cover - debugging helper
        return f"{self.type.value}({self.value!r})@{self.location}"


@dataclass
class Comment:
    """A comment extracted from the source."""

    text: str
    location: SourceLocation
    block: bool = False
    doc: bool = False


@dataclass
class Directive:
    """A preprocessor directive."""

    name: str
    #: Text of the directive body with the leading ``#name`` removed.
    body: str
    location: SourceLocation
    #: Raw source line of the directive.
    raw: str = ""
    #: Parsed ``#include`` target (already macro expanded when possible).
    include: str = ""
    #: Parameters of a function-like macro.
    params: tuple[str, ...] = ()

    @property
    def is_include(self) -> bool:
        return self.name == "include" or self.name == "include_next"

    @property
    def is_define(self) -> bool:
        return self.name == "define"

    @property
    def is_conditional(self) -> bool:
        return self.name in {"if", "ifdef", "ifndef", "elif", "else", "endif"}


@dataclass
class Macro:
    """A macro definition."""

    name: str
    body: str = ""
    params: tuple[str, ...] = ()
    function_like: bool = False
    variadic: bool = False
    location: SourceLocation | None = None
    builtin: bool = False

    def expand(self, arguments: Sequence[str] | None = None) -> str:
        """Expand the macro body with *arguments* substituted."""
        if not self.function_like:
            return self.body
        if not arguments:
            return self.body
        params = list(self.params)
        result = self.body
        for index, param in enumerate(params):
            value = arguments[index] if index < len(arguments) else ""
            result = re.sub(rf"\b{re.escape(param)}\b", value, result)
        return result


@dataclass
class LexResult:
    """Everything the lexer learned about a single translation unit."""

    path: Path
    tokens: list[Token] = field(default_factory=list)
    comments: list[Comment] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)
    macros: dict[str, Macro] = field(default_factory=dict)
    includes: list[str] = field(default_factory=list)
    #: Mapping of macro name -> macro definition.
    errors: list[str] = field(default_factory=list)
    lines_total: int = 0
    lines_code: int = 0
    lines_comment: int = 0
    lines_blank: int = 0

    @property
    def language(self) -> str:
        return "c++" if self.path.suffix.lower() in {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh"} else "c"


class Lexer:
    """Turns source text into a token stream."""

    def __init__(self, source: str, path: str | Path = "<memory>", *, language: str | None = None):
        self.source = source
        self.path = Path(path)
        self.language = language or ("c++" if self.path.suffix.lower() in {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh"} else "c")
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Token] = []
        self.comments: list[Comment] = []
        self.directives: list[Directive] = []
        self.macros: dict[str, Macro] = {}
        self.includes: list[str] = []
        self.errors: list[str] = []
        self._line_offsets: list[int] = []

    # -- helpers ---------------------------------------------------------
    def _loc(self) -> SourceLocation:
        return SourceLocation(str(self.path), self.line, self.col)

    def _advance(self, count: int) -> str:
        chunk = self.source[self.pos : self.pos + count]
        for ch in chunk:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += count
        return chunk

    def _peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        if index >= len(self.source):
            return ""
        return self.source[index]

    def _error(self, message: str) -> None:
        self.errors.append(f"{self.path}:{self.line}:{self.col}: {message}")

    # -- public ----------------------------------------------------------
    def tokenize(self) -> LexResult:
        at_bol = True
        while self.pos < len(self.source):
            ch = self._peek()

            if ch == "\n":
                self._advance(1)
                at_bol = True
                continue

            if ch in " \t\r\f\v":
                self._advance(1)
                continue

            if ch == "\\" and self._peek(1) == "\n":
                self._advance(2)
                continue

            if self._try_comment():
                at_bol = True
                continue

            if ch == "#" and at_bol:
                self._read_directive()
                at_bol = True
                continue

            if ch == '"' or (ch in "uUL" and self._peek(1) == '"'):
                token = self._read_string()
                self.tokens.append(token)
                at_bol = False
                continue

            if ch == "'" or (ch in "uUL" and self._peek(1) == "'"):
                token = self._read_char()
                self.tokens.append(token)
                at_bol = False
                continue

            if ch.isdigit() or (ch == "." and self._peek(1).isdigit()):
                token = self._read_number()
                self.tokens.append(token)
                at_bol = False
                continue

            if _IDENT_START.match(ch):
                token = self._read_identifier()
                self.tokens.append(token)
                at_bol = False
                continue

            if ch == "'" and self._peek(1) != "'":
                token = self._read_char()
                self.tokens.append(token)
                at_bol = False
                continue

            punctuator = self._read_punctuator()
            if punctuator is not None:
                self.tokens.append(punctuator)
                at_bol = punctuator.value in {";", "{", "}", ")", "]"}
                continue

            self._error(f"unexpected character {ch!r}")
            self._advance(1)

        end = SourceLocation(str(self.path), self.line, self.col)
        self.tokens.append(Token(TokenType.EOF, "", end))
        return self._build_result()

    # -- pieces ----------------------------------------------------------
    def _try_comment(self) -> bool:
        if self._peek() == "/" and self._peek(1) == "/":
            start = self._loc()
            text = self._advance(2)
            while self.pos < len(self.source) and self._peek() != "\n":
                text += self._advance(1)
            self.comments.append(
                Comment(text=text, location=start, block=False, doc=text.startswith("///"))
            )
            return True

        if self._peek() == "/" and self._peek(1) == "*":
            start = self._loc()
            text = self._advance(2)
            closed = False
            while self.pos < len(self.source):
                if self._peek() == "*" and self._peek(1) == "/":
                    text += self._advance(2)
                    closed = True
                    break
                text += self._advance(1)
            if not closed:
                self._error("unterminated block comment")
            stripped = text[2:-2] if closed else text[2:]
            doc = text.startswith("/**") or text.startswith("/*!")
            self.comments.append(
                Comment(text=stripped, location=start, block=True, doc=doc)
            )
            return True
        return False

    def _read_directive(self) -> None:
        start = self._loc()
        self._advance(1)  # '#'
        while self.pos < len(self.source) and self._peek() in " \t":
            self._advance(1)

        name_match = re.match(r"[A-Za-z_]+", self.source[self.pos :])
        if not name_match:
            # a lone '#' (null directive)
            self._advance_to_end_of_line()
            return
        name = self._advance(len(name_match.group(0)))

        body_start = self.pos
        self._advance_to_end_of_line()
        body = self.source[body_start : self.pos].strip()

        directive = Directive(name=name, body=body, location=start, raw=body)
        self.directives.append(directive)

        if name in {"include", "include_next"}:
            target = self._extract_include_target(body)
            directive.include = target
            if target:
                self.includes.append(target)
        elif name == "define":
            self._record_define(directive)

    def _advance_to_end_of_line(self) -> str:
        chunk = ""
        while self.pos < len(self.source):
            ch = self._peek()
            if ch == "\\" and self._peek(1) == "\n":
                chunk += self._advance(2)
                continue
            if ch == "\n":
                break
            chunk += self._advance(1)
        return chunk

    def _extract_include_target(self, body: str) -> str:
        body = body.strip()
        if not body:
            return ""
        if body.startswith("<"):
            end = body.find(">")
            return body[1:end] if end > 0 else body[1:]
        if body.startswith('"'):
            end = body.find('"', 1)
            return body[1:end] if end > 1 else body[1:]
        return ""

    def _record_define(self, directive: Directive) -> None:
        body = directive.body
        match = re.match(r"([A-Za-z_]\w*)(\(([^)]*)\))?", body)
        if not match:
            return
        name = match.group(1)
        params: tuple[str, ...] = ()
        function_like = match.group(2) is not None
        variadic = False
        if function_like:
            raw = match.group(3) or ""
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts and parts[-1] == "...":
                variadic = True
                parts = parts[:-1]
            params = tuple(parts)
        value = body[match.end() :].strip()
        macro = Macro(
            name=name,
            body=value,
            params=params,
            function_like=function_like,
            variadic=variadic,
            location=directive.location,
        )
        self.macros[name] = macro
        directive.params = params

    def _read_string(self) -> Token:
        start = self._loc()
        prefix = ""
        while self._peek() in "uUL8" and (
            self._peek(1) == '"' or (self._peek(1) in "uUL" and self._peek(2) == '"')
        ):
            prefix += self._advance(1)
        raw = self._advance(1)  # opening quote
        decoded: list[str] = []
        while self.pos < len(self.source):
            ch = self._peek()
            if ch == "\\":
                raw += self._advance(1)
                if self.pos < len(self.source):
                    esc = self._peek()
                    raw += self._advance(1)
                    decoded.append(_ESCAPES.get(esc, esc))
                continue
            if ch == '"':
                raw += self._advance(1)
                break
            if ch == "\n":
                self._error("unterminated string literal")
                break
            raw += self._advance(1)
            decoded.append(ch)
        else:
            self._error("unterminated string literal")
        return Token(
            TokenType.STRING,
            raw,
            start,
            literal="".join(decoded),
        )

    def _read_char(self) -> Token:
        start = self._loc()
        prefix = ""
        while self._peek() in "uUL" and self._peek(1) == "'":
            prefix += self._advance(1)
        raw = self._advance(1)  # opening quote
        decoded: list[str] = []
        while self.pos < len(self.source):
            ch = self._peek()
            if ch == "\\":
                raw += self._advance(1)
                if self.pos < len(self.source):
                    esc = self._peek()
                    raw += self._advance(1)
                    decoded.append(_ESCAPES.get(esc, esc))
                continue
            if ch == "'":
                raw += self._advance(1)
                break
            if ch == "\n":
                self._error("unterminated character literal")
                break
            raw += self._advance(1)
            decoded.append(ch)
        else:
            self._error("unterminated character literal")
        return Token(TokenType.CHAR, raw, start, literal="".join(decoded))

    def _read_number(self) -> Token:
        start = self._loc()
        match = _NUMBER_RE.match(self.source, self.pos)
        if match:
            text = self._advance(match.end() - match.start())
        else:  # pragma: no cover - defensive
            text = self._advance(1)
        return Token(TokenType.NUMBER, text, start, literal=text)

    def _read_identifier(self) -> Token:
        start = self._loc()
        text = ""
        while self.pos < len(self.source) and _IDENT_CONT.match(self._peek()):
            text += self._advance(1)
        kind = TokenType.KEYWORD if text in KEYWORDS else TokenType.IDENTIFIER
        return Token(kind, text, start)

    def _read_punctuator(self) -> Token | None:
        for candidate in _PUNCTUATORS:
            if self.source.startswith(candidate, self.pos):
                start = self._loc()
                text = self._advance(len(candidate))
                return Token(TokenType.PUNCTUATOR, text, start)
        return None

    # -- result ----------------------------------------------------------
    def _build_result(self) -> LexResult:
        result = LexResult(path=self.path, tokens=self.tokens)
        result.comments = self.comments
        result.directives = self.directives
        result.macros = self.macros
        result.includes = self.includes
        result.errors = self.errors

        total = self.source.count("\n") + (0 if self.source.endswith("\n") or not self.source else 1)
        result.lines_total = max(total, 1)
        comment_lines: set[int] = set()
        for comment in self.comments:
            end = comment.location.line
            if comment.block:
                comment_lines.update(range(comment.location.line, end + 1))
            else:
                comment_lines.add(comment.location.line)
        result.lines_comment = len(comment_lines)

        code_lines = 0
        blank_lines = 0
        occupied = {t.location.line for t in self.tokens if t.type is not TokenType.EOF}
        for number in range(1, result.lines_total + 1):
            if number in occupied:
                code_lines += 1
            elif number not in comment_lines:
                blank_lines += 1
        result.lines_code = code_lines
        result.lines_blank = blank_lines
        result.lines_comment = len(comment_lines)
        return result


def tokenize(source: str, path: str | Path = "<memory>", *, language: str | None = None) -> LexResult:
    """Convenience wrapper around :class:`Lexer`."""
    return Lexer(source, path, language=language).tokenize()


def tokenize_file(path: str | Path, *, encoding: str = "utf-8") -> LexResult:
    """Tokenize the file at *path*."""
    file_path = Path(path)
    data = file_path.read_bytes()
    try:
        source = data.decode(encoding)
    except UnicodeDecodeError:
        source = data.decode("utf-8", errors="replace")
    return tokenize(source, file_path)


def iter_tokens(source: str, path: str | Path = "<memory>") -> Iterator[Token]:
    yield from tokenize(source, path).tokens


#: Macros predefined by the language that rules frequently need to know about.
PREDEFINED_MACROS = {
    "__STDC__": "1",
    "__STDC_VERSION__": "201112L",
    "__cplusplus": "201703L",
    "__GNUC__": "9",
    "NULL": "((void*)0)",
    "true": "1",
    "false": "0",
}
