"""A tree walking interpreter for a practical subset of C.

The interpreter consumes the lightweight AST produced by
:mod:`sast.ast.parser` and executes it directly in Python.  It is used as the
portable test engine: it needs no compiler, it understands pointers and
structs, and it reports every executed statement to a coverage collector so
that statement, branch, condition and MC/DC coverage can be computed.

Memory is modelled by a byte addressable store.  ``malloc`` hands out
integer addresses, local arrays are backed by blocks of the very same store
and pointer arithmetic is plain integer arithmetic on those addresses.  As a
consequence ``memcpy``, ``strcpy`` and friends behave realistically and an
out of bounds access is reported instead of silently succeeding.
"""

from __future__ import annotations

import io
import math
import re
import struct
from typing import Any, Sequence

from sast.ast.nodes import (
    ArrayType,
    Assignment,
    BinaryOp,
    Call,
    CaseStmt,
    Cast,
    CompoundStmt,
    ConditionalOp,
    DeclStmt,
    DefaultStmt,
    DeleteExpr,
    DoWhileStmt,
    EnumDecl,
    EnumType,
    Expr,
    ExprStmt,
    ForStmt,
    FunctionDecl,
    FunctionType,
    GotoStmt,
    Identifier,
    IfStmt,
    InitList,
    LabelStmt,
    Literal,
    NewExpr,
    Node,
    PointerType,
    PrimitiveType,
    ReferenceType,
    ReturnStmt,
    SizeOfExpr,
    Stmt,
    StructType,
    SwitchStmt,
    TranslationUnit,
    TypeNode,
    TypedefDecl,
    TypedefType,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from sast.analysis.scope import SIZEOF_PRIMITIVES
from sast.ast.parser import QUALIFIER_KEYWORDS, TYPE_KEYWORDS, Parser
from sast.core.models import SourceLocation
from sast.lexer.clexer import Token, TokenType, tokenize

__all__ = [
    "InterpreterError",
    "InterpreterTimeout",
    "InterpreterLimit",
    "MemoryFault",
    "AbortSignal",
    "ExitSignal",
    "AssertionFailure",
    "CParseFailure",
    "OutParameter",
    "Buffer",
    "Memory",
    "CInterpreter",
]


class InterpreterError(Exception):
    """Base class of every error raised by the interpreter."""

    def __init__(self, message: str, location: SourceLocation | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.location = location

    def __str__(self) -> str:
        if self.location is not None:
            return f"{self.message} ({self.location})"
        return self.message


class InterpreterTimeout(InterpreterError):
    """The step budget of the interpreter was exhausted."""


class InterpreterLimit(InterpreterError):
    """The recursion limit of the interpreter was reached."""


class MemoryFault(InterpreterError):
    """An invalid memory access was attempted."""


class AbortSignal(InterpreterError):
    """``abort()`` was called."""


class ExitSignal(InterpreterError):
    """``exit()`` was called."""

    def __init__(
        self,
        message: str = "program exited",
        location: SourceLocation | None = None,
        code: int = 0,
    ) -> None:
        super().__init__(message, location)
        self.code = code


class AssertionFailure(InterpreterError):
    """``assert()`` failed."""


class CParseFailure(InterpreterError):
    """The source could not be parsed."""


class OutParameter:
    """A caller owned cell that is passed to a C function as ``&arg``.

    The interpreter allocates the storage, hands the address to the callee
    and reads the final content back once the call returned.
    """

    def __init__(
        self,
        name: str = "",
        size: int = 4,
        value: int = 0,
        type: TypeNode | None = None,
    ) -> None:
        self.name = name
        self.size = int(size)
        self.value = value
        self.type = type
        self.address = 0
        self.source: Memory | None = None
        self.source_size: int = int(size)

    def current(self) -> int:
        """Read the value the callee left in the cell."""
        if self.source is not None and self.address:
            try:
                return self.source.load_int(self.address, max(self.source_size, 1))
            except MemoryFault:
                return self.value
        return self.value

    def __repr__(self) -> str:
        return f"<OutParameter {self.name!r} size={self.size} value={self.value}>"


class Buffer:
    """A writable byte buffer that is passed to a C function as ``char *``."""

    def __init__(
        self, name: str = "", data: bytes | str = b"", capacity: int | None = None
    ) -> None:
        self.name = name
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.data = bytes(data)
        self.capacity = int(capacity) if capacity is not None else max(len(self.data), 1)
        self.address = 0
        self.source: Memory | None = None
        self.source_size: int = self.capacity

    def current(self) -> bytes:
        """Read the bytes the callee left in the buffer."""
        if self.source is not None and self.address:
            try:
                return self.source.read(self.address, max(self.source_size, 1))
            except MemoryFault:
                return self.data
        return self.data

    def text(self) -> str:
        return self.current().split(b"\x00")[0].decode("utf-8", errors="replace")

    def __repr__(self) -> str:
        return f"<Buffer {self.name!r} capacity={self.capacity}>"


class Memory:
    """A byte addressable store with a bump allocator."""

    def __init__(self) -> None:
        self._blocks: dict[int, bytearray] = {}
        self._sizes: dict[int, int] = {}
        self._bases: list[int] = []
        self._next_address: int = 0x1000
        self._freed: set[int] = set()

    def allocate(self, size: int) -> int:
        size = max(int(size), 1)
        address = self._next_address
        self._next_address += size + 16
        self._blocks[address] = bytearray(size)
        self._sizes[address] = size
        self._bases.append(address)
        self._bases.sort()
        return address

    def free(self, address: int) -> None:
        if address in self._blocks:
            del self._blocks[address]
            self._sizes.pop(address, None)
            self._freed.add(address)

    def is_valid(self, address: int, size: int = 1) -> bool:
        try:
            self._locate(address, size)
        except MemoryFault:
            return False
        return True

    def _locate(self, address: int, size: int) -> tuple[int, bytearray]:
        if address < 0:
            raise MemoryFault(f"invalid memory access at {address}")
        for base in self._bases:
            if base > address:
                break
            length = self._sizes.get(base)
            if length is None:
                continue
            if address + size <= base + length:
                return base, self._blocks[base]
        if address in self._freed:
            raise MemoryFault(f"access to freed memory at {address}")
        raise MemoryFault(f"invalid memory access at {address} ({size} bytes)")

    def read(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        base, block = self._locate(address, size)
        offset = address - base
        return bytes(block[offset : offset + size])

    def write(self, address: int, data: bytes) -> None:
        if not data:
            return
        base, block = self._locate(address, len(data))
        offset = address - base
        block[offset : offset + len(data)] = data

    def load_int(self, address: int, size: int = 4, signed: bool = True) -> int:
        raw = self.read(address, size)
        if not raw:
            return 0
        value = int.from_bytes(raw, "little", signed=False)
        if signed and size > 0 and value >= (1 << (size * 8 - 1)):
            value -= 1 << (size * 8)
        return value

    def store_int(self, address: int, value: int, size: int = 4) -> None:
        mask = (1 << (size * 8)) - 1 if size > 0 else 0
        self.write(address, (int(value) & mask).to_bytes(size, "little", signed=False))

    def load_float(self, address: int, size: int = 8) -> float:
        raw = self.read(address, size)
        if not raw:
            return 0.0
        if size == 4:
            return float(struct.unpack("<f", raw)[0])
        if size == 8:
            return float(struct.unpack("<d", raw)[0])
        raise MemoryFault(f"cannot read a float of {size} bytes")

    def store_float(self, address: int, value: float, size: int = 8) -> None:
        if size == 4:
            self.write(address, struct.pack("<f", float(value)))
        elif size == 8:
            self.write(address, struct.pack("<d", float(value)))
        else:
            raise MemoryFault(f"cannot store a float of {size} bytes")

    def read_cstring(self, address: int, limit: int = 1 << 20) -> str:
        if address == 0:
            raise MemoryFault("read from a null pointer")
        data = bytearray()
        current = address
        while len(data) < limit:
            chunk = self.read(current, 1)
            if not chunk:
                break
            if chunk[0] == 0:
                break
            data.extend(chunk)
            current += 1
        return data.decode("utf-8", errors="replace")

    def snapshot(self) -> bytes:
        chunks = []
        for base in sorted(self._blocks):
            chunks.append(bytes(self._blocks[base]))
        return b"".join(chunks)

    @property
    def blocks(self) -> dict[int, bytearray]:
        return self._blocks


class Val:
    """A runtime value together with its declared type."""

    __slots__ = ("value", "type")

    def __init__(self, value: Any = 0, type: TypeNode | None = None) -> None:
        self.value = value
        self.type = type

    def __repr__(self) -> str:
        return f"<Val {self.value!r}>"


class Binding:
    """A named storage location."""

    __slots__ = (
        "name",
        "value",
        "type",
        "address",
        "memory_backed",
        "initialized",
        "init_expr",
        "size",
    )

    def __init__(
        self,
        name: str,
        value: Any = 0,
        type: TypeNode | None = None,
        address: int | None = None,
        memory_backed: bool = False,
        init_expr: Expr | None = None,
        size: int = 0,
    ) -> None:
        self.name = name
        self.value = value
        self.type = type
        self.address = address
        self.memory_backed = memory_backed
        self.initialized = init_expr is None
        self.init_expr = init_expr
        self.size = size


class Environment:
    """A lexical scope."""

    def __init__(self, parent: "Environment | None" = None) -> None:
        self.parent = parent
        self.vars: dict[str, Binding] = {}

    def define(
        self,
        name: str,
        value: Any = 0,
        type: TypeNode | None = None,
        address: int | None = None,
        memory_backed: bool = False,
        init_expr: Expr | None = None,
        size: int = 0,
    ) -> Binding:
        binding = Binding(name, value, type, address, memory_backed, init_expr, size)
        self.vars[name] = binding
        return binding

    def lookup_local(self, name: str) -> Binding | None:
        return self.vars.get(name)

    def lookup(self, name: str) -> Binding | None:
        scope: Environment | None = self
        while scope is not None:
            binding = scope.vars.get(name)
            if binding is not None:
                return binding
            scope = scope.parent
        return None


class LValue:
    """The storage a value can be read from or written to."""

    __slots__ = ("kind", "binding", "address", "type")

    def __init__(
        self,
        kind: str,
        binding: Binding | None = None,
        address: int | None = None,
        type: TypeNode | None = None,
    ) -> None:
        self.kind = kind
        self.binding = binding
        self.address = address
        self.type = type


class _ReturnSignal(Exception):
    def __init__(self, value: Val) -> None:
        super().__init__("return")
        self.value = value


class _BreakSignal(Exception):
    pass


class _ContinueSignal(Exception):
    pass


class _GotoSignal(Exception):
    def __init__(self, label: str) -> None:
        super().__init__(label)
        self.label = label


def _expand_macro_tokens(
    tokens: list[Token], macros: dict[str, Any], path: str
) -> tuple[list[Token], bool]:
    """Expand object like and function like macros inside *tokens*."""
    if not macros:
        return tokens, False
    result: list[Token] = []
    changed = False
    index = 0
    count = len(tokens)
    while index < count:
        token = tokens[index]
        if token.type is TokenType.IDENTIFIER and token.value in macros:
            macro = macros[token.value]
            if getattr(macro, "function_like", False):
                open_index = index + 1
                if open_index < count and tokens[open_index].value == "(":
                    close_index = _matching_paren(tokens, open_index)
                    if close_index is not None:
                        arguments = _split_arguments(tokens, open_index + 1, close_index)
                        text = macro.expand(arguments)
                        result.extend(_retokenize(text, path, token.location))
                        index = close_index + 1
                        changed = True
                        continue
            else:
                result.extend(_retokenize(macro.body, path, token.location))
                index += 1
                changed = True
                continue
        result.append(token)
        index += 1
    return result, changed


def _matching_paren(tokens: list[Token], open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(tokens)):
        value = tokens[index].value
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_arguments(tokens: list[Token], start: int, end: int) -> list[str]:
    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    for index in range(start, end):
        token = tokens[index]
        if token.value in "([{":
            depth += 1
        elif token.value in ")]}":
            depth -= 1
        if token.value == "," and depth == 0:
            arguments.append(" ".join(current))
            current = []
            continue
        current.append(token.value)
    if current:
        arguments.append(" ".join(current))
    return arguments


def _retokenize(text: str, path: str, location: SourceLocation) -> list[Token]:
    if not text.strip():
        return []
    produced = tokenize(text, path).tokens
    tokens = [token for token in produced if token.type is not TokenType.EOF]
    for token in tokens:
        token.location = location
    return tokens


def _extract_typedef_names(source: str) -> set[str]:
    """Return the names introduced by the ``typedef`` declarations of *source*."""
    names: set[str] = set()
    for text in _extract_typedef_sources(source):
        body = text.rstrip().rstrip(";").strip()
        identifiers = re.findall(r"[A-Za-z_]\w*", body)
        if identifiers:
            names.add(identifiers[-1])
    return names


class _CastAwareParser(Parser):
    """A parser that recognises cast expressions.

    The bundled parser counts the parentheses of a cast starting at zero and
    therefore never finds the closing parenthesis of ``(type)value``.  This
    subclass only corrects that scan; everything else is inherited.
    """

    def _is_cast(self) -> bool:
        if not self._check("("):
            return False
        following = self._peek(1)
        if following.type is TokenType.KEYWORD:
            if following.value in TYPE_KEYWORDS or following.value in QUALIFIER_KEYWORDS:
                return self._cast_closes_before_operand()
        if following.type is TokenType.IDENTIFIER and following.value in self.typedef_names:
            return self._cast_closes_before_operand()
        return False

    def _cast_closes_before_operand(self) -> bool:
        index = self.pos + 1
        depth = 1
        while index < len(self.tokens):
            token = self.tokens[index]
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
                if depth == 0:
                    after = self.tokens[index + 1] if index + 1 < len(self.tokens) else None
                    if after is None:
                        return False
                    if after.type in (
                        TokenType.IDENTIFIER,
                        TokenType.NUMBER,
                        TokenType.STRING,
                        TokenType.CHAR,
                    ):
                        return True
                    if after.type is TokenType.KEYWORD and after.value != "sizeof":
                        return True
                    if after.value in {"(", "!", "~", "*", "&", "-", "+", "++", "--"}:
                        return True
                    return False
            elif token.type is TokenType.EOF:
                return False
            index += 1
        return False


def _parse_source_with_macros(
    source: str,
    path: str,
    language: str = "c",
    extra_macros: dict[str, Any] | None = None,
    typedef_names: set[str] | None = None,
) -> tuple[TranslationUnit, list[tuple[SourceLocation, str]], dict[str, Any]]:
    """Parse *source* after expanding the macros it defines."""
    result = tokenize(source, path, language=language)
    macros: dict[str, Any] = dict(result.macros)
    if extra_macros:
        for name, macro in extra_macros.items():
            macros.setdefault(name, macro)
    tokens = result.tokens
    for _ in range(8):
        tokens, changed = _expand_macro_tokens(tokens, macros, path)
        if not changed:
            break
    parser = _CastAwareParser(tokens, path=path, language=language)
    if typedef_names is None:
        typedef_names = _extract_typedef_names(source)
    parser.typedef_names.update(typedef_names)
    try:
        unit = parser.parse()
    except Exception as error:
        raise CParseFailure(f"cannot parse {path}: {error}") from error
    unit.includes = list(result.includes)
    return unit, list(parser.errors), macros


def _top_level_segments(source: str) -> list[tuple[int, int]]:
    """Split *source* into the chunks delimited by top level braces.

    A chunk ends at the closing brace of a top level block and, when the
    block is followed by a declarator (``} Point;``), it also contains that
    declarator so that the chunk stays a valid declaration.
    """
    segments: list[tuple[int, int]] = []
    depth = 0
    start = 0
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                probe = index + 1
                while probe < length and source[probe] not in ";{":
                    probe += 1
                end = probe + 1 if probe < length and source[probe] == ";" else index + 1
                segments.append((start, end))
                start = end
                index = end
                continue
        index += 1
    if start < length:
        segments.append((start, length))
    return segments


def _mask_out(source: str, start: int, end: int) -> str:
    """Blank everything but the ``[start, end)`` slice, keeping the layout."""
    characters = list(source)
    for index in range(len(characters)):
        if start <= index < end:
            continue
        if characters[index] != "\n":
            characters[index] = " "
    return "".join(characters)


_POINTER_CAST_CALL = re.compile(
    r"\(\s*(?:const\s+|volatile\s+)*(?:unsigned\s+|signed\s+)?"
    r"[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*\)\s*(?=[A-Za-z_]\w*\s*\()"
)


def _strip_pointer_casts(text: str) -> str:
    """Remove the pointer casts applied to a call expression.

    The parser reads ``= (type *)call(...)`` as a compound literal and gives
    up on it.  Dropping the cast keeps the meaning of the statement in C and
    makes such a file parsable again.
    """
    return _POINTER_CAST_CALL.sub("", text)


def _parse_resilient(
    source: str,
    path: str,
    language: str = "c",
    extra_macros: dict[str, Any] | None = None,
    known_typedefs: set[str] | None = None,
) -> tuple[TranslationUnit, list[tuple[SourceLocation, str]], dict[str, Any]]:
    """Parse *source*, isolating the chunks the parser cannot handle."""
    typedef_names = set(known_typedefs or ())
    typedef_names |= _extract_typedef_names(source)
    try:
        return _parse_source_with_macros(
            source, path, language, extra_macros, typedef_names
        )
    except CParseFailure:
        pass
    unit = TranslationUnit(SourceLocation(path, 1, 1))
    unit.path = path
    unit.language = language
    errors: list[tuple[SourceLocation, str]] = []
    macros: dict[str, Any] = {}
    for start, end in _top_level_segments(source):
        masked = _mask_out(source, start, end)
        if not masked.strip():
            continue
        chunk = None
        chunk_errors: list[tuple[SourceLocation, str]] = []
        chunk_macros: dict[str, Any] = {}
        failure: Exception | None = None
        for candidate in (masked, _strip_pointer_casts(masked)):
            try:
                chunk, chunk_errors, chunk_macros = _parse_source_with_macros(
                    candidate, path, language, extra_macros, typedef_names
                )
                break
            except CParseFailure as error:
                failure = error
        if chunk is None:
            errors.append((SourceLocation(path, 1, 1), str(failure)))
            continue
        macros.update(chunk_macros)
        errors.extend(chunk_errors)
        for declaration in chunk.declarations:
            unit.declarations.append(declaration)
            unit.add(declaration)
    if not unit.declarations:
        raise CParseFailure(f"cannot parse {path}")
    return unit, errors, macros


def _extract_typedef_sources(source: str) -> list[str]:
    """Return the text of every ``typedef`` declaration found in *source*."""
    results: list[str] = []
    for match in re.finditer(r"\btypedef\b", source):
        index = match.end()
        depth = 0
        while index < len(source):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == ";" and depth <= 0:
                results.append(source[match.start() : index + 1])
                break
            index += 1
    return results


_ENUM_PATTERN = re.compile(r"\benum\b(?:\s+class\b)?(?:\s+\w+)?\s*\{([^{}]*)\}", re.DOTALL)


class CInterpreter:
    """Executes a subset of C directly on the AST."""

    MAX_STEPS = 2_000_000
    MAX_DEPTH = 100

    def __init__(
        self,
        units: list[TranslationUnit],
        sources: dict[str, str],
        *,
        collector: Any = None,
        globals_overrides: dict[str, Any] | None = None,
        stubs: dict[str, Any] | None = None,
    ) -> None:
        self.units: list[TranslationUnit] = list(units)
        self.sources: dict[str, str] = dict(sources)
        self.collector = collector
        self.globals_overrides: dict[str, Any] = dict(globals_overrides or {})
        self.stubs: dict[str, Any] = dict(stubs or {})

        self.memory = Memory()
        self.globals = Environment()
        self.functions: dict[str, FunctionDecl] = {}
        self.typedefs: dict[str, TypeNode] = {}
        self.struct_types: dict[str, StructType] = {}
        self.enum_constants: dict[str, int] = {}
        self.macros: dict[str, Any] = {}
        self.static_locals: dict[tuple[str, str], Binding] = {}

        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

        self._steps = 0
        self._depth = 0
        self._max_steps = self.MAX_STEPS
        self._max_depth = self.MAX_DEPTH
        self._decision_ids: dict[Node, str] = {}
        self._branch_sites: dict[Node, str] = {}
        self._switch_cases: dict[Node, list[tuple[str, Any]]] = {}
        self._struct_layouts: dict[int, dict[str, tuple[int, int, TypeNode]]] = {}
        self._keyword_cache: dict[str, dict[tuple[int, int], str]] = {}
        self._current_function = ""

        self._prepare_units()
        self._register_globals()

    def _prepare_units(self) -> None:
        prepared: list[TranslationUnit] = []
        for unit in self.units:
            source = self.sources.get(unit.path)
            if source is not None:
                if "#define" in source:
                    new_unit, _errors, macros = _parse_resilient(
                        source, unit.path, unit.language
                    )
                    self.macros.update(macros)
                    prepared.append(new_unit)
                else:
                    try:
                        self.macros.update(tokenize(source, unit.path, language=unit.language).macros)
                    except Exception:
                        pass
                    prepared.append(unit)
            else:
                prepared.append(unit)
        self.units = prepared
        for unit in self.units:
            self._register_declarations(unit)
            self._register_typedefs(unit)
            self._register_enums(unit)
            self._assign_site_ids(unit)
            self._declare_coverable(unit)

    def _register_declarations(self, unit: TranslationUnit) -> None:
        for declaration in unit.declarations:
            if isinstance(declaration, FunctionDecl):
                self.functions.setdefault(declaration.name, declaration)
                continue
            if isinstance(declaration, TypedefDecl):
                self.typedefs[declaration.name] = declaration.target
                self._register_type_alias(declaration.name, declaration.target)
                continue
            if isinstance(declaration, VariableDecl):
                self._register_type_alias(declaration.name, declaration.type)

    def _register_type_alias(self, name: str, type_node: TypeNode | None) -> None:
        if not name or type_node is None:
            return
        resolved = type_node
        if isinstance(resolved, TypedefType):
            target = self.typedefs.get(resolved.alias)
            if target is not None:
                resolved = target
        if isinstance(resolved, StructType):
            self.struct_types.setdefault(name, resolved)
            if resolved.tag:
                self.struct_types.setdefault(resolved.tag, resolved)
            self.typedefs.setdefault(name, resolved)

    def _register_typedefs(self, unit: TranslationUnit) -> None:
        source = self.sources.get(unit.path)
        if not source:
            return
        for text in _extract_typedef_sources(source):
            synthetic = "void __cs_typedef_scope(void) { " + text + " }"
            try:
                parsed, _errors, _macros = _parse_source_with_macros(
                    synthetic, unit.path, unit.language, self.macros
                )
            except Exception:
                continue
            for node in parsed.walk():
                if isinstance(node, TypedefDecl):
                    if node.name in self.typedefs:
                        continue
                    self.typedefs[node.name] = node.target
                    self._register_type_alias(node.name, node.target)

    def _register_enums(self, unit: TranslationUnit) -> None:
        scope = Environment(self.globals)
        for node in unit.walk():
            if isinstance(node, EnumDecl):
                for constant in node.constants:
                    self._register_enum_constant(constant, scope)
        for node in unit.walk():
            if isinstance(node, EnumType):
                self._register_enum_type(node, scope)
        source = self.sources.get(unit.path)
        if not source:
            self._publish_enum_constants(scope)
            return
        for index, match in enumerate(_ENUM_PATTERN.finditer(source)):
            body = match.group(1)
            synthetic = f"typedef enum {{ {body} }} __cs_enum_{index};"
            try:
                parsed, _errors, _macros = _parse_source_with_macros(
                    synthetic, unit.path, unit.language, self.macros
                )
            except Exception:
                continue
            for node in parsed.walk():
                if isinstance(node, EnumType):
                    self._register_enum_type(node, scope)
            for declaration in parsed.declarations:
                type_node = getattr(declaration, "type", None)
                if isinstance(type_node, EnumType):
                    self._register_enum_type(type_node, scope)
        self._publish_enum_constants(scope)

    def _publish_enum_constants(self, scope: Environment) -> None:
        for name, binding in scope.vars.items():
            value = int(binding.value or 0)
            self.enum_constants.setdefault(name, value)
            self.globals.define(name, value, None)

    def _register_enum_constant(self, constant: Any, scope: Environment) -> None:
        value = 0
        if getattr(constant, "value", None) is not None:
            try:
                value = int(self.eval_expr(constant.value, scope).value)
            except InterpreterError:
                value = 0
        scope.define(constant.name, value, None)

    def _register_enum_type(self, enum_type: EnumType, scope: Environment) -> None:
        next_value = 0
        for constant in enum_type.enumerators:
            if constant.value is not None:
                try:
                    value = int(self.eval_expr(constant.value, scope).value)
                except InterpreterError:
                    value = next_value
            else:
                value = next_value
            scope.define(constant.name, value, None)
            next_value = value + 1

    def _assign_site_ids(self, unit: TranslationUnit) -> None:
        counters: dict[tuple[str, int, str], int] = {}
        for node in unit.walk():
            if isinstance(node, (IfStmt, WhileStmt, DoWhileStmt, ForStmt)):
                kind = {
                    IfStmt: "if",
                    WhileStmt: "while",
                    DoWhileStmt: "do",
                    ForStmt: "for",
                }[type(node)]
                key = (node.location.file, node.location.line, kind)
                counters[key] = counters.get(key, 0) + 1
                suffix = "" if counters[key] == 1 else f".{counters[key]}"
                self._decision_ids[node] = f"{kind}@{node.location.line}{suffix}"
            elif isinstance(node, BinaryOp) and node.operator in ("&&", "||"):
                kind = "and" if node.operator == "&&" else "or"
                key = (node.location.file, node.location.line, kind)
                counters[key] = counters.get(key, 0) + 1
                suffix = "" if counters[key] == 1 else f".{counters[key]}"
                self._branch_sites[node] = f"{kind}@{node.location.line}{suffix}"
            elif isinstance(node, SwitchStmt):
                self._branch_sites[node] = f"switch@{node.location.line}"
                self._switch_cases[node] = self._collect_switch_cases(node)

    def _collect_switch_cases(self, node: SwitchStmt) -> list[tuple[str, Any]]:
        cases: list[tuple[str, Any]] = []
        body = node.body
        if not isinstance(body, CompoundStmt):
            return cases
        for statement in body.statements:
            if isinstance(statement, CaseStmt):
                cases.append((f"case:{self._case_label(statement)}", statement))
            elif isinstance(statement, DefaultStmt):
                cases.append(("default", statement))
        return cases

    def _case_label(self, statement: CaseStmt) -> str:
        if statement.value is None:
            return "default"
        value = self._const_int(statement.value)
        if value is None:
            return f"line{statement.location.line}"
        return str(value)

    def _declare_coverable(self, unit: TranslationUnit) -> None:
        if self.collector is None:
            return
        for node in unit.walk():
            if self._is_coverable(node):
                self.collector.declare_statement(node.location.file, node.location.line)

    def _is_coverable(self, node: Node) -> bool:
        if isinstance(node, ExprStmt):
            if node.expression is not None:
                return True
            return self._statement_keyword(node) in ("break", "continue")
        if isinstance(node, DeclStmt):
            return any(getattr(item, "init", None) is not None for item in node.declarations)
        if isinstance(
            node, (ReturnStmt, IfStmt, WhileStmt, DoWhileStmt, ForStmt, SwitchStmt, GotoStmt)
        ):
            return True
        return False

    def _register_globals(self) -> None:
        for unit in self.units:
            for declaration in unit.declarations:
                if not isinstance(declaration, VariableDecl) or declaration.is_parameter:
                    continue
                if not declaration.name:
                    continue
                binding = self._declare_variable(declaration, self.globals, global_scope=True)
                if binding is None:
                    continue
                if declaration.name in self.globals_overrides:
                    value = self.globals_overrides[declaration.name]
                    binding.initialized = True
                    binding.init_expr = None
                    self._write_binding(binding, value)
        for name, value in self.enum_constants.items():
            if self.globals.lookup_local(name) is None:
                self.globals.define(name, value, None)

    def load(self, path: str, source: str) -> None:
        """Parse *source* and add it to the program."""
        unit, _errors, macros = _parse_resilient(source, path, "c")
        self.sources[path] = source
        self.macros.update(macros)
        self.units.append(unit)
        self._assign_site_ids(unit)
        self._register_declarations(unit)
        self._register_typedefs(unit)
        self._register_enums(unit)
        self._declare_coverable(unit)
        for declaration in unit.declarations:
            if isinstance(declaration, VariableDecl) and not declaration.is_parameter:
                if declaration.name:
                    self._declare_variable(declaration, self.globals, global_scope=True)

    def resolve_function(self, name: str) -> FunctionDecl | None:
        """Return the declaration of the function called *name*."""
        return self.functions.get(name)

    def run_function(self, name: str, args: Sequence[Any] | None = None) -> Any:
        """Call the function *name* and return its result."""
        function = self.resolve_function(name)
        if function is None:
            raise InterpreterError(f"unknown function {name!r}")
        values = [self._convert_argument(argument) for argument in (args or [])]
        result = self._call_function(function, values)
        return result.value

    def execute_statements(self, statements: Any, env: Environment | None = None) -> Any:
        """Execute *statements* inside *env* and return the produced value."""
        if env is None:
            env = self.globals
        if isinstance(statements, CompoundStmt):
            items: list[Stmt] = list(statements.statements)
        elif statements is None:
            items = []
        else:
            items = list(statements)
        try:
            for statement in items:
                self._exec_stmt(statement, env)
        except _ReturnSignal as signal:
            return signal.value.value
        return None

    def evaluate_expression(self, expression: str, env: Environment | None = None) -> Any:
        """Evaluate the C expression *expression* inside *env*."""
        if env is None:
            env = self.globals
        text = expression.strip()
        if not text:
            return None
        source = "int __cs_assert_expression(void) { return (" + text + "); }"
        unit, errors, _macros = _parse_source_with_macros(
            source, "<expression>", "c", self.macros
        )
        if errors:
            raise InterpreterError(f"cannot parse expression {text!r}: {errors[0][1]}")
        statement: ReturnStmt | None = None
        for node in unit.walk():
            if isinstance(node, ReturnStmt):
                statement = node
                break
        if statement is None or statement.value is None:
            raise InterpreterError(f"cannot evaluate expression {text!r}")
        return self.eval_expr(statement.value, env).value

    def memory_snapshot(self) -> bytes:
        """Return the raw content of the interpreter memory."""
        return self.memory.snapshot()

    def resolve_address(self, name: str, env: Environment | None = None) -> int:
        """Return the address of the variable called *name*."""
        if env is None:
            env = self.globals
        binding = self._lookup_binding(name, env)
        return self._address_of(binding)

    def resolve_value(self, name: str, env: Environment | None = None) -> Any:
        """Return the value of the variable called *name*."""
        if env is None:
            env = self.globals
        binding = self._lookup_binding(name, env)
        if binding.memory_backed and binding.address is not None:
            size = binding.size or self._size_of(binding.type) or 8
            if self._is_float(binding.type):
                return self.memory.load_float(binding.address, size)
            return self.memory.load_int(binding.address, size)
        return binding.value

    def allocate(self, size: int) -> int:
        """Allocate *size* bytes and return the address."""
        return self.memory.allocate(size)

    def read_int(self, address: int, size: int = 4, signed: bool = True) -> int:
        return self.memory.load_int(address, size, signed)

    def write_int(self, address: int, value: int, size: int = 4) -> None:
        self.memory.store_int(address, value, size)

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.memory.read(address, size)

    def write_bytes(self, address: int, data: bytes) -> None:
        self.memory.write(address, data)

    def read_cstring(self, address: int) -> str:
        return self.memory.read_cstring(address)

    def run_statements(self, source: str, env: Environment | None = None) -> Any:
        """Parse and execute the C statements contained in *source*."""
        text = source.strip()
        if not text:
            return None
        wrapped = "void __cs_setup(void) { " + text + " }"
        unit, errors, _macros = _parse_resilient(
            wrapped, "<setup>", "c", self.macros, set(self.typedefs)
        )
        if errors:
            raise InterpreterError(
                f"cannot parse the statement {text!r}: {errors[0][1]}"
            )
        body: CompoundStmt | None = None
        for node in unit.walk():
            if isinstance(node, FunctionDecl) and node.body is not None:
                body = node.body
                break
        if body is None:
            raise InterpreterError(f"cannot execute the statement {text!r}")
        return self.execute_statements(body.statements, env)

    def return_type(self, name: str) -> TypeNode | None:
        """Return the declared return type of the function called *name*."""
        return self._return_type(self.resolve_function(name))

    def is_string_pointer(self, type_node: TypeNode | None) -> bool:
        """True when *type_node* is a ``char *``."""
        resolved = self._resolve_type(type_node)
        if not isinstance(resolved, PointerType):
            return False
        pointee = self._resolve_type(resolved.pointee)
        return isinstance(pointee, PrimitiveType) and pointee.name.strip() == "char"

    def truth(self, value: Any) -> bool:
        """C truthiness of *value*."""
        return self._truth(value)

    def _resolve_type(self, type_node: TypeNode | None) -> TypeNode | None:
        seen = 0
        current = type_node
        while isinstance(current, TypedefType) and seen < 16:
            target = self.typedefs.get(current.alias)
            if target is None:
                return current
            current = target
            seen += 1
        return current

    def _primitive_size(self, name: str) -> int:
        key = " ".join(str(name).replace("const", " ").split())
        if key in SIZEOF_PRIMITIVES:
            return SIZEOF_PRIMITIVES[key]
        parts = key.split()
        if "double" in parts:
            return 16 if "long" in parts else 8
        if "float" in parts:
            return 4
        if "char" in parts:
            return 1
        if "bool" in parts or "_Bool" in parts:
            return 1
        if "short" in parts:
            return 2
        if "long" in parts:
            return 8 if parts.count("long") > 1 else 4
        if "int" in parts or "signed" in parts or "unsigned" in parts:
            return 4
        if "void" in parts:
            return 1
        return 4

    def _size_of(self, type_node: TypeNode | None) -> int | None:
        resolved = self._resolve_type(type_node)
        if resolved is None:
            return None
        if isinstance(resolved, PrimitiveType):
            return self._primitive_size(resolved.name)
        if isinstance(resolved, (PointerType, ReferenceType)):
            return 8
        if isinstance(resolved, ArrayType):
            element = self._size_of(resolved.element)
            count = resolved.size
            if count is None and resolved.size_expr is not None:
                count = self._const_int(resolved.size_expr)
            if element is None or count is None:
                return None
            return element * count
        if isinstance(resolved, EnumType):
            return 4
        if isinstance(resolved, StructType):
            return self._struct_size(resolved)
        return None

    def _struct_size(self, struct_type: StructType) -> int | None:
        layout = self._struct_layout(struct_type)
        if not layout:
            return None
        total = 0
        for offset, size, _type in layout.values():
            total = max(total, offset + size)
        return total or None

    def _struct_layout(self, struct_type: StructType) -> dict[str, tuple[int, int, TypeNode]]:
        key = id(struct_type)
        cached = self._struct_layouts.get(key)
        if cached is not None:
            return cached
        layout: dict[str, tuple[int, int, TypeNode]] = {}
        offset = 0
        for field in struct_type.fields:
            size = self._size_of(field.type)
            if size is None:
                size = 8
            alignment = min(max(size, 1), 8)
            if alignment > 1:
                offset = ((offset + alignment - 1) // alignment) * alignment
            layout[field.name] = (offset, size, field.type)
            offset += size
        self._struct_layouts[key] = layout
        return layout

    def _is_float(self, type_node: TypeNode | None) -> bool:
        resolved = self._resolve_type(type_node)
        return isinstance(resolved, PrimitiveType) and resolved.name in {
            "float",
            "double",
            "long double",
        }

    def _is_unsigned(self, type_node: TypeNode | None) -> bool:
        resolved = self._resolve_type(type_node)
        return isinstance(resolved, PrimitiveType) and "unsigned" in resolved.name

    def _is_pointer(self, type_node: TypeNode | None) -> bool:
        resolved = self._resolve_type(type_node)
        return isinstance(resolved, (PointerType, ReferenceType))

    def _is_array(self, type_node: TypeNode | None) -> bool:
        resolved = self._resolve_type(type_node)
        return isinstance(resolved, ArrayType)

    def _is_struct(self, type_node: TypeNode | None) -> bool:
        resolved = self._resolve_type(type_node)
        return isinstance(resolved, StructType)

    def _pointee_type(self, type_node: TypeNode | None) -> TypeNode | None:
        resolved = self._resolve_type(type_node)
        if isinstance(resolved, (PointerType, ReferenceType)):
            return resolved.pointee
        if isinstance(resolved, ArrayType):
            return resolved.element
        return None

    def _as_struct(self, type_node: TypeNode | None) -> StructType | None:
        resolved = self._resolve_type(type_node)
        if isinstance(resolved, StructType):
            return resolved
        if isinstance(resolved, TypedefType):
            return self.struct_types.get(resolved.alias)
        return None

    def _pointer_type(self, pointee: TypeNode | None) -> PointerType:
        pointer = PointerType(SourceLocation("<builtin>", 1, 1))
        pointer.pointee = pointee
        return pointer

    def _lookup_binding(self, name: str, env: Environment) -> Binding:
        binding = env.lookup(name)
        if binding is not None:
            self._ensure_initialized(binding)
            return binding
        if name in self.enum_constants:
            return self.globals.define(name, self.enum_constants[name], None)
        raise InterpreterError(f"undefined identifier {name!r}")

    def _ensure_initialized(self, binding: Binding) -> None:
        if binding.initialized or binding.init_expr is None:
            return
        binding.initialized = True
        init = binding.init_expr
        binding.init_expr = None
        self._apply_initializer(binding, init, self.globals)

    def _address_of(self, binding: Binding) -> int:
        if binding.memory_backed and binding.address is not None:
            return binding.address
        size = binding.size or self._size_of(binding.type) or 8
        address = self.memory.allocate(size)
        binding.address = address
        binding.memory_backed = True
        binding.size = size
        if binding.type is not None and self._is_float(binding.type):
            self.memory.store_float(address, float(binding.value or 0), size)
        elif binding.type is not None and self._is_struct(binding.type):
            pass
        else:
            self.memory.store_int(address, int(binding.value or 0), size)
        return address

    def _convert_for_type(self, value: Any, type_node: TypeNode | None) -> Any:
        if isinstance(value, Val):
            value = value.value
        resolved = self._resolve_type(type_node)
        if resolved is None:
            return value
        if self._is_float(resolved):
            return float(value or 0)
        if self._is_pointer(resolved):
            return int(value or 0)
        if self._is_struct(resolved) or self._is_array(resolved):
            return value
        size = self._size_of(resolved) or 4
        return self._truncate(int(value or 0), size, not self._is_unsigned(resolved))

    def _truncate(self, value: int, size: int, signed: bool = True) -> int:
        if size <= 0:
            return value
        bits = size * 8
        value &= (1 << bits) - 1
        if signed and value >= (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def _truth(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, float):
            return value != 0.0
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return bool(value)
        return bool(value)

    def _const_int(self, expr: Expr | None, env: Environment | None = None) -> int | None:
        """Best effort evaluation of a constant integer expression."""
        if expr is None:
            return None
        scope = env if env is not None else self.globals
        if isinstance(expr, Literal):
            if expr.literal_type == "float":
                return int(float(expr.value))
            return self._parse_int_literal(expr.value)
        if isinstance(expr, Identifier):
            binding = scope.lookup(expr.name)
            if binding is not None and not binding.memory_backed:
                return int(binding.value or 0)
            if expr.name in self.enum_constants:
                return self.enum_constants[expr.name]
            return None
        if isinstance(expr, UnaryOp):
            value = self._const_int(expr.operand, scope)
            if value is None:
                return None
            if expr.operator == "-":
                return -value
            if expr.operator == "+":
                return value
            if expr.operator == "!":
                return int(not value)
            return None
        if isinstance(expr, BinaryOp):
            left = self._const_int(expr.left, scope)
            right = self._const_int(expr.right, scope)
            if left is None or right is None:
                return None
            try:
                if expr.operator == "+":
                    return left + right
                if expr.operator == "-":
                    return left - right
                if expr.operator == "*":
                    return left * right
                if expr.operator == "/":
                    return int(left / right) if right else None
                if expr.operator == "%":
                    return left - int(left / right) * right if right else None
                if expr.operator == "<<":
                    return left << right
                if expr.operator == ">>":
                    return left >> right
                if expr.operator == "&":
                    return left & right
                if expr.operator == "|":
                    return left | right
                if expr.operator == "^":
                    return left ^ right
            except (ValueError, ZeroDivisionError):
                return None
        if isinstance(expr, Cast):
            return self._const_int(expr.operand, scope)
        return None

    def _declare_variable(
        self, declaration: VariableDecl, env: Environment, *, global_scope: bool = False
    ) -> Binding | None:
        name = declaration.name
        if not name:
            return None
        type_node = declaration.type
        resolved = self._resolve_type(type_node)
        if self._is_array(resolved) or self._is_struct(resolved):
            size = self._size_of(resolved) or 8
            address = self.memory.allocate(size)
            binding = env.define(
                name,
                address,
                type_node,
                address=address,
                memory_backed=True,
                init_expr=declaration.init,
                size=size,
            )
            if declaration.init is not None:
                self._apply_initializer(binding, declaration.init, env)
            binding.initialized = True
            binding.init_expr = None
            return binding
        binding = env.define(
            name,
            0,
            type_node,
            init_expr=declaration.init,
            size=self._size_of(type_node) or 0,
        )
        if declaration.init is not None:
            self._apply_initializer(binding, declaration.init, env)
            binding.initialized = True
            binding.init_expr = None
        return binding

    def _apply_initializer(self, binding: Binding, init: Any, env: Environment) -> None:
        if init is None:
            return
        resolved = self._resolve_type(binding.type)
        if isinstance(init, InitList):
            if not self._is_array(resolved) and not self._is_struct(resolved):
                elements = list(init.elements)
                if not elements:
                    return
                init = elements[0]
            else:
                self._init_list(binding, init, env)
                return
        if isinstance(init, Literal) and init.literal_type == "string":
            if self._is_array(resolved):
                self._init_string(binding, init)
                return
        value = self.eval_expr(init, env)
        self._write_binding(binding, value)

    def _init_string(self, binding: Binding, literal: Literal) -> None:
        data = literal.value.encode("utf-8", errors="replace") + b"\x00"
        capacity = binding.size or len(data)
        self.memory.write(binding.address or 0, data[:capacity])

    def _init_list(self, binding: Binding, init: InitList, env: Environment) -> None:
        resolved = self._resolve_type(binding.type)
        elements = list(init.elements)
        if self._is_struct(resolved):
            struct_type = self._as_struct(resolved)
            if struct_type is None:
                return
            layout = self._struct_layout(struct_type)
            for index, element in enumerate(elements):
                if index >= len(struct_type.fields):
                    break
                field = struct_type.fields[index]
                offset, size, field_type = layout.get(field.name, (0, 0, field.type))
                value = self.eval_expr(element, env)
                self._store_to_memory((binding.address or 0) + offset, field_type, value, size)
            return
        element_type = self._pointee_type(resolved)
        element_size = self._size_of(element_type) or 1
        for index, element in enumerate(elements):
            address = (binding.address or 0) + index * element_size
            value = self.eval_expr(element, env)
            self._store_to_memory(address, element_type, value, element_size)

    def _tick(self) -> None:
        self._steps += 1
        if self._steps > self._max_steps:
            raise InterpreterTimeout(
                f"execution exceeded {self._max_steps} steps", self._current_location()
            )

    def _hit_statement(self, node: Node) -> None:
        if self.collector is None:
            return
        location = node.location
        self.collector.hit_statement(location.file, location.line)

    def _hit_branch(self, node: Node, branch_id: str) -> None:
        if self.collector is None:
            return
        location = node.location
        self.collector.hit_branch(location.file, location.line, branch_id)

    def _record_decision(self, node: Node, outcomes: dict[str, bool], result: bool) -> None:
        if self.collector is None:
            return
        decision_id = self._decision_ids.get(node)
        if decision_id is None:
            return
        recorder = getattr(self.collector, "record_decision", None)
        if recorder is None:
            for condition_id, outcome in outcomes.items():
                self.collector.hit_condition(
                    node.location.file, node.location.line, condition_id, outcome
                )
            return
        recorder(node.location.file, node.location.line, decision_id, outcomes, result)

    def _statement_keyword(self, node: Node) -> str:
        index = self._keyword_index(node.location.file)
        if not index:
            return ""
        return index.get((node.location.line, node.location.column), "")

    def _keyword_index(self, path: str) -> dict[tuple[int, int], str]:
        cached = self._keyword_cache.get(path)
        if cached is not None:
            return cached
        index: dict[tuple[int, int], str] = {}
        source = self.sources.get(path)
        if source:
            try:
                result = tokenize(source, path)
            except Exception:
                result = None
            if result is not None:
                for token in result.tokens:
                    if token.type is TokenType.KEYWORD and token.value in ("break", "continue"):
                        index[(token.location.line, token.location.column)] = token.value
        self._keyword_cache[path] = index
        return index

    def _exec_stmt(self, stmt: Stmt, env: Environment) -> Val:
        self._tick()
        kind = stmt.kind
        if kind == "compound_stmt":
            self._hit_statement(stmt)
            return self._exec_block(stmt, env)
        if kind == "expr_stmt":
            keyword = self._statement_keyword(stmt)
            if keyword == "break":
                self._hit_statement(stmt)
                raise _BreakSignal()
            if keyword == "continue":
                self._hit_statement(stmt)
                raise _ContinueSignal()
            if stmt.expression is None:
                return Val(None)
            self._hit_statement(stmt)
            return self.eval_expr(stmt.expression, env)
        if kind == "decl_stmt":
            return self._exec_decl_stmt(stmt, env)
        if kind == "return_stmt":
            self._hit_statement(stmt)
            value = Val(None)
            if stmt.value is not None:
                value = self.eval_expr(stmt.value, env)
            raise _ReturnSignal(value)
        if kind == "if_stmt":
            return self._exec_if(stmt, env)
        if kind == "while_stmt":
            return self._exec_while(stmt, env)
        if kind == "do_while_stmt":
            return self._exec_do_while(stmt, env)
        if kind == "for_stmt":
            return self._exec_for(stmt, env)
        if kind == "switch_stmt":
            return self._exec_switch(stmt, env)
        if kind == "goto_stmt":
            self._hit_statement(stmt)
            raise _GotoSignal(stmt.label)
        if kind == "label_stmt":
            if stmt.body is not None:
                return self._exec_stmt(stmt.body, env)
            return Val(None)
        if kind == "assert_stmt":
            value = self.eval_expr(stmt.condition, env)
            if not self._truth(value.value):
                message = ""
                if stmt.message is not None:
                    message = str(self.eval_expr(stmt.message, env).value)
                raise AssertionFailure(message or "assertion failed", stmt.location)
            return Val(None)
        if kind in ("empty_stmt", "asm_stmt"):
            return Val(None)
        return Val(None)

    def _exec_block(self, compound: CompoundStmt, env: Environment) -> Val:
        scope = Environment(env)
        statements = compound.statements
        index = 0
        result = Val(None)
        while index < len(statements):
            statement = statements[index]
            try:
                result = self._exec_stmt(statement, scope)
            except _GotoSignal as signal:
                target = self._find_label(statements, signal.label)
                if target is None:
                    raise
                index = target
                continue
            index += 1
        return result

    def _find_label(self, statements: list[Stmt], label: str) -> int | None:
        for index, statement in enumerate(statements):
            if isinstance(statement, LabelStmt) and statement.label == label:
                return index
        return None

    def _exec_decl_stmt(self, stmt: DeclStmt, env: Environment) -> Val:
        has_init = any(getattr(item, "init", None) is not None for item in stmt.declarations)
        if has_init:
            self._hit_statement(stmt)
        for declaration in stmt.declarations:
            if isinstance(declaration, TypedefDecl):
                self.typedefs[declaration.name] = declaration.target
                self._register_type_alias(declaration.name, declaration.target)
                continue
            if isinstance(declaration, VariableDecl):
                if declaration.is_static:
                    self._declare_static_local(declaration, env)
                else:
                    self._declare_variable(declaration, env)
        return Val(None)

    def _declare_static_local(self, declaration: VariableDecl, env: Environment) -> None:
        key = (self._current_function, declaration.name)
        binding = self.static_locals.get(key)
        if binding is not None:
            env.vars[declaration.name] = binding
            return
        resolved = self._resolve_type(declaration.type)
        if self._is_array(resolved) or self._is_struct(resolved):
            size = self._size_of(resolved) or 8
            address = self.memory.allocate(size)
            binding = Binding(
                declaration.name,
                address,
                declaration.type,
                address=address,
                memory_backed=True,
                size=size,
            )
        else:
            binding = Binding(
                declaration.name, 0, declaration.type, size=self._size_of(declaration.type) or 0
            )
        self.static_locals[key] = binding
        env.vars[declaration.name] = binding
        if declaration.init is not None:
            self._apply_initializer(binding, declaration.init, env)

    def _exec_if(self, stmt: Any, env: Environment) -> Val:
        self._hit_statement(stmt)
        result, _outcomes = self._eval_decision(stmt.condition, env, stmt)
        prefix = self._decision_ids.get(stmt, f"if@{stmt.location.line}")
        if result:
            self._hit_branch(stmt, prefix + "#true")
            return self._exec_stmt(stmt.then_branch, env)
        if stmt.else_branch is not None:
            self._hit_branch(stmt, prefix + "#else")
            return self._exec_stmt(stmt.else_branch, env)
        self._hit_branch(stmt, prefix + "#false")
        return Val(None)

    def _exec_while(self, stmt: Any, env: Environment) -> Val:
        self._hit_statement(stmt)
        prefix = self._decision_ids.get(stmt, f"while@{stmt.location.line}")
        while True:
            result, _outcomes = self._eval_decision(stmt.condition, env, stmt)
            if not result:
                self._hit_branch(stmt, prefix + "#exit")
                break
            self._hit_branch(stmt, prefix + "#body")
            try:
                self._exec_stmt(stmt.body, env)
            except _BreakSignal:
                break
            except _ContinueSignal:
                continue
        return Val(None)

    def _exec_do_while(self, stmt: Any, env: Environment) -> Val:
        self._hit_statement(stmt)
        prefix = self._decision_ids.get(stmt, f"do@{stmt.location.line}")
        while True:
            self._hit_branch(stmt, prefix + "#body")
            try:
                self._exec_stmt(stmt.body, env)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
            result, _outcomes = self._eval_decision(stmt.condition, env, stmt)
            if not result:
                self._hit_branch(stmt, prefix + "#exit")
                break
        return Val(None)

    def _exec_for(self, stmt: Any, env: Environment) -> Val:
        self._hit_statement(stmt)
        prefix = self._decision_ids.get(stmt, f"for@{stmt.location.line}")
        scope = Environment(env)
        if stmt.init is not None:
            self._exec_stmt(stmt.init, scope)
        while True:
            if stmt.condition is not None:
                result, _outcomes = self._eval_decision(stmt.condition, scope)
                if not result:
                    self._hit_branch(stmt, prefix + "#exit")
                    break
            self._hit_branch(stmt, prefix + "#body")
            try:
                self._exec_stmt(stmt.body, scope)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
            if stmt.update is not None:
                self.eval_expr(stmt.update, scope)
        return Val(None)

    def _exec_switch(self, stmt: Any, env: Environment) -> Val:
        self._hit_statement(stmt)
        prefix = self._branch_sites.get(stmt, f"switch@{stmt.location.line}")
        value = self.eval_expr(stmt.condition, env)
        body = stmt.body
        if not isinstance(body, CompoundStmt):
            return Val(None)
        selected: str | None = None
        default_label: str | None = None
        for label, case in self._switch_cases.get(stmt, []):
            if label == "default":
                default_label = label
                continue
            case_value = self._const_int(case.value) if isinstance(case, CaseStmt) else None
            if case_value is not None and case_value == int(value.value or 0):
                selected = label
                break
        if selected is None:
            selected = default_label
        if selected is not None:
            self._hit_branch(stmt, prefix + "#" + selected)
        matched = False
        try:
            for statement in body.statements:
                if isinstance(statement, CaseStmt):
                    label = f"case:{self._case_label(statement)}"
                    if not matched and label == selected:
                        matched = True
                        if statement.body is not None:
                            self._exec_stmt(statement.body, env)
                    continue
                if isinstance(statement, DefaultStmt):
                    if not matched and selected == "default":
                        matched = True
                        if statement.body is not None:
                            self._exec_stmt(statement.body, env)
                    continue
                if matched:
                    self._exec_stmt(statement, env)
        except _BreakSignal:
            pass
        return Val(None)

    def _eval_decision(
        self, expr: Expr, env: Environment, node: Node | None = None
    ) -> tuple[bool, dict[str, bool]]:
        value = self.eval_expr(expr, env)
        result = self._truth(value.value)
        outcomes: dict[str, bool] = {}
        target = node if node is not None else expr
        prefix = self._decision_ids.get(target)
        if prefix is None:
            return result, outcomes
        for index, atom in enumerate(self._split_atoms(expr)):
            outcome = self._probe_condition(atom, env)
            if outcome is None:
                continue
            outcomes[f"{prefix}$c{index + 1}"] = outcome
        self._record_decision(target, outcomes, result)
        return result, outcomes

    def _split_atoms(self, expr: Expr) -> list[Expr]:
        if isinstance(expr, BinaryOp) and expr.operator in ("&&", "||"):
            return self._split_atoms(expr.left) + self._split_atoms(expr.right)
        return [expr]

    def _probe_condition(self, atom: Expr, env: Environment) -> bool | None:
        if not self._is_pure(atom):
            return None
        try:
            value = self.eval_expr(atom, env)
        except InterpreterError:
            return None
        return self._truth(value.value)

    def _is_pure(self, expr: Node) -> bool:
        if isinstance(expr, (Call, Assignment, NewExpr, DeleteExpr)):
            return False
        if isinstance(expr, UnaryOp) and expr.operator in ("++", "--", "post++", "post--"):
            return False
        for child in expr.children:
            if not self._is_pure(child):
                return False
        return True

    def _current_location(self) -> SourceLocation | None:
        return None

    def eval_expr(self, expr: Expr | None, env: Environment) -> Val:
        self._tick()
        if expr is None:
            return Val(None)
        kind = expr.kind
        if kind == "literal":
            return self._eval_literal(expr)
        if kind == "identifier":
            return self._eval_identifier(expr, env)
        if kind == "binary_op":
            return self._eval_binary(expr, env)
        if kind == "unary_op":
            return self._eval_unary(expr, env)
        if kind == "assignment":
            return self._eval_assignment(expr, env)
        if kind == "conditional":
            return self._eval_conditional(expr, env)
        if kind == "comma_op":
            self.eval_expr(expr.left, env)
            return self.eval_expr(expr.right, env)
        if kind == "call":
            return self._eval_call(expr, env)
        if kind == "member_access":
            return self._read_lvalue(self.eval_lvalue(expr, env))
        if kind == "index_access":
            return self._read_lvalue(self.eval_lvalue(expr, env))
        if kind == "cast":
            return self._eval_cast(expr, env)
        if kind == "sizeof":
            return self._eval_sizeof(expr, env)
        if kind == "init_list":
            return Val(0)
        raise InterpreterError(f"unsupported expression {kind!r}", expr.location)

    def _eval_literal(self, expr: Literal) -> Val:
        literal_type = expr.literal_type
        if literal_type == "string":
            data = expr.value.encode("utf-8", errors="replace") + b"\x00"
            address = self.memory.allocate(len(data))
            self.memory.write(address, data)
            return Val(address, self._pointer_type(PrimitiveType("char")))
        if literal_type == "char":
            text = expr.value
            if not text:
                return Val(0, PrimitiveType("char"))
            return Val(ord(text[0]), PrimitiveType("char"))
        if literal_type == "bool":
            return Val(1 if expr.value in ("true", "1") else 0, PrimitiveType("bool"))
        if literal_type == "null":
            return Val(0, self._pointer_type(PrimitiveType("void")))
        if literal_type == "float":
            try:
                return Val(float(expr.value), PrimitiveType("double"))
            except ValueError:
                return Val(0.0, PrimitiveType("double"))
        return Val(self._parse_int_literal(expr.value), PrimitiveType("int"))

    def _parse_int_literal(self, text: str) -> int:
        cleaned = str(text).strip().replace("'", "")
        while cleaned and cleaned[-1] in "uUlL":
            cleaned = cleaned[:-1]
        cleaned = cleaned.replace(" ", "")
        try:
            if cleaned.lower().startswith("0x"):
                return int(cleaned, 16)
            if cleaned.lower().startswith("0b"):
                return int(cleaned, 2)
            if cleaned.lower().startswith("0o"):
                return int(cleaned, 8)
            if len(cleaned) > 1 and cleaned.startswith("0") and cleaned[1:].isdigit():
                return int(cleaned, 8)
            return int(cleaned)
        except ValueError:
            try:
                return int(float(cleaned))
            except ValueError:
                return 0

    def _eval_identifier(self, expr: Identifier, env: Environment) -> Val:
        name = expr.name
        if name == "NULL":
            return Val(0, self._pointer_type(PrimitiveType("void")))
        binding = env.lookup(name)
        if binding is None:
            if name in self.enum_constants:
                return Val(self.enum_constants[name], PrimitiveType("int"))
            raise InterpreterError(f"undefined identifier {name!r}", expr.location)
        self._ensure_initialized(binding)
        if binding.memory_backed and binding.address is not None:
            if self._is_array(binding.type) or self._is_struct(binding.type):
                return Val(binding.address, binding.type)
            value = self._load_from_memory(binding.address, binding.type)
            return Val(value, binding.type)
        return self._decay(Val(binding.value, binding.type))

    def _decay(self, value: Val) -> Val:
        if self._is_array(value.type):
            element = self._pointee_type(value.type)
            return Val(value.value, self._pointer_type(element))
        return value

    def _eval_binary(self, expr: BinaryOp, env: Environment) -> Val:
        operator = expr.operator
        if operator in ("&&", "||"):
            left = self.eval_expr(expr.left, env)
            truth = self._truth(left.value)
            site = self._branch_sites.get(
                expr, f"{'and' if operator == '&&' else 'or'}@{expr.location.line}"
            )
            if operator == "&&":
                if not truth:
                    self._hit_branch(expr, site + "#short")
                    return Val(0, PrimitiveType("int"))
                self._hit_branch(expr, site + "#taken")
                right = self.eval_expr(expr.right, env)
                return Val(1 if self._truth(right.value) else 0, PrimitiveType("int"))
            if truth:
                self._hit_branch(expr, site + "#short")
                return Val(1, PrimitiveType("int"))
            self._hit_branch(expr, site + "#taken")
            right = self.eval_expr(expr.right, env)
            return Val(1 if self._truth(right.value) else 0, PrimitiveType("int"))

        left = self.eval_expr(expr.left, env)
        right = self.eval_expr(expr.right, env)
        return self._binary_value(operator, left, right, expr)

    def _binary_value(self, operator: str, left: Val, right: Val, expr: Expr) -> Val:
        if operator == "+":
            if self._is_pointer(left.type) and not self._is_pointer(right.type):
                return self._pointer_add(left, int(right.value or 0))
            if self._is_pointer(right.type) and not self._is_pointer(left.type):
                return self._pointer_add(right, int(left.value or 0))
            if self._is_pointer(left.type) and self._is_pointer(right.type):
                return self._pointer_add(left, int(right.value or 0))
            return self._numeric_result(left, right, lambda a, b: a + b)
        if operator == "-":
            if self._is_pointer(left.type) and not self._is_pointer(right.type):
                return self._pointer_add(left, -int(right.value or 0))
            if self._is_pointer(left.type) and self._is_pointer(right.type):
                element = self._size_of(self._pointee_type(left.type)) or 1
                return Val((int(left.value or 0) - int(right.value or 0)) // element, left.type)
            return self._numeric_result(left, right, lambda a, b: a - b)
        if operator == "*":
            return self._numeric_result(left, right, lambda a, b: a * b)
        if operator == "/":
            return self._divide(left, right, expr)
        if operator == "%":
            return self._modulo(left, right, expr)
        if operator == "<<":
            return Val(int(left.value or 0) << int(right.value or 0), PrimitiveType("int"))
        if operator == ">>":
            return Val(int(left.value or 0) >> int(right.value or 0), PrimitiveType("int"))
        if operator == "&":
            return Val(int(left.value or 0) & int(right.value or 0), PrimitiveType("int"))
        if operator == "|":
            return Val(int(left.value or 0) | int(right.value or 0), PrimitiveType("int"))
        if operator == "^":
            return Val(int(left.value or 0) ^ int(right.value or 0), PrimitiveType("int"))
        if operator == "==":
            return Val(1 if self._compare_equal(left, right) else 0, PrimitiveType("int"))
        if operator == "!=":
            return Val(0 if self._compare_equal(left, right) else 1, PrimitiveType("int"))
        if operator == "<":
            return Val(1 if self._ordered(left, right) < 0 else 0, PrimitiveType("int"))
        if operator == ">":
            return Val(1 if self._ordered(left, right) > 0 else 0, PrimitiveType("int"))
        if operator == "<=":
            return Val(1 if self._ordered(left, right) <= 0 else 0, PrimitiveType("int"))
        if operator == ">=":
            return Val(1 if self._ordered(left, right) >= 0 else 0, PrimitiveType("int"))
        raise InterpreterError(f"unsupported operator {operator!r}", expr.location)

    def _numeric_result(self, left: Val, right: Val, operation) -> Val:
        if self._is_float(left.type) or self._is_float(right.type):
            value = operation(float(left.value or 0), float(right.value or 0))
            return Val(float(value), PrimitiveType("double"))
        value = operation(int(left.value or 0), int(right.value or 0))
        return Val(int(value), PrimitiveType("int"))

    def _divide(self, left: Val, right: Val, expr: Expr) -> Val:
        if self._is_float(left.type) or self._is_float(right.type):
            divisor = float(right.value or 0)
            if divisor == 0.0:
                raise InterpreterError("division by zero", expr.location)
            return Val(float(left.value or 0) / divisor, PrimitiveType("double"))
        divisor = int(right.value or 0)
        if divisor == 0:
            raise InterpreterError("division by zero", expr.location)
        dividend = int(left.value or 0)
        quotient = abs(dividend) // abs(divisor)
        if (dividend < 0) != (divisor < 0):
            quotient = -quotient
        return Val(quotient, PrimitiveType("int"))

    def _modulo(self, left: Val, right: Val, expr: Expr) -> Val:
        divisor = int(right.value or 0)
        if divisor == 0:
            raise InterpreterError("division by zero", expr.location)
        dividend = int(left.value or 0)
        remainder = abs(dividend) % abs(divisor)
        if dividend < 0:
            remainder = -remainder
        return Val(remainder, PrimitiveType("int"))

    def _compare_equal(self, left: Val, right: Val) -> bool:
        if self._is_float(left.type) or self._is_float(right.type):
            return float(left.value or 0) == float(right.value or 0)
        return int(left.value or 0) == int(right.value or 0)

    def _ordered(self, left: Val, right: Val) -> int:
        if self._is_float(left.type) or self._is_float(right.type):
            first = float(left.value or 0)
            second = float(right.value or 0)
        else:
            first = int(left.value or 0)
            second = int(right.value or 0)
        if first < second:
            return -1
        if first > second:
            return 1
        return 0

    def _pointer_add(self, value: Val, delta: int) -> Val:
        element = self._size_of(self._pointee_type(value.type)) or 1
        return Val(int(value.value or 0) + delta * element, value.type)

    def _eval_unary(self, expr: UnaryOp, env: Environment) -> Val:
        operator = expr.operator
        if operator == "&":
            lvalue = self.eval_lvalue(expr.operand, env)
            if lvalue.kind == "cell" and lvalue.binding is not None:
                return Val(
                    self._address_of(lvalue.binding),
                    self._pointer_type(lvalue.binding.type),
                )
            return Val(lvalue.address or 0, self._pointer_type(lvalue.type))
        if operator == "*":
            base = self.eval_expr(expr.operand, env)
            pointee = self._pointee_type(base.type)
            if pointee is None:
                raise InterpreterError(
                    "cannot dereference a value that is not a pointer", expr.location
                )
            if self._is_array(pointee) or self._is_struct(pointee):
                return Val(int(base.value or 0), pointee)
            return Val(self._load_from_memory(int(base.value or 0), pointee), pointee)
        if operator in ("++", "--", "post++", "post--"):
            return self._eval_increment(expr, env)
        operand = self.eval_expr(expr.operand, env)
        if operator == "+":
            return operand
        if operator == "-":
            if self._is_float(operand.type):
                return Val(-float(operand.value or 0), operand.type)
            return Val(-int(operand.value or 0), PrimitiveType("int"))
        if operator == "!":
            return Val(0 if self._truth(operand.value) else 1, PrimitiveType("int"))
        if operator == "~":
            return Val(~int(operand.value or 0), PrimitiveType("int"))
        raise InterpreterError(f"unsupported unary operator {operator!r}", expr.location)

    def _eval_increment(self, expr: UnaryOp, env: Environment) -> Val:
        lvalue = self.eval_lvalue(expr.operand, env)
        current = self._read_lvalue(lvalue)
        delta = 1
        if expr.operator in ("--", "post--"):
            delta = -1
        if self._is_pointer(current.type):
            updated = self._pointer_add(current, delta)
        elif self._is_float(current.type):
            updated = Val(float(current.value or 0) + delta, current.type)
        else:
            updated = Val(
                int(current.value or 0) + delta, current.type or PrimitiveType("int")
            )
        self._write_lvalue(lvalue, updated)
        if expr.operator in ("post++", "post--"):
            return current
        return updated

    def _eval_assignment(self, expr: Assignment, env: Environment) -> Val:
        operator = expr.operator
        if operator == "=":
            value = self.eval_expr(expr.value, env)
            lvalue = self.eval_lvalue(expr.target, env)
            self._write_lvalue(lvalue, value)
            return self._read_lvalue(lvalue)
        lvalue = self.eval_lvalue(expr.target, env)
        current = self._read_lvalue(lvalue)
        value = self.eval_expr(expr.value, env)
        binary = operator[:-1]
        if binary == "+" and self._is_pointer(current.type) and not self._is_pointer(value.type):
            updated = self._pointer_add(current, int(value.value or 0))
        else:
            updated = self._binary_value(binary, current, value, expr)
        self._write_lvalue(lvalue, updated)
        return self._read_lvalue(lvalue)

    def _eval_conditional(self, expr: ConditionalOp, env: Environment) -> Val:
        condition = self.eval_expr(expr.condition, env)
        if self._truth(condition.value):
            return self.eval_expr(expr.then_branch, env)
        return self.eval_expr(expr.else_branch, env)

    def _eval_cast(self, expr: Cast, env: Environment) -> Val:
        value = self.eval_expr(expr.operand, env)
        target = expr.target_type
        if self._is_float(target):
            return Val(float(value.value or 0), target)
        if self._is_pointer(target):
            return Val(int(value.value or 0), target)
        if self._is_struct(target) or self._is_array(target):
            return Val(value.value, target)
        size = self._size_of(target) or 4
        return Val(
            self._truncate(int(value.value or 0), size, not self._is_unsigned(target)), target
        )

    def _eval_sizeof(self, expr: SizeOfExpr, env: Environment) -> Val:
        operand = expr.operand
        if isinstance(operand, TypeNode):
            size = self._size_of(operand) or 1
            return Val(size, PrimitiveType("unsigned long"))
        if operand is None:
            return Val(1, PrimitiveType("unsigned long"))
        type_node = self._expr_type(operand, env)
        size = self._size_of(type_node) or 1
        return Val(size, PrimitiveType("unsigned long"))

    def _expr_type(self, expr: Expr, env: Environment) -> TypeNode | None:
        kind = expr.kind
        if kind == "identifier":
            binding = env.lookup(expr.name)
            return binding.type if binding is not None else None
        if kind == "index_access":
            base = self.eval_expr(expr.object, env)
            return self._pointee_type(base.type)
        if kind == "member_access":
            base = self.eval_expr(expr.object, env)
            if expr.operator == "->":
                base = Val(int(base.value or 0), self._pointee_type(base.type))
            struct_type = self._as_struct(base.type)
            if struct_type is None:
                return None
            layout = self._struct_layout(struct_type)
            entry = layout.get(expr.member)
            return entry[2] if entry else None
        if kind == "unary_op" and expr.operator == "*":
            base = self.eval_expr(expr.operand, env)
            return self._pointee_type(base.type)
        if kind == "unary_op" and expr.operator == "&":
            lvalue = self.eval_lvalue(expr.operand, env)
            return lvalue.type
        if kind == "cast":
            return expr.target_type
        if kind == "conditional":
            return self._expr_type(expr.then_branch, env)
        if kind == "call":
            function = self.resolve_function(expr.callee_name)
            if function is None or function.type is None:
                return None
            resolved = self._resolve_type(function.type)
            return getattr(resolved, "return_type", None)
        if kind == "literal":
            if expr.literal_type == "float":
                return PrimitiveType("double")
            if expr.literal_type == "string":
                return self._pointer_type(PrimitiveType("char"))
            if expr.literal_type == "char":
                return PrimitiveType("char")
            return PrimitiveType("int")
        if kind == "binary_op":
            if expr.operator in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return PrimitiveType("int")
            left = self._expr_type(expr.left, env)
            right = self._expr_type(expr.right, env)
            if self._is_float(left) or self._is_float(right):
                return PrimitiveType("double")
            if self._is_pointer(left):
                return left
            return right or left or PrimitiveType("int")
        return None

    def eval_lvalue(self, expr: Expr, env: Environment) -> LValue:
        kind = expr.kind
        if kind == "identifier":
            binding = self._lookup_binding(expr.name, env)
            return LValue("cell", binding=binding, type=binding.type)
        if kind == "index_access":
            base = self.eval_expr(expr.object, env)
            index = self.eval_expr(expr.index, env)
            element_type = self._pointee_type(base.type)
            size = self._size_of(element_type) or 1
            address = int(base.value or 0) + int(index.value or 0) * size
            return LValue("memory", address=address, type=element_type)
        if kind == "member_access":
            if expr.operator == "->":
                base = self.eval_expr(expr.object, env)
                pointee = self._pointee_type(base.type)
                struct_type = self._as_struct(pointee)
                if struct_type is None:
                    raise InterpreterError(
                        "'->' applied to a value that is not a pointer to a structure",
                        expr.location,
                    )
                address = int(base.value or 0)
            else:
                base = self.eval_expr(expr.object, env)
                struct_type = self._as_struct(base.type)
                if struct_type is None:
                    raise InterpreterError(
                        "'.' applied to a value that is not a structure", expr.location
                    )
                address = int(base.value or 0)
            layout = self._struct_layout(struct_type)
            entry = layout.get(expr.member)
            if entry is None:
                raise InterpreterError(f"unknown member {expr.member!r}", expr.location)
            offset, _size, field_type = entry
            return LValue("memory", address=address + offset, type=field_type)
        if kind == "unary_op" and expr.operator == "*":
            base = self.eval_expr(expr.operand, env)
            pointee = self._pointee_type(base.type)
            if pointee is None:
                raise InterpreterError(
                    "cannot dereference a value that is not a pointer", expr.location
                )
            return LValue("memory", address=int(base.value or 0), type=pointee)
        if kind == "cast":
            inner = self.eval_lvalue(expr.operand, env)
            return LValue(
                inner.kind,
                binding=inner.binding,
                address=inner.address,
                type=expr.target_type,
            )
        raise InterpreterError("expression is not assignable", expr.location)

    def _read_lvalue(self, lvalue: LValue) -> Val:
        if lvalue.kind == "cell":
            binding = lvalue.binding
            if binding is None:
                return Val(0, lvalue.type)
            self._ensure_initialized(binding)
            if binding.memory_backed and binding.address is not None:
                if self._is_array(binding.type) or self._is_struct(binding.type):
                    return Val(binding.address, binding.type)
                return Val(self._load_from_memory(binding.address, binding.type), binding.type)
            return Val(binding.value, binding.type)
        return Val(self._load_from_memory(lvalue.address or 0, lvalue.type), lvalue.type)

    def _write_lvalue(self, lvalue: LValue, value: Val) -> None:
        if lvalue.kind == "cell":
            binding = lvalue.binding
            if binding is None:
                return
            self._ensure_initialized(binding)
            self._write_binding(binding, value)
            return
        self._store_to_memory(lvalue.address or 0, lvalue.type, value)

    def _write_binding(self, binding: Binding, value: Any) -> None:
        if binding.memory_backed and binding.address is not None:
            self._store_to_memory(binding.address, binding.type, value, binding.size or None)
            return
        binding.value = self._convert_for_type(value, binding.type)

    def _load_from_memory(self, address: int, type_node: TypeNode | None) -> Any:
        resolved = self._resolve_type(type_node)
        if resolved is None:
            return 0
        if self._is_array(resolved) or self._is_struct(resolved):
            return address
        size = self._size_of(resolved) or 8
        if self._is_float(resolved):
            return self.memory.load_float(address, size)
        return self.memory.load_int(address, size, not self._is_unsigned(resolved))

    def _store_to_memory(
        self, address: int, type_node: TypeNode | None, value: Any, size: int | None = None
    ) -> None:
        if isinstance(value, Val):
            value = value.value
        resolved = self._resolve_type(type_node)
        if resolved is None:
            return
        if self._is_struct(resolved) or self._is_array(resolved):
            length = size or self._size_of(resolved) or 8
            source = int(value or 0)
            try:
                data = self.memory.read(source, length)
            except MemoryFault:
                return
            self.memory.write(address, data)
            return
        length = size or self._size_of(resolved) or 8
        if self._is_float(resolved):
            self.memory.store_float(address, float(value or 0), length)
            return
        converted = self._convert_for_type(value, resolved)
        self.memory.store_int(address, int(converted or 0), length)

    def _eval_call(self, expr: Call, env: Environment) -> Val:
        callee = expr.callee
        if not isinstance(callee, Identifier):
            raise InterpreterError(
                "only direct calls to named functions are supported", expr.location
            )
        name = callee.name
        args = [self._decay(self.eval_expr(argument, env)) for argument in expr.arguments]
        builtin = self._builtins().get(name)
        if builtin is not None:
            return builtin(self, args, expr)
        function = self.resolve_function(name)
        if function is None:
            raise InterpreterError(f"unknown function {name!r}", expr.location)
        return self._call_function(function, args)

    def _call_function(self, function: FunctionDecl, args: list[Val]) -> Val:
        if function.name in self.stubs:
            return_type = self._return_type(function)
            return Val(self._convert_for_type(self.stubs[function.name], return_type), return_type)
        if self._depth >= self._max_depth:
            raise InterpreterLimit(
                f"maximum recursion depth ({self._max_depth}) reached", function.location
            )
        self._depth += 1
        previous = self._current_function
        self._current_function = function.name
        env = Environment(self.globals)
        try:
            self._bind_parameters(function, args, env)
            if function.body is None:
                return Val(0, self._return_type(function))
            try:
                self._exec_block(function.body, env)
            except _ReturnSignal as signal:
                return signal.value
            except _GotoSignal as signal:
                raise InterpreterError(
                    f"unknown label {signal.label!r}", function.location
                ) from signal
            except RecursionError as error:
                raise InterpreterLimit(
                    "maximum recursion depth reached", function.location
                ) from error
            return Val(0, self._return_type(function))
        finally:
            self._depth -= 1
            self._current_function = previous

    def _return_type(self, function: FunctionDecl | None) -> TypeNode | None:
        if function is None or function.type is None:
            return None
        resolved = self._resolve_type(function.type)
        pointers = 0
        while isinstance(resolved, PointerType):
            pointers += 1
            resolved = self._resolve_type(resolved.pointee)
        if not isinstance(resolved, FunctionType):
            return None
        inner = resolved.return_type
        for _ in range(pointers):
            inner = self._pointer_type(inner)
        return inner

    def _bind_parameters(
        self, function: FunctionDecl, args: list[Val], env: Environment
    ) -> None:
        for index, parameter in enumerate(function.parameters):
            value = args[index] if index < len(args) else Val(0, None)
            declared = parameter.type
            resolved = self._resolve_type(declared)
            if self._is_array(resolved):
                element = self._pointee_type(resolved)
                env.define(parameter.name, int(value.value or 0), self._pointer_type(element))
                continue
            if self._is_struct(resolved):
                size = self._size_of(resolved) or 8
                address = self.memory.allocate(size)
                env.define(
                    parameter.name,
                    address,
                    declared,
                    address=address,
                    memory_backed=True,
                    size=size,
                )
                self._store_to_memory(address, resolved, value, size)
                continue
            if self._is_pointer(resolved):
                env.define(parameter.name, int(value.value or 0), declared)
                continue
            env.define(
                parameter.name, self._convert_for_type(value.value, declared), declared
            )

    def _convert_argument(self, argument: Any) -> Val:
        if isinstance(argument, OutParameter):
            size = max(argument.size, 1)
            address = self.memory.allocate(size)
            argument.address = address
            argument.source = self.memory
            argument.source_size = size
            if argument.type is not None:
                self._store_to_memory(address, argument.type, argument.value, size)
            else:
                self.memory.store_int(address, int(argument.value or 0), size)
            return Val(address, self._pointer_type(argument.type))
        if isinstance(argument, Buffer):
            size = max(argument.capacity, len(argument.data) + 1)
            address = self.memory.allocate(size)
            argument.address = address
            argument.source = self.memory
            argument.source_size = size
            self.memory.write(address, argument.data[:argument.capacity])
            return Val(address, self._pointer_type(PrimitiveType("char")))
        if isinstance(argument, str):
            data = argument.encode("utf-8", errors="replace") + b"\x00"
            address = self.memory.allocate(len(data))
            self.memory.write(address, data)
            return Val(address, self._pointer_type(PrimitiveType("char")))
        if isinstance(argument, (bytes, bytearray)):
            address = self.memory.allocate(max(len(argument), 1))
            self.memory.write(address, bytes(argument))
            return Val(address, self._pointer_type(PrimitiveType("char")))
        if isinstance(argument, bool):
            return Val(1 if argument else 0, PrimitiveType("int"))
        if isinstance(argument, int):
            return Val(argument, PrimitiveType("int"))
        if isinstance(argument, float):
            return Val(argument, PrimitiveType("double"))
        if argument is None:
            return Val(0, self._pointer_type(PrimitiveType("void")))
        raise InterpreterError(
            f"cannot convert a {type(argument).__name__} into a C argument"
        )

    def _builtins(self) -> dict[str, Any]:
        table = getattr(self, "_builtin_table", None)
        if table is not None:
            return table
        table = {
            "malloc": _builtin_malloc,
            "calloc": _builtin_calloc,
            "realloc": _builtin_realloc,
            "free": _builtin_free,
            "memcpy": _builtin_memcpy,
            "memmove": _builtin_memmove,
            "memset": _builtin_memset,
            "memcmp": _builtin_memcmp,
            "strlen": _builtin_strlen,
            "strcpy": _builtin_strcpy,
            "strncpy": _builtin_strncpy,
            "strcat": _builtin_strcat,
            "strncat": _builtin_strncat,
            "strcmp": _builtin_strcmp,
            "strncmp": _builtin_strncmp,
            "strchr": _builtin_strchr,
            "strrchr": _builtin_strrchr,
            "strstr": _builtin_strstr,
            "atoi": _builtin_atoi,
            "atof": _builtin_atof,
            "abs": _builtin_abs,
            "labs": _builtin_abs,
            "llabs": _builtin_abs,
            "sqrt": _builtin_sqrt,
            "fabs": _builtin_fabs,
            "pow": _builtin_pow,
            "sin": _builtin_sin,
            "cos": _builtin_cos,
            "tan": _builtin_tan,
            "log": _builtin_log,
            "log10": _builtin_log10,
            "exp": _builtin_exp,
            "floor": _builtin_floor,
            "ceil": _builtin_ceil,
            "round": _builtin_round,
            "printf": _builtin_printf,
            "fprintf": _builtin_fprintf,
            "sprintf": _builtin_sprintf,
            "snprintf": _builtin_snprintf,
            "puts": _builtin_puts,
            "putchar": _builtin_putchar,
            "abort": _builtin_abort,
            "exit": _builtin_exit,
            "_exit": _builtin_exit,
            "assert": _builtin_assert,
        }
        self._builtin_table = table
        return table

    def _string_value(self, value: Val) -> str:
        if isinstance(value.value, str):
            return value.value
        address = int(value.value or 0)
        if address == 0:
            return ""
        return self.memory.read_cstring(address)

    def _format(self, template: str, values: list[Val]) -> str:
        result: list[str] = []
        index = 0
        position = 0
        length = len(template)
        while position < length:
            char = template[position]
            if char != "%":
                result.append(char)
                position += 1
                continue
            position += 1
            if position < length and template[position] == "%":
                result.append("%")
                position += 1
                continue
            spec = ""
            while position < length and template[position] in "0123456789.+-# hlLjzt":
                spec += template[position]
                position += 1
            if position >= length:
                break
            conversion = template[position]
            position += 1
            value = values[index] if index < len(values) else Val(0)
            if conversion in "di":
                index += 1
                result.append(str(int(value.value or 0)))
            elif conversion in "uoxX":
                index += 1
                number = int(value.value or 0)
                if conversion == "u":
                    result.append(str(number))
                elif conversion == "o":
                    result.append(format(number, "o"))
                elif conversion == "x":
                    result.append(format(number, "x"))
                else:
                    result.append(format(number, "X"))
            elif conversion in "fFeEgG":
                index += 1
                number = float(value.value or 0)
                precision = _precision_of(spec)
                if conversion in "fF":
                    result.append(f"{number:.{precision}f}")
                else:
                    result.append(f"{number:g}")
            elif conversion == "s":
                index += 1
                result.append(self._string_value(value))
            elif conversion == "c":
                index += 1
                result.append(chr(int(value.value or 0) & 0xFF))
            elif conversion == "p":
                index += 1
                result.append(f"0x{int(value.value or 0):x}")
            else:
                result.append("%" + conversion)
        return "".join(result)


def _precision_of(spec: str) -> int:
    if "." in spec:
        tail = spec.split(".", 1)[1]
        digits = ""
        for char in tail:
            if char.isdigit():
                digits += char
            else:
                break
        if digits:
            return int(digits)
    return 6


def _builtin_malloc(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    size = int(args[0].value or 0) if args else 0
    if size <= 0:
        return Val(0, self._pointer_type(PrimitiveType("void")))
    return Val(self.memory.allocate(size), self._pointer_type(PrimitiveType("void")))


def _builtin_calloc(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    count = int(args[0].value or 0) if args else 0
    size = int(args[1].value or 0) if len(args) > 1 else 0
    total = count * size
    if total <= 0:
        return Val(0, self._pointer_type(PrimitiveType("void")))
    address = self.memory.allocate(total)
    self.memory.write(address, b"\x00" * total)
    return Val(address, self._pointer_type(PrimitiveType("void")))


def _builtin_realloc(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    old = int(args[0].value or 0) if args else 0
    size = int(args[1].value or 0) if len(args) > 1 else 0
    if size <= 0:
        return Val(0, self._pointer_type(PrimitiveType("void")))
    address = self.memory.allocate(size)
    if old:
        for base, block in list(self.memory.blocks.items()):
            length = len(block)
            if base <= old < base + length:
                keep = min(length, size)
                self.memory.write(address, bytes(block[old - base : old - base + keep]))
                break
    return Val(address, self._pointer_type(PrimitiveType("void")))


def _builtin_free(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if args:
        self.memory.free(int(args[0].value or 0))
    return Val(None)


def _builtin_memcpy(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    source = int(args[1].value or 0)
    size = int(args[2].value or 0) if len(args) > 2 else 0
    if size > 0:
        self.memory.write(destination, self.memory.read(source, size))
    return Val(destination, args[0].type)


def _builtin_memmove(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    return _builtin_memcpy(self, args, expr)


def _builtin_memset(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    value = int(args[1].value or 0) if len(args) > 1 else 0
    size = int(args[2].value or 0) if len(args) > 2 else 0
    if size > 0:
        self.memory.write(destination, bytes([value & 0xFF]) * size)
    return Val(destination, args[0].type)


def _builtin_memcmp(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    first = self.memory.read(int(args[0].value or 0), int(args[2].value or 0))
    second = self.memory.read(int(args[1].value or 0), int(args[2].value or 0))
    if first == second:
        return Val(0, PrimitiveType("int"))
    return Val(-1 if first < second else 1, PrimitiveType("int"))


def _builtin_strlen(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if not args:
        return Val(0, PrimitiveType("unsigned long"))
    address = int(args[0].value or 0)
    if address == 0:
        raise InterpreterError("strlen of a null pointer", expr.location)
    return Val(len(self.memory.read_cstring(address)), PrimitiveType("unsigned long"))


def _builtin_strcpy(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    source = int(args[1].value or 0)
    data = self.memory.read_cstring(source).encode("utf-8") + b"\x00"
    self.memory.write(destination, data)
    return Val(destination, args[0].type)


def _builtin_strncpy(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    source = int(args[1].value or 0)
    size = int(args[2].value or 0) if len(args) > 2 else 0
    text = self.memory.read_cstring(source).encode("utf-8")[:size]
    data = text + b"\x00" * max(size - len(text), 0)
    self.memory.write(destination, data)
    return Val(destination, args[0].type)


def _builtin_strcat(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    source = int(args[1].value or 0)
    current = self.memory.read_cstring(destination).encode("utf-8")
    addition = self.memory.read_cstring(source).encode("utf-8")
    self.memory.write(destination + len(current), addition + b"\x00")
    return Val(destination, args[0].type)


def _builtin_strncat(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    destination = int(args[0].value or 0)
    source = int(args[1].value or 0)
    size = int(args[2].value or 0) if len(args) > 2 else 0
    current = self.memory.read_cstring(destination).encode("utf-8")
    addition = self.memory.read_cstring(source).encode("utf-8")[:size]
    self.memory.write(destination + len(current), addition + b"\x00")
    return Val(destination, args[0].type)


def _builtin_strcmp(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    first = self.memory.read_cstring(int(args[0].value or 0))
    second = self.memory.read_cstring(int(args[1].value or 0))
    if first == second:
        return Val(0, PrimitiveType("int"))
    return Val(-1 if first < second else 1, PrimitiveType("int"))


def _builtin_strncmp(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    size = int(args[2].value or 0) if len(args) > 2 else 0
    first = self.memory.read_cstring(int(args[0].value or 0))[:size]
    second = self.memory.read_cstring(int(args[1].value or 0))[:size]
    if first == second:
        return Val(0, PrimitiveType("int"))
    return Val(-1 if first < second else 1, PrimitiveType("int"))


def _builtin_strchr(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    address = int(args[0].value or 0)
    needle = int(args[1].value or 0) & 0xFF if len(args) > 1 else 0
    if address == 0:
        return Val(0, args[0].type)
    text = self.memory.read_cstring(address)
    index = text.find(chr(needle))
    if index < 0:
        return Val(0, args[0].type)
    return Val(address + index, args[0].type)


def _builtin_strrchr(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    address = int(args[0].value or 0)
    needle = int(args[1].value or 0) & 0xFF if len(args) > 1 else 0
    if address == 0:
        return Val(0, args[0].type)
    text = self.memory.read_cstring(address)
    index = text.rfind(chr(needle))
    if index < 0:
        return Val(0, args[0].type)
    return Val(address + index, args[0].type)


def _builtin_strstr(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    address = int(args[0].value or 0)
    needle = self.memory.read_cstring(int(args[1].value or 0)) if len(args) > 1 else ""
    if address == 0:
        return Val(0, args[0].type)
    text = self.memory.read_cstring(address)
    index = text.find(needle)
    if index < 0:
        return Val(0, args[0].type)
    return Val(address + index, args[0].type)


def _builtin_atoi(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    text = self._string_value(args[0]).strip() if args else ""
    digits = ""
    for char in text:
        if char.isdigit() or (char in "+-" and not digits):
            digits += char
        else:
            break
    try:
        return Val(int(digits or "0"), PrimitiveType("int"))
    except ValueError:
        return Val(0, PrimitiveType("int"))


def _builtin_atof(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    text = self._string_value(args[0]).strip() if args else ""
    try:
        return Val(float(text or "0"), PrimitiveType("double"))
    except ValueError:
        return Val(0.0, PrimitiveType("double"))


def _builtin_abs(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = int(args[0].value or 0) if args else 0
    return Val(abs(value), PrimitiveType("int"))


def _builtin_sqrt(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.sqrt(value), PrimitiveType("double"))


def _builtin_fabs(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(abs(value), PrimitiveType("double"))


def _builtin_pow(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    base = float(args[0].value or 0) if args else 0.0
    exponent = float(args[1].value or 0) if len(args) > 1 else 0.0
    return Val(math.pow(base, exponent), PrimitiveType("double"))


def _builtin_sin(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.sin(value), PrimitiveType("double"))


def _builtin_cos(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.cos(value), PrimitiveType("double"))


def _builtin_tan(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.tan(value), PrimitiveType("double"))


def _builtin_log(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    if value <= 0:
        raise InterpreterError("log of a non positive number", expr.location)
    return Val(math.log(value), PrimitiveType("double"))


def _builtin_log10(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    if value <= 0:
        raise InterpreterError("log10 of a non positive number", expr.location)
    return Val(math.log10(value), PrimitiveType("double"))


def _builtin_exp(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.exp(value), PrimitiveType("double"))


def _builtin_floor(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.floor(value), PrimitiveType("double"))


def _builtin_ceil(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(math.ceil(value), PrimitiveType("double"))


def _builtin_round(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = float(args[0].value or 0) if args else 0.0
    return Val(float(round(value)), PrimitiveType("double"))


def _builtin_printf(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    template = self._string_value(args[0]) if args else ""
    text = self._format(template, args[1:])
    self.stdout.write(text)
    return Val(len(text), PrimitiveType("int"))


def _builtin_fprintf(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if len(args) < 2:
        return Val(0, PrimitiveType("int"))
    template = self._string_value(args[1])
    text = self._format(template, args[2:])
    self.stdout.write(text)
    return Val(len(text), PrimitiveType("int"))


def _builtin_sprintf(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if len(args) < 2:
        return Val(0, PrimitiveType("int"))
    destination = int(args[0].value or 0)
    template = self._string_value(args[1])
    text = self._format(template, args[2:])
    self.memory.write(destination, text.encode("utf-8") + b"\x00")
    return Val(len(text), PrimitiveType("int"))


def _builtin_snprintf(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if len(args) < 3:
        return Val(0, PrimitiveType("int"))
    destination = int(args[0].value or 0)
    size = int(args[1].value or 0)
    template = self._string_value(args[2])
    text = self._format(template, args[3:])
    if size > 0:
        data = text.encode("utf-8")[: size - 1] + b"\x00"
        self.memory.write(destination, data)
    return Val(len(text), PrimitiveType("int"))


def _builtin_puts(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    text = self._string_value(args[0]) if args else ""
    self.stdout.write(text + "\n")
    return Val(len(text), PrimitiveType("int"))


def _builtin_putchar(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    value = int(args[0].value or 0) if args else 0
    self.stdout.write(chr(value & 0xFF))
    return Val(value & 0xFF, PrimitiveType("int"))


def _builtin_abort(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    raise AbortSignal("abort() was called", expr.location)


def _builtin_exit(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    code = int(args[0].value or 0) if args else 0
    raise ExitSignal("exit() was called", expr.location, code)


def _builtin_assert(self: CInterpreter, args: list[Val], expr: Call) -> Val:
    if not args:
        return Val(None)
    if not self._truth(args[0].value):
        message = self._string_value(args[1]) if len(args) > 1 else ""
        raise AssertionFailure(message or "assertion failed", expr.location)
    return Val(None)
