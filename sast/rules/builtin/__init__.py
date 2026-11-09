"""Bundled rule packs for CodeShield.

Importing this package registers every built in rule with the global rule
registry.  Besides the imports it hosts the handful of helpers that the
packs share: a small AST repair pass that guarantees that every declaration
is reachable from the translation unit, and a set of type/expression
utilities that keep the individual rules short and declarative.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from sast.ast.nodes import (
    ArrayType,
    Call,
    Expr,
    FunctionDecl,
    Identifier,
    IndexAccess,
    Literal,
    MemberAccess,
    Node,
    PrimitiveType,
    SizeOfExpr,
    TranslationUnit,
    TypeNode,
    UnaryOp,
    Cast,
)

__all__ = [
    "prepare",
    "iter_nodes",
    "iter_functions",
    "find_calls",
    "find_calls_ci",
    "string_value",
    "is_null_expression",
    "base_name",
    "word_tokens",
    "matches_sensitive",
    "format_specifier_count",
    "buffer_capacity",
    "sizeof_capacity",
    "resolve_symbol",
    "resolve_type",
    "is_pointer",
    "signedness",
    "security",
    "quality",
]

_CAMEL_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")

_SIGNED_NAMES = frozenset(
    {
        "int",
        "signed",
        "signed int",
        "short",
        "short int",
        "signed short",
        "long",
        "long int",
        "signed long",
        "long long",
        "long long int",
        "signed long long",
        "char",
        "signed char",
        "wchar_t",
        "char16_t",
        "char32_t",
    }
)

_UNSIGNED_NAMES = frozenset(
    {
        "unsigned",
        "unsigned int",
        "unsigned char",
        "unsigned short",
        "unsigned long",
        "unsigned long long",
        "size_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "uintptr_t",
    }
)

_FORMAT_CONVERSIONS = frozenset("diouxXeEfFgGaAcspnCS")


def _link_children(node: Node) -> bool:
    """Attach the children a node owns but does not link itself."""
    changed = False
    kind = node.kind
    if kind == "decl_stmt":
        for declaration in list(getattr(node, "declarations", []) or []):
            if declaration not in node.children:
                node.add(declaration)
                changed = True
    elif kind == "variable_decl":
        initialiser = getattr(node, "init", None)
        if initialiser is not None and initialiser not in node.children:
            node.add(initialiser)
            changed = True
    elif kind == "function_decl":
        for parameter in list(getattr(node, "parameters", []) or []):
            if parameter not in node.children:
                node.add(parameter)
                changed = True
        body = getattr(node, "body", None)
        if body is not None and body not in node.children:
            node.add(body)
            changed = True
    elif kind == "class_decl":
        for member in list(getattr(node, "members", []) or []):
            if member not in node.children:
                node.add(member)
                changed = True
    return changed


def _refresh_symbols(ctx: Any) -> None:
    """Rebuild the symbol table so that local variables become visible."""
    try:
        from sast.analysis.scope import SymbolTable
    except Exception:
        return
    try:
        if isinstance(getattr(ctx, "symbols", None), SymbolTable):
            ctx.symbols = SymbolTable(ctx.unit)
    except Exception:
        return


def prepare(ctx: Any) -> TranslationUnit:
    """Make the translation unit fully traversable.

    Declarations that are not attached to their parent stay invisible to a
    plain tree walk, which would hide whole functions from the rules.  The
    repair only adds the missing links, so a correctly linked tree is left
    untouched.
    """
    unit = ctx.unit
    if getattr(ctx, "_codeshield_prepared", False):
        return unit
    try:
        for declaration in list(getattr(unit, "declarations", []) or []):
            if declaration not in unit.children:
                unit.add(declaration)
        for _ in range(8):
            changed = False
            for node in list(unit.walk()):
                if _link_children(node):
                    changed = True
            if not changed:
                break
        _refresh_symbols(ctx)
        setattr(ctx, "_codeshield_prepared", True)
    except Exception:
        return unit
    return unit


def iter_nodes(ctx: Any) -> Iterator[Node]:
    """Every node of the translation unit."""
    return ctx.unit.walk()


def iter_functions(ctx: Any) -> Iterator[FunctionDecl]:
    """Every function definition of the translation unit."""
    for node in ctx.unit.walk():
        if isinstance(node, FunctionDecl):
            yield node


def find_calls(ctx: Any, *names: str) -> Iterator[Call]:
    """Every call to one of *names*.

    The context helper is consulted first, the tree walk afterwards, so the
    result stays complete no matter how the parser linked the tree.
    """
    wanted = set(names)
    seen: set[int] = set()
    try:
        for call in ctx.find_calls(*names):
            seen.add(id(call))
            yield call
    except Exception:
        pass
    for node in ctx.unit.walk():
        if isinstance(node, Call) and node.callee_name in wanted and id(node) not in seen:
            seen.add(id(node))
            yield node


def find_calls_ci(ctx: Any, *names: str) -> Iterator[Call]:
    """Every call to one of *names*, ignoring the case of the callee."""
    wanted = {name.lower() for name in names}
    for node in ctx.unit.walk():
        if isinstance(node, Call) and node.callee_name.lower() in wanted:
            yield node


def string_value(expression: Expr | None) -> str | None:
    """The text of a string literal, or ``None``."""
    if isinstance(expression, Literal) and expression.literal_type == "string":
        return expression.value
    return None


def is_null_expression(expression: Expr | None) -> bool:
    """True for ``NULL``, ``nullptr`` and friends."""
    if expression is None:
        return False
    if isinstance(expression, Literal):
        if expression.literal_type == "null":
            return True
        return expression.literal_type == "int" and expression.value.strip() == "0"
    if isinstance(expression, Identifier):
        return expression.name == "NULL"
    if isinstance(expression, Cast):
        return is_null_expression(expression.operand)
    return False


def base_name(expression: Expr | None) -> str | None:
    """The name of the variable an lvalue chain is rooted in."""
    if expression is None:
        return None
    if isinstance(expression, Identifier):
        return expression.name
    if isinstance(expression, MemberAccess):
        return base_name(expression.object)
    if isinstance(expression, IndexAccess):
        return base_name(expression.object)
    if isinstance(expression, UnaryOp) and expression.operator in {"*", "&"}:
        return base_name(expression.operand)
    if isinstance(expression, Cast):
        return base_name(expression.operand)
    return None


def word_tokens(name: str) -> set[str]:
    """Split an identifier into its lower case words."""
    tokens: set[str] = set()
    for chunk in re.split(r"[^0-9A-Za-z]+", name or ""):
        if not chunk:
            continue
        for piece in _CAMEL_SPLIT.findall(chunk):
            tokens.add(piece.lower())
    return tokens


def matches_sensitive(name: str, keywords: frozenset[str] | set[str]) -> bool:
    """Does *name* contain one of the sensitive *keywords* as a word?"""
    if not name:
        return False
    return bool(word_tokens(name) & set(keywords))


def format_specifier_count(text: str) -> tuple[int, int]:
    """Number of conversions and of ``*`` width/precision specifiers."""
    conversions = 0
    stars = 0
    index = 0
    length = len(text or "")
    while index < length:
        if text[index] != "%":
            index += 1
            continue
        if index + 1 < length and text[index + 1] == "%":
            index += 2
            continue
        index += 1
        while index < length and text[index] in "-+ #0'":
            index += 1
        if index < length and text[index] == "*":
            stars += 1
            index += 1
        else:
            while index < length and text[index].isdigit():
                index += 1
        if index < length and text[index] == ".":
            index += 1
            if index < length and text[index] == "*":
                stars += 1
                index += 1
            else:
                while index < length and text[index].isdigit():
                    index += 1
        while index < length and text[index] in "hlLqjzt":
            index += 1
        if index < length and text[index] in _FORMAT_CONVERSIONS:
            conversions += 1
            index += 1
    return conversions, stars


def resolve_symbol(ctx: Any, name: str, node: Node | None = None) -> Any:
    """Resolve *name* in the scope that belongs to *node*.

    The symbol table keeps the scopes of every function in one flat list, so
    a plain lookup can return the variable of an unrelated function that
    happens to use the same name.  The scope of the enclosing function is
    therefore preferred whenever the reference can be placed.
    """
    symbols = getattr(ctx, "symbols", None)
    scopes = getattr(symbols, "scopes", None)
    if scopes and node is not None and name:
        function = None
        try:
            function = ctx.enclosing_function(node)
        except Exception:
            function = None
        if function is not None:
            for scope in scopes:
                if scope.kind == "function" and scope.name == function.name:
                    found = _lookup_in_scope(scope, name)
                    if found is not None:
                        return found
    try:
        return ctx.resolve(name)
    except Exception:
        return None


def _lookup_in_scope(scope: Any, name: str) -> Any:
    symbol = scope.lookup_local(name)
    if symbol is not None:
        return symbol
    for child in getattr(scope, "children", []) or []:
        found = _lookup_in_scope(child, name)
        if found is not None:
            return found
    return None


def resolve_type(ctx: Any, expression: Expr | None) -> Any:
    """The declared type of the variable an expression refers to."""
    identifier = ctx.base_identifier(expression)
    if identifier is None:
        return None
    symbol = resolve_symbol(ctx, identifier.name, expression)
    if symbol is not None:
        return getattr(symbol, "type", None)
    try:
        return ctx.resolve_type(expression)
    except Exception:
        return None


def is_pointer(ctx: Any, expression: Expr | None) -> bool:
    """Does the expression refer to a pointer?"""
    identifier = ctx.base_identifier(expression)
    if identifier is None:
        return False
    symbol = resolve_symbol(ctx, identifier.name, expression)
    if symbol is not None:
        return bool(getattr(symbol, "is_pointer", False))
    try:
        return bool(ctx.is_pointer_type(expression))
    except Exception:
        return False


def sizeof_capacity(ctx: Any, expression: Expr | None) -> int | None:
    """The capacity of the array a sizeof() expression refers to."""
    if not isinstance(expression, SizeOfExpr):
        return None
    operand = expression.operand
    if operand is None or isinstance(operand, TypeNode):
        return None
    return buffer_capacity(ctx, operand)


def buffer_capacity(ctx: Any, expression: Expr | None) -> int | None:
    """The number of elements of a fixed size buffer, when it is known."""
    identifier = ctx.base_identifier(expression)
    if identifier is not None:
        symbol = resolve_symbol(ctx, identifier.name, expression)
        if symbol is not None and getattr(symbol, "is_array", False):
            size = getattr(symbol, "array_size", None)
            if size is not None:
                return size
            type_node = getattr(symbol, "type", None)
            if isinstance(type_node, ArrayType):
                try:
                    return ctx.const_int(type_node.size_expr)
                except Exception:
                    return None
    try:
        return ctx.array_size_of(expression)
    except Exception:
        return None


def signedness(type_node: Any) -> int:
    """``1`` for signed, ``-1`` for unsigned and ``0`` when unknown."""
    if not isinstance(type_node, PrimitiveType):
        return 0
    name = type_node.name.replace("const ", "").strip()
    if name in _UNSIGNED_NAMES:
        return -1
    if name in _SIGNED_NAMES:
        return 1
    return 0


from sast.rules.builtin import security, quality  # noqa: E402,F401
from sast.rules.builtin import standards  # noqa: E402,F401
from sast.rules.builtin import loops  # noqa: E402,F401
