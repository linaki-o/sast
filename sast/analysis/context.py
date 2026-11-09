"""The per-file context handed to every rule.

The context bundles everything a rule needs (AST, symbols, source text,
configuration) behind a handful of convenience helpers so that rules stay
short and declarative.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from sast.ast.nodes import (
    ArrayType,
    Assignment,
    BinaryOp,
    Call,
    Cast,
    CompoundStmt,
    Expr,
    FunctionDecl,
    Identifier,
    IndexAccess,
    Literal,
    MemberAccess,
    Node,
    PointerType,
    ReferenceType,
    SizeOfExpr,
    Stmt,
    TranslationUnit,
    UnaryOp,
    VariableDecl,
)
from sast.core.config import AnalysisConfig
from sast.core.models import Severity, SourceLocation, Violation
from sast.lexer.clexer import Comment, Directive, Macro
from sast.rules.base import Rule


class FileContext:
    """Everything a rule can inspect about one translation unit."""

    def __init__(
        self,
        unit: TranslationUnit,
        *,
        path: str,
        source: str,
        symbols: Any,
        macros: dict[str, Macro] | None = None,
        comments: list[Comment] | None = None,
        directives: list[Directive] | None = None,
        config: AnalysisConfig | None = None,
        language: str = "c",
    ) -> None:
        self.unit = unit
        self.path = path
        self.source = source
        self.lines: list[str] = source.splitlines()
        self.symbols = symbols
        self.macros = macros or {}
        self.comments = comments or []
        self.directives = directives or []
        self.config = config or AnalysisConfig()
        self.language = language
        self._violations: list[Violation] = []

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    def report(
        self,
        rule: Rule | type[Rule],
        node: Node,
        message: str,
        *,
        severity: Severity | None = None,
        snippet: str | None = None,
        recommendation: str | None = None,
        trace: Iterable[SourceLocation] = (),
        **metrics: Any,
    ) -> Violation:
        """Build a :class:`Violation` for *rule* at *node*."""
        instance = rule() if isinstance(rule, type) else rule
        location = node.location
        violation = Violation(
            rule_id=instance.id,
            rule_name=instance.name,
            severity=severity or instance.severity,
            message=message,
            location=location,
            category=instance.category,
            language=self.language,
            function=self.function_name(node),
            snippet=snippet if snippet is not None else self.snippet(node),
            recommendation=recommendation or instance.recommendation,
            cwe=instance.cwe,
            owasp=instance.owasp,
            standards=instance.standards,
            trace=tuple(trace),
            metrics=dict(metrics),
        )
        self._violations.append(violation)
        return violation

    @property
    def violations(self) -> list[Violation]:
        return self._violations

    # ------------------------------------------------------------------
    # source helpers
    # ------------------------------------------------------------------
    def line_text(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    def snippet(self, node: Node, max_lines: int = 3) -> str:
        """The source text covered by *node*."""
        start = node.location.line
        end = node.end_location.line or start
        if end <= start:
            end = min(start, len(self.lines))
        end = min(end, start + max_lines - 1)
        chunk = [self.line_text(number) for number in range(start, end + 1)]
        text = "\n".join(chunk).strip()
        if len(text) > 400:
            text = text[:397] + "..."
        return text

    def macro_value(self, name: str) -> str | None:
        macro = self.macros.get(name)
        return macro.body if macro else None

    def macro_int(self, name: str) -> int | None:
        body = self.macro_value(name)
        if body is None:
            return None
        try:
            return int(body.strip().rstrip("uUlL"))
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------
    @property
    def functions(self) -> list[FunctionDecl]:
        result: list[FunctionDecl] = []

        def walk(node: Node) -> None:
            for child in node.children:
                if isinstance(child, FunctionDecl):
                    result.append(child)
                walk(child)

        walk(self.unit)
        return result

    def function_name(self, node: Node) -> str:
        current: Node | None = node
        while current is not None:
            if isinstance(current, FunctionDecl):
                return current.qualified_name or current.name
            current = current.parent
        return ""

    def enclosing_function(self, node: Node) -> FunctionDecl | None:
        current: Node | None = node.parent
        while current is not None:
            if isinstance(current, FunctionDecl):
                return current
            current = current.parent
        return None

    def enclosing(self, node: Node, *kinds: str) -> Node | None:
        current: Node | None = node.parent
        while current is not None:
            if current.kind in kinds:
                return current
            current = current.parent
        return None

    def find_calls(self, *names: str) -> Iterator[Call]:
        """Every call whose callee matches one of *names*."""
        wanted = set(names)
        for node in self.unit.walk():
            if isinstance(node, Call) and node.callee_name in wanted:
                yield node

    def calls_named(self, name: str) -> Iterator[Call]:
        yield from self.find_calls(name)

    def iter_nodes(self, *kinds: str) -> Iterator[Node]:
        for node in self.unit.walk():
            if not kinds or node.kind in kinds:
                yield node

    # ------------------------------------------------------------------
    # expression helpers
    # ------------------------------------------------------------------
    def is_literal_zero(self, expression: Expr | None) -> bool:
        return self.const_int(expression) == 0

    def const_int(self, expression: Expr | None, depth: int = 0) -> int | None:
        """Evaluate a compile time constant integer expression.

        Besides literals and macros the evaluation follows a variable that
        was initialised with a constant expression, so that a size such as
        ``size_t length = 32;`` can be resolved.
        """
        if expression is None or depth > 8:
            return None
        if isinstance(expression, Literal):
            text = expression.value.strip()
            if expression.literal_type == "bool":
                return 1 if text in {"true", "1"} else 0
            if expression.literal_type == "null":
                return 0
            text = text.replace("'", "")
            try:
                if text.lower().startswith("0x"):
                    return int(text, 16)
                if text.lower().startswith("0b"):
                    return int(text, 2)
                if text.lower().startswith("0o"):
                    return int(text, 8)
                if len(text) > 1 and text.startswith("0") and text[1:].isdigit():
                    return int(text, 8)
                return int(text)
            except ValueError:
                return None
        if isinstance(expression, UnaryOp):
            value = self.const_int(expression.operand, depth + 1)
            if value is None:
                return None
            if expression.operator == "-":
                return -value
            if expression.operator == "+":
                return value
            if expression.operator == "!":
                return int(not value)
            return None
        if isinstance(expression, BinaryOp):
            left = self.const_int(expression.left, depth + 1)
            right = self.const_int(expression.right, depth + 1)
            if left is None or right is None:
                return None
            try:
                if expression.operator == "+":
                    return left + right
                if expression.operator == "-":
                    return left - right
                if expression.operator == "*":
                    return left * right
                if expression.operator == "/":
                    return left // right if right else None
                if expression.operator == "%":
                    return left % right if right else None
                if expression.operator == "<<":
                    return left << right
                if expression.operator == ">>":
                    return left >> right
                if expression.operator == "&":
                    return left & right
                if expression.operator == "|":
                    return left | right
                if expression.operator == "^":
                    return left ^ right
            except (ValueError, ZeroDivisionError):
                return None
            return None
        if isinstance(expression, Identifier):
            macro = self.macro_int(expression.name)
            if macro is not None:
                return macro
            symbol = self.resolve(expression.name, expression)
            initialiser = getattr(symbol, "init_expr", None) if symbol else None
            if initialiser is None or initialiser is expression:
                return None
            return self.const_int(initialiser, depth + 1)
        if isinstance(expression, Cast):
            return self.const_int(expression.operand, depth + 1)
        return None

    def base_identifier(self, expression: Expr | None) -> Identifier | None:
        """The innermost identifier of an lvalue chain (``a.b[c]`` -> ``a``)."""
        current = expression
        while current is not None:
            if isinstance(current, Identifier):
                return current
            if isinstance(current, MemberAccess):
                current = current.object
                continue
            if isinstance(current, IndexAccess):
                current = current.object
                continue
            if isinstance(current, UnaryOp) and current.operator == "*":
                current = current.operand
                continue
            if isinstance(current, Cast):
                current = current.operand
                continue
            return None
        return None

    def strip_casts(self, expression: Expr | None) -> Expr | None:
        while isinstance(expression, Cast):
            expression = expression.operand
        return expression

    def contains_identifier(self, expression: Expr | None, name: str) -> bool:
        if expression is None:
            return False
        for node in expression.walk():
            if isinstance(node, Identifier) and node.name == name:
                return True
        return False

    def identifiers_in(self, expression: Expr | None) -> set[str]:
        if expression is None:
            return set()
        return {
            node.name
            for node in expression.walk()
            if isinstance(node, Identifier)
        }

    def resolve(self, name: str, node: Node | None = None) -> Any:
        """Resolve *name* in the symbol table.

        When *node* is given the enclosing function scope takes precedence,
        so a local variable is never confused with a global of the same name.
        """
        lookup_at = getattr(self.symbols, "lookup_at", None)
        if lookup_at is not None:
            return lookup_at(name, node)
        return self.symbols.lookup(name)

    def resolve_type(self, expression: Expr | None) -> Any:
        """The declared type of the variable an expression refers to."""
        identifier = self.base_identifier(expression)
        if identifier is None:
            return None
        symbol = self.resolve(identifier.name, expression)
        return getattr(symbol, "type", None) if symbol else None

    def array_size_of(self, expression: Expr | None) -> int | None:
        identifier = self.base_identifier(expression)
        if identifier is None:
            return None
        symbol = self.resolve(identifier.name, expression)
        if symbol is None:
            return None
        return symbol.array_size

    def is_array_type(self, expression: Expr | None) -> bool:
        identifier = self.base_identifier(expression)
        if identifier is None:
            return False
        symbol = self.resolve(identifier.name, expression)
        if symbol is None:
            return False
        return bool(symbol.is_array)

    def is_pointer_type(self, expression: Expr | None) -> bool:
        identifier = self.base_identifier(expression)
        if identifier is None:
            return False
        symbol = self.resolve(identifier.name, expression)
        if symbol is None:
            return False
        return bool(symbol.is_pointer)

    def type_of(self, expression: Expr | None) -> Any:
        return self.resolve_type(expression)

    def pointer_depth(self, expression: Expr | None) -> int:
        identifier = self.base_identifier(expression)
        if identifier is None:
            return 0
        symbol = self.resolve(identifier.name, expression)
        if symbol is None or symbol.type is None:
            return 0
        depth = 0
        current = symbol.type
        while isinstance(current, (PointerType, ReferenceType, ArrayType)):
            depth += 1
            current = (
                current.pointee
                if isinstance(current, (PointerType, ReferenceType))
                else current.element
            )
        return depth

    def is_null_check(self, expression: Expr | None) -> bool:
        """True when the expression compares something against NULL/0."""
        if isinstance(expression, BinaryOp) and expression.operator in {"==", "!="}:
            for side in (expression.left, expression.right):
                if isinstance(side, Literal) and side.literal_type == "null":
                    return True
                if isinstance(side, Identifier) and side.name == "NULL":
                    return True
                if isinstance(side, Literal) and side.literal_type == "int" and side.value == "0":
                    return True
                if isinstance(side, UnaryOp) and side.operator == "!" and isinstance(
                    side.operand, Cast
                ):
                    return True
        if isinstance(expression, UnaryOp) and expression.operator == "!":
            inner = expression.operand
            if isinstance(inner, Cast) and isinstance(inner.operand, Identifier):
                return inner.operand.name == "NULL"
        return False

    def doc_comment_for(self, node: Node) -> str:
        """The doc comment immediately preceding *node*."""
        target_line = node.location.line
        best = ""
        for comment in self.comments:
            if comment.location.line < target_line and target_line - comment.location.line <= 3:
                if comment.block and (comment.text.startswith("*") or comment.text.startswith("!")):
                    best = comment.text
                elif comment.doc:
                    best = comment.text
        return best.strip()

    def has_doc_comment(self, node: Node) -> bool:
        return bool(self.doc_comment_for(node))

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<FileContext {self.path}>"
