"""Value range analysis.

The analyser computes whether the outcome of a comparison is constant and
whether a loop is able to leave its body.  Together these two questions
answer the question the compiler answers with ``-Wtype-limits``: an
unsigned value compared against zero can never be negative.

The analysis is deliberately conservative.  When the value of an operand
cannot be determined the comparison is reported as *unknown* rather than
guessed, so that the rules built on top of it stay free of false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

from sast.ast.nodes import (
    BinaryOp,
    BreakStmt,
    DoWhileStmt,
    ForStmt,
    GotoStmt,
    Literal,
    Node,
    RangeForStmt,
    ReturnStmt,
    Stmt,
    SwitchStmt,
    ThrowStmt,
    WhileStmt,
)

#: The operators whose result is a boolean.
COMPARISON_OPERATORS = frozenset({"==", "!=", "<", ">", "<=", ">="})

#: The types that can never hold a negative value.
UNSIGNED_TYPE_NAMES = frozenset(
    {
        "unsigned char",
        "unsigned short",
        "unsigned short int",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "unsigned long long",
        "unsigned long long int",
        "unsigned",
        "size_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "uintptr_t",
        "unsigned _BitInt",
    }
)

_LITERAL_RE = re.compile(
    r"""
    ^
    (?P<sign>[+-])?
    (?:
        0[xX](?P<hex>[0-9a-fA-F]+)
      | 0[bB](?P<bin>[01]+)
      | 0[oO](?P<oct>[0-7]+)
      | (?P<dec>\d+)
    )
    (?P<suffix>[uUlL]*)
    $
    """,
    re.VERBOSE,
)


def literal_integer(expression: Any) -> int | None:
    """The value of an integer literal, ignoring any type suffix."""
    if not isinstance(expression, Literal):
        return None
    if expression.literal_type not in {"int", "bool"}:
        return None
    text = expression.value.strip()
    if expression.literal_type == "bool":
        return 1 if text in {"true", "1"} else 0
    match = _LITERAL_RE.match(text)
    if match is None:
        return None
    value = int(match.group("hex"), 16) if match.group("hex") else None
    if value is None and match.group("bin"):
        value = int(match.group("bin"), 2)
    if value is None and match.group("oct"):
        value = int(match.group("oct"), 8)
    if value is None:
        value = int(match.group("dec"))
    if match.group("sign") == "-":
        value = -value
    return value


def is_unsigned_type(type_node: Any) -> bool:
    """Can *type_node* never hold a negative value?"""
    if type_node is None:
        return False
    name = getattr(type_node, "name", "")
    if not name:
        return False
    return name.replace("const ", "").strip() in UNSIGNED_TYPE_NAMES


def is_unsigned_expression(ctx: Any, expression: Any) -> bool:
    """Is the value of *expression* known to be unsigned?"""
    if expression is None:
        return False
    try:
        type_node = ctx.resolve_type(expression)
    except Exception:
        return False
    if type_node is None:
        return False
    resolved = type_node
    try:
        from sast.analysis.scope import resolve_typedef

        resolved = resolve_typedef(type_node, ctx.symbols.types)
    except Exception:
        resolved = type_node
    return is_unsigned_type(resolved)


def comparison_outcome(ctx: Any, expression: Any) -> tuple[str, str] | None:
    """The constant outcome of a comparison.

    Returns a tuple of the outcome (``"true"`` or ``"false"``) and the
    reason, or ``None`` when the outcome depends on the runtime values.
    """
    if not isinstance(expression, BinaryOp):
        return None
    operator = expression.operator
    if operator not in COMPARISON_OPERATORS:
        return None

    left_value = literal_integer(expression.left)
    right_value = literal_integer(expression.right)
    if left_value is not None and right_value is not None:
        outcome = _compare(operator, left_value, right_value)
        if outcome is None:
            return None
        return outcome, (
            f"both operands are constants, so the comparison is always {outcome}"
        )

    for constant_side, other_side in (
        (expression.left, expression.right),
        (expression.right, expression.left),
    ):
        value = literal_integer(constant_side)
        if value != 0:
            continue
        if not is_unsigned_expression(ctx, other_side):
            continue
        if operator == ">=":
            return (
                "true",
                "the left operand is unsigned, so the comparison against zero "
                "is always true",
            )
        if operator == "<":
            return (
                "false",
                "the left operand is unsigned, so the comparison against zero "
                "is always false",
            )
    return None


def _compare(operator: str, left: int, right: int) -> str | None:
    if operator == "==":
        return "true" if left == right else "false"
    if operator == "!=":
        return "true" if left != right else "false"
    if operator == "<":
        return "true" if left < right else "false"
    if operator == ">":
        return "true" if left > right else "false"
    if operator == "<=":
        return "true" if left <= right else "false"
    if operator == ">=":
        return "true" if left >= right else "false"
    return None


# --------------------------------------------------------------------------
# Loop helpers
# --------------------------------------------------------------------------


def loop_condition(node: Node) -> Any:
    """The controlling expression of a loop, when the node is a loop."""
    if isinstance(node, (WhileStmt, DoWhileStmt)):
        return node.condition
    if isinstance(node, ForStmt):
        return node.condition
    if isinstance(node, RangeForStmt):
        return None
    return None


def loop_body(node: Node) -> Any:
    """The body statement of a loop."""
    if isinstance(node, (WhileStmt, DoWhileStmt, ForStmt, RangeForStmt)):
        return node.body
    return None


def find_exit(body: Node | None) -> str | None:
    """Find a statement that leaves the enclosing loop.

    A ``break`` that belongs to a nested loop or to a nested switch does not
    leave the enclosing loop, while a ``return``, ``goto`` or ``throw``
    always does.
    """
    if body is None:
        return None
    return _find_exit(body, in_nested_loop=False)


def _find_exit(node: Node, in_nested_loop: bool) -> str | None:
    for child in node.children:
        if isinstance(child, BreakStmt):
            if not in_nested_loop:
                return "break"
            continue
        if isinstance(child, (ReturnStmt, GotoStmt, ThrowStmt)):
            return child.kind
        if isinstance(child, SwitchStmt):
            found = _find_exit(child, in_nested_loop=True)
            if found and found != "break":
                return found
            continue
        if isinstance(child, (WhileStmt, DoWhileStmt, ForStmt, RangeForStmt)):
            found = _find_exit(child, in_nested_loop=True)
            if found:
                return found
            continue
        found = _find_exit(child, in_nested_loop)
        if found:
            return found
    return None
