"""Rules about the termination of loops.

A loop whose condition can never become false is a defect that neither the
compiler nor a plain syntax check can be relied upon to catch.  The rules
below combine the value range analysis of :mod:`sast.analysis.values` with
the control flow of the loop body.
"""

from __future__ import annotations

from typing import Any, Iterator

from sast.analysis.values import (
    comparison_outcome,
    find_exit,
    is_unsigned_expression,
    literal_integer,
    loop_body,
    loop_condition,
)
from sast.ast.nodes import Node
from sast.core.models import Severity, Violation
from sast.rules.base import Rule, register
from sast.rules.builtin import prepare


@register
class TautologicalLoopCondition(Rule):
    id = "QLT-LOOP-001"
    name = "Loop condition is always true"
    category = "quality"
    severity = Severity.HIGH
    description = (
        "The controlling expression of a loop has a constant outcome, so the "
        "loop can never be left through its condition."
    )
    rationale = (
        "A loop whose condition is always true keeps running until the "
        "program is interrupted, which turns a local logic error into a "
        "hang of the whole application."
    )
    recommendation = (
        "Rewrite the condition so that it can become false, and check the "
        "types of the operands: an unsigned value is never negative."
    )
    cwe = (835,)
    tags = ("loop", "termination", "control-flow")

    def check(self, ctx) -> Iterator[Violation]:
        prepare(ctx)
        for node in ctx.unit.walk():
            condition = loop_condition(node)
            if condition is None:
                continue
            outcome = comparison_outcome(ctx, condition)
            if outcome is None:
                continue
            value, reason = outcome
            if value != "true":
                continue
            yield ctx.report(
                self,
                node,
                f"the condition of this loop is always true because {reason}; "
                "the loop may never terminate",
            )


@register
class NonTerminatingLoop(Rule):
    id = "QLT-LOOP-002"
    name = "Loop can never terminate"
    category = "quality"
    severity = Severity.CRITICAL
    description = (
        "The condition of a loop is always true and the body of the loop "
        "contains no statement that leaves it."
    )
    rationale = (
        "The program is guaranteed to hang: the condition never becomes "
        "false and no break, return or goto can escape the loop."
    )
    recommendation = (
        "Add a counter with a reachable bound, or turn the condition into "
        "one that can become false."
    )
    cwe = (835,)
    tags = ("loop", "termination", "hang", "control-flow")

    def check(self, ctx) -> Iterator[Violation]:
        prepare(ctx)
        for node in ctx.unit.walk():
            condition = loop_condition(node)
            if condition is None:
                continue
            outcome = comparison_outcome(ctx, condition)
            if outcome is None or outcome[0] != "true":
                continue
            body = loop_body(node)
            exit_kind = find_exit(body)
            if exit_kind is not None:
                continue
            yield ctx.report(
                self,
                node,
                "the condition of this loop is always true and its body "
                "cannot leave the loop, so the loop never terminates",
            )


@register
class UnsignedCounterDecrement(Rule):
    id = "QLT-LOOP-003"
    name = "Unsigned counter can wrap around"
    category = "quality"
    severity = Severity.MEDIUM
    description = (
        "A loop decrements an unsigned counter, which wraps around to its "
        "maximum value instead of becoming negative."
    )
    rationale = (
        "The wrap around silently turns a terminating loop into an endless "
        "one, and the subtraction itself is well defined so nothing warns "
        "about it."
    )
    recommendation = (
        "Use a signed counter, or test the counter against zero before "
        "decrementing it."
    )
    cwe = (190,)
    tags = ("loop", "unsigned", "wrap-around", "arithmetic")

    def check(self, ctx) -> Iterator[Violation]:
        prepare(ctx)
        for node in ctx.unit.walk():
            condition = loop_condition(node)
            if condition is None:
                continue
            body = loop_body(node)
            if body is None:
                continue
            decremented = _decremented_identifier(body)
            if decremented is None:
                continue
            if not is_unsigned_expression(ctx, decremented):
                continue
            yield ctx.report(
                self,
                node,
                f"'{decremented.name}' is unsigned and is decremented in this "
                "loop, so it wraps around to its maximum value instead of "
                "reaching zero",
            )


def _decremented_identifier(body: Node) -> Any:
    """The unsigned variable that the loop body decrements, if any."""
    from sast.ast.nodes import UnaryOp

    for node in body.walk():
        if not isinstance(node, UnaryOp):
            continue
        if node.operator not in {"--", "pre--", "post--"}:
            continue
        operand = node.operand
        if getattr(operand, "name", ""):
            return operand
    return None
