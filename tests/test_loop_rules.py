"""Tests for the value range analysis and the loop termination rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from sast.analysis.values import (
    comparison_outcome,
    find_exit,
    is_unsigned_expression,
    literal_integer,
)
from sast.core.config import AnalysisConfig, Project
from sast.rules.base import RULE_REGISTRY
from sast.rules.builtin import loops  # noqa: F401
from sast.rules.engine import RuleEngine


def analyse(code: str, tmp_path: Path, name: str = "sample.c"):
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / name).write_text(code, encoding="utf-8")
    config = AnalysisConfig(source_dirs=["src"])
    project = Project(root=tmp_path, config=config)
    return RuleEngine(project).analyze()


def rule_ids(result):
    return {violation.rule_id for violation in result.violations}


def context_for(code: str, tmp_path: Path, name: str = "sample.c"):
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / name).write_text(code, encoding="utf-8")
    config = AnalysisConfig(source_dirs=["src"])
    project = Project(root=tmp_path, config=config)
    return RuleEngine(project).build_context(source / name)


def test_literal_integer_handles_suffixes_and_bases():
    from sast.ast.nodes import Literal
    from sast.core.models import SourceLocation

    location = SourceLocation("a.c", 1, 1)
    assert literal_integer(Literal("0", "int", location)) == 0
    assert literal_integer(Literal("0U", "int", location)) == 0
    assert literal_integer(Literal("0x10", "int", location)) == 16
    assert literal_integer(Literal("0b101", "int", location)) == 5
    assert literal_integer(Literal("0o17", "int", location)) == 15
    assert literal_integer(Literal("-3", "int", location)) == -3
    assert literal_integer(Literal("abc", "string", location)) is None


def test_unsigned_expression_detection(tmp_path):
    ctx = context_for(
        """
        void f(void)
        {
            unsigned int counter = 0;
            int signed_counter = 0;
            counter++;
            signed_counter++;
        }
        """,
        tmp_path,
    )
    from sast.ast.nodes import Identifier

    unsigned = [n for n in ctx.unit.walk() if isinstance(n, Identifier) and n.name == "counter"]
    signed = [n for n in ctx.unit.walk() if isinstance(n, Identifier) and n.name == "signed_counter"]
    assert is_unsigned_expression(ctx, unsigned[0])
    assert not is_unsigned_expression(ctx, signed[0])


def test_comparison_outcome_of_unsigned_against_zero(tmp_path):
    ctx = context_for(
        """
        void f(void)
        {
            unsigned int counter = 0;
            int value = 0;
            if (counter >= 0) { }
            if (counter < 0) { }
            if (value >= 0) { }
        }
        """,
        tmp_path,
    )
    from sast.ast.nodes import BinaryOp

    comparisons = [
        node
        for node in ctx.unit.walk()
        if isinstance(node, BinaryOp) and node.operator in {">=", "<"}
    ]
    outcomes = [comparison_outcome(ctx, node) for node in comparisons]
    values = [outcome[0] for outcome in outcomes if outcome is not None]
    assert "true" in values
    assert "false" in values
    assert len(values) == 2


def test_comparison_of_two_constants(tmp_path):
    ctx = context_for(
        """
        void f(void)
        {
            if (1 > 2) { }
        }
        """,
        tmp_path,
    )
    from sast.ast.nodes import BinaryOp

    comparison = next(
        node
        for node in ctx.unit.walk()
        if isinstance(node, BinaryOp) and node.operator == ">"
    )
    outcome = comparison_outcome(ctx, comparison)
    assert outcome is not None
    assert outcome[0] == "false"


def test_infinite_loop_is_reported(tmp_path):
    result = analyse(
        """
        unsigned int counter = 0;
        void f(void)
        {
            while (counter >= 0) {
                counter--;
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-001" in rule_ids(result)
    assert "QLT-LOOP-002" in rule_ids(result)


def test_unsigned_decrement_is_reported(tmp_path):
    result = analyse(
        """
        unsigned int counter = 10;
        void f(void)
        {
            while (counter != 0) {
                counter--;
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-003" in rule_ids(result)


def test_signed_loop_is_not_reported(tmp_path):
    result = analyse(
        """
        void f(int limit)
        {
            int counter = 0;
            while (counter < limit) {
                counter++;
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-001" not in rule_ids(result)
    assert "QLT-LOOP-002" not in rule_ids(result)


def test_loop_with_a_break_is_not_reported_as_non_terminating(tmp_path):
    result = analyse(
        """
        unsigned int counter = 0;
        void f(void)
        {
            while (counter >= 0) {
                if (counter == 5) {
                    break;
                }
                counter++;
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-001" in rule_ids(result)
    assert "QLT-LOOP-002" not in rule_ids(result)


def test_break_of_a_nested_loop_does_not_exit_the_outer_one(tmp_path):
    result = analyse(
        """
        unsigned int counter = 0;
        void f(void)
        {
            while (counter >= 0) {
                int inner = 0;
                while (inner < 3) {
                    break;
                }
                counter++;
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-002" in rule_ids(result)


def test_for_loop_with_an_unsigned_bound(tmp_path):
    result = analyse(
        """
        void f(void)
        {
            unsigned int i;
            for (i = 0; i >= 0; i--) {
            }
        }
        """,
        tmp_path,
    )
    assert "QLT-LOOP-001" in rule_ids(result)
    assert "QLT-LOOP-002" in rule_ids(result)


def test_no_false_positive_on_the_example_project():
    from sast.core.config import load_project

    root = Path(__file__).resolve().parent.parent / "examples" / "sample_project"
    project = load_project(root)
    result = RuleEngine(project).analyze()
    assert result.warnings == []
    loop_findings = [
        violation
        for violation in result.violations
        if violation.rule_id.startswith("QLT-LOOP")
    ]
    assert len(loop_findings) == 3
    assert all(
        violation.location.file.endswith("buffer.cpp")
        and violation.location.line == 41
        for violation in loop_findings
    )


def test_the_rules_are_registered():
    for rule_id in ("QLT-LOOP-001", "QLT-LOOP-002", "QLT-LOOP-003"):
        assert rule_id in RULE_REGISTRY
        rule = RULE_REGISTRY[rule_id]()
        assert rule.category == "quality"
        assert rule.description
        assert rule.recommendation
