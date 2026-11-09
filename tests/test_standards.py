"""Tests for the MISRA C:2012 rule pack."""

from __future__ import annotations

from pathlib import Path

from sast.core.config import AnalysisConfig, Project
from sast.rules.base import RULE_REGISTRY
from sast.rules.builtin import standards  # noqa: F401
from sast.rules.engine import RuleEngine


def analyse(code: str, tmp_path: Path, name: str = "sample.c"):
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / name).write_text(code, encoding="utf-8")
    config = AnalysisConfig(source_dirs=["src"], categories=["standards"])
    project = Project(root=tmp_path, config=config)
    return RuleEngine(project).analyze()


def rule_ids(result):
    return {violation.rule_id for violation in result.violations}


def test_the_pack_is_registered():
    misra = [rule for rule in RULE_REGISTRY.values() if rule.id.startswith("MISRA")]
    assert len(misra) >= 20
    for rule in misra:
        assert rule.category == "standards"
        assert rule.standards
        assert rule.standards[0].startswith("MISRA C:2012")


def test_rule_ids_are_unique():
    ids = [rule.id for rule in RULE_REGISTRY.values()]
    assert len(ids) == len(set(ids))


def test_no_rule_raises_on_valid_code(tmp_path):
    result = analyse(
        """
        int add(int a, int b)
        {
            int result = a + b;
            return result;
        }
        """,
        tmp_path,
    )
    assert result.warnings == []


def test_switch_without_default_is_reported(tmp_path):
    result = analyse(
        """
        int f(int value)
        {
            switch (value)
            {
            case 1:
                return 1;
            case 2:
                return 2;
            }
            return 0;
        }
        """,
        tmp_path,
    )
    assert "MISRA-16-004" in rule_ids(result)


def test_default_in_the_middle_is_reported(tmp_path):
    result = analyse(
        """
        int f(int value)
        {
            switch (value)
            {
            case 1:
                return 1;
            default:
                return 0;
            case 2:
                return 2;
            }
        }
        """,
        tmp_path,
    )
    assert "MISRA-16-005" in rule_ids(result)


def test_unbraced_body_is_reported(tmp_path):
    result = analyse(
        """
        void f(int value)
        {
            if (value > 0)
                value++;
            else
                value--;
        }
        """,
        tmp_path,
    )
    assert "MISRA-15-007" in rule_ids(result)


def test_unused_return_value_is_reported(tmp_path):
    result = analyse(
        """
        int compute(int a) { return a + 1; }
        void f(void) { compute(1); }
        """,
        tmp_path,
    )
    assert "MISRA-17-007" in rule_ids(result)


def test_comma_operator_is_reported(tmp_path):
    result = analyse(
        """
        int f(int a, int b)
        {
            int result = (a, b);
            return result;
        }
        """,
        tmp_path,
    )
    assert "MISRA-12-003" in rule_ids(result)


def test_signed_to_unsigned_conversion_is_reported(tmp_path):
    result = analyse(
        """
        unsigned int target;
        void f(int value) { target = value; }
        """,
        tmp_path,
    )
    assert "MISRA-10-003" in rule_ids(result)


def test_incompatible_pointer_conversion_is_reported(tmp_path):
    result = analyse(
        """
        int  *int_pointer;
        char *char_pointer;
        void f(void) { char_pointer = int_pointer; }
        """,
        tmp_path,
    )
    assert "MISRA-11-005" in rule_ids(result)


def test_non_boolean_condition_is_reported(tmp_path):
    result = analyse(
        """
        void f(int a, int b) { if (a && b) { } }
        """,
        tmp_path,
    )
    assert "MISRA-14-004" in rule_ids(result)


def test_standard_library_allocation_is_reported(tmp_path):
    result = analyse(
        """
        #include <stdlib.h>
        void f(void) { void *memory = malloc(10); }
        """,
        tmp_path,
    )
    assert "MISRA-21-006" in rule_ids(result)


def test_duplicate_external_definition_is_reported(tmp_path):
    result = analyse(
        """
        int shared = 1;
        int shared = 2;
        """,
        tmp_path,
    )
    assert "MISRA-8-007" in rule_ids(result)


def test_the_pack_does_not_crash_on_the_example_project(tmp_path):
    from sast.core.config import load_project

    root = Path(__file__).resolve().parent.parent / "examples" / "sample_project"
    project = load_project(root)
    result = RuleEngine(project).analyze()
    assert result.warnings == []
