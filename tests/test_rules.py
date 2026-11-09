"""Tests for the rule engine and the bundled rule packs."""

from __future__ import annotations

from pathlib import Path

import pytest

from sast.core.config import AnalysisConfig, Project
from sast.rules.base import RULE_REGISTRY, Rule, rule_catalog
from sast.rules.builtin import quality, security  # noqa: F401
from sast.rules.engine import RuleEngine


def analyse(code: str, tmp_path: Path, name: str = "sample.c", **config_kwargs):
    """Write *code* to a temporary project and analyse it."""
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / name).write_text(code, encoding="utf-8")
    config = AnalysisConfig(source_dirs=["src"], **config_kwargs)
    project = Project(root=tmp_path, config=config)
    return RuleEngine(project).analyze()


def rule_ids(result):
    return {violation.rule_id for violation in result.violations}


def test_registry_contains_security_and_quality_packs():
    assert len(RULE_REGISTRY) >= 40
    categories = {rule.category for rule in RULE_REGISTRY.values()}
    assert "security" in categories
    assert "quality" in categories


def test_every_rule_has_complete_metadata():
    for rule in RULE_REGISTRY.values():
        assert rule.id
        assert rule.name
        assert rule.category
        assert rule.severity
        info = rule().info()
        assert info.rule_id == rule.id


def test_rule_ids_are_unique():
    ids = [rule.id for rule in RULE_REGISTRY.values()]
    assert len(ids) == len(set(ids))


def test_catalog_is_serialisable():
    catalog = rule_catalog()
    assert catalog
    for info in catalog:
        data = info.to_dict()
        assert "rule_id" in data and "severity" in data


def test_deprecated_function_is_reported(tmp_path):
    result = analyse(
        """
        #include <string.h>
        void f(char *dst, const char *src) { strcpy(dst, src); }
        """,
        tmp_path,
    )
    assert "QLT-DEPRECATED-001" in rule_ids(result)


def test_hardcoded_credential_is_reported(tmp_path):
    result = analyse(
        """
        void f(void) { const char *password = "hunter2"; }
        """,
        tmp_path,
    )
    assert "SEC-CRED-001" in rule_ids(result)


def test_command_injection_is_reported(tmp_path):
    result = analyse(
        """
        #include <stdlib.h>
        void f(const char *user) { system(user); }
        """,
        tmp_path,
    )
    assert "SEC-CMD-001" in rule_ids(result)


def test_format_string_is_reported(tmp_path):
    result = analyse(
        """
        #include <stdio.h>
        void f(const char *user) { printf(user); }
        """,
        tmp_path,
    )
    assert "SEC-FMT-001" in rule_ids(result)


def test_unused_variable_is_reported(tmp_path):
    result = analyse(
        """
        void f(void) { int unused_value = 42; }
        """,
        tmp_path,
    )
    assert "QLT-UNUSED-001" in rule_ids(result)


def test_goto_is_reported(tmp_path):
    result = analyse(
        """
        void f(int x) { if (x) goto end; end: return; }
        """,
        tmp_path,
    )
    assert "QLT-GOTO-001" in rule_ids(result)


def test_complexity_threshold_is_configurable(tmp_path):
    code = """
    int f(int a, int b, int c) {
        if (a > 0 && b > 0 && c > 0) { return 1; }
        if (a > 1 && b > 1 && c > 1) { return 2; }
        if (a > 2 && b > 2 && c > 2) { return 3; }
        if (a > 3 && b > 3 && c > 3) { return 4; }
        return 0;
    }
    """
    strict = analyse(code, tmp_path, max_cyclomatic_complexity=2)
    assert "QLT-COMPLEX-001" in rule_ids(strict)

    relaxed = analyse(code, tmp_path, max_cyclomatic_complexity=50)
    assert "QLT-COMPLEX-001" not in rule_ids(relaxed)


def test_disabled_rule_is_not_executed(tmp_path):
    result = analyse(
        "void f(void) { int unused_value = 42; }",
        tmp_path,
        disabled_rules=["QLT-UNUSED-001"],
    )
    assert "QLT-UNUSED-001" not in rule_ids(result)


def test_enabled_rule_only_runs_when_selected(tmp_path):
    result = analyse(
        "void f(void) { int unused_value = 42; }",
        tmp_path,
        enabled_rules=["QLT-UNUSED-001"],
    )
    assert "QLT-UNUSED-001" in rule_ids(result)


def test_inline_suppression_is_honoured(tmp_path):
    result = analyse(
        """
        void f(void) {
            int unused_value = 42; // sast:ignore QLT-UNUSED-001
        }
        """,
        tmp_path,
    )
    assert "QLT-UNUSED-001" not in rule_ids(result)


def test_analysis_produces_no_warnings_on_valid_code(tmp_path):
    result = analyse(
        """
        int add(int a, int b) { return a + b; }
        """,
        tmp_path,
    )
    assert result.warnings == []
    assert result.files_scanned == 1


def test_result_exposes_severity_buckets(tmp_path):
    result = analyse("void f(void) { int unused_value = 1; }", tmp_path)
    buckets = result.by_severity()
    assert buckets
    assert result.count_by_severity()["low"] >= 1
    assert result.risk_score > 0


def test_result_filtering(tmp_path):
    result = analyse("void f(void) { int unused_value = 1; }", tmp_path)
    filtered = result.filter(severities=[result.violations[0].severity])
    assert len(filtered.violations) <= len(result.violations)
