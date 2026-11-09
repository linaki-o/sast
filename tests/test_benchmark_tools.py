"""Tests for the cross tool comparison of the benchmark."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from benchmarks.engines import (
    ClangTidyEngine,
    CodeShieldEngine,
    CppcheckEngine,
    available_engines,
)
from benchmarks.engines.base import Engine, EngineResult, Finding
from benchmarks.mapping import (
    CODESHIELD_TO_DEFECT,
    DEFECTS,
    applicable_defects,
    defect_of,
    tool_rules,
)
from benchmarks.run_bench import CORPUS, compare_engines

pytestmark = pytest.mark.skipif(
    not (shutil.which("cppcheck") or shutil.which("clang-tidy")),
    reason="no external analyser is installed",
)


def test_every_canonical_defect_has_a_description():
    for defect, entry in DEFECTS.items():
        assert entry.get("description"), defect
        assert "codeshield" in entry


def test_the_rule_ids_of_the_canonicals_are_unique():
    seen: dict[str, str] = {}
    for defect, entry in DEFECTS.items():
        for rule_id in entry.get("codeshield") or set():
            assert rule_id not in seen, f"{rule_id} maps to {seen[rule_id]} and {defect}"
            seen[rule_id] = defect


def test_the_reverse_mapping_is_consistent():
    for rule_id, defect in CODESHIELD_TO_DEFECT.items():
        assert rule_id in tool_rules(defect, "codeshield")
        assert defect_of(rule_id) == defect


def test_the_planted_defects_all_have_a_canonical_counterpart():
    from benchmarks.run_bench import collect_expectations

    for expectation in collect_expectations(CORPUS):
        assert defect_of(expectation.rule_id) is not None, expectation.rule_id


def test_applicable_defects_differ_per_tool():
    codeshield = applicable_defects("codeshield")
    cppcheck = applicable_defects("cppcheck")
    clang_tidy = applicable_defects("clang-tidy")
    assert len(codeshield) == len(DEFECTS)
    assert set(cppcheck) < set(codeshield)
    assert set(clang_tidy) < set(codeshield)


def test_the_codeshield_engine_reports_the_planted_defects():
    engine = CodeShieldEngine(CORPUS)
    result = engine.run(sorted(CORPUS.glob("*.c")) + sorted(CORPUS.glob("*.cpp")))
    assert result.available
    assert result.findings
    assert result.seconds > 0
    rules = {finding.rule_id for finding in result.findings}
    assert "SEC-BUF-001" in rules


def test_the_engines_report_their_absence_gracefully():
    class Missing(Engine):
        name = "missing"
        executable = "a-tool-that-does-not-exist"

    engine = Missing(CORPUS)
    assert not engine.available()
    result = engine.run([])
    assert not result.available
    assert result.reason


def test_the_comparison_scores_every_available_engine():
    scores = compare_engines(CORPUS)
    names = {score.engine for score in scores}
    assert "CodeShield" in names
    assert "Cppcheck" in names
    assert "Clang-Tidy" in names

    for score in scores:
        if not score.available:
            assert score.reason
            continue
        assert score.applicable > 0
        assert 0 <= score.detected <= score.applicable
        assert score.total_findings >= score.mapped_findings
        assert score.seconds >= 0


def test_the_codeshield_engine_detects_every_planted_defect():
    scores = compare_engines(CORPUS, [CodeShieldEngine(CORPUS)])
    assert len(scores) == 1
    score = scores[0]
    assert score.applicable == score.detected
    assert score.recall == 100.0


@pytest.mark.skipif(not shutil.which("cppcheck"), reason="cppcheck is not installed")
def test_cppcheck_actually_runs():
    engine = CppcheckEngine(CORPUS)
    assert engine.available()
    result = engine.run([CORPUS / "quality.c"])
    assert result.available
    assert result.findings
    assert all(isinstance(finding, Finding) for finding in result.findings)
    assert any(finding.rule_id == "shadowVariable" for finding in result.findings)


@pytest.mark.skipif(not shutil.which("clang-tidy"), reason="clang-tidy is not installed")
def test_clang_tidy_actually_runs():
    engine = ClangTidyEngine(CORPUS)
    assert engine.available()
    result = engine.run([CORPUS / "quality.c"])
    assert result.available
    assert result.findings
    assert any(
        finding.rule_id == "bugprone-assignment-in-if-condition"
        for finding in result.findings
    )


def test_the_available_engines_are_listed():
    engines = available_engines(CORPUS)
    assert len(engines) == 3
    for engine in engines:
        assert isinstance(engine, Engine)
