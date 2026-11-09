"""Tests for the benchmark suite.

The benchmark doubles as a regression test: the recall on the planted
defects must not drop and the manifest of the corpus must stay stable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytest.importorskip("yaml")

from benchmarks.run_bench import (  # noqa: E402
    CORPUS,
    collect_expectations,
    load_manifest,
    measure_accuracy,
)


@pytest.fixture(scope="module")
def accuracy():
    return measure_accuracy(CORPUS, CORPUS)


def test_the_corpus_contains_planted_defects():
    expectations = collect_expectations(CORPUS)
    assert len(expectations) >= 25
    rules = {expectation.rule_id for expectation in expectations}
    assert len(rules) >= 15


def test_every_planted_defect_is_detected(accuracy):
    assert accuracy.missed == [], f"missed: {accuracy.missed}"
    assert accuracy.recall == 100.0


def test_the_manifest_is_complete(accuracy):
    assert accuracy.manifest_expected >= 50
    assert accuracy.manifest_detected == accuracy.manifest_expected


def test_no_rule_raises_on_the_corpus(accuracy):
    from sast.core.config import AnalysisConfig, Project
    from sast.rules.engine import RuleEngine

    config = AnalysisConfig(source_dirs=["."])
    project = Project(root=CORPUS, config=config)
    result = RuleEngine(project).analyze()
    assert result.warnings == []


def test_the_clean_file_produces_no_security_finding(accuracy):
    for path, line, rule_id in accuracy.false_positives:
        if path == "clean.c":
            assert not rule_id.startswith("SEC-"), f"{rule_id} on clean code"


def test_the_manifest_lists_known_rules_only():
    from sast.rules.base import RULE_REGISTRY
    import sast.rules.builtin  # noqa: F401

    known = set(RULE_REGISTRY)
    for _path, _line, rule_id in load_manifest(CORPUS):
        assert rule_id in known


def test_the_planted_defects_are_part_of_the_manifest():
    from benchmarks.run_bench import build_scopes, covering_scope

    manifest = load_manifest(CORPUS)
    scopes = build_scopes(CORPUS)
    manifest_set = set(manifest)
    for expectation in collect_expectations(CORPUS):
        if (expectation.path, expectation.line, expectation.rule_id) in manifest_set:
            continue
        scope = covering_scope(scopes, expectation.path, expectation.line)
        covered = scope is not None and any(
            path == expectation.path
            and rule_id == expectation.rule_id
            and scope.start <= line <= scope.end
            for path, line, rule_id in manifest
        )
        assert covered, f"{expectation.rule_id} at {expectation.path}:{expectation.line} is not pinned"


def test_the_benchmark_throughput_is_acceptable():
    """A rough guard so that a performance regression is noticed."""
    import time

    from sast.core.config import AnalysisConfig, Project
    from sast.rules.engine import RuleEngine

    config = AnalysisConfig(source_dirs=["."])
    project = Project(root=CORPUS, config=config)
    engine = RuleEngine(project)
    started = time.perf_counter()
    result = engine.analyze()
    elapsed = time.perf_counter() - started
    assert result.lines_scanned > 0
    assert elapsed < 10.0, f"the analysis of the corpus took {elapsed:.1f}s"
    assert result.lines_scanned / elapsed > 1000.0
