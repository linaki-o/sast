"""Tests for the unit test runtime, the C interpreter and the coverage model."""

from __future__ import annotations

from pathlib import Path

import pytest

from sast.core.config import AnalysisConfig, Project
from sast.testing import (
    CoverageCollector,
    CoverageReport,
    TestCase,
    TestRunner,
    TestSuite,
    discover_suites,
    load_suites_from_paths,
)

SAMPLE = """
int add(int a, int b)
{
    return a + b;
}

int divide(int a, int b)
{
    if (b == 0) {
        return 0;
    }
    return a / b;
}

void fill(char *buffer, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        buffer[i] = 'x';
    }
}
"""


@pytest.fixture()
def c_project(tmp_path: Path) -> Project:
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "math.c").write_text(SAMPLE, encoding="utf-8")
    config = AnalysisConfig(source_dirs=["src"], test_dirs=["tests"])
    return Project(root=tmp_path, config=config)


def suite(*tests: TestCase) -> TestSuite:
    return TestSuite(name="math", source_files=["src/math.c"], tests=list(tests))


def test_interpreter_computes_arithmetic(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(TestCase(id="T1", name="add", target="add", params=[2, 3], expected=5))
    )
    assert len(result.results) == 1
    assert result.results[0].passed
    assert result.passed
    assert result.pass_rate == 100.0


def test_failing_expectation_is_reported(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(TestCase(id="T1", name="add", target="add", params=[2, 3], expected=99))
    )
    assert not result.results[0].passed
    assert "expected" in result.results[0].message


def test_unknown_function_is_reported_as_a_failure(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(TestCase(id="T1", name="missing", target="does_not_exist"))
    )
    assert not result.results[0].passed
    assert result.results[0].message


def test_branch_protection_is_covered(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(
            TestCase(id="T1", name="zero", target="divide", params=[1, 0], expected=0),
            TestCase(id="T2", name="nonzero", target="divide", params=[6, 3], expected=2),
        )
    )
    assert all(item.passed for item in result.results)
    assert result.coverage is not None
    assert result.coverage.branch_coverage > 0


def test_coverage_report_exposes_percentages(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(TestCase(id="T1", name="add", target="add", params=[1, 1], expected=2))
    )
    coverage = result.coverage
    assert isinstance(coverage, CoverageReport)
    assert 0 <= coverage.statement_coverage <= 100
    assert 0 <= coverage.branch_coverage <= 100
    assert 0 <= coverage.condition_coverage <= 100
    assert coverage.total_lines >= 0


def test_out_parameters_are_written_back(c_project):
    runner = TestRunner(c_project, engine="interpreter")
    result = runner.run_suite(
        suite(
            TestCase(
                id="T1",
                name="fill",
                target="fill",
                params=["&buffer", 3],
                setup=["char buffer[8];"],
                assert_expr="buffer[0] == 'x' && buffer[2] == 'x'",
            )
        )
    )
    assert result.results[0].passed, result.results[0].message


def test_collector_merges_hits():
    collector = CoverageCollector()
    collector.hit_statement("a.c", 1)
    collector.hit_statement("a.c", 1)
    collector.hit_statement("a.c", 2)
    collector.hit_branch("a.c", 3, "if:1")
    other = CoverageCollector()
    other.hit_statement("a.c", 1)
    collector.merge(other)
    report = collector.report()
    assert report.covered_lines >= 2


def test_suite_discovery_and_loading(c_project, tmp_path):
    tests_dir = c_project.root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "test_math.py").write_text(
        "from sast.testing import TestCase, TestSuite\n"
        "SUITES = [TestSuite(name='math', source_files=['src/math.c'], tests=[\n"
        "    TestCase(id='T1', name='add', target='add', params=[1, 2], expected=3),\n"
        "])]\n",
        encoding="utf-8",
    )
    suites = discover_suites(c_project)
    assert len(suites) == 1
    assert suites[0].tests[0].target == "add"
    loaded = load_suites_from_paths([str(tests_dir / "test_math.py")])
    assert len(loaded) == 1


def test_suite_can_be_loaded_from_json(c_project, tmp_path):
    import json

    path = tmp_path / "math_test.json"
    path.write_text(
        json.dumps(
            {
                "name": "math",
                "source_files": ["src/math.c"],
                "tests": [
                    {"id": "T1", "name": "add", "target": "add", "params": [1, 2], "expected": 3}
                ],
            }
        ),
        encoding="utf-8",
    )
    suites = load_suites_from_paths([path])
    assert len(suites) == 1
    assert suites[0].tests[0].expected == 3


def test_example_project_suite_passes():
    root = Path(__file__).resolve().parent.parent / "examples" / "sample_project"
    from sast.core.config import load_project

    project = load_project(root)
    suites = discover_suites(project)
    assert suites
    runner = TestRunner(project, engine="interpreter")
    result = runner.run_suite(suites[0])
    assert result.passed
    assert result.coverage.statement_coverage > 0
