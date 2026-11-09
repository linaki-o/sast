"""Tests for the requirements traceability engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sast.core.config import AnalysisConfig, Project
from sast.traceability import (
    Requirement,
    RequirementSet,
    TraceLink,
    TraceabilityMatrix,
    build_matrix,
    load_requirements,
    load_requirements_from_paths,
    to_csv,
    to_html,
    to_json,
    write_reports,
)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_yaml_requirements_are_loaded(tmp_path):
    path = write(
        tmp_path / "reqs.yaml",
        """
requirements:
  - id: REQ-001
    title: first
    description: the first requirement
    priority: high
    status: approved
    tags: [alpha, beta]
  - id: REQ-002
    title: second
""",
    )
    requirements = load_requirements(path)
    assert len(requirements) == 2
    first = requirements.get("REQ-001")
    assert first is not None
    assert first.title == "first"
    assert first.priority == "high"
    assert first.tags == ["alpha", "beta"]


def test_csv_requirements_are_loaded(tmp_path):
    path = write(
        tmp_path / "reqs.csv",
        "id,title,description,priority\n"
        "REQ-001,First,the first,high\n"
        "REQ-002,Second,the second,low\n",
    )
    requirements = load_requirements(path)
    assert len(requirements) == 2
    assert requirements.get("REQ-002").priority == "low"


def test_markdown_requirements_are_loaded(tmp_path):
    path = write(
        tmp_path / "reqs.md",
        "# Title\n\n"
        "### REQ-001 The first requirement\n\n"
        "A description of the first requirement.\n\n"
        "- **Priority**: high\n\n"
        "### REQ-002 The second requirement\n\n"
        "A description of the second requirement.\n",
    )
    requirements = load_requirements(path)
    assert len(requirements) == 2
    assert requirements.get("REQ-001").priority == "high"


def test_json_requirements_are_loaded(tmp_path):
    path = tmp_path / "reqs.json"
    path.write_text(
        json.dumps({"requirements": [{"id": "REQ-001", "title": "one"}]}),
        encoding="utf-8",
    )
    requirements = load_requirements(path)
    assert len(requirements) == 1


def test_malformed_rows_are_skipped_with_a_warning(tmp_path):
    path = write(
        tmp_path / "reqs.csv",
        "id,title\n"
        "REQ-001,First\n"
        ",NoIdentifier\n",
    )
    requirements = load_requirements(path)
    assert len(requirements) == 1
    assert requirements.warnings


def test_requirement_set_filters():
    requirements = RequirementSet(
        [
            Requirement(id="REQ-001", priority="high", category="security"),
            Requirement(id="REQ-002", priority="low", category="quality"),
        ]
    )
    high = requirements.filter(priority="high")
    assert len(high) == 1
    assert "REQ-001" in high
    assert len(requirements.filter(category="quality")) == 1


def test_matrix_tracks_links_and_gaps():
    requirements = RequirementSet(
        [
            Requirement(id="REQ-001", title="alpha"),
            Requirement(id="REQ-002", title="beta"),
        ]
    )
    matrix = TraceabilityMatrix(
        requirements,
        [TraceLink(requirement_id="REQ-001", target_kind="test", target_id="T1")],
    )
    assert matrix.cell("REQ-001").covered
    assert not matrix.cell("REQ-002").covered
    assert matrix.coverage_percentage == 50.0
    assert len(matrix.gaps()) == 1


def test_build_matrix_links_tests_by_requirement_id(tmp_path):
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "calc.c").write_text("int add(int a, int b) { return a + b; }", encoding="utf-8")
    (tmp_path / "reqs.yaml").write_text(
        "requirements:\n"
        "  - id: REQ-001\n"
        "    title: add two numbers\n"
        "    metadata:\n"
        "      function: add\n",
        encoding="utf-8",
    )
    config = AnalysisConfig(source_dirs=["src"], requirements_files=["reqs.yaml"])
    project = Project(root=tmp_path, config=config)
    requirements = load_requirements_from_paths([str(tmp_path / "reqs.yaml")])

    from sast.testing import TestCase

    matrix = build_matrix(
        project,
        requirements,
        test_suites=[TestCase(id="T1", name="add", target="add", requirement_ids=["REQ-001"])],
    )
    cell = matrix.cell("REQ-001")
    assert cell.covered
    assert "T1" in cell.tests


def test_reports_are_written(tmp_path):
    requirements = RequirementSet([Requirement(id="REQ-001", title="alpha")])
    matrix = TraceabilityMatrix(requirements, [])
    csv_text = to_csv(matrix)
    assert "REQ-001" in csv_text
    assert json.loads(to_json(matrix))["total_requirements"] == 1
    html = to_html(matrix)
    assert "REQ-001" in html
    written = write_reports(matrix, tmp_path)
    assert len(written) == 3
    for path in written:
        assert path.exists()
