"""Tests for the report renderers."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sast.core.models import AnalysisResult, FileMetrics, Severity, SourceLocation, Violation
from sast.report import RENDERERS, render, render_all


@pytest.fixture()
def result() -> AnalysisResult:
    violations = [
        Violation(
            rule_id="SEC-BUF-001",
            rule_name="Unbounded string copy",
            severity=Severity.HIGH,
            message="strcpy may overflow the destination",
            location=SourceLocation("src/main.c", 42, 5),
            category="security",
            function="copy",
            snippet="strcpy(dst, src);",
            recommendation="Use strncpy with an explicit size.",
            cwe=(120,),
            standards=("MISRA C:2012 Rule 21.6",),
        ),
        Violation(
            rule_id="QLT-GOTO-001",
            rule_name="Use of goto",
            severity=Severity.LOW,
            message="goto jumps inside the function",
            location=SourceLocation("src/main.c", 60, 3),
            category="quality",
            function="copy",
        ),
        Violation(
            rule_id="QLT-UNUSED-001",
            rule_name="Unused local variable",
            severity=Severity.INFO,
            message="'unused' is never used",
            location=SourceLocation("src/other.c", 10, 1),
            category="quality",
        ),
    ]
    return AnalysisResult(
        project="demo",
        violations=violations,
        file_metrics=[FileMetrics(path="src/main.c", lines_total=100, lines_code=70)],
        files_scanned=2,
        lines_scanned=180,
        rules_executed=50,
        duration_seconds=0.42,
    )


def test_every_format_is_registered():
    assert set(RENDERERS) == {"json", "sarif", "xml", "html"}


def test_json_report_is_valid(result, tmp_path):
    paths = render_all(result, ["json"], tmp_path)
    assert paths
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data["project"] == "demo"
    assert len(data["violations"]) == 3
    assert "summary" in data


def test_sarif_report_is_valid(result, tmp_path):
    paths = render_all(result, ["sarif"], tmp_path)
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert len(run["results"]) == 3
    first = run["results"][0]
    assert first["ruleId"]
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"]


def test_xml_report_is_well_formed(result, tmp_path):
    paths = render_all(result, ["xml"], tmp_path)
    root = ET.parse(paths[0]).getroot()
    assert root.tag == "CodeShieldReport"
    violations = root.findall(".//violation")
    assert len(violations) == 3


def test_html_report_contains_the_findings(result, tmp_path):
    paths = render_all(result, ["html"], tmp_path)
    html = paths[0].read_text(encoding="utf-8")
    assert "SEC-BUF-001" in html
    assert "QLT-GOTO-001" in html
    assert "http://" not in html.replace("http://www.w3.org", "")
    assert "<script" not in html or "src=" not in html


def test_render_dispatches_on_format(result, tmp_path):
    for fmt in RENDERERS:
        paths = render(result, fmt, tmp_path)
        assert paths and paths[0].exists()


def test_unknown_format_raises(result, tmp_path):
    with pytest.raises(ValueError):
        render(result, "docx", tmp_path)


def test_empty_result_renders(result, tmp_path):
    empty = AnalysisResult(project="empty")
    for fmt in RENDERERS:
        paths = render(empty, fmt, tmp_path)
        assert paths and paths[0].exists()


def test_html_theme_switches(result, tmp_path):
    dark = render(result, "html", tmp_path / "dark", theme="dark")[0].read_text(encoding="utf-8")
    light = render(result, "html", tmp_path / "light", theme="light")[0].read_text(encoding="utf-8")
    assert dark != light
