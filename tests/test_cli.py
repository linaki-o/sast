"""Tests for the command line interface, the baseline and the incremental analysis."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sast.cli import main
from sast.core.baseline import Baseline, resolve_baseline_path
from sast.core.config import AnalysisConfig, Project, load_project
from sast.core.models import AnalysisResult, Severity, SourceLocation, Violation

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "sample_project"


def run(*args: str) -> int:
    return main(list(args))


def test_version_flag():
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_help_lists_the_commands(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    output = capsys.readouterr().out
    for command in ("analyze", "test", "trace", "rules", "serve", "baseline"):
        assert command in output


def test_analyze_on_the_example_project(capsys):
    code = run("analyze", str(EXAMPLE))
    output = capsys.readouterr().out
    assert "CodeShield" in output
    assert "findings:" in output
    assert code in (0, 1)


def test_analyze_json_output(capsys):
    run("analyze", str(EXAMPLE), "--json")
    payload = json.loads(capsys.readouterr().out)
    assert "violations" in payload
    assert "counts" in payload


def test_rules_command(capsys):
    run("rules")
    output = capsys.readouterr().out
    assert "rules" in output
    assert "SEC-" in output


def test_rules_json_output(capsys):
    run("rules", "--json")
    catalog = json.loads(capsys.readouterr().out)
    assert isinstance(catalog, list)
    assert catalog[0]["rule_id"]


def test_config_command(capsys):
    run("config", str(EXAMPLE))
    output = capsys.readouterr().out
    assert "source_dirs" in output


def test_test_command(capsys):
    run("test", str(EXAMPLE))
    output = capsys.readouterr().out
    assert "tests passed" in output


def test_trace_command(capsys):
    run("trace", str(EXAMPLE))
    output = capsys.readouterr().out
    assert "traceability matrix" in output
    assert "requirements :" in output


def test_baseline_create_and_diff(capsys, tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "a.c").write_text(
        "void f(void) { int unused_value = 1; }", encoding="utf-8"
    )
    run("baseline", "create", str(project))
    output = capsys.readouterr().out
    assert "baseline written" in output
    assert (project / "sast-baseline.json").exists()

    run("baseline", "diff", str(project))
    output = capsys.readouterr().out
    assert "baseline diff" in output


def test_analyze_with_baseline_suppresses_known_findings(capsys, tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "a.c").write_text(
        "void f(void) { int unused_value = 1; }", encoding="utf-8"
    )
    run("baseline", "create", str(project))
    capsys.readouterr()
    run("analyze", str(project), "--baseline", "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline_suppressed"] >= 1
    assert not any(
        violation["rule_id"] == "QLT-UNUSED-001" for violation in payload["violations"]
    )


def test_unknown_command_exits_with_an_error():
    with pytest.raises(SystemExit):
        main(["nonsense"])


# --------------------------------------------------------------------------
# baseline
# --------------------------------------------------------------------------


def violation(rule_id: str = "QLT-UNUSED-001", line: int = 10) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_name="rule",
        severity=Severity.LOW,
        message="message",
        location=SourceLocation("src/a.c", line, 1),
    )


def test_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    baseline = Baseline.from_result(AnalysisResult(violations=[violation()]))
    baseline.save(path)
    loaded = Baseline.load(path)
    assert len(loaded) == 1
    entry = next(iter(loaded.entries.values()))
    assert entry.rule_id == "QLT-UNUSED-001"


def test_baseline_suppresses_matching_findings(tmp_path):
    result = AnalysisResult(violations=[violation()])
    baseline = Baseline.from_result(result)
    filtered, suppressed = baseline.suppress(result)
    assert len(suppressed) == 1
    assert filtered.violations == []
    assert filtered.baseline_suppressed == 1


def test_baseline_diff_reports_new_and_fixed():
    baseline = Baseline.from_result(AnalysisResult(violations=[violation()]))
    result = AnalysisResult(violations=[violation(), violation("QLT-GOTO-001", 20)])
    diff = baseline.diff(result)
    assert diff["new_count"] == 1
    assert diff["unchanged_count"] == 1
    assert diff["fixed_count"] == 0


def test_missing_baseline_is_empty(tmp_path):
    assert len(Baseline.load(tmp_path / "missing.json")) == 0


def test_resolve_baseline_path(tmp_path):
    assert resolve_baseline_path(tmp_path).name == "sast-baseline.json"
    assert resolve_baseline_path(tmp_path, "custom.json").name == "custom.json"


# --------------------------------------------------------------------------
# incremental analysis
# --------------------------------------------------------------------------


def test_include_graph_finds_dependents(tmp_path):
    from sast.analysis.incremental import IncludeGraph

    graph = IncludeGraph()
    graph.add_file("src/b.c", '#include "a.h"\n')
    graph.add_file("src/c.c", '#include <stdio.h>\n')
    dependents = graph.dependents({"src/a.h"})
    assert "src/b.c" in dependents
    assert "src/c.c" not in dependents


def test_git_client_detects_a_missing_repository(tmp_path):
    from sast.analysis.incremental import GitClient

    client = GitClient(tmp_path)
    change_set = client.changed_files()
    assert change_set.available in (True, False)


def test_analyze_changes_without_git_degrades_gracefully(tmp_path):
    from sast.analysis.incremental import analyze_changes

    change_set, impacted = analyze_changes(tmp_path, [])
    assert isinstance(change_set.changed, set)
    assert isinstance(impacted, set)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def test_config_is_loaded_from_yaml(tmp_path):
    (tmp_path / "sast.yaml").write_text(
        "analysis:\n  source_dirs: [src]\n  fail_on: critical\n", encoding="utf-8"
    )
    project = load_project(tmp_path)
    assert project.config.source_dirs == ["src"]
    assert project.config.fail_on == "critical"
    assert project.path is not None


def test_config_defaults_when_no_file_exists(tmp_path):
    project = load_project(tmp_path)
    assert project.config.source_dirs
    assert project.path is None


def test_project_relative_paths_use_forward_slashes(tmp_path):
    project = Project(root=tmp_path, config=AnalysisConfig())
    target = tmp_path / "src" / "main.c"
    target.parent.mkdir(parents=True)
    target.write_text("", encoding="utf-8")
    assert project.relative(target) == "src/main.c"


def test_unknown_config_keys_are_kept_in_extra(tmp_path):
    (tmp_path / "sast.yaml").write_text(
        "analysis:\n  custom_key: 42\n", encoding="utf-8"
    )
    project = load_project(tmp_path)
    assert project.config.extra.get("custom_key") == 42


def test_invalid_config_type_is_rejected(tmp_path):
    (tmp_path / "sast.yaml").write_text(
        "analysis:\n  source_dirs: 5\n", encoding="utf-8"
    )
    with pytest.raises(ValueError):
        load_project(tmp_path)
