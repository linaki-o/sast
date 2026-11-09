"""The ``sast`` command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from sast import __version__
from sast.core.config import Project, load_project
from sast.core.models import AnalysisResult, Severity

# --------------------------------------------------------------------------
# terminal helpers
# --------------------------------------------------------------------------

_COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[1;30m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
}


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *styles: str) -> str:
    if not _use_color() or not styles:
        return text
    prefix = "".join(_COLORS.get(style, "") for style in styles)
    return f"{prefix}{text}{_COLORS['reset']}"


def _severity_style(severity: str) -> str:
    return severity if severity in _COLORS else "info"


def _print(message: str = "") -> None:
    print(message)


def _rule(char: str = "-", width: int = 72) -> str:
    return char * width


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def _load_project(args: argparse.Namespace) -> Project:
    root = getattr(args, "path", None) or getattr(args, "root", None) or "."
    return load_project(root, getattr(args, "config", None))


def _apply_rule_selection(project: Project, args: argparse.Namespace) -> None:
    config = project.config
    if getattr(args, "enable", None):
        config.enabled_rules.extend(args.enable)
    if getattr(args, "disable", None):
        config.disabled_rules.extend(args.disable)
    if getattr(args, "category", None):
        config.categories.extend(args.category)
    if getattr(args, "severity", None):
        config.severity_threshold = args.severity
    if getattr(args, "format", None):
        config.report_formats = list(args.format)


def cmd_analyze(args: argparse.Namespace) -> int:
    from sast.core.baseline import Baseline, resolve_baseline_path
    from sast.rules.engine import RuleEngine
    from sast.rules.builtin import security, quality  # noqa: F401

    project = _load_project(args)
    _apply_rule_selection(project, args)

    if getattr(args, "incremental", False):
        from sast.analysis.incremental import analyze_changes
        from sast.rules.engine import AnalysisOptions

        client_files = RuleEngine(project).discover_files()
        change_set, impacted = analyze_changes(
            project.root,
            client_files,
            getattr(args, "base", "HEAD"),
            getattr(args, "target", "WORKTREE"),
            project.relative,
        )
        if not change_set.available:
            _print(_paint(f"incremental analysis unavailable: {change_set.message}", "yellow"))
        else:
            _print(
                f"changed files: {len(change_set.changed)}, "
                f"impacted files: {len(impacted)}"
            )
        engine = RuleEngine(
            project,
            options=AnalysisOptions(
                changed_files_only=True,
                changed_files=impacted,
            ),
        )
    else:
        engine = RuleEngine(project)

    result = engine.analyze()
    result.tool_version = __version__

    baseline = None
    if getattr(args, "baseline", None):
        path = resolve_baseline_path(project.root, args.baseline)
        baseline = Baseline.load(path)
        result, suppressed = baseline.suppress(result)
        result.baseline_suppressed = len(suppressed)
        result.new_violations = len(result.violations)

    if getattr(args, "json", False):
        _print(result.to_json())
        return _exit_code(result, project)

    _print_report(result, project, args)
    return _exit_code(result, project)


def _exit_code(result: AnalysisResult, project: Project) -> int:
    threshold = project.config.fail_on
    if threshold == "never":
        return 0
    limit = Severity.parse(threshold)
    for violation in result.violations:
        if violation.severity.rank <= limit.rank:
            return 1
    return 0


def _print_report(result: AnalysisResult, project: Project, args: argparse.Namespace) -> None:
    counts = result.count_by_severity()
    _print()
    _print(_paint(f"CodeShield {__version__} - {result.project}", "bold"))
    _print(_rule())
    _print(
        f"scanned {result.files_scanned} files / {result.lines_scanned} lines "
        f"with {result.rules_executed} rules in {result.duration_seconds:.2f}s"
    )
    if result.warnings:
        _print(_paint(f"{len(result.warnings)} warning(s):", "yellow"))
        for warning in result.warnings[:5]:
            _print(_paint(f"  ! {warning}", "yellow"))

    total = len(result.violations)
    _print()
    _print(
        f"findings: {total}  "
        + "  ".join(
            f"{_paint(severity, _severity_style(severity))}={counts.get(severity, 0)}"
            for severity in ("critical", "high", "medium", "low", "info")
        )
    )

    if result.violations:
        _print()
        limit = getattr(args, "max_findings", 0) or 50
        for violation in result.sorted_violations()[:limit]:
            style = _severity_style(violation.severity.value)
            location = f"{violation.location.file}:{violation.location.line}"
            _print(
                f"  {_paint(violation.severity.value.upper(), style)} "
                f"{_paint(violation.rule_id, 'dim')} {location}"
            )
            _print(f"      {violation.message}")
            if violation.recommendation:
                _print(_paint(f"      -> {violation.recommendation}", "dim"))
        if total > limit:
            _print(_paint(f"  ... and {total - limit} more", "dim"))

    if result.passed:
        _print()
        _print(_paint("quality gate: PASS", "green"))
    else:
        _print()
        _print(_paint("quality gate: FAIL", "red"))

    formats = getattr(args, "format", None) or project.config.report_formats
    if formats and not getattr(args, "no_report", False):
        from sast.report import render_all

        output = project.report_dir()
        try:
            written = render_all(
                result,
                formats,
                output,
                project=project.name,
                theme=project.config.html_theme,
            )
            _print()
            _print("reports:")
            for path in written:
                _print(f"  {path}")
        except Exception as error:  # pragma: no cover - defensive
            _paint(f"report generation failed: {error}", "red")


def cmd_test(args: argparse.Namespace) -> int:
    from sast.testing import TestRunner, discover_suites, load_suites_from_paths

    project = _load_project(args)
    suites = []
    if getattr(args, "suite", None):
        suites = load_suites_from_paths(args.suite)
    else:
        suites = discover_suites(project)
    if not suites:
        _print(_paint("no test suites found", "yellow"))
        return 0

    runner = TestRunner(project, engine=getattr(args, "engine", "auto"))
    started = time.perf_counter()
    total = passed = 0
    for suite in suites:
        result = runner.run_suite(suite)
        total += len(result.results)
        passed += sum(1 for item in result.results if item.passed)
        _print()
        _print(_paint(f"{suite.name}", "bold"))
        for item in result.results:
            style = "green" if item.passed else "red"
            mark = "PASS" if item.passed else "FAIL"
            _print(f"  {_paint(mark, style)} {item.name} ({item.duration_ms:.1f} ms)")
            if not item.passed:
                _print(f"       {item.message}")
        if result.coverage is not None:
            _print(
                f"  coverage: statement {result.coverage.statement_coverage:.1f}%  "
                f"branch {result.coverage.branch_coverage:.1f}%  "
                f"condition {result.coverage.condition_coverage:.1f}%  "
                f"MC/DC {result.coverage.mc_dc_coverage:.1f}%"
            )
    _print()
    _print(
        f"{passed}/{total} tests passed in {time.perf_counter() - started:.2f}s"
    )
    if getattr(args, "json", False):
        _print(json.dumps([r.to_dict() for r in []], indent=2))
    return 0 if passed == total else 1


def cmd_trace(args: argparse.Namespace) -> int:
    from sast.traceability import build_matrix, load_requirements_from_paths, write_reports

    project = _load_project(args)
    paths = args.requirements or project.config.requirements_files
    if not paths:
        _print(_paint("no requirement files configured", "yellow"))
        return 0

    resolved = [str(project.resolve(path)) for path in paths]
    requirements = load_requirements_from_paths(resolved)
    matrix = build_matrix(project, requirements)
    written = write_reports(matrix, project.report_dir())
    _print()
    _print(_paint("traceability matrix", "bold"))
    _print(f"  requirements : {matrix.total_requirements}")
    _print(f"  coverage     : {matrix.coverage_percentage:.1f}%")
    gaps = matrix.gaps()
    _print(f"  uncovered    : {len(gaps)}")
    for gap in gaps[:10]:
        _print(_paint(f"    {gap.get('id', '')} {gap.get('title', '')}", "yellow"))
    for warning in getattr(requirements, "warnings", [])[:5]:
        _print(_paint(f"  ! {warning}", "yellow"))
    _print()
    for path in written:
        _print(f"  {path}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from sast.rules.base import rule_catalog
    from sast.rules.builtin import security, quality  # noqa: F401

    catalog = rule_catalog()
    if getattr(args, "category", None):
        wanted = set(args.category)
        catalog = [rule for rule in catalog if rule.category in wanted]
    if getattr(args, "json", False):
        _print(json.dumps([rule.to_dict() for rule in catalog], indent=2, ensure_ascii=False))
        return 0

    by_category: dict[str, list] = {}
    for rule in catalog:
        by_category.setdefault(rule.category, []).append(rule)

    _print()
    _print(_paint(f"{len(catalog)} rules", "bold"))
    for category in sorted(by_category):
        _print()
        _print(_paint(f"{category} ({len(by_category[category])})", "bold"))
        for rule in sorted(by_category[category], key=lambda r: r.rule_id):
            style = _severity_style(rule.severity.value)
            cwe = f" CWE-{','.join(str(c) for c in rule.cwe)}" if rule.cwe else ""
            _print(
                f"  {_paint(rule.severity.value, style).ljust(9)} "
                f"{rule.rule_id.ljust(16)} {rule.name}{cwe}"
            )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        _print(_paint("uvicorn is required: pip install 'sast[web]'", "red"))
        return 1
    from sast.server.app import create_app

    app = create_app(args.path)
    _print(_paint(f"CodeShield server on http://{args.host}:{args.port}", "green"))
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from sast.gui import run_gui
    except ImportError as error:
        _print(_paint(str(error), "red"))
        return 1
    run_gui(args.path)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    from sast.core.baseline import Baseline, resolve_baseline_path
    from sast.rules.engine import RuleEngine
    from sast.rules.builtin import security, quality  # noqa: F401

    project = _load_project(args)
    path = resolve_baseline_path(project.root, args.file)

    if args.baseline_action == "diff":
        baseline = Baseline.load(path)
        result = RuleEngine(project).analyze()
        diff = baseline.diff(result)
        _print()
        _print(_paint("baseline diff", "bold"))
        _print(f"  new      : {diff['new_count']}")
        _print(f"  fixed    : {diff['fixed_count']}")
        _print(f"  unchanged: {diff['unchanged_count']}")
        for item in diff["new"][:20]:
            _print(_paint(f"  + {item['rule_id']} {item['location']['file']}:{item['location']['line']}", "red"))
        for item in diff["fixed"][:20]:
            _print(_paint(f"  - {item['rule_id']} {item['file']}:{item['line']}", "green"))
        return 0

    result = RuleEngine(project).analyze()
    baseline = Baseline.from_result(result)
    baseline.created_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    written = baseline.save(path)
    _print(_paint(f"baseline written: {written} ({len(baseline)} findings)", "green"))
    return 0


def cmd_changes(args: argparse.Namespace) -> int:
    from sast.analysis.incremental import analyze_changes
    from sast.rules.engine import RuleEngine

    project = _load_project(args)
    files = RuleEngine(project).discover_files()
    change_set, impacted = analyze_changes(
        project.root, files, args.base, args.target, project.relative
    )
    if not change_set.available:
        _print(_paint(f"unavailable: {change_set.message}", "yellow"))
        return 1
    _print()
    _print(_paint("change impact", "bold"))
    _print(f"  changed  : {len(change_set.changed)}")
    _print(f"  added    : {len(change_set.added)}")
    _print(f"  modified : {len(change_set.modified)}")
    _print(f"  removed  : {len(change_set.removed)}")
    _print(f"  impacted : {len(impacted)}")
    for path in sorted(change_set.changed):
        _print(f"    {path}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Run the benchmark suite."""
    root = Path(__file__).resolve().parent.parent
    benchmarks = root / "benchmarks"
    if not benchmarks.is_dir():
        _print(_paint("the benchmark suite is not installed", "yellow"))
        return 1
    sys.path.insert(0, str(root))
    from benchmarks.run_bench import main as bench_main

    argv = ["--mode", args.mode]
    if args.repetitions:
        argv += ["--repetitions", str(args.repetitions)]
    if getattr(args, "sizes", None):
        argv += ["--sizes"] + [str(size) for size in args.sizes]
    if args.json:
        argv += ["--json", args.json]
    return bench_main(argv)


def cmd_config(args: argparse.Namespace) -> int:
    project = _load_project(args)
    _print()
    _print(_paint(f"project : {project.root}", "bold"))
    _print(f"config  : {project.path or '<defaults>'}")
    _print()
    for key, value in sorted(project.config.to_dict().items()):
        _print(f"  {key.ljust(24)} {value}")
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast",
        description="CodeShield - C/C++ static analysis, unit testing and traceability",
    )
    parser.add_argument("--version", action="version", version=f"CodeShield {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("path", nargs="?", default=".", help="project directory")
        sub.add_argument("-c", "--config", help="path to the configuration file")
        sub.add_argument("--json", action="store_true", help="machine readable output")

    # analyze
    analyze = subparsers.add_parser("analyze", help="run the static analysis")
    add_common(analyze)
    analyze.add_argument("-e", "--enable", action="append", help="enable a rule id")
    analyze.add_argument("-d", "--disable", action="append", help="disable a rule id")
    analyze.add_argument("-C", "--category", action="append", dest="category", help="rule category")
    analyze.add_argument("-s", "--severity", help="minimum severity to report")
    analyze.add_argument("-f", "--format", action="append", help="report format")
    analyze.add_argument(
        "--baseline",
        nargs="?",
        const="sast-baseline.json",
        default=None,
        help="suppress the findings recorded in the baseline",
    )
    analyze.add_argument("--no-report", action="store_true", help="do not write report files")
    analyze.add_argument("--incremental", action="store_true", help="only analyse changed files")
    analyze.add_argument("--base", default="HEAD", help="base ref for the incremental diff")
    analyze.add_argument("--target", default="WORKTREE", help="target ref for the incremental diff")
    analyze.add_argument("--max-findings", type=int, default=50)
    analyze.set_defaults(func=cmd_analyze)

    # test
    test = subparsers.add_parser("test", help="run the unit tests")
    add_common(test)
    test.add_argument("-s", "--suite", action="append", help="a test suite file")
    test.add_argument("--engine", default="auto", choices=["auto", "native", "interpreter"])
    test.set_defaults(func=cmd_test)

    # trace
    trace = subparsers.add_parser("trace", help="build the traceability matrix")
    add_common(trace)
    trace.add_argument("-r", "--requirements", action="append", help="requirement file")
    trace.set_defaults(func=cmd_trace)

    # rules
    rules = subparsers.add_parser("rules", help="list the available rules")
    rules.add_argument("--category", action="append", help="filter by category")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    # baseline
    baseline = subparsers.add_parser("baseline", help="manage the baseline")
    baseline.add_argument("baseline_action", choices=["create", "diff"])
    baseline.add_argument("path", nargs="?", default=".", help="project directory")
    baseline.add_argument("-c", "--config", help="path to the configuration file")
    baseline.add_argument("--json", action="store_true")
    baseline.add_argument("--file", help="baseline file")
    baseline.set_defaults(func=cmd_baseline)

    # changes
    changes = subparsers.add_parser("changes", help="show the change impact")
    add_common(changes)
    changes.add_argument("--base", default="HEAD")
    changes.add_argument("--target", default="WORKTREE")
    changes.set_defaults(func=cmd_changes)

    # config
    config = subparsers.add_parser("config", help="show the effective configuration")
    add_common(config)
    config.set_defaults(func=cmd_config)

    # bench
    bench = subparsers.add_parser("bench", help="run the benchmark suite")
    bench.add_argument(
        "--mode",
        choices=["all", "accuracy", "speed", "scale", "size", "profile", "compare"],
        default="all",
    )
    bench.add_argument("--repetitions", type=int, default=3)
    bench.add_argument("--sizes", type=int, nargs="*", default=[1, 2, 4, 8])
    bench.add_argument("--json", help="write the measurements to this file")
    bench.set_defaults(func=cmd_bench)

    # serve
    serve = subparsers.add_parser("serve", help="start the web dashboard")
    serve.add_argument("path", nargs="?", default=".")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    # gui
    gui = subparsers.add_parser("gui", help="start the desktop application")
    gui.add_argument("path", nargs="?", default=".")
    gui.set_defaults(func=cmd_gui)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        _print()
        _print(_paint("interrupted", "yellow"))
        return 130
    except FileNotFoundError as error:
        _print(_paint(f"error: {error}", "red"))
        return 2
    except Exception as error:  # pragma: no cover - defensive
        _print(_paint(f"error: {error}", "red"))
        if os.environ.get("SAST_DEBUG"):
            raise
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
