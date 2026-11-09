"""Benchmark harness for CodeShield.

The harness measures four things:

``accuracy``
    Recall and precision against the ``sast:expect`` annotations of the
    benchmark corpus.
``speed``
    Wall clock throughput on the corpus and on a synthetic project.
``scale``
    How the runtime grows when the project grows, which exposes rules with
    a super linear cost.
``profile``
    The time spent in each phase and in each rule.

Run it with::

    python -m benchmarks.run_bench
    python -m benchmarks.run_bench --mode all --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sast.core.config import AnalysisConfig, Project  # noqa: E402
from sast.rules.base import RULE_REGISTRY  # noqa: E402
from sast.rules.builtin import loops, quality, security, standards  # noqa: E402,F401
from sast.rules.engine import RuleEngine  # noqa: E402

CORPUS = ROOT / "benchmarks" / "corpus"
EXPECT_MARKER = "sast:expect"

try:
    from benchmarks.mapping import DEFECTS as _DEFECT_ENTRIES
except ImportError:  # pragma: no cover - the package is always present
    _DEFECT_ENTRIES = {}


# --------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Expectation:
    """A defect the tool is expected to report."""

    path: str
    line: int
    rule_id: str
    text: str = ""


def parse_expectations(source: str, path: str) -> list[Expectation]:
    """Read the ``sast:expect`` annotations of a source file."""
    expectations: list[Expectation] = []
    for number, line in enumerate(source.splitlines(), start=1):
        marker = line.find(EXPECT_MARKER)
        if marker < 0:
            continue
        rule_id = line[marker + len(EXPECT_MARKER) :].strip()
        rule_id = rule_id.split()[0] if rule_id.split() else ""
        if not rule_id or rule_id.startswith("<"):
            continue
        expectations.append(
            Expectation(path=path, line=number, rule_id=rule_id, text=line.strip())
        )
    return expectations


def collect_expectations(root: Path) -> list[Expectation]:
    """Every expectation of a corpus."""
    expectations: list[Expectation] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".c", ".h", ".cpp", ".cc", ".hpp"}:
            continue
        source = path.read_text(encoding="utf-8")
        expectations.extend(parse_expectations(source, path.relative_to(root).as_posix()))
    return expectations


# --------------------------------------------------------------------------
# Accuracy
# --------------------------------------------------------------------------


@dataclass
class AccuracyReport:
    """The result of comparing the findings with the ground truth.

    Two measurements are combined:

    ``recall``
        over the *planted* defects, the ones annotated inline with
        ``sast:expect``.  This measures whether the analyser finds the
        defects it is supposed to find.
    ``precision``
        over the whole *manifest*, the complete list of expected findings.
        A reported finding that is not in the manifest is a false positive.
    """

    expected: int = 0
    detected: int = 0
    manifest_expected: int = 0
    manifest_detected: int = 0
    missed: list[tuple[str, int, str]] = field(default_factory=list)
    false_positives: list[tuple[str, int, str]] = field(default_factory=list)
    per_rule: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        return (self.detected / self.expected * 100.0) if self.expected else 100.0

    @property
    def precision(self) -> float:
        if not self.manifest_expected:
            return 100.0
        return (self.manifest_detected / self.manifest_expected * 100.0)

    @property
    def f1(self) -> float:
        precision = self.precision / 100.0
        recall = self.recall / 100.0
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall) * 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "planted_expected": self.expected,
            "planted_detected": self.detected,
            "manifest_expected": self.manifest_expected,
            "manifest_detected": self.manifest_detected,
            "missed": [
                {"file": path, "line": line, "rule_id": rule}
                for path, line, rule in self.missed
            ],
            "false_positives": [
                {"file": path, "line": line, "rule_id": rule}
                for path, line, rule in self.false_positives
            ],
            "recall": round(self.recall, 2),
            "precision": round(self.precision, 2),
            "f1": round(self.f1, 2),
            "per_rule": self.per_rule,
        }


def load_manifest(corpus: Path) -> list[tuple[str, int, str]]:
    """The expected findings of the corpus, read from the manifest."""
    path = corpus / "manifest.yaml"
    if not path.is_file():
        return []
    try:
        import yaml

        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    entries = []
    for item in document.get("expectations", []) or []:
        try:
            entries.append(
                (str(item["file"]), int(item["line"]), str(item["rule"]))
            )
        except (KeyError, TypeError, ValueError):
            continue
    return entries


@dataclass
class Scope:
    """The range of source lines a function covers."""

    name: str
    start: int
    end: int


def build_scopes(root: Path) -> dict[str, list[Scope]]:
    """Map every corpus file to the functions it declares."""
    from sast.ast.nodes import FunctionDecl
    from sast.ast.parser import parse_file

    scopes: dict[str, list[Scope]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".c", ".h", ".cpp", ".cc", ".hpp"}:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            unit, _errors = parse_file(path)
        except Exception:
            scopes[relative] = []
            continue
        entries: list[Scope] = []
        for node in unit.walk():
            if not isinstance(node, FunctionDecl):
                continue
            start = node.location.line
            end = node.end_location.line or start
            entries.append(Scope(name=node.name, start=start, end=max(end, start)))
        scopes[relative] = entries
    return scopes


def covering_scope(scopes: dict[str, list[Scope]], path: str, line: int) -> Scope | None:
    """The function whose declaration sits on *line*."""
    for scope in scopes.get(path, []):
        if scope.start == line:
            return scope
    return None


def measure_accuracy(root: Path, corpus: Path, rules: Sequence[str] | None = None) -> AccuracyReport:
    """Compare the findings with the ground truth of the corpus."""
    expectations = collect_expectations(corpus)
    manifest = load_manifest(corpus)
    scopes = build_scopes(corpus)
    config = AnalysisConfig(source_dirs=["."], enabled_rules=list(rules or []))
    project = Project(root=root, config=config)
    engine = RuleEngine(project)
    result = engine.analyze()

    report = AccuracyReport(expected=len(expectations))
    report.manifest_expected = len(manifest)
    found: set[tuple[str, int, str]] = set()

    for path, line, rule_id in manifest:
        scope = covering_scope(scopes, path, line)
        for violation in result.violations:
            if violation.rule_id != rule_id or violation.location.file != path:
                continue
            if violation.location.line == line:
                report.manifest_detected += 1
                found.add((path, violation.location.line, rule_id))
                break
            if scope is not None and scope.start <= violation.location.line <= scope.end:
                report.manifest_detected += 1
                found.add((path, violation.location.line, rule_id))
                break

    for expectation in expectations:
        scope = covering_scope(scopes, expectation.path, expectation.line)
        detected = False
        for violation in result.violations:
            if violation.rule_id != expectation.rule_id:
                continue
            if violation.location.file != expectation.path:
                continue
            if violation.location.line == expectation.line:
                detected = True
                break
            if scope is not None and scope.start <= violation.location.line <= scope.end:
                detected = True
                break
        entry = report.per_rule.setdefault(
            expectation.rule_id, {"expected": 0, "detected": 0}
        )
        entry["expected"] += 1
        if detected:
            report.detected += 1
            entry["detected"] += 1
        else:
            report.missed.append(
                (expectation.path, expectation.line, expectation.rule_id)
            )

    for violation in result.violations:
        key = (violation.location.file, violation.location.line, violation.rule_id)
        if key in found:
            continue
        report.false_positives.append(
            (violation.location.file, violation.location.line, violation.rule_id)
        )

    return report


# --------------------------------------------------------------------------
# Speed
# --------------------------------------------------------------------------


@dataclass
class SpeedReport:
    files: int = 0
    lines: int = 0
    bytes: int = 0
    runs: list[float] = field(default_factory=list)
    findings: int = 0
    phase_timings: dict[str, float] = field(default_factory=dict)
    rule_timings: dict[str, float] = field(default_factory=dict)

    @property
    def best(self) -> float:
        return min(self.runs) if self.runs else 0.0

    @property
    def median(self) -> float:
        return statistics.median(self.runs) if self.runs else 0.0

    @property
    def worst(self) -> float:
        return max(self.runs) if self.runs else 0.0

    @property
    def lines_per_second(self) -> float:
        return (self.lines / self.best) if self.best else 0.0

    @property
    def files_per_second(self) -> float:
        return (self.files / self.best) if self.best else 0.0

    @property
    def megabytes_per_second(self) -> float:
        return (self.bytes / 1048576.0 / self.best) if self.best else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "lines": self.lines,
            "bytes": self.bytes,
            "runs_seconds": [round(value, 6) for value in self.runs],
            "best_seconds": round(self.best, 6),
            "median_seconds": round(self.median, 6),
            "worst_seconds": round(self.worst, 6),
            "lines_per_second": round(self.lines_per_second, 1),
            "files_per_second": round(self.files_per_second, 2),
            "megabytes_per_second": round(self.megabytes_per_second, 3),
            "findings": self.findings,
            "phase_timings": {k: round(v, 6) for k, v in self.phase_timings.items()},
            "rule_timings": {
                k: round(v, 6) for k, v in sorted(
                    self.rule_timings.items(), key=lambda kv: -kv[1]
                )
            },
        }


def measure_speed(
    root: Path,
    repetitions: int = 3,
    warmup: bool = True,
    rules: Sequence[str] | None = None,
) -> SpeedReport:
    """Measure the throughput of the analyser."""
    config = AnalysisConfig(source_dirs=["."], enabled_rules=list(rules or []))
    project = Project(root=root, config=config)
    report = SpeedReport()

    if warmup:
        RuleEngine(project).analyze()

    for _ in range(repetitions):
        engine = RuleEngine(project)
        started = time.perf_counter()
        result = engine.analyze()
        elapsed = time.perf_counter() - started
        report.runs.append(elapsed)
        report.files = result.files_scanned
        report.lines = result.lines_scanned
        report.findings = len(result.violations)
        report.phase_timings = dict(engine.phase_timings)
        report.rule_timings = dict(engine.rule_timings)

    report.bytes = sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".c", ".h", ".cpp", ".cc", ".hpp"}
    )
    return report


# --------------------------------------------------------------------------
# Scale
# --------------------------------------------------------------------------


@dataclass
class ScalePoint:
    label: str
    files: int
    lines: int
    seconds: float

    @property
    def lines_per_second(self) -> float:
        return (self.lines / self.seconds) if self.seconds else 0.0


def measure_scale(
    workdir: Path,
    sizes: Sequence[int] = (1, 2, 4, 8),
    template: Path | None = None,
) -> list[ScalePoint]:
    """Measure how the runtime grows with the size of the project."""
    from benchmarks.generate import generate_project

    points: list[ScalePoint] = []
    template = template or (CORPUS / "clean.c")
    for factor in sizes:
        target = workdir / f"scale_{factor}"
        generate_project(target, modules=factor, template=template)
        config = AnalysisConfig(source_dirs=["."])
        project = Project(root=target, config=config)
        engine = RuleEngine(project)
        started = time.perf_counter()
        result = engine.analyze()
        elapsed = time.perf_counter() - started
        points.append(
            ScalePoint(
                label=f"{factor}x",
                files=result.files_scanned,
                lines=result.lines_scanned,
                seconds=elapsed,
            )
        )
    return points


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * width for width in widths),
    ]
    for row in rows:
        lines.append(
            "  ".join(str(cell).ljust(widths[index]) for index, cell in enumerate(row))
        )
    return "\n".join(lines)


@dataclass
class EngineScore:
    """The score of one engine on the shared ground truth."""

    engine: str
    version: str = ""
    available: bool = True
    reason: str = ""
    applicable: int = 0
    detected: int = 0
    mapped_findings: int = 0
    total_findings: int = 0
    seconds: float = 0.0
    missed: list[tuple[str, str]] = field(default_factory=list)
    detected_defects: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return (self.detected / self.applicable * 100.0) if self.applicable else 0.0

    @property
    def noise(self) -> int:
        """The findings whose rule has no counterpart in the taxonomy."""
        return max(self.total_findings - self.mapped_findings, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "version": self.version,
            "available": self.available,
            "reason": self.reason,
            "applicable_defects": self.applicable,
            "detected_defects": self.detected,
            "recall": round(self.recall, 2),
            "mapped_findings": self.mapped_findings,
            "total_findings": self.total_findings,
            "noise": self.noise,
            "seconds": round(self.seconds, 4),
            "missed": [
                {"defect": defect, "rule_id": rule_id}
                for defect, rule_id in self.missed
            ],
            "detected": list(self.detected_defects),
        }


def _matches_location(
    finding_file: str,
    finding_line: int,
    path: str,
    line: int,
    scope: Any,
) -> bool:
    """Does a finding of an engine correspond to an annotated defect?"""
    if finding_file != path:
        return False
    if finding_line == line:
        return True
    if scope is not None and scope.start <= finding_line <= scope.end:
        return True
    return False


def compare_engines(
    corpus: Path,
    engines: Sequence[Any] | None = None,
) -> list[EngineScore]:
    """Run every engine on the corpus and score it against the ground truth."""
    from benchmarks.engines import available_engines
    from benchmarks.mapping import CODESHIELD_TO_DEFECT, tool_rules

    engines = list(engines) if engines else available_engines(corpus)
    expectations = collect_expectations(corpus)
    scopes = build_scopes(corpus)
    files = sorted(
        path
        for path in corpus.rglob("*")
        if path.is_file() and path.suffix.lower() in {".c", ".h", ".cpp", ".cc", ".hpp"}
    )

    planted: list[tuple[str, int, str, str]] = []
    for expectation in expectations:
        defect = CODESHIELD_TO_DEFECT.get(expectation.rule_id)
        if defect is None:
            continue
        planted.append(
            (expectation.path, expectation.line, expectation.rule_id, defect)
        )

    scores: list[EngineScore] = []
    for engine in engines:
        result = engine.run(files)
        if not result.available:
            scores.append(
                EngineScore(
                    engine=engine.name,
                    version=engine.version(),
                    available=False,
                    reason=result.reason,
                )
            )
            continue

        tool = engine.name.lower()
        score = EngineScore(
            engine=engine.name,
            version=engine.version(),
            available=True,
            total_findings=len(result.findings),
            seconds=result.seconds,
        )

        applicable: list[tuple[str, int, str, str, set[str]]] = []
        for path, line, rule_id, defect in planted:
            names = tool_rules(defect, tool)
            if not names:
                continue
            applicable.append((path, line, rule_id, defect, names))
        score.applicable = len(applicable)

        matched_findings: set[int] = set()
        for index, (path, line, rule_id, defect, names) in enumerate(applicable):
            scope = covering_scope(scopes, path, line)
            hit = None
            for finding in result.findings:
                if finding.rule_id not in names:
                    continue
                if _matches_location(finding.file, finding.line, path, line, scope):
                    hit = finding
                    break
            if hit is None:
                score.missed.append((defect, f"{path}:{line} ({rule_id})"))
                continue
            score.detected += 1
            score.detected_defects.append(defect)
            matched_findings.add(id(hit))

        score.mapped_findings = _count_mapped(result.findings, tool)
        scores.append(score)
    return scores


def _count_mapped(findings: Sequence[Any], tool: str) -> int:
    """The findings whose rule is a known counterpart of a canonical defect."""
    known: set[str] = set()
    for entry in _DEFECT_ENTRIES.values():
        known |= set(entry.get(tool) or set())
    return sum(1 for finding in findings if finding.rule_id in known)


def print_comparison(scores: Sequence[EngineScore]) -> None:
    print()
    print("Cross tool comparison")
    print("-" * 72)
    rows = []
    for score in scores:
        if not score.available:
            rows.append([score.engine, score.version or "-", "-", "-", "-", "-", score.reason])
            continue
        rows.append(
            [
                score.engine,
                score.version or "-",
                f"{score.recall:.1f} %",
                f"{score.detected}/{score.applicable}",
                str(score.total_findings),
                str(score.noise),
                f"{score.seconds * 1000:.0f} ms",
            ]
        )
    print(
        _format_table(
            ["tool", "version", "recall", "defects", "findings", "unmapped", "time"],
            rows,
        )
    )
    print()
    print("  recall    the share of the applicable defects the tool found")
    print("  defects   detected / applicable (defects a tool cannot express are")
    print("            skipped, so the denominators differ)")
    print("  findings  the total number of findings the tool reports")
    print("  unmapped  the findings whose rule has no counterpart in the taxonomy")
    print()
    print("  Only the recall is directly comparable: the tools report very")
    print("  different finding sets, so their precision cannot be compared.")

    for score in scores:
        if not score.available or not score.missed:
            continue
        print()
        print(f"  {score.engine} missed:")
        for defect, where in score.missed:
            print(f"    {defect:34} {where}")


def print_accuracy(report: AccuracyReport) -> None:
    print()
    print("Accuracy")
    print("-" * 60)
    print(f"  planted defects      : {report.expected}")
    print(f"  detected             : {report.detected}")
    print(f"  missed               : {len(report.missed)}")
    print(f"  recall               : {report.recall:.1f} %")
    print()
    print(f"  manifest findings    : {report.manifest_expected}")
    print(f"  manifest detected    : {report.manifest_detected}")
    print(f"  unexpected findings  : {len(report.false_positives)}")
    print(f"  manifest conformance : {report.precision:.1f} %")
    print(f"  F1                   : {report.f1:.1f} %")
    print()
    print("  recall is measured against the planted defects, manifest")
    print("  conformance against the frozen baseline of the whole corpus.")

    if report.missed:
        print()
        print("  missed:")
        for path, line, rule in report.missed:
            print(f"    {path}:{line}  {rule}")

    if report.false_positives:
        print()
        print("  false positives:")
        for path, line, rule in report.false_positives[:40]:
            print(f"    {path}:{line}  {rule}")
        if len(report.false_positives) > 40:
            print(f"    ... and {len(report.false_positives) - 40} more")

    if report.per_rule:
        print()
        rows = [
            [rule, str(data["detected"]), str(data["expected"])]
            for rule, data in sorted(report.per_rule.items())
        ]
        print(_format_table(["rule", "found", "expected"], rows))


def print_speed(report: SpeedReport) -> None:
    print()
    print("Speed")
    print("-" * 60)
    print(f"  files               : {report.files}")
    print(f"  lines               : {report.lines}")
    print(f"  best run            : {report.best * 1000:.1f} ms")
    print(f"  median run          : {report.median * 1000:.1f} ms")
    print(f"  throughput          : {report.lines_per_second:,.0f} lines/s")
    print(f"                        {report.files_per_second:.1f} files/s")
    print(f"                        {report.megabytes_per_second:.2f} MB/s")
    print(f"  findings            : {report.findings}")

    if report.phase_timings:
        print()
        total = sum(report.phase_timings.values()) or 1.0
        rows = [
            [phase, f"{value * 1000:.1f} ms", f"{value / total * 100:.1f} %"]
            for phase, value in sorted(
                report.phase_timings.items(), key=lambda kv: -kv[1]
            )
        ]
        print(_format_table(["phase", "time", "share"], rows))

    if report.rule_timings:
        print()
        print("  slowest rules:")
        for rule, value in sorted(
            report.rule_timings.items(), key=lambda kv: -kv[1]
        )[:12]:
            print(f"    {rule:18} {value * 1000:8.2f} ms")


def measure_file_size(
    workdir: Path, functions: Sequence[int] = (20, 80, 320)
) -> list[dict[str, Any]]:
    """Compare the throughput of one large file with many small ones.

    A rule that is quadratic in the size of a translation unit shows up
    here: the throughput of the single large file drops while the total
    amount of code stays the same.
    """
    from benchmarks.generate import generate_project, generate_single

    rows: list[dict[str, Any]] = []
    for count in functions:
        single = workdir / f"single_{count}"
        generate_single(single, functions=count)
        config = AnalysisConfig(source_dirs=["."])
        project = Project(root=single, config=config)
        engine = RuleEngine(project)
        started = time.perf_counter()
        result = engine.analyze()
        elapsed = time.perf_counter() - started
        rows.append(
            {
                "kind": "one file",
                "files": result.files_scanned,
                "lines": result.lines_scanned,
                "seconds": round(elapsed, 6),
                "lines_per_second": round(result.lines_scanned / elapsed, 1),
                "rule_timings": {
                    key: round(value, 6)
                    for key, value in sorted(
                        engine.rule_timings.items(), key=lambda kv: -kv[1]
                    )[:6]
                },
            }
        )

    modules = 40
    many = workdir / f"many_{modules}"
    generate_project(many, modules=modules)
    config = AnalysisConfig(source_dirs=["."])
    project = Project(root=many, config=config)
    engine = RuleEngine(project)
    started = time.perf_counter()
    result = engine.analyze()
    elapsed = time.perf_counter() - started
    rows.append(
        {
            "kind": "many files",
            "files": result.files_scanned,
            "lines": result.lines_scanned,
            "seconds": round(elapsed, 6),
            "lines_per_second": round(result.lines_scanned / elapsed, 1),
            "rule_timings": {
                key: round(value, 6)
                for key, value in sorted(
                    engine.rule_timings.items(), key=lambda kv: -kv[1]
                )[:6]
            },
        }
    )
    return rows


def print_file_size(rows: Sequence[dict[str, Any]]) -> None:
    print()
    print("Translation unit size")
    print("-" * 60)
    print(
        _format_table(
            ["layout", "files", "lines", "time", "throughput"],
            [
                [
                    row["kind"],
                    str(row["files"]),
                    str(row["lines"]),
                    f"{row['seconds'] * 1000:.1f} ms",
                    f"{row['lines_per_second']:,.0f} lines/s",
                ]
                for row in rows
            ],
        )
    )
    singles = [row for row in rows if row["kind"] == "one file"]
    if len(singles) >= 2:
        first = singles[0]
        last = singles[-1]
        size_ratio = (last["lines"] / first["lines"]) if first["lines"] else 0.0
        speed_ratio = (
            (last["lines_per_second"] / first["lines_per_second"])
            if first["lines_per_second"]
            else 0.0
        )
        print()
        print(f"  the translation unit grew {size_ratio:.1f}x")
        print(f"  the throughput changed by {speed_ratio:.2f}x")
        if speed_ratio < 0.6:
            print("  -> a rule is super linear in the size of a file")
        else:
            print("  -> the cost per line stays stable")


def print_scale(points: Sequence[ScalePoint]) -> None:
    print()
    print("Scaling")
    print("-" * 60)
    rows = [
        [
            point.label,
            str(point.files),
            str(point.lines),
            f"{point.seconds * 1000:.1f} ms",
            f"{point.lines_per_second:,.0f} lines/s",
        ]
        for point in points
    ]
    print(_format_table(["size", "files", "lines", "time", "throughput"], rows))

    if len(points) >= 2:
        first = points[0]
        last = points[-1]
        size_ratio = (last.lines / first.lines) if first.lines else 0.0
        time_ratio = (last.seconds / first.seconds) if first.seconds else 0.0
        ratio = (time_ratio / size_ratio) if size_ratio else 0.0
        print()
        print(f"  size grew {size_ratio:.1f}x, time grew {time_ratio:.1f}x")
        print(f"  scaling factor      : {ratio:.2f}  (1.00 is perfectly linear)")
        if ratio > 1.6:
            print("  -> super linear, a rule is likely quadratic")
        elif ratio < 0.7:
            print("  -> sub linear, the fixed cost dominates")


def environment() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }


def run_all(
    workdir: Path,
    repetitions: int = 3,
    sizes: Sequence[int] = (1, 2, 4, 8),
) -> dict[str, Any]:
    """Run every benchmark and return the collected measurements."""
    accuracy = measure_accuracy(CORPUS, CORPUS)
    speed = measure_speed(CORPUS, repetitions=repetitions)
    points = measure_scale(workdir, sizes=sizes)

    print_accuracy(accuracy)
    print_speed(speed)
    print_scale(points)

    return {
        "environment": environment(),
        "rules_registered": len(RULE_REGISTRY),
        "accuracy": accuracy.to_dict(),
        "speed": speed.to_dict(),
        "scale": [
            {
                "label": point.label,
                "files": point.files,
                "lines": point.lines,
                "seconds": round(point.seconds, 6),
                "lines_per_second": round(point.lines_per_second, 1),
            }
            for point in points
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bench",
        description="Benchmark the CodeShield static analyser",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "accuracy", "speed", "scale", "size", "profile", "compare"],
        default="all",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--sizes", type=int, nargs="*", default=[1, 2, 4, 8])
    parser.add_argument("--json", help="write the measurements to this file")
    parser.add_argument("--workdir", help="directory for the generated projects")
    args = parser.parse_args(argv)

    import tempfile

    workdir = Path(args.workdir) if args.workdir else Path(
        tempfile.mkdtemp(prefix="codeshield-bench-")
    )
    workdir.mkdir(parents=True, exist_ok=True)

    print()
    print("CodeShield benchmark")
    print("=" * 60)
    for key, value in environment().items():
        print(f"  {key:16} {value}")

    payload: dict[str, Any] = {"environment": environment()}

    if args.mode in {"all", "accuracy"}:
        accuracy = measure_accuracy(CORPUS, CORPUS)
        print_accuracy(accuracy)
        payload["accuracy"] = accuracy.to_dict()

    if args.mode in {"all", "speed", "profile"}:
        speed = measure_speed(CORPUS, repetitions=args.repetitions)
        print_speed(speed)
        payload["speed"] = speed.to_dict()

    if args.mode in {"all", "scale"}:
        points = measure_scale(workdir, sizes=tuple(args.sizes))
        print_scale(points)
        payload["scale"] = [
            {
                "label": point.label,
                "files": point.files,
                "lines": point.lines,
                "seconds": round(point.seconds, 6),
                "lines_per_second": round(point.lines_per_second, 1),
            }
            for point in points
        ]

    if args.mode in {"all", "size"}:
        rows = measure_file_size(workdir)
        print_file_size(rows)
        payload["file_size"] = rows

    if args.mode in {"all", "compare"}:
        scores = compare_engines(CORPUS)
        print_comparison(scores)
        payload["comparison"] = [score.to_dict() for score in scores]

    if args.json:
        Path(args.json).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print()
        print(f"measurements written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
