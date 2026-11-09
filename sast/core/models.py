"""Core domain model.

Every other layer of CodeShield speaks in terms of the types declared here.
Keeping the contract small and dependency free makes it easy to serialise
results to JSON/SARIF, to diff two analysis runs, or to feed findings into a
CI system without pulling the whole engine in.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity.

    Ordered from most to least severe so that ``sorted`` can be used to build
    ranked reports. The numeric ``weight`` drives the risk score used by the
    dashboard and by the quality gate.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Lower is more severe."""
        return _SEVERITY_RANK[self]

    @property
    def sarif_level(self) -> str:
        return _SEVERITY_SARIF[self]

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "严重",
            Severity.HIGH: "高危",
            Severity.MEDIUM: "中危",
            Severity.LOW: "低危",
            Severity.INFO: "提示",
        }[self]

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        text = str(value).strip().lower()
        aliases = {
            "crit": cls.CRITICAL,
            "critical": cls.CRITICAL,
            "blocker": cls.CRITICAL,
            "error": cls.HIGH,
            "high": cls.HIGH,
            "warn": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "minor": cls.LOW,
            "low": cls.LOW,
            "note": cls.LOW,
            "info": cls.INFO,
            "information": cls.INFO,
        }
        if text not in aliases:
            raise ValueError(f"unknown severity: {value!r}")
        return aliases[text]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


# --------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class SourceLocation:
    """A position inside a source file.

    ``line`` and ``column`` are 1 based. ``end_line``/``end_column`` are
    optional; ``-1`` means "unknown".
    """

    file: str
    line: int = 1
    column: int = 1
    end_line: int = -1
    end_column: int = -1

    def with_end(self, end_line: int, end_column: int) -> "SourceLocation":
        return SourceLocation(self.file, self.line, self.column, end_line, end_column)

    def to_dict(self) -> dict[str, Any]:
        data = {"file": self.file, "line": self.line, "column": self.column}
        if self.end_line >= 0:
            data["end_line"] = self.end_line
        if self.end_column >= 0:
            data["end_column"] = self.end_column
        return data

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.file}:{self.line}:{self.column}"


@dataclass(frozen=True)
class SourceRange:
    """A span of source code together with the text it covers."""

    start: SourceLocation
    end: SourceLocation
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.to_dict(),
            "end": self.end.to_dict(),
            "text": self.text,
        }


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass
class Violation:
    """A single finding produced by a rule.

    A violation is the atomic unit of the whole product: static analysis,
    unit test failure and traceability gaps all normalise into this shape so
    that the dashboard and the reports can treat them uniformly.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    location: SourceLocation
    category: str = "quality"
    language: str = "c"
    function: str = ""
    snippet: str = ""
    recommendation: str = ""
    cwe: tuple[int, ...] = ()
    owasp: tuple[str, ...] = ()
    standards: tuple[str, ...] = ()
    trace: tuple[SourceLocation, ...] = ()
    metrics: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        self.cwe = tuple(self.cwe)
        self.owasp = tuple(self.owasp)
        self.standards = tuple(self.standards)
        self.trace = tuple(self.trace)
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Stable identity of the finding across runs.

        Built from the rule id plus the normalised location so that a file
        which merely shifted down a few lines keeps the same fingerprint and
        can be recognised as "still broken" by the baseline feature.
        """
        key = f"{self.rule_id}|{self.location.file}|{self.location.line}|{self.function}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

    @property
    def risk_score(self) -> int:
        return self.severity.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "severity_label": self.severity.label,
            "message": self.message,
            "category": self.category,
            "language": self.language,
            "function": self.function,
            "location": self.location.to_dict(),
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "standards": list(self.standards),
            "trace": [loc.to_dict() for loc in self.trace],
            "metrics": self.metrics,
            "fingerprint": self.fingerprint,
        }


@dataclass
class RuleInfo:
    """Metadata describing a rule, used for documentation and reporting."""

    rule_id: str
    name: str
    category: str
    severity: Severity
    description: str = ""
    rationale: str = ""
    recommendation: str = ""
    cwe: tuple[int, ...] = ()
    owasp: tuple[str, ...] = ()
    standards: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("c", "c++")
    references: tuple[str, ...] = ()
    enabled_by_default: bool = True
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "rationale": self.rationale,
            "recommendation": self.recommendation,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "standards": list(self.standards),
            "languages": list(self.languages),
            "references": list(self.references),
            "enabled_by_default": self.enabled_by_default,
            "tags": list(self.tags),
        }


@dataclass
class FileMetrics:
    """Per-file metrics collected during analysis."""

    path: str
    language: str = "c"
    lines_total: int = 0
    lines_code: int = 0
    lines_comment: int = 0
    lines_blank: int = 0
    functions: int = 0
    classes: int = 0
    cyclomatic_complexity: int = 0
    max_nesting: int = 0
    parameters: int = 0
    globals: int = 0
    comment_ratio: float = 0.0
    duplicate_blocks: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    """Aggregated outcome of an analysis run."""

    project: str = ""
    violations: list[Violation] = field(default_factory=list)
    file_metrics: list[FileMetrics] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_seconds: float = 0.0
    rules_executed: int = 0
    baseline_suppressed: int = 0
    new_violations: int = 0
    warnings: list[str] = field(default_factory=list)
    tool_version: str = ""

    # -- severity helpers -------------------------------------------------
    def by_severity(self) -> dict[Severity, list[Violation]]:
        buckets: dict[Severity, list[Violation]] = {s: [] for s in Severity}
        for violation in self.violations:
            buckets[violation.severity].append(violation)
        return buckets

    def count_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for violation in self.violations:
            counts[violation.severity.value] += 1
        return counts

    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for violation in self.violations:
            counts[violation.category] = counts.get(violation.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for violation in self.violations:
            counts[violation.rule_id] = counts.get(violation.rule_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def risk_score(self) -> int:
        return sum(v.risk_score for v in self.violations)

    @property
    def passed(self) -> bool:
        """The quality gate: no critical or high severity finding."""
        return not any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) for v in self.violations
        )

    def sorted_violations(self) -> list[Violation]:
        return sorted(
            self.violations,
            key=lambda v: (
                v.severity.rank,
                v.location.file,
                v.location.line,
                v.location.column,
                v.rule_id,
            ),
        )

    def files_with_findings(self) -> list[str]:
        seen: list[str] = []
        for violation in self.violations:
            if violation.location.file not in seen:
                seen.append(violation.location.file)
        return seen

    def filter(
        self,
        severities: Iterable[Severity] | None = None,
        categories: Iterable[str] | None = None,
        rules: Iterable[str] | None = None,
        paths: Iterable[str] | None = None,
    ) -> "AnalysisResult":
        severities = set(severities) if severities else None
        categories = set(categories) if categories else None
        rules = set(rules) if rules else None
        paths = set(paths) if paths else None

        def keep(v: Violation) -> bool:
            if severities and v.severity not in severities:
                return False
            if categories and v.category not in categories:
                return False
            if rules and v.rule_id not in rules:
                return False
            if paths and not any(p in v.location.file for p in paths):
                return False
            return True

        clone = dataclasses.replace(self)
        clone.violations = [v for v in self.violations if keep(v)]
        return clone

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "tool_version": self.tool_version,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "rules_executed": self.rules_executed,
            "duration_seconds": round(self.duration_seconds, 4),
            "risk_score": self.risk_score,
            "passed": self.passed,
            "counts": self.count_by_severity(),
            "by_category": self.by_category(),
            "by_rule": self.by_rule(),
            "violations": [v.to_dict() for v in self.sorted_violations()],
            "file_metrics": [m.to_dict() for m in self.file_metrics],
            "warnings": list(self.warnings),
            "baseline_suppressed": self.baseline_suppressed,
            "new_violations": self.new_violations,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------
# Suppression
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Suppression:
    """A ``// sast:ignore`` style directive parsed out of the source."""

    rule_ids: tuple[str, ...]
    reason: str = ""
    location: SourceLocation | None = None
    kind: str = "inline"  # inline | file | config


def iter_violations(result: AnalysisResult) -> Iterator[Violation]:
    yield from result.violations
