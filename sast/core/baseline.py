"""Baseline handling.

A baseline records the findings that are already known and accepted.  On
subsequent runs those findings are suppressed, so that only newly
introduced problems are reported.  This is the mechanism that lets a large
legacy code base adopt a static analyser incrementally.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sast.core.models import AnalysisResult, Severity, Violation

BASELINE_VERSION = 1


@dataclass
class BaselineEntry:
    """A single accepted finding."""

    fingerprint: str
    rule_id: str
    file: str
    line: int
    severity: Severity = Severity.MEDIUM
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value,
            "message": self.message,
        }

    @classmethod
    def from_violation(cls, violation: Violation) -> "BaselineEntry":
        return cls(
            fingerprint=violation.fingerprint,
            rule_id=violation.rule_id,
            file=violation.location.file,
            line=violation.location.line,
            severity=violation.severity,
            message=violation.message,
        )


@dataclass
class Baseline:
    """A set of accepted findings."""

    entries: dict[str, BaselineEntry] = field(default_factory=dict)
    version: int = BASELINE_VERSION
    created_at: str = ""
    project: str = ""

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        file_path = Path(path)
        if not file_path.is_file():
            return cls()
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        baseline = cls(
            version=int(data.get("version", BASELINE_VERSION)),
            created_at=data.get("created_at", ""),
            project=data.get("project", ""),
        )
        for raw in data.get("entries", []):
            entry = BaselineEntry(
                fingerprint=raw.get("fingerprint", ""),
                rule_id=raw.get("rule_id", ""),
                file=raw.get("file", ""),
                line=int(raw.get("line", 0)),
                severity=Severity.parse(raw.get("severity", "medium")),
                message=raw.get("message", ""),
            )
            if entry.fingerprint:
                baseline.entries[entry.fingerprint] = entry
        return baseline

    def save(self, path: str | Path) -> Path:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.version,
            "created_at": self.created_at,
            "project": self.project,
            "entries": [
                self.entries[key].to_dict() for key in sorted(self.entries)
            ],
        }
        file_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return file_path

    # ------------------------------------------------------------------
    @classmethod
    def from_result(cls, result: AnalysisResult) -> "Baseline":
        baseline = cls(project=result.project)
        for violation in result.violations:
            baseline.add(violation)
        return baseline

    def add(self, violation: Violation) -> None:
        entry = BaselineEntry.from_violation(violation)
        self.entries[violation.fingerprint] = entry

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def suppress(self, result: AnalysisResult) -> tuple[AnalysisResult, list[Violation]]:
        """Remove the accepted findings from *result*.

        Returns the filtered result and the list of suppressed findings.
        """
        suppressed: list[Violation] = []
        kept: list[Violation] = []
        for violation in result.violations:
            if violation.fingerprint in self.entries:
                suppressed.append(violation)
            else:
                kept.append(violation)
        filtered = AnalysisResult(
            project=result.project,
            violations=kept,
            file_metrics=result.file_metrics,
            files_scanned=result.files_scanned,
            lines_scanned=result.lines_scanned,
            duration_seconds=result.duration_seconds,
            rules_executed=result.rules_executed,
            baseline_suppressed=len(suppressed),
            new_violations=len(kept),
            warnings=result.warnings,
            tool_version=result.tool_version,
        )
        return filtered, suppressed

    def diff(self, result: AnalysisResult) -> dict[str, Any]:
        """Compare a fresh result with the baseline."""
        new: list[Violation] = []
        fixed: list[BaselineEntry] = []
        seen: set[str] = set()

        for violation in result.violations:
            if violation.fingerprint in self.entries:
                seen.add(violation.fingerprint)
            else:
                new.append(violation)

        for fingerprint, entry in self.entries.items():
            if fingerprint not in seen:
                fixed.append(entry)

        return {
            "new": [v.to_dict() for v in new],
            "fixed": [e.to_dict() for e in fixed],
            "new_count": len(new),
            "fixed_count": len(fixed),
            "unchanged_count": len(seen),
        }


def resolve_baseline_path(project_root: Path, name: str | None = None) -> Path:
    """The path of the baseline file for a project."""
    if name:
        candidate = Path(name)
        if candidate.is_absolute():
            return candidate
        return project_root / candidate
    return project_root / "sast-baseline.json"
