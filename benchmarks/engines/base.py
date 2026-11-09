"""The interface every analysis engine of the benchmark implements."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class Finding:
    """A single finding reported by an engine."""

    file: str
    line: int
    rule_id: str
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "message": self.message,
        }


@dataclass
class EngineResult:
    """The outcome of one engine run."""

    engine: str
    findings: list[Finding] = field(default_factory=list)
    seconds: float = 0.0
    available: bool = True
    reason: str = ""

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return counts


class Engine:
    """The base class of the benchmark engines."""

    #: The name used in the reports.
    name: str = "engine"
    #: The tool the engine drives, empty for the built in analyser.
    executable: str = ""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    # ------------------------------------------------------------------
    def available(self) -> bool:
        """Is the tool installed?"""
        if not self.executable:
            return True
        return shutil.which(self.executable) is not None

    def unavailable_reason(self) -> str:
        return f"{self.executable} is not installed"

    def version(self) -> str:
        """The version of the tool, for the report."""
        return ""

    def run(self, files: Sequence[Path]) -> EngineResult:
        """Analyse *files* and return the findings."""
        if not self.available():
            return EngineResult(
                engine=self.name, available=False, reason=self.unavailable_reason()
            )
        return EngineResult(engine=self.name)

    # ------------------------------------------------------------------
    def relative(self, path: str) -> str:
        """Normalise a reported path to a path relative to the corpus."""
        candidate = Path(path)
        try:
            return candidate.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return candidate.as_posix()
