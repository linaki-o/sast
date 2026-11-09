"""The CodeShield engine of the benchmark."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Sequence

from benchmarks.engines.base import Engine, EngineResult, Finding


class CodeShieldEngine(Engine):
    """Drives the analyser of this repository."""

    name = "CodeShield"

    def version(self) -> str:
        from sast import __version__

        return __version__

    def run(self, files: Sequence[Path]) -> EngineResult:
        from sast.core.config import AnalysisConfig, Project
        from sast.rules.builtin import loops, quality, security, standards  # noqa: F401
        from sast.rules.engine import RuleEngine

        config = AnalysisConfig(source_dirs=["."])
        project = Project(root=self.root, config=config)
        engine = RuleEngine(project)
        started = time.perf_counter()
        result = engine.analyze()
        elapsed = time.perf_counter() - started
        findings = [
            Finding(
                file=violation.location.file,
                line=violation.location.line,
                rule_id=violation.rule_id,
                message=violation.message,
            )
            for violation in result.violations
        ]
        return EngineResult(engine=self.name, findings=findings, seconds=elapsed)
