"""The Cppcheck engine of the benchmark."""

from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence

from benchmarks.engines.base import Engine, EngineResult, Finding

#: The checks that describe the state of the tool rather than the code.
IGNORED_CHECKS = frozenset(
    {
        "missingInclude",
        "missingIncludeSystem",
        "normalCheckLevelMaxBranches",
        "toomanyconfigs",
        "checkersReport",
        "unusedSuppression",
        "nofile",
    }
)


class CppcheckEngine(Engine):
    """Drives the ``cppcheck`` command line tool."""

    name = "Cppcheck"
    executable = "cppcheck"

    def version(self) -> str:
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.strip().splitlines()[0]
        except Exception:
            return ""

    def run(self, files: Sequence[Path]) -> EngineResult:
        if not self.available():
            return EngineResult(
                engine=self.name, available=False, reason=self.unavailable_reason()
            )
        command = [
            self.executable,
            "--enable=all",
            "--inline-suppr",
            "--xml",
            "--xml-version=2",
            "--std=c11",
            "--check-level=exhaustive",
            "--suppress=missingIncludeSystem",
            "--suppress=unmatchedSuppression",
            "--quiet",
            *[str(path.resolve()) for path in files],
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=str(self.root),
                timeout=600,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return EngineResult(
                engine=self.name, available=False, reason=f"cppcheck failed: {error}"
            )
        elapsed = time.perf_counter() - started

        document = completed.stdout
        if not document.strip().startswith("<?xml"):
            document = completed.stderr
        findings = self._parse(document)
        return EngineResult(engine=self.name, findings=findings, seconds=elapsed)

    def _parse(self, document: str) -> list[Finding]:
        if not document.strip():
            return []
        try:
            root = ET.fromstring(document)
        except ET.ParseError:
            return []
        findings: list[Finding] = []
        for error in root.iter("error"):
            identifier = error.get("id", "")
            if not identifier or identifier in IGNORED_CHECKS:
                continue
            message = error.get("msg", "")
            for location in error.iter("location"):
                line = location.get("line", "0")
                if line == "0":
                    continue
                findings.append(
                    Finding(
                        file=self.relative(location.get("file", "")),
                        line=int(line),
                        rule_id=identifier,
                        message=message,
                    )
                )
                break
        return findings
