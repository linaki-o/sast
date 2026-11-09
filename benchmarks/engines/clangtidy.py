"""The Clang-Tidy engine of the benchmark."""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Sequence

from benchmarks.engines.base import Engine, EngineResult, Finding

#: ``path:line:column: severity: message [check-name]``
DIAGNOSTIC_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+):\s+"
    r"(?P<severity>warning|error):\s+"
    r"(?P<message>.*?)\s+"
    r"\[(?P<checks>[^\]]+)\]$"
)

#: The checks that the engine runs.
DEFAULT_CHECKS = (
    "clang-analyzer-*,bugprone-*,cert-*,misc-*,"
    "readability-braces-around-statements,"
    "readability-magic-numbers,"
    "readability-function-size"
)

#: The compiler diagnostics are not checks, they are compilation errors.
IGNORED_PREFIXES = ("clang-diagnostic-",)


class ClangTidyEngine(Engine):
    """Drives the ``clang-tidy`` command line tool."""

    name = "Clang-Tidy"
    executable = "clang-tidy"

    def version(self) -> str:
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in result.stdout.splitlines():
                if "LLVM version" in line:
                    return line.strip()
            return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        except Exception:
            return ""

    def run(self, files: Sequence[Path]) -> EngineResult:
        if not self.available():
            return EngineResult(
                engine=self.name, available=False, reason=self.unavailable_reason()
            )
        findings: list[Finding] = []
        started = time.perf_counter()
        for path in files:
            language = "c++" if path.suffix.lower() in {".cpp", ".cc", ".cxx"} else "c"
            command = [
                self.executable,
                f"--checks={DEFAULT_CHECKS}",
                "--quiet",
                str(path.resolve()),
                "--",
                "-x",
                language,
                "-std=c11",
            ]
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
                    engine=self.name, available=False, reason=f"clang-tidy failed: {error}"
                )
            findings.extend(self._parse(completed.stdout + completed.stderr))
        elapsed = time.perf_counter() - started
        return EngineResult(engine=self.name, findings=findings, seconds=elapsed)

    def _parse(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            match = DIAGNOSTIC_RE.match(line.strip())
            if match is None:
                continue
            checks = match.group("checks")
            names = [name.strip() for name in checks.split(",")]
            names = [
                name for name in names if not name.startswith(IGNORED_PREFIXES)
            ]
            if not names:
                continue
            findings.append(
                Finding(
                    file=self.relative(match.group("file")),
                    line=int(match.group("line")),
                    rule_id=names[0],
                    message=match.group("message"),
                )
            )
            for extra in names[1:]:
                findings.append(
                    Finding(
                        file=self.relative(match.group("file")),
                        line=int(match.group("line")),
                        rule_id=extra,
                        message=match.group("message"),
                    )
                )
        return findings
