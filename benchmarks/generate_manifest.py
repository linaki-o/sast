"""Generate the ground truth manifest of the benchmark corpus.

The manifest lists every finding the analyser is expected to report on the
corpus.  It is the reference used to measure the precision; the inline
``sast:expect`` annotations measure the recall on the planted defects.

Run it after changing a rule and review the diff::

    python -m benchmarks.generate_manifest --write
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from sast.core.config import AnalysisConfig, Project  # noqa: E402
from sast.rules.builtin import loops, quality, security, standards  # noqa: E402,F401
from sast.rules.engine import RuleEngine  # noqa: E402

CORPUS = ROOT / "benchmarks" / "corpus"
MANIFEST = CORPUS / "manifest.yaml"

#: Rules whose findings are not pinned.  Everything else is part of the
#: frozen baseline so that a change in a rule shows up as a difference.
UNPINNED_PREFIXES: tuple[str, ...] = ()


def collect() -> list[dict]:
    """Every finding the analyser reports on the corpus."""
    config = AnalysisConfig(source_dirs=["."])
    project = Project(root=CORPUS, config=config)
    result = RuleEngine(project).analyze()
    entries = []
    for violation in result.sorted_violations():
        if violation.rule_id.startswith(UNPINNED_PREFIXES):
            continue
        entries.append(
            {
                "file": violation.location.file,
                "line": violation.location.line,
                "rule": violation.rule_id,
                "severity": violation.severity.value,
                "message": violation.message[:110],
            }
        )
    return entries


def render(entries: Sequence[dict]) -> str:
    lines = [
        "# Ground truth of the CodeShield benchmark corpus.",
        "#",
        "# Every entry is a finding the analyser must report at that exact",
        "# location.  A reported finding that is not listed here is counted",
        "# as a false positive by the benchmark.",
        "#",
        "# Regenerate with: python -m benchmarks.generate_manifest --write",
        "",
        "expectations:",
    ]
    for entry in entries:
        lines.append(
            f"  - file: {entry['file']}\n"
            f"    line: {entry['line']}\n"
            f"    rule: {entry['rule']}\n"
            f"    severity: {entry['severity']}\n"
            f"    message: {json_escape(entry['message'])}"
        )
    return "\n".join(lines) + "\n"


def json_escape(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate-manifest",
        description="Regenerate the ground truth manifest of the corpus",
    )
    parser.add_argument("--write", action="store_true", help="write the manifest")
    args = parser.parse_args(argv)

    entries = collect()
    document = render(entries)
    if args.write:
        MANIFEST.write_text(document, encoding="utf-8")
        print(f"{len(entries)} expectations written to {MANIFEST}")
    else:
        print(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
