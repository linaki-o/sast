"""XML report renderer.

The document is built by hand so that every value passes through
``xml.sax.saxutils`` and the result is guaranteed to be well formed.
The layout is intentionally flat: a project node, a summary node, one node
per file with its violations and finally the collected file metrics.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape, quoteattr

from sast import __version__
from sast.core.models import AnalysisResult, Violation
from sast.report import relative_uri, resolve_output_dir
from sast.report.json_report import SEVERITY_ORDER, build_summary


def _attributes(pairs: dict[str, Any]) -> str:
    """Render *pairs* as escaped XML attributes."""
    return "".join(f" {key}={quoteattr(str(value))}" for key, value in pairs.items())


def _text(value: Any) -> str:
    """Escape *value* so that it is safe as XML character data."""
    return escape(str(value))


def group_by_file(violations: Iterable[Violation]) -> dict[str, list[Violation]]:
    """Group *violations* by their file, keeping the order of appearance."""
    grouped: dict[str, list[Violation]] = {}
    for violation in violations:
        grouped.setdefault(violation.location.file, []).append(violation)
    return grouped


def build_xml(result: AnalysisResult) -> str:
    """Build the XML document describing *result*."""
    summary = build_summary(result)
    project_name = result.project or "unknown"
    lines: list[str] = []

    lines.append('<?xml version="1.0" encoding="utf-8"?>')
    lines.append(
        "<CodeShieldReport"
        + _attributes(
            {
                "version": result.tool_version or __version__,
                "generated": datetime.now().isoformat(timespec="seconds"),
            }
        )
        + ">"
    )

    lines.append(
        "  <project" + _attributes({"name": project_name}) + ">" + _text(project_name) + "</project>"
    )

    lines.append(
        "  <summary"
        + _attributes(
            {
                "total": summary["total_findings"],
                "risk_score": summary["risk_score"],
                "health_score": summary["health_score"],
                "passed": "true" if result.passed else "false",
                "files_scanned": result.files_scanned,
                "lines_scanned": result.lines_scanned,
                "duration_seconds": summary["duration_seconds"],
            }
        )
        + ">"
    )
    for name in SEVERITY_ORDER:
        lines.append(
            "    <severity" + _attributes({"name": name, "count": summary["by_severity"][name]}) + "/>"
        )
    for category, count in summary["by_category"].items():
        lines.append(
            "    <category" + _attributes({"name": category, "count": count}) + "/>"
        )
    lines.append("  </summary>")

    lines.append("  <files>")
    for path, violations in group_by_file(result.sorted_violations()).items():
        lines.append(
            "    <file"
            + _attributes({"path": relative_uri(path), "violations": len(violations)})
            + ">"
        )
        lines.append("      <violations>")
        for violation in violations:
            lines.append(
                "        <violation"
                + _attributes(
                    {
                        "id": violation.fingerprint,
                        "severity": violation.severity.value,
                        "line": violation.location.line,
                        "column": violation.location.column,
                        "rule": violation.rule_id,
                        "message": violation.message,
                        "category": violation.category,
                        "name": violation.rule_name,
                    }
                )
                + ">"
            )
            if violation.function:
                lines.append("          <function>" + _text(violation.function) + "</function>")
            if violation.snippet:
                lines.append("          <snippet>" + _text(violation.snippet) + "</snippet>")
            if violation.recommendation:
                lines.append(
                    "          <recommendation>" + _text(violation.recommendation) + "</recommendation>"
                )
            for cwe in violation.cwe:
                lines.append("          <cwe>" + _text(cwe) + "</cwe>")
            for owasp in violation.owasp:
                lines.append("          <owasp>" + _text(owasp) + "</owasp>")
            for standard in violation.standards:
                lines.append("          <standard>" + _text(standard) + "</standard>")
            if violation.trace:
                lines.append("          <trace>")
                for step in violation.trace:
                    lines.append(
                        "            <step"
                        + _attributes(
                            {
                                "file": relative_uri(step.file),
                                "line": step.line,
                                "column": step.column,
                            }
                        )
                        + "/>"
                    )
                lines.append("          </trace>")
            lines.append("        </violation>")
        lines.append("      </violations>")
        lines.append("    </file>")
    lines.append("  </files>")

    lines.append("  <fileMetrics>")
    for metrics in result.file_metrics:
        lines.append(
            "    <file"
            + _attributes(
                {
                    "path": relative_uri(metrics.path),
                    "language": metrics.language,
                    "lines_total": metrics.lines_total,
                    "lines_code": metrics.lines_code,
                    "lines_comment": metrics.lines_comment,
                    "lines_blank": metrics.lines_blank,
                    "functions": metrics.functions,
                    "classes": metrics.classes,
                    "cyclomatic_complexity": metrics.cyclomatic_complexity,
                    "max_nesting": metrics.max_nesting,
                    "parameters": metrics.parameters,
                    "globals": metrics.globals,
                    "comment_ratio": round(metrics.comment_ratio, 4),
                    "duplicate_blocks": metrics.duplicate_blocks,
                }
            )
            + "/>"
        )
    lines.append("  </fileMetrics>")

    if result.warnings:
        lines.append("  <warnings>")
        for warning in result.warnings:
            lines.append("    <warning>" + _text(warning) + "</warning>")
        lines.append("  </warnings>")

    lines.append("</CodeShieldReport>")
    return "\n".join(lines) + "\n"


def render_xml(result: AnalysisResult, output_dir: str | Path | None = None) -> Path:
    """Write ``report.xml`` for *result* and return the written path."""
    path = resolve_output_dir(output_dir) / "report.xml"
    path.write_text(build_xml(result), encoding="utf-8")
    return path
