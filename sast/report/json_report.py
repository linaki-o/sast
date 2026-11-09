"""JSON report renderer.

The JSON document is the machine readable twin of the HTML dashboard: it
contains the full serialisation of the analysis result plus a ``summary``
section with the aggregated numbers used by the dashboards and by CI
pipelines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sast.core.models import AnalysisResult, Severity
from sast.report import resolve_output_dir

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

TOP_RULES_LIMIT = 10


def collect_rules(result: AnalysisResult) -> list[dict[str, Any]]:
    """Aggregate the metadata of every distinct rule seen in *result*."""
    rules: dict[str, dict[str, Any]] = {}
    for violation in result.sorted_violations():
        entry = rules.get(violation.rule_id)
        if entry is None:
            entry = {
                "rule_id": violation.rule_id,
                "name": violation.rule_name,
                "category": violation.category,
                "severity": violation.severity.value,
                "level": violation.severity.sarif_level,
                "message": violation.message,
                "description": violation.recommendation or violation.message,
                "recommendation": violation.recommendation,
                "cwe": [],
                "owasp": [],
                "standards": [],
                "count": 0,
            }
            rules[violation.rule_id] = entry
        entry["count"] += 1
        if violation.severity.rank < Severity.parse(entry["severity"]).rank:
            entry["severity"] = violation.severity.value
            entry["level"] = violation.severity.sarif_level
        if not entry["description"] and violation.message:
            entry["description"] = violation.message
        if not entry["recommendation"] and violation.recommendation:
            entry["recommendation"] = violation.recommendation
        entry["cwe"] = sorted(set(entry["cwe"]) | set(violation.cwe))
        entry["owasp"] = sorted(set(entry["owasp"]) | set(violation.owasp))
        entry["standards"] = sorted(set(entry["standards"]) | set(violation.standards))
    return list(rules.values())


def build_summary(result: AnalysisResult) -> dict[str, Any]:
    """Build the aggregated ``summary`` section of the report."""
    counts = result.count_by_severity()
    by_category = result.by_category()
    by_rule = result.by_rule()
    names = {entry["rule_id"]: entry["name"] for entry in collect_rules(result)}
    top_rules = [
        {"rule_id": rule_id, "name": names.get(rule_id, rule_id), "count": count}
        for rule_id, count in list(by_rule.items())[:TOP_RULES_LIMIT]
    ]
    risk = result.risk_score
    return {
        "total_findings": len(result.violations),
        "by_severity": {name: counts.get(name, 0) for name in SEVERITY_ORDER},
        "by_category": by_category,
        "by_rule": by_rule,
        "top_rules": top_rules,
        "risk_score": risk,
        "health_score": max(0, 100 - risk // 2),
        "files_scanned": result.files_scanned,
        "lines_scanned": result.lines_scanned,
        "duration_seconds": round(result.duration_seconds, 4),
        "passed": result.passed,
    }


def build_payload(result: AnalysisResult) -> dict[str, Any]:
    """Build the full JSON document for *result*."""
    payload = result.to_dict()
    payload["summary"] = build_summary(result)
    return payload


def to_json_string(result: AnalysisResult, indent: int = 2) -> str:
    """Serialise *result* into a JSON document."""
    return json.dumps(build_payload(result), indent=indent, ensure_ascii=False)


def render_json(result: AnalysisResult, output_dir: str | Path | None = None) -> Path:
    """Write ``report.json`` for *result* and return the written path."""
    path = resolve_output_dir(output_dir) / "report.json"
    path.write_text(to_json_string(result), encoding="utf-8")
    return path
