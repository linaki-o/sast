"""SARIF 2.1.0 report renderer.

The generated document follows the OASIS SARIF 2.1.0 schema closely enough
to be consumed by GitHub code scanning, Azure DevOps and other CI systems.
A structural sanity check is executed before the document is written so a
malformed report is never published.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sast import __version__
from sast.core.models import AnalysisResult
from sast.report import relative_uri, resolve_output_dir
from sast.report.json_report import collect_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SARIF_VERSION = "2.1.0"

TOOL_NAME = "CodeShield"

TOOL_INFORMATION_URI = "https://github.com/codeshield/codeshield"

VALID_LEVELS = ("none", "note", "warning", "error")


def build_sarif(result: AnalysisResult) -> dict[str, Any]:
    """Build the SARIF document describing *result*."""
    rules = collect_rules(result)
    index_by_rule = {entry["rule_id"]: position for position, entry in enumerate(rules)}

    sarif_rules = [
        {
            "id": entry["rule_id"],
            "name": entry["name"] or entry["rule_id"],
            "shortDescription": {"text": entry["name"] or entry["rule_id"]},
            "fullDescription": {"text": entry["description"] or entry["rule_id"]},
            "defaultConfiguration": {"level": entry["level"]},
            "properties": {
                "category": entry["category"],
                "cwe": entry["cwe"],
                "owasp": entry["owasp"],
                "standards": entry["standards"],
                "recommendation": entry["recommendation"],
                "occurrences": entry["count"],
            },
        }
        for entry in rules
    ]

    sarif_results = []
    for violation in result.sorted_violations():
        sarif_results.append(
            {
                "ruleId": violation.rule_id,
                "ruleIndex": index_by_rule.get(violation.rule_id, 0),
                "level": violation.severity.sarif_level,
                "message": {"text": violation.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": relative_uri(violation.location.file),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, violation.location.line),
                                "startColumn": max(1, violation.location.column),
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": violation.fingerprint,
                },
                "properties": {
                    "severity": violation.severity.value,
                    "category": violation.category,
                    "language": violation.language,
                    "function": violation.function,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": result.tool_version or __version__,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": sarif_rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "description": {"text": "Root directory of the analysed project."}
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "durationSeconds": round(result.duration_seconds, 4),
                        },
                    }
                ],
                "results": sarif_results,
            }
        ],
    }


def validate_sarif(document: dict[str, Any]) -> list[str]:
    """Check the structural invariants of a SARIF document.

    Returns the list of problems found; an empty list means the document is
    considered valid.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["document must be a JSON object"]
    if document.get("version") != SARIF_VERSION:
        problems.append(f"version must be {SARIF_VERSION!r}")
    if not document.get("$schema"):
        problems.append("$schema is missing")

    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non empty array")
        return problems

    for run_index, run in enumerate(runs):
        prefix = f"run {run_index}"
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name"):
            problems.append(f"{prefix}: tool.driver.name is missing")
        if not driver.get("informationUri"):
            problems.append(f"{prefix}: tool.driver.informationUri is missing")
        rules = driver.get("rules") or []
        if not isinstance(rules, list):
            problems.append(f"{prefix}: tool.driver.rules must be an array")
            rules = []
        rule_ids = {rule.get("id") for rule in rules if isinstance(rule, dict)}
        for rule in rules:
            if not isinstance(rule, dict) or not rule.get("id"):
                problems.append(f"{prefix}: every rule needs an id")
                continue
            configuration = rule.get("defaultConfiguration") or {}
            if configuration.get("level") not in VALID_LEVELS:
                problems.append(f"{prefix}: rule {rule.get('id')!r} has an invalid default level")

        results = run.get("results")
        if not isinstance(results, list):
            problems.append(f"{prefix}: results must be an array")
            results = []
        for position, item in enumerate(results):
            where = f"{prefix} result {position}"
            if not isinstance(item, dict):
                problems.append(f"{where}: must be an object")
                continue
            rule_id = item.get("ruleId")
            if not rule_id:
                problems.append(f"{where}: ruleId is missing")
            elif rules and rule_id not in rule_ids:
                problems.append(f"{where}: ruleId {rule_id!r} is not declared in the rules array")
            if item.get("level") not in VALID_LEVELS:
                problems.append(f"{where}: level is invalid")
            if not (item.get("message") or {}).get("text"):
                problems.append(f"{where}: message.text is missing")
            locations = item.get("locations") or []
            if not locations:
                problems.append(f"{where}: locations are missing")
            for location in locations:
                physical = (location or {}).get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                if not artifact.get("uri"):
                    problems.append(f"{where}: artifactLocation.uri is missing")
                region = physical.get("region") or {}
                try:
                    start_line = int(region.get("startLine", 0))
                except (TypeError, ValueError):
                    start_line = 0
                if start_line < 1:
                    problems.append(f"{where}: region.startLine must be a positive integer")
            fingerprints = item.get("partialFingerprints") or {}
            if not fingerprints.get("primaryLocationLineHash"):
                problems.append(f"{where}: partialFingerprints.primaryLocationLineHash is missing")

        invocations = run.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            problems.append(f"{prefix}: invocations are missing")
        else:
            for invocation in invocations:
                if not isinstance(invocation.get("executionSuccessful"), bool):
                    problems.append(f"{prefix}: invocations.executionSuccessful must be a boolean")
                properties = invocation.get("properties") or {}
                if "durationSeconds" not in properties:
                    problems.append(f"{prefix}: invocations.properties.durationSeconds is missing")
    return problems


def render_sarif(result: AnalysisResult, output_dir: str | Path | None = None) -> Path:
    """Write ``report.sarif`` for *result* and return the written path."""
    document = build_sarif(result)
    problems = validate_sarif(document)
    if problems:
        raise ValueError("invalid SARIF document: " + "; ".join(problems))
    path = resolve_output_dir(output_dir) / "report.sarif"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
