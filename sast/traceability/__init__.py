"""Requirements traceability subsystem.

The package turns requirement documents into a matrix that connects every
requirement with the tests that verify it, the code that implements it and
the findings that were reported for that code.

Typical use::

    from sast.traceability import build_matrix, load_requirements, write_reports

    requirements = load_requirements("requirements.yaml")
    matrix = build_matrix(project, requirements, analysis=result)
    write_reports(matrix, "sast-report")
"""

from __future__ import annotations

from sast.traceability.importer import (
    detect_format,
    load_requirements,
    load_requirements_from_paths,
)
from sast.traceability.matrix import (
    TraceCell,
    TraceLink,
    TraceabilityMatrix,
    build_matrix,
)
from sast.traceability.report import to_csv, to_html, to_json, write_reports
from sast.traceability.requirements import Requirement, RequirementSet

__all__ = [
    "Requirement",
    "RequirementSet",
    "TraceLink",
    "TraceCell",
    "TraceabilityMatrix",
    "load_requirements",
    "load_requirements_from_paths",
    "detect_format",
    "build_matrix",
    "to_csv",
    "to_html",
    "to_json",
    "write_reports",
]
