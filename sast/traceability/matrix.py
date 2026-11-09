"""The traceability matrix.

The matrix connects requirements with the artefacts that realise them:
unit tests, the code locations that implement them and the findings that were
reported for those locations.  Links can be declared explicitly, but the
interesting part is the automatic inference implemented by
:func:`build_matrix`: requirement identifiers, titles and tags are matched
against test targets, function names and finding locations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from sast.core.models import AnalysisResult, SourceLocation
from sast.traceability.requirements import Requirement, RequirementSet

__all__ = ["TraceLink", "TraceCell", "TraceabilityMatrix", "build_matrix"]

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^0-9A-Za-z]+")


def _tokens(value: Any) -> list[str]:
    """Split *value* into lower case word tokens."""
    text = _CAMEL_RE.sub(" ", str(value or ""))
    return [token.lower() for token in _TOKEN_SPLIT_RE.split(text) if token]


def _tokens_equal(left: Sequence[str], right: Sequence[str]) -> bool:
    return list(left) == list(right)


def _token_prefix_match(left: Sequence[str], right: Sequence[str]) -> bool:
    """Is one token list a prefix of the other?

    A pair of tokens may differ by a stem, so ``parse_config`` matches
    ``parse configuration``.  Stems are only considered when the shorter list
    carries more than one token, which keeps single words such as
    ``checksum`` apart from ``check``.
    """
    if not left or not right:
        return False
    short, long = (left, right) if len(left) <= len(right) else (right, left)
    allow_stem = len(short) > 1
    for index in range(len(short)):
        first = short[index].lower()
        second = long[index].lower()
        if first == second:
            continue
        if allow_stem:
            if len(first) >= 4 and second.startswith(first):
                continue
            if len(second) >= 4 and first.startswith(second):
                continue
        return False
    return True


def _token_subset(left: Sequence[str], right: Sequence[str]) -> bool:
    """Does *left* use only words that also appear in *right*?"""
    if not left:
        return False
    owned = set(right)
    return all(token in owned for token in left)


def _contains_sequence(haystack: Sequence[str], needle: Sequence[str]) -> bool:
    """Does *needle* appear as a contiguous run inside *haystack*?"""
    if not needle or len(needle) > len(haystack):
        return False
    for start in range(len(haystack) - len(needle) + 1):
        if list(haystack[start : start + len(needle)]) == list(needle):
            return True
    return False


class _RequirementIndex:
    """Lookup structure that maps names to requirement identifiers."""

    def __init__(self, requirements: RequirementSet) -> None:
        self.requirements = requirements
        self._ids: dict[str, str] = {}
        self._keys: list[tuple[list[str], str]] = []
        for requirement in requirements:
            lowered = requirement.id.lower()
            self._ids.setdefault(lowered, requirement.id)
            self._ids.setdefault("".join(_tokens(requirement.id)), requirement.id)
            for key in _requirement_keys(requirement):
                tokens = _tokens(key)
                if tokens:
                    self._keys.append((tokens, requirement.id))

    def match_id(self, candidate: str) -> str:
        """Return the requirement whose identifier equals *candidate*."""
        text = str(candidate or "").strip().lower()
        if not text:
            return ""
        if text in self._ids:
            return self._ids[text]
        joined = "".join(_tokens(candidate))
        return self._ids.get(joined, "")

    def match(self, candidate: str) -> str:
        """Return the requirement that matches the name *candidate*."""
        tokens = _tokens(candidate)
        if not tokens:
            return ""
        for key_tokens, identifier in self._keys:
            if _tokens_equal(tokens, key_tokens):
                return identifier
        for key_tokens, identifier in self._keys:
            if _token_prefix_match(tokens, key_tokens):
                return identifier
        for key_tokens, identifier in self._keys:
            if _token_subset(tokens, key_tokens):
                return identifier
        return ""

    def descriptions(self) -> list[tuple[str, list[str]]]:
        """Return the identifier and the description tokens of every item."""
        result: list[tuple[str, list[str]]] = []
        for requirement in self.requirements:
            tokens = _tokens(requirement.description)
            if tokens:
                result.append((requirement.id, tokens))
        return result


def _requirement_keys(requirement: Requirement) -> list[str]:
    """Return every name a requirement can be recognised by."""
    keys: list[str] = [requirement.id, requirement.title]
    keys.extend(requirement.tags)
    metadata = requirement.metadata if isinstance(requirement.metadata, dict) else {}
    for name in ("function", "component", "module", "symbol", "target"):
        value = metadata.get(name)
        if isinstance(value, str) and value.strip():
            keys.append(value)
    return [key for key in keys if key and str(key).strip()]


@dataclass
class TraceLink:
    """A single link between a requirement and an artefact."""

    requirement_id: str
    target_kind: str
    target_id: str
    target_name: str = ""
    location: SourceLocation | None = None
    comment: str = ""
    severity: str = ""

    def to_dict(self) -> dict:
        """Return a JSON friendly representation."""
        return {
            "requirement_id": self.requirement_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "location": self.location.to_dict() if self.location else None,
            "comment": self.comment,
            "severity": self.severity,
        }


@dataclass
class TraceCell:
    """The cell of one requirement inside the matrix."""

    requirement_id: str
    tests: list[str] = field(default_factory=list)
    code_locations: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        """Is the requirement covered by at least one test?"""
        return bool(self.tests)

    @property
    def implemented(self) -> bool:
        """Is the requirement backed by at least one code location?"""
        return bool(self.code_locations)

    @property
    def verified(self) -> bool:
        """Is the requirement both implemented and covered by a test?"""
        return bool(self.tests) and bool(self.code_locations)

    @property
    def coverage_state(self) -> str:
        """Return ``covered``, ``implemented`` or ``uncovered``."""
        if self.tests:
            return "covered"
        if self.code_locations:
            return "implemented"
        return "uncovered"

    def to_dict(self) -> dict:
        """Return a JSON friendly representation."""
        return {
            "requirement_id": self.requirement_id,
            "tests": list(self.tests),
            "code_locations": list(self.code_locations),
            "findings": list(self.findings),
            "covered": self.covered,
            "implemented": self.implemented,
            "verified": self.verified,
            "coverage_state": self.coverage_state,
        }


class TraceabilityMatrix:
    """Requirements linked to tests, code locations and findings."""

    def __init__(
        self,
        requirements: RequirementSet | Iterable[Requirement],
        links: list[TraceLink] | None = None,
    ) -> None:
        if isinstance(requirements, RequirementSet):
            self.requirements = requirements
        else:
            self.requirements = RequirementSet(list(requirements or []))
        self.links: list[TraceLink] = []
        self.known_test_ids: set[str] = set()
        for link in links or []:
            self.add(link)

    def add(self, link: TraceLink) -> TraceLink:
        """Append *link* to the matrix."""
        self.links.append(link)
        if link.target_kind == "test" and link.target_id:
            self.known_test_ids.add(link.target_id)
        return link

    def register_test(self, test_id: str) -> None:
        """Remember a test that exists in the project.

        Tests that are not linked to any requirement are orphans, so they have
        to be known even when no link was created for them.
        """
        text = str(test_id or "").strip()
        if text:
            self.known_test_ids.add(text)

    def links_for(self, requirement_id: str, kind: str = "") -> list[TraceLink]:
        """Return the links of a requirement, optionally of a single kind."""
        return [
            link
            for link in self.links
            if link.requirement_id == requirement_id and (not kind or link.target_kind == kind)
        ]

    def cell(self, requirement_id: str) -> TraceCell:
        """Return the matrix cell of *requirement_id*."""
        cell = TraceCell(requirement_id=requirement_id)
        for link in self.links_for(requirement_id):
            if link.target_kind == "test":
                entry = link.target_id or link.target_name
                if entry and entry not in cell.tests:
                    cell.tests.append(entry)
            elif link.target_kind == "code":
                entry = str(link.location) if link.location else link.target_id
                if link.target_name:
                    entry = f"{link.target_name} {entry}".strip()
                if entry and entry not in cell.code_locations:
                    cell.code_locations.append(entry)
            elif link.target_kind == "finding":
                entry = link.target_id or link.target_name
                if link.location is not None:
                    entry = f"{link.target_name} {link.location}".strip()
                if entry and entry not in cell.findings:
                    cell.findings.append(entry)
        return cell

    def rows(self) -> list[tuple[Requirement, TraceCell]]:
        """Return every requirement together with its cell."""
        return [(requirement, self.cell(requirement.id)) for requirement in self.requirements]

    @property
    def coverage_percentage(self) -> float:
        """The share of requirements that are covered by a test."""
        total = len(self.requirements)
        if not total:
            return 0.0
        covered = sum(1 for _, cell in self.rows() if cell.covered)
        return covered * 100.0 / total

    @property
    def total_requirements(self) -> int:
        """The number of requirements in the matrix."""
        return len(self.requirements)

    @property
    def covered_requirements(self) -> int:
        """The number of requirements that are covered by a test."""
        return sum(1 for _, cell in self.rows() if cell.covered)

    def gaps(self) -> list[dict]:
        """Return the requirements that are not covered by any test."""
        gaps: list[dict] = []
        for requirement, cell in self.rows():
            if cell.covered:
                continue
            gaps.append(
                {
                    "id": requirement.id,
                    "title": requirement.title,
                    "priority": requirement.priority,
                    "status": requirement.status,
                    "category": requirement.category,
                    "state": cell.coverage_state,
                    "implemented": cell.implemented,
                    "reason": "no test linked",
                }
            )
        return gaps

    def orphan_tests(self, test_ids: list[str]) -> list[str]:
        """Return the identifiers of tests that are not linked to a requirement."""
        linked = {
            link.target_id for link in self.links if link.target_kind == "test"
        }
        orphans: list[str] = []
        for identifier in test_ids or []:
            text = str(identifier)
            if not text or text in linked or text in orphans:
                continue
            orphans.append(text)
        return orphans

    def to_dict(self) -> dict:
        """Return a JSON friendly representation."""
        rows: list[dict] = []
        for requirement, cell in self.rows():
            data = requirement.to_dict()
            data["cell"] = cell.to_dict()
            data["links"] = [
                link.to_dict() for link in self.links_for(requirement.id)
            ]
            rows.append(data)
        return {
            "total_requirements": self.total_requirements,
            "covered_requirements": self.covered_requirements,
            "coverage_percentage": round(self.coverage_percentage, 2),
            "orphan_tests": self.orphan_tests(sorted(self.known_test_ids)),
            "requirements": rows,
            "links": [link.to_dict() for link in self.links],
            "gaps": self.gaps(),
        }

    def __len__(self) -> int:
        return len(self.requirements)

    def __repr__(self) -> str:
        return (
            f"<TraceabilityMatrix {len(self.requirements)} requirements, "
            f"{len(self.links)} links>"
        )


def _as_requirement_set(requirements: Any) -> RequirementSet:
    """Coerce *requirements* into a :class:`RequirementSet`."""
    if requirements is None:
        return RequirementSet()
    if isinstance(requirements, RequirementSet):
        return requirements
    if isinstance(requirements, dict):
        return RequirementSet(
            [Requirement.from_dict(item) for item in requirements.values() if isinstance(item, dict)]
        )
    return RequirementSet(list(requirements))


def _project_requirements(project: Any) -> RequirementSet:
    """Load the requirement files configured for *project*."""
    config = getattr(project, "config", None)
    files = list(getattr(config, "requirements_files", []) or [])
    if not files:
        return RequirementSet()
    from sast.traceability.importer import load_requirements_from_paths

    return load_requirements_from_paths(files, project=project)


def _collect_test_cases(project: Any, test_suites: Any) -> list[Any]:
    """Return the test cases of *test_suites*.

    The argument may hold :class:`~sast.testing.model.TestSuite` objects,
    plain :class:`~sast.testing.model.TestCase` objects or dictionaries.  When
    nothing is given the suites of the project are discovered.
    """
    cases: list[Any] = []
    if test_suites is None:
        if project is None:
            return cases
        try:
            from sast.testing import discover_suites
        except Exception:
            return cases
        try:
            suites = discover_suites(project)
        except Exception:
            suites = []
        for suite in suites:
            cases.extend(list(getattr(suite, "tests", []) or []))
        return cases
    if isinstance(test_suites, (str, Path)):
        return cases
    for entry in test_suites:
        if entry is None:
            continue
        tests = getattr(entry, "tests", None)
        if tests is not None:
            cases.extend(list(tests))
            continue
        if hasattr(entry, "id") and hasattr(entry, "target"):
            cases.append(entry)
            continue
        if isinstance(entry, dict):
            try:
                from sast.testing.model import TestCase

                cases.append(TestCase.from_dict(entry))
            except Exception:
                continue
    return cases


def _collect_sources(project: Any, analysis: Any, sources: Any) -> list[Path]:
    """Return the source files that should be scanned for function names."""
    candidates: list[Path] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        if not value:
            return
        candidate = Path(str(value))
        if not candidate.is_absolute() and project is not None:
            resolver = getattr(project, "resolve", None)
            if callable(resolver):
                candidate = resolver(candidate)
        key = str(candidate)
        if key in seen:
            return
        seen.add(key)
        candidates.append(candidate)

    for entry in sources or []:
        add(entry)
    if analysis is not None:
        for violation in getattr(analysis, "violations", []) or []:
            add(getattr(violation.location, "file", ""))
        for metrics in getattr(analysis, "file_metrics", []) or []:
            add(getattr(metrics, "path", ""))
    if not candidates and project is not None:
        for path in _discover_project_sources(project):
            add(path)
    return [candidate for candidate in candidates if candidate.is_file()]


def _discover_project_sources(project: Any) -> list[Path]:
    """Return the source files of *project*."""
    try:
        from sast.rules.engine import RuleEngine

        return list(RuleEngine(project).discover_files())
    except Exception:
        return []


def _relative_path(project: Any, path: Path) -> str:
    """Return *path* relative to the project root."""
    if project is not None:
        relative = getattr(project, "relative", None)
        if callable(relative):
            try:
                return relative(path)
            except Exception:
                pass
    return path.as_posix()


def _functions_of(declaration: Any) -> list[Any]:
    """Return the function declarations of a parsed node.

    Namespaces and classes are traversed so that the functions they hold are
    linked as well.
    """
    kind = getattr(declaration, "kind", "")
    if kind == "function_decl":
        return [declaration]
    if kind == "class_decl":
        found: list[Any] = []
        for method in getattr(declaration, "methods", []) or []:
            found.extend(_functions_of(method))
        return found
    if kind == "namespace_decl":
        found = []
        body = getattr(declaration, "body", None)
        for child in getattr(body, "statements", []) or []:
            found.extend(_functions_of(child))
        return found
    return []


def _iter_functions(path: Path) -> list[tuple[str, SourceLocation]]:
    """Return the functions declared in *path*."""
    try:
        from sast.ast.parser import parse_file
    except Exception:
        return []
    try:
        unit, _errors = parse_file(str(path))
    except Exception:
        return []
    functions: list[tuple[str, SourceLocation]] = []
    for declaration in getattr(unit, "declarations", []) or []:
        for function in _functions_of(declaration):
            name = getattr(function, "name", "")
            location = getattr(function, "location", None)
            if not name or not isinstance(location, SourceLocation):
                continue
            functions.append((name, location))
    return functions


def _match_tests(case: Any, index: _RequirementIndex) -> list[str]:
    """Return the requirements a test case belongs to."""
    matched: list[str] = []

    def remember(identifier: str) -> None:
        if identifier and identifier not in matched:
            matched.append(identifier)

    for identifier in getattr(case, "requirement_ids", []) or []:
        found = index.match_id(str(identifier))
        if found:
            remember(found)
    target = str(getattr(case, "target", "") or "")
    if target:
        found = index.match(target)
        if found:
            remember(found)
    name = str(getattr(case, "name", "") or "")
    if name:
        found = index.match(name)
        if found:
            remember(found)
    description_needles = [
        tokens
        for tokens in (_tokens(target), _tokens(name))
        if len(tokens) >= 1 and any(len(token) >= 3 for token in tokens)
    ]
    if description_needles:
        for identifier, description_tokens in index.descriptions():
            if identifier in matched:
                continue
            for needle in description_needles:
                if _contains_sequence(description_tokens, needle):
                    remember(identifier)
                    break
    return matched


def build_matrix(
    project: Any,
    requirements: Any,
    *,
    analysis: AnalysisResult | None = None,
    test_suites: Any = None,
    sources: Any = None,
) -> TraceabilityMatrix:
    """Build a traceability matrix for *requirements*.

    ``test_suites`` accepts test suites as well as plain test cases,
    ``sources`` a list of files that should be scanned for function names.
    When no test suites are given the suites of the project are discovered.
    When no requirements are given the requirement files configured for the
    project are loaded.
    """
    requirement_set = _as_requirement_set(requirements)
    if not len(requirement_set) and project is not None:
        requirement_set = _project_requirements(project)
    matrix = TraceabilityMatrix(requirement_set, [])
    index = _RequirementIndex(requirement_set)

    for case in _collect_test_cases(project, test_suites):
        identifier = str(getattr(case, "id", "") or getattr(case, "name", "") or "")
        if not identifier:
            continue
        matrix.register_test(identifier)
        target_name = str(getattr(case, "name", "") or identifier)
        for requirement_id in _match_tests(case, index):
            matrix.add(
                TraceLink(
                    requirement_id=requirement_id,
                    target_kind="test",
                    target_id=identifier,
                    target_name=target_name,
                    comment="auto",
                )
            )

    for path in _collect_sources(project, analysis, sources):
        relative = _relative_path(project, path)
        for name, location in _iter_functions(path):
            requirement_id = index.match(name)
            if not requirement_id:
                continue
            matrix.add(
                TraceLink(
                    requirement_id=requirement_id,
                    target_kind="code",
                    target_id=f"{relative}:{location.line}",
                    target_name=name,
                    location=SourceLocation(
                        file=relative,
                        line=location.line,
                        column=location.column,
                    ),
                    comment="auto",
                )
            )
        requirement_id = index.match(path.stem)
        if requirement_id:
            matrix.add(
                TraceLink(
                    requirement_id=requirement_id,
                    target_kind="code",
                    target_id=relative,
                    target_name=path.stem,
                    location=SourceLocation(file=relative, line=1, column=1),
                    comment="auto",
                )
            )

    if analysis is not None:
        for violation in getattr(analysis, "violations", []) or []:
            requirement_id = index.match(getattr(violation, "function", "") or "")
            if not requirement_id:
                location = getattr(violation, "location", None)
                file_name = getattr(location, "file", "") or ""
                requirement_id = index.match(Path(file_name).stem)
            if not requirement_id:
                continue
            severity = getattr(violation, "severity", "")
            severity_value = getattr(severity, "value", str(severity))
            matrix.add(
                TraceLink(
                    requirement_id=requirement_id,
                    target_kind="finding",
                    target_id=str(getattr(violation, "fingerprint", "") or violation.rule_id),
                    target_name=str(getattr(violation, "rule_id", "")),
                    location=getattr(violation, "location", None),
                    comment=str(getattr(violation, "message", "")),
                    severity=str(severity_value),
                )
            )
    return matrix
