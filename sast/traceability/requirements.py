"""Requirement model of the traceability subsystem.

A requirement is a small, serialisable record: a stable identifier, a couple
of descriptive fields and a bag of free form metadata.  Requirements are read
from a number of external formats (see :mod:`sast.traceability.importer`) and
are afterwards linked to tests, code locations and findings by
:mod:`sast.traceability.matrix`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from sast.core.models import SourceLocation

__all__ = ["Requirement", "RequirementSet", "PRIORITIES", "STATUSES"]

PRIORITIES: tuple[str, ...] = ("high", "medium", "low")

STATUSES: tuple[str, ...] = (
    "draft",
    "approved",
    "implemented",
    "verified",
    "deprecated",
)


def _as_text(value: Any) -> str:
    """Convert *value* into a stripped string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _as_tags(value: Any) -> list[str]:
    """Convert *value* into a list of tags."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace(",", ";").split(";")
        return [part.strip() for part in parts if part.strip()]
    if isinstance(value, (list, tuple, set)):
        tags: list[str] = []
        for item in value:
            tags.extend(_as_tags(item))
        return tags
    text = _as_text(value)
    return [text] if text else []


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _as_location(value: Any) -> SourceLocation | None:
    """Build a :class:`SourceLocation` from a mapping or an instance."""
    if value is None:
        return None
    if isinstance(value, SourceLocation):
        return value
    if isinstance(value, dict):
        file = _as_text(value.get("file") or value.get("path") or value.get("name"))
        if not file:
            return None
        return SourceLocation(
            file=file,
            line=_as_int(value.get("line"), 1),
            column=_as_int(value.get("column"), 1),
            end_line=_as_int(value.get("end_line"), -1),
            end_column=_as_int(value.get("end_column"), -1),
        )
    return None


@dataclass
class Requirement:
    """A single requirement of the project."""

    id: str
    title: str = ""
    description: str = ""
    source: str = ""
    priority: str = "medium"
    status: str = "draft"
    category: str = ""
    tags: list[str] = field(default_factory=list)
    parent_id: str = ""
    source_location: SourceLocation | None = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.id = _as_text(self.id)
        self.title = _as_text(self.title)
        self.description = _as_text(self.description)
        self.source = _as_text(self.source)
        self.priority = (_as_text(self.priority) or "medium").lower()
        self.status = (_as_text(self.status) or "draft").lower()
        self.category = _as_text(self.category)
        self.tags = _as_tags(self.tags)
        self.parent_id = _as_text(self.parent_id)
        self.source_location = _as_location(self.source_location)
        if not isinstance(self.metadata, dict):
            self.metadata = {}

    def to_dict(self) -> dict:
        """Return a JSON friendly representation."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "priority": self.priority,
            "status": self.status,
            "category": self.category,
            "tags": list(self.tags),
            "parent_id": self.parent_id,
            "source_location": (
                self.source_location.to_dict() if self.source_location else None
            ),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Requirement":
        """Build a requirement from a mapping.

        Raises :class:`ValueError` when the mapping carries no identifier.
        """
        if not isinstance(data, dict):
            raise ValueError("a requirement must be a mapping")
        identifier = _as_text(
            data.get("id") or data.get("requirement_id") or data.get("req_id")
        )
        if not identifier:
            raise ValueError("a requirement needs an id")
        location = _as_location(data.get("source_location") or data.get("location"))
        if location is None:
            source = _as_text(data.get("source"))
            line = data.get("line")
            if source and line is not None:
                location = SourceLocation(source, _as_int(line, 1), 1)
        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        return cls(
            id=identifier,
            title=_as_text(data.get("title")),
            description=_as_text(data.get("description")),
            source=_as_text(data.get("source")),
            priority=_as_text(data.get("priority")) or "medium",
            status=_as_text(data.get("status")) or "draft",
            category=_as_text(data.get("category")),
            tags=_as_tags(data.get("tags")),
            parent_id=_as_text(data.get("parent_id") or data.get("parent")),
            source_location=location,
            metadata=dict(metadata),
        )


class RequirementSet:
    """An ordered collection of requirements.

    The set also carries the warnings collected by the importers so that a
    caller can tell the user which rows could not be understood.
    """

    def __init__(self, requirements: list[Requirement] | None = None) -> None:
        self.requirements: list[Requirement] = []
        self.warnings: list[str] = []
        if requirements:
            self.extend(requirements)

    def add(self, requirement: Requirement | dict) -> Requirement:
        """Append *requirement* to the set and return it."""
        if isinstance(requirement, dict):
            requirement = Requirement.from_dict(requirement)
        self.requirements.append(requirement)
        return requirement

    def extend(self, requirements: Iterable[Requirement | dict]) -> None:
        """Append every requirement of *requirements*."""
        for requirement in requirements or []:
            self.add(requirement)

    def get(self, requirement_id: str) -> Requirement | None:
        """Return the requirement with *requirement_id* or ``None``."""
        if not requirement_id:
            return None
        wanted = str(requirement_id).strip()
        for requirement in self.requirements:
            if requirement.id == wanted:
                return requirement
        lowered = wanted.lower()
        for requirement in self.requirements:
            if requirement.id.lower() == lowered:
                return requirement
        return None

    def by_id(self) -> dict[str, Requirement]:
        """Return a mapping of identifier to requirement."""
        return {requirement.id: requirement for requirement in self.requirements}

    def ids(self) -> list[str]:
        """Return the identifiers in insertion order."""
        return [requirement.id for requirement in self.requirements]

    def filter(
        self,
        *,
        priority: str | Iterable[str] | None = None,
        status: str | Iterable[str] | None = None,
        category: str | Iterable[str] | None = None,
        tags: str | Iterable[str] | None = None,
    ) -> "RequirementSet":
        """Return a new set holding the requirements matching the filters.

        ``tags`` matches when a requirement carries at least one of the
        requested tags.
        """
        wanted_priorities = _as_filter_values(priority)
        wanted_statuses = _as_filter_values(status)
        wanted_categories = _as_filter_values(category)
        wanted_tags = _as_filter_values(tags)

        def keep(requirement: Requirement) -> bool:
            if wanted_priorities and requirement.priority not in wanted_priorities:
                return False
            if wanted_statuses and requirement.status not in wanted_statuses:
                return False
            if wanted_categories and requirement.category not in wanted_categories:
                return False
            if wanted_tags:
                owned = {tag.lower() for tag in requirement.tags}
                if not owned.intersection(wanted_tags):
                    return False
            return True

        result = RequirementSet([r for r in self.requirements if keep(r)])
        result.warnings = list(self.warnings)
        return result

    def to_dict(self) -> dict:
        """Return a JSON friendly representation."""
        return {
            "count": len(self.requirements),
            "requirements": [requirement.to_dict() for requirement in self.requirements],
            "warnings": list(self.warnings),
        }

    def __len__(self) -> int:
        return len(self.requirements)

    def __iter__(self) -> Iterator[Requirement]:
        return iter(self.requirements)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, Requirement):
            return self.get(item.id) is not None
        return self.get(str(item)) is not None

    def __repr__(self) -> str:
        return f"<RequirementSet {len(self.requirements)} requirements>"


def _as_filter_values(value: str | Iterable[str] | None) -> set[str]:
    """Normalise a filter argument into a set of lower case strings."""
    if value is None:
        return set()
    if isinstance(value, str):
        text = value.strip().lower()
        return {text} if text else set()
    result: set[str] = set()
    for item in value:
        text = str(item).strip().lower()
        if text:
            result.add(text)
    return result
