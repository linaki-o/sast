"""Requirement importers.

Supported formats are YAML, JSON, CSV, Excel workbooks, Markdown and Word
documents.  The format is derived from the file extension.  Every importer is
tolerant: unknown columns are ignored, missing columns stay empty and rows
that cannot be understood are skipped with a warning instead of aborting the
whole import.
"""

from __future__ import annotations

import csv
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree

from sast.core.models import SourceLocation
from sast.traceability.requirements import Requirement, RequirementSet

__all__ = [
    "detect_format",
    "load_requirements",
    "load_requirements_from_paths",
    "load_yaml_requirements",
    "load_json_requirements",
    "load_csv_requirements",
    "load_excel_requirements",
    "load_markdown_requirements",
    "load_docx_requirements",
]

YAML_SUFFIXES = frozenset({".yaml", ".yml"})
JSON_SUFFIXES = frozenset({".json"})
CSV_SUFFIXES = frozenset({".csv", ".tsv"})
EXCEL_SUFFIXES = frozenset({".xlsx", ".xlsm"})
MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})
DOCX_SUFFIXES = frozenset({".docx"})

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "id": (
        "id",
        "requirement_id",
        "req_id",
        "requirementid",
        "identifier",
        "key",
        "number",
    ),
    "title": (
        "title",
        "summary",
        "name",
        "subject",
        "headline",
        "requirement",
        "requirement_title",
        "short_description",
    ),
    "description": (
        "description",
        "text",
        "detail",
        "details",
        "desc",
        "body",
        "requirement_text",
        "acceptance_criteria",
    ),
    "priority": ("priority", "prio", "importance"),
    "status": ("status", "state", "lifecycle", "phase", "workflow_state"),
    "category": ("category", "type", "area", "module", "group", "domain", "component"),
    "tags": ("tags", "labels", "keywords", "tag"),
    "parent_id": (
        "parent_id",
        "parent",
        "parent_req_id",
        "parent_requirement",
        "parentid",
        "parent_requirement_id",
    ),
    "source": ("source", "origin", "system", "document", "doc", "file"),
}

_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_ID_TOKEN_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_]*[-_][A-Za-z0-9_]+)\s*[:.]?\s*(.*)$"
)
_MARKER_RE = re.compile(r"<!--\s*req(?:uirement)?\s*:\s*(.*?)\s*-->", re.IGNORECASE)
_ID_PARAGRAPH_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_]*[-_][A-Za-z0-9_]+)\s*[:.]\s*(.+)$"
)
_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.*)$")
_META_RE = re.compile(r"^(?:\*\*|__)?\s*([A-Za-z][A-Za-z _-]*?)\s*(?:\*\*|__)?\s*:\s*(.*)$")
_WORD_NAMESPACE = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _normalise_key(key: Any) -> str:
    """Normalise a column name so that aliases can be compared."""
    text = str(key or "").strip().lower()
    text = re.sub(r"[^0-9a-z]+", "_", text)
    return text.strip("_")


_ALIAS_MAP: dict[str, str] = {}
for _field, _aliases in FIELD_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_MAP.setdefault(_normalise_key(_alias), _field)


def detect_format(path: str | Path) -> str:
    """Return the format name implied by the extension of *path*."""
    suffix = Path(path).suffix.lower()
    if suffix in YAML_SUFFIXES:
        return "yaml"
    if suffix in JSON_SUFFIXES:
        return "json"
    if suffix in CSV_SUFFIXES:
        return "csv"
    if suffix in EXCEL_SUFFIXES:
        return "excel"
    if suffix in MARKDOWN_SUFFIXES:
        return "markdown"
    if suffix in DOCX_SUFFIXES:
        return "docx"
    return "unknown"


def _requirement_from_mapping(mapping: dict, source: str = "") -> Requirement:
    """Build a requirement from an arbitrary mapping."""
    if not isinstance(mapping, dict):
        raise ValueError("entry is not a mapping")
    values: dict[str, Any] = {}
    extras: dict[str, Any] = {}
    for key, value in mapping.items():
        field = _ALIAS_MAP.get(_normalise_key(key))
        if field is None:
            extras[key] = value
        elif field not in values or values[field] in (None, ""):
            values[field] = value
    identifier = str(values.get("id") or "").strip()
    if not identifier:
        raise ValueError("entry has no id")
    metadata = values.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    metadata = dict(metadata)
    for key, value in extras.items():
        metadata.setdefault(str(key), value)
    location = values.get("source_location")
    if location is None:
        location = mapping.get("source_location") or mapping.get("location")
    requirement = Requirement.from_dict(
        {
            "id": identifier,
            "title": values.get("title") or "",
            "description": values.get("description") or "",
            "source": values.get("source") or source,
            "priority": values.get("priority") or "medium",
            "status": values.get("status") or "draft",
            "category": values.get("category") or "",
            "tags": values.get("tags") or [],
            "parent_id": values.get("parent_id") or "",
            "source_location": location,
            "metadata": metadata,
        }
    )
    if requirement.source_location is None and requirement.source:
        line = mapping.get("line")
        if line is not None:
            try:
                requirement.source_location = SourceLocation(
                    requirement.source, int(line), 1
                )
            except (TypeError, ValueError):
                requirement.source_location = None
    return requirement


def _looks_like_identifier(token: str) -> bool:
    """Is *token* shaped like a requirement identifier?"""
    if not token:
        return False
    if any(character.isdigit() for character in token):
        return True
    return token.isupper()


def _split_identifier(text: str) -> tuple[str, str]:
    """Split *text* into a requirement identifier and a title."""
    stripped = str(text or "").strip()
    match = _ID_TOKEN_RE.match(stripped)
    if not match:
        return "", stripped
    token = match.group(1)
    rest = match.group(2).strip()
    if not _looks_like_identifier(token):
        return "", stripped
    return token, rest


class _Builder:
    """Collects requirements while walking a document."""

    def __init__(self, source: str = "") -> None:
        self.result = RequirementSet()
        self.source = source
        self._current: Requirement | None = None
        self._body: list[str] = []
        self._counter = 0
        self._ids: set[str] = set()

    def _synthesise_id(self) -> str:
        while True:
            self._counter += 1
            candidate = f"REQ-{self._counter:03d}"
            if candidate not in self._ids:
                return candidate

    def begin(
        self, identifier: str, title: str, *, synthetic: bool = True
    ) -> Requirement | None:
        """Start a new requirement.

        When *synthetic* is false a heading without an identifier is treated
        as a document title and no requirement is created.
        """
        self.flush()
        wanted = str(identifier or "").strip()
        if not wanted:
            if not synthetic:
                return None
            wanted = self._synthesise_id()
        if wanted in self._ids:
            self.result.warnings.append(
                f"{self.source}: duplicate requirement id {wanted!r} ignored"
            )
            self._current = None
            return None
        self._ids.add(wanted)
        requirement = Requirement(id=wanted, title=str(title or "").strip(), source=self.source)
        self.result.add(requirement)
        self._current = requirement
        return requirement

    def current(self) -> Requirement | None:
        """Return the requirement that is currently being filled in."""
        return self._current

    def flush(self) -> None:
        """Store the buffered body as the description of the current item."""
        if self._current is not None:
            text = "\n".join(self._body).strip()
            if text and not self._current.description:
                self._current.description = text
            self._body = []

    def add_text(self, text: str) -> None:
        """Append a line of free text to the current requirement."""
        if self._current is None:
            return
        self._body.append(text)

    def set_field(self, name: str, value: str) -> None:
        """Assign a metadata field to the current requirement."""
        if self._current is None:
            return
        text = str(value or "").strip()
        if not text:
            return
        field = _ALIAS_MAP.get(_normalise_key(name))
        if field == "priority":
            self._current.priority = text.lower()
        elif field == "status":
            self._current.status = text.lower()
        elif field == "category":
            self._current.category = text
        elif field == "tags":
            for tag in re.split(r"[;,]", text):
                tag = tag.strip()
                if tag and tag not in self._current.tags:
                    self._current.tags.append(tag)
        elif field == "parent_id":
            self._current.parent_id = text
        elif field == "title":
            if not self._current.title:
                self._current.title = text
        elif field == "description":
            if not self._current.description:
                self._current.description = text
        elif field == "id":
            pass
        else:
            self._current.metadata[str(name).strip().lower()] = text


def _load_structured(data: Any, source: str) -> RequirementSet:
    """Load requirements from a parsed YAML or JSON document."""
    result = RequirementSet()
    if isinstance(data, dict):
        payload: Any = None
        for key in ("requirements", "items", "rows", "records", "entries"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                payload = candidate
                break
        if payload is None:
            if any(_ALIAS_MAP.get(_normalise_key(key)) == "id" for key in data):
                payload = [data]
            else:
                result.warnings.append(f"{source}: no requirement list found")
                return result
        data = payload
    if not isinstance(data, list):
        result.warnings.append(f"{source}: unsupported document structure")
        return result
    for number, entry in enumerate(data, start=1):
        if not isinstance(entry, dict):
            result.warnings.append(f"{source}: entry {number} is not a mapping, skipped")
            continue
        try:
            requirement = _requirement_from_mapping(entry, source)
        except ValueError as error:
            result.warnings.append(f"{source}: entry {number} skipped ({error})")
            continue
        result.add(requirement)
    return result


def load_yaml_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from a YAML document."""
    import yaml

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        result = RequirementSet()
        result.warnings.append(f"{file_path}: {error}")
        return result
    try:
        data = yaml.safe_load(text)
    except Exception as error:
        result = RequirementSet()
        result.warnings.append(f"{file_path}: invalid YAML ({error})")
        return result
    return _load_structured(data, str(file_path))


def load_json_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from a JSON document."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        result = RequirementSet()
        result.warnings.append(f"{file_path}: {error}")
        return result
    try:
        data = json.loads(text)
    except Exception as error:
        result = RequirementSet()
        result.warnings.append(f"{file_path}: invalid JSON ({error})")
        return result
    return _load_structured(data, str(file_path))


def _row_to_requirement(
    mapping: dict, source: str, result: RequirementSet, position: int
) -> None:
    try:
        requirement = _requirement_from_mapping(mapping, source)
    except ValueError as error:
        result.warnings.append(f"{source}: row {position} skipped ({error})")
        return
    result.add(requirement)


def load_csv_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from a delimiter separated file."""
    file_path = Path(path)
    result = RequirementSet()
    try:
        text = file_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as error:
        result.warnings.append(f"{file_path}: {error}")
        return result
    if not text.strip():
        return result
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(text.splitlines(), dialect=dialect)
    if not reader.fieldnames:
        result.warnings.append(f"{file_path}: no header row found")
        return result
    for position, row in enumerate(reader, start=2):
        if not row:
            continue
        mapping = {
            key: value
            for key, value in row.items()
            if isinstance(key, str) and key.strip()
        }
        if not any(str(value or "").strip() for value in mapping.values()):
            continue
        _row_to_requirement(mapping, str(file_path), result, position)
    return result


def load_excel_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from an Excel workbook."""
    try:
        import openpyxl
    except ImportError as error:
        raise RuntimeError(
            "openpyxl is required to read Excel requirement files"
        ) from error

    file_path = Path(path)
    result = RequirementSet()
    try:
        workbook = openpyxl.load_workbook(
            filename=str(file_path), data_only=True, read_only=True
        )
    except Exception as error:
        result.warnings.append(f"{file_path}: cannot read workbook ({error})")
        return result
    try:
        for sheet in workbook.worksheets:
            rows = sheet.iter_rows(values_only=True)
            try:
                header = next(rows)
            except StopIteration:
                continue
            columns: dict[str, int] = {}
            for index, title in enumerate(header):
                if title is None:
                    continue
                field = _ALIAS_MAP.get(_normalise_key(title))
                if field and field not in columns:
                    columns[field] = index
            if "id" not in columns:
                result.warnings.append(
                    f"{file_path}: sheet '{sheet.title}' has no id column, skipped"
                )
                continue
            for position, row in enumerate(rows, start=2):
                if row is None:
                    continue
                mapping: dict[str, Any] = {}
                for field, index in columns.items():
                    value = row[index] if index < len(row) else None
                    if value is None:
                        continue
                    if isinstance(value, str) and not value.strip():
                        continue
                    mapping[field] = value
                if not mapping:
                    continue
                _row_to_requirement(mapping, str(file_path), result, position)
    finally:
        try:
            workbook.close()
        except Exception:
            pass
    return result


def load_markdown_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from a Markdown document."""
    file_path = Path(path)
    result = RequirementSet()
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        result.warnings.append(f"{file_path}: {error}")
        return result

    builder = _Builder(str(file_path))
    for line in text.splitlines():
        marker = _MARKER_RE.search(line)
        if marker:
            _apply_marker(builder, marker.group(1))
            continue
        heading = _HEADING_RE.match(line)
        if heading:
            identifier, title = _split_identifier(heading.group(2))
            builder.begin(identifier, title, synthetic=len(heading.group(1)) > 1)
            continue
        bullet = _BULLET_RE.match(line)
        if bullet:
            content = bullet.group(1).strip()
            meta = _META_RE.match(content)
            if meta and _ALIAS_MAP.get(_normalise_key(meta.group(1))):
                builder.set_field(meta.group(1), meta.group(2))
                continue
            builder.add_text(content)
            continue
        if not line.strip():
            if builder.current() is not None:
                builder.add_text("")
            continue
        builder.add_text(line.strip())
    builder.flush()
    result = builder.result
    return result


def _apply_marker(builder: _Builder, payload: str) -> None:
    """Apply a ``<!-- req: id=..., priority=... -->`` marker."""
    text = str(payload or "").strip()
    if not text:
        return
    fields: dict[str, str] = {}
    identifier = ""
    title_hint = ""
    if "=" in text:
        for chunk in re.split(r"[,;]", text):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key:
                fields[key] = value
        identifier = fields.get("id") or fields.get("requirement_id") or ""
        title_hint = (
            fields.get("title") or fields.get("summary") or fields.get("name") or ""
        )
        if not identifier:
            candidate = fields.get("requirement") or ""
            head = candidate.split()[0] if candidate.split() else ""
            if candidate and _looks_like_identifier(head):
                identifier = candidate
            elif candidate:
                title_hint = title_hint or candidate
    else:
        identifier = text
    if identifier:
        split_identifier, title = _split_identifier(identifier)
        builder.begin(split_identifier or identifier, title_hint or title)
    else:
        requirement = builder.current()
        if requirement is None:
            return
    for key, value in fields.items():
        if key.lower() in {"id", "requirement_id"}:
            continue
        builder.set_field(key, value)


def load_docx_requirements(path: str | Path) -> RequirementSet:
    """Load requirements from a Word document.

    The document is read straight from the OPC package: ``word/document.xml``
    is parsed with :mod:`xml.etree` so that no third party library is needed.
    """
    file_path = Path(path)
    builder = _Builder(str(file_path))
    try:
        archive = zipfile.ZipFile(file_path)
    except (OSError, zipfile.BadZipFile) as error:
        builder.result.warnings.append(f"{file_path}: cannot read document ({error})")
        return builder.result
    try:
        try:
            payload = archive.read("word/document.xml")
        except KeyError:
            builder.result.warnings.append(
                f"{file_path}: not a Word document (no word/document.xml)"
            )
            return builder.result
    finally:
        archive.close()

    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        builder.result.warnings.append(f"{file_path}: invalid document ({error})")
        return builder.result

    for style, text in _document_paragraphs(root):
        if not text:
            continue
        level = _heading_level(style)
        if level:
            identifier, title = _split_identifier(text)
            builder.begin(identifier, title, synthetic=level > 1)
            continue
        inline = _ID_PARAGRAPH_RE.match(text)
        if inline and _looks_like_identifier(inline.group(1)):
            builder.begin(inline.group(1), inline.group(2).strip())
            continue
        bullet = _BULLET_RE.match(text)
        if bullet:
            content = bullet.group(1).strip()
            meta = _META_RE.match(content)
            if meta and _ALIAS_MAP.get(_normalise_key(meta.group(1))):
                builder.set_field(meta.group(1), meta.group(2))
                continue
            builder.add_text(content)
            continue
        meta = _META_RE.match(text)
        if meta and _ALIAS_MAP.get(_normalise_key(meta.group(1))):
            builder.set_field(meta.group(1), meta.group(2))
            continue
        builder.add_text(text)
    builder.flush()
    return builder.result


def _document_paragraphs(root: ElementTree.Element) -> list[tuple[str, str]]:
    """Return the ``(style, text)`` pairs of a Word document."""
    paragraphs: list[tuple[str, str]] = []
    for element in root.iter(f"{_WORD_NAMESPACE}p"):
        text = "".join(node.text or "" for node in element.iter(f"{_WORD_NAMESPACE}t"))
        style = ""
        properties = element.find(f"{_WORD_NAMESPACE}pPr")
        if properties is not None:
            style_node = properties.find(f"{_WORD_NAMESPACE}pStyle")
            if style_node is not None:
                style = (style_node.get(f"{_WORD_NAMESPACE}val") or "").strip()
        paragraphs.append((style, text.strip()))
    return paragraphs


def _heading_level(style: str) -> int:
    """Return the heading level of a Word paragraph style.

    Zero means that the paragraph is not a heading at all.
    """
    normalised = str(style or "").replace(" ", "").replace("_", "").lower()
    if not normalised:
        return 0
    if normalised.startswith("heading"):
        rest = normalised[len("heading") :]
        try:
            return max(1, int(rest))
        except ValueError:
            return 2
    if normalised in {"title", "subtitle"}:
        return 1
    return 0


def _load_single(path: Path) -> RequirementSet:
    """Load one requirement file."""
    fmt = detect_format(path)
    if fmt == "yaml":
        return load_yaml_requirements(path)
    if fmt == "json":
        return load_json_requirements(path)
    if fmt == "csv":
        return load_csv_requirements(path)
    if fmt == "excel":
        return load_excel_requirements(path)
    if fmt == "markdown":
        return load_markdown_requirements(path)
    if fmt == "docx":
        return load_docx_requirements(path)
    raise ValueError(f"unsupported requirement file format: {path.suffix or path.name}")


def load_requirements_from_paths(
    paths: Iterable[str | Path], *, project: Any = None
) -> RequirementSet:
    """Load every requirement file of *paths* into a single set."""
    result = RequirementSet()
    if paths is None:
        return result
    if isinstance(paths, (str, Path)):
        paths = [paths]
    seen: set[str] = set()
    for entry in paths:
        if entry is None:
            continue
        candidate = Path(entry)
        if project is not None and not candidate.is_absolute():
            resolver = getattr(project, "resolve", None)
            if callable(resolver):
                candidate = resolver(candidate)
        if not candidate.is_file():
            result.warnings.append(f"{entry}: file not found")
            continue
        try:
            loaded = _load_single(candidate)
        except Exception as error:
            result.warnings.append(f"{entry}: {error}")
            continue
        result.warnings.extend(loaded.warnings)
        for requirement in loaded.requirements:
            if requirement.id in seen:
                result.warnings.append(
                    f"{entry}: duplicate requirement id {requirement.id!r} skipped"
                )
                continue
            seen.add(requirement.id)
            result.add(requirement)
    return result


def load_requirements(path: str | Path | Iterable[str | Path] | Any) -> RequirementSet:
    """Load requirements from a file, a list of files or a project.

    Passing a project uses the requirement files configured for it, which is
    what the server front end does.
    """
    if path is None:
        return RequirementSet()
    if isinstance(path, (list, tuple, set)):
        return load_requirements_from_paths(list(path))
    config = getattr(path, "config", None)
    if config is not None and hasattr(path, "root"):
        files = getattr(config, "requirements_files", []) or []
        return load_requirements_from_paths(list(files), project=path)
    return load_requirements_from_paths([path])
