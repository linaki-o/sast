"""Report renderers for CodeShield.

The package exposes one renderer per output format (``json``, ``sarif``,
``xml`` and ``html``) plus two convenience helpers (:func:`render` and
:func:`render_all`) that write the reports into an output directory.

The small path helpers used by the individual renderers live here as well.
They are defined before the renderer imports so that the sub modules can use
them without running into a circular import.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from sast.core.models import AnalysisResult
    from sast.core.config import Project

DEFAULT_OUTPUT_DIRNAME = "sast-report"

FORMAT_ALIASES = {
    "json": "json",
    "sarif": "sarif",
    "xml": "xml",
    "html": "html",
    "htm": "html",
}


def resolve_output_dir(output_dir: str | Path | None = None) -> Path:
    """Create (when needed) and return the directory the reports go to."""
    path = Path(output_dir) if output_dir else Path.cwd() / DEFAULT_OUTPUT_DIRNAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def relative_uri(path: str | Path) -> str:
    """Normalise *path* into a relative POSIX style URI."""
    text = str(path).replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    if len(text) > 2 and text[1] == ":":
        text = text[2:].lstrip("/")
    return text or "unknown"


def sanitize_anchor(path: str | Path) -> str:
    """Build a stable HTML anchor identifier for *path*."""
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in relative_uri(path))
    parts = [part for part in cleaned.split("-") if part]
    return "-".join(parts) or "file"


from sast.report.html_report import render_html
from sast.report.json_report import render_json
from sast.report.sarif import render_sarif
from sast.report.xml_report import render_xml

RENDERERS = {
    "json": render_json,
    "sarif": render_sarif,
    "xml": render_xml,
    "html": render_html,
}

__all__ = [
    "RENDERERS",
    "render",
    "render_all",
    "render_html",
    "render_json",
    "render_sarif",
    "render_xml",
]


def _normalise_format(fmt: str) -> str:
    """Map *fmt* onto one of the supported format keys."""
    key = FORMAT_ALIASES.get(str(fmt).strip().lower())
    if key is None:
        supported = ", ".join(sorted(RENDERERS))
        raise ValueError(f"unsupported report format: {fmt!r} (expected one of: {supported})")
    return key


def render(
    result: "AnalysisResult",
    fmt: str,
    output_dir: str | Path | None = None,
    *,
    project: "Project | None" = None,
    theme: str = "dark",
) -> list[Path]:
    """Render *result* as *fmt* and return the list of written files."""
    key = _normalise_format(fmt)
    if key == "html":
        return [render_html(result, output_dir, project=project, theme=theme)]
    return [RENDERERS[key](result, output_dir)]


def render_all(
    result: "AnalysisResult",
    formats: Iterable[str],
    output_dir: str | Path | None = None,
    *,
    project: "Project | None" = None,
    theme: str = "dark",
) -> list[Path]:
    """Render *result* in every requested format and return the written files."""
    written: list[Path] = []
    seen: set[str] = set()
    for fmt in formats:
        key = _normalise_format(fmt)
        if key in seen:
            continue
        seen.add(key)
        written.extend(render(result, key, output_dir, project=project, theme=theme))
    return written
