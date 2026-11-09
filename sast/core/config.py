"""Project configuration.

The configuration is read from ``sast.yaml`` / ``.sast.yaml`` at the project
root (or from an explicit ``--config`` path). Every field has a sane default
so that a project can be analysed without writing any configuration at all.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_NAMES = ("sast.yaml", "sast.yml", ".sast.yaml", ".sast.yml")

DEFAULT_EXCLUDES = (
    "**/build/**",
    "**/out/**",
    "**/third_party/**",
    "**/thirdparty/**",
    "**/vendor/**",
    "**/node_modules/**",
    "**/.git/**",
    "**/generated/**",
)


@dataclass
class AnalysisConfig:
    """Everything that influences how the analyser behaves."""

    # -- sources ---------------------------------------------------------
    source_dirs: list[str] = field(default_factory=lambda: ["src", "include", "."])
    files: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    language: str = "auto"  # auto | c | c++ | mixed
    encoding: str = "utf-8"

    # -- rule selection --------------------------------------------------
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    rule_packs: list[str] = field(default_factory=list)
    severity_threshold: str = "info"
    categories: list[str] = field(default_factory=list)

    # -- thresholds ------------------------------------------------------
    max_cyclomatic_complexity: int = 10
    max_function_lines: int = 60
    max_file_lines: int = 800
    max_nesting_depth: int = 4
    max_parameters: int = 5
    min_comment_ratio: float = 0.0
    max_duplicate_blocks: int = 0

    # -- behaviour -------------------------------------------------------
    follow_includes: bool = True
    include_system_headers: bool = False
    analyse_tests: bool = True
    suppress_via_comments: bool = True
    ignore_pattern: list[str] = field(
        default_factory=lambda: ["sast:ignore", "coverity", "codescan"]
    )

    # -- reporting -------------------------------------------------------
    report_formats: list[str] = field(default_factory=lambda: ["html", "json"])
    report_dir: str = "sast-report"
    html_theme: str = "dark"

    # -- unit testing ----------------------------------------------------
    test_dirs: list[str] = field(default_factory=lambda: ["test", "tests", "unittest"])
    coverage_dir: str = "coverage"
    test_framework: str = "auto"  # auto | native | interpreter

    # -- traceability ----------------------------------------------------
    requirements_files: list[str] = field(default_factory=list)
    trace_matrix_output: str = "traceability.csv"

    # -- incremental -----------------------------------------------------
    incremental: bool = False
    baseline_file: str = "sast-baseline.json"

    # -- quality gate ----------------------------------------------------
    fail_on: str = "high"  # never | info | low | medium | high | critical

    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def source_roots(self, project_root: Path) -> list[Path]:
        roots: list[Path] = []
        for entry in self.source_dirs:
            candidate = (project_root / entry).resolve()
            if candidate.exists():
                roots.append(candidate)
        if not roots:
            roots.append(project_root.resolve())
        # de-duplicate while preserving order
        seen: set[Path] = set()
        unique: list[Path] = []
        for root in roots:
            if root not in seen:
                seen.add(root)
                unique.append(root)
        return unique

    def to_dict(self) -> dict[str, Any]:
        data = {
            "source_dirs": self.source_dirs,
            "files": self.files,
            "excludes": self.excludes,
            "language": self.language,
            "encoding": self.encoding,
            "enabled_rules": self.enabled_rules,
            "disabled_rules": self.disabled_rules,
            "rule_packs": self.rule_packs,
            "severity_threshold": self.severity_threshold,
            "categories": self.categories,
            "max_cyclomatic_complexity": self.max_cyclomatic_complexity,
            "max_function_lines": self.max_function_lines,
            "max_file_lines": self.max_file_lines,
            "max_nesting_depth": self.max_nesting_depth,
            "max_parameters": self.max_parameters,
            "min_comment_ratio": self.min_comment_ratio,
            "max_duplicate_blocks": self.max_duplicate_blocks,
            "follow_includes": self.follow_includes,
            "include_system_headers": self.include_system_headers,
            "analyse_tests": self.analyse_tests,
            "suppress_via_comments": self.suppress_via_comments,
            "ignore_pattern": self.ignore_pattern,
            "report_formats": self.report_formats,
            "report_dir": self.report_dir,
            "html_theme": self.html_theme,
            "test_dirs": self.test_dirs,
            "coverage_dir": self.coverage_dir,
            "test_framework": self.test_framework,
            "requirements_files": self.requirements_files,
            "trace_matrix_output": self.trace_matrix_output,
            "incremental": self.incremental,
            "baseline_file": self.baseline_file,
            "fail_on": self.fail_on,
        }
        if self.extra:
            data["extra"] = self.extra
        return data


_FIELD_TYPES = {
    "source_dirs": list,
    "files": list,
    "excludes": list,
    "enabled_rules": list,
    "disabled_rules": list,
    "rule_packs": list,
    "categories": list,
    "ignore_pattern": list,
    "report_formats": list,
    "test_dirs": list,
    "requirements_files": list,
    "language": str,
    "encoding": str,
    "severity_threshold": str,
    "max_cyclomatic_complexity": int,
    "max_function_lines": int,
    "max_file_lines": int,
    "max_nesting_depth": int,
    "max_parameters": int,
    "min_comment_ratio": float,
    "max_duplicate_blocks": int,
    "follow_includes": bool,
    "include_system_headers": bool,
    "analyse_tests": bool,
    "suppress_via_comments": bool,
    "report_dir": str,
    "html_theme": str,
    "coverage_dir": str,
    "test_framework": str,
    "trace_matrix_output": str,
    "incremental": bool,
    "baseline_file": str,
    "fail_on": str,
}


@dataclass
class Project:
    """A configured project: root directory plus the analysis settings."""

    root: Path
    config: AnalysisConfig
    path: Path | None = None

    @property
    def name(self) -> str:
        return self.root.name or str(self.root)

    def relative(self, path: str | Path) -> str:
        """Normalise *path* to a POSIX style path relative to the project root."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = (self.root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        try:
            return candidate.relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return candidate.as_posix()

    def resolve(self, value: str | Path) -> Path:
        candidate = Path(value)
        if candidate.is_absolute():
            return candidate
        return (self.root / candidate).resolve()

    def report_dir(self) -> Path:
        return self.resolve(self.config.report_dir)

    def source_roots(self) -> list[Path]:
        """The directories that are scanned for source files."""
        return self.config.source_roots(self.root)


def find_config_file(start: Path) -> Path | None:
    """Walk up from *start* looking for a configuration file."""
    current = start.resolve()
    for directory in [current, *current.parents]:
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_config_file(path: Path) -> AnalysisConfig:
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"invalid configuration file: {path}")

    known = {f.name for f in dataclasses.fields(AnalysisConfig)}
    values: dict[str, Any] = {}
    extra: dict[str, Any] = {}

    section = raw.get("analysis", raw)
    for key, value in (section or {}).items():
        if key == "extra":
            extra.update(value or {})
        elif key in known:
            expected = _FIELD_TYPES.get(key)
            if expected and value is not None and not isinstance(value, expected):
                if expected is float and isinstance(value, int):
                    value = float(value)
                elif expected is int and isinstance(value, float):
                    value = int(value)
                else:
                    raise ValueError(
                        f"configuration key '{key}' expects {expected.__name__}, "
                        f"got {type(value).__name__}"
                    )
            values[key] = value
        else:
            extra[key] = value

    config = AnalysisConfig(**values)
    config.extra.update(extra)
    return config


def load_project(root: str | Path | None = None, config_path: str | Path | None = None) -> Project:
    """Build a :class:`Project` from *root* (defaults to the CWD)."""
    base = Path(root).resolve() if root else Path.cwd().resolve()
    path: Path | None = None
    if config_path:
        path = Path(config_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"configuration file not found: {path}")
    else:
        path = find_config_file(base)

    config = load_config_file(path) if path else AnalysisConfig()
    return Project(root=base, config=config, path=path)


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
