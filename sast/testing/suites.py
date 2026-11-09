"""Discovery and loading of test suites.

A suite can live in three different places:

* a Python module exposing ``SUITES`` (a list of suites or dictionaries) or a
  ``suite()`` function;
* a JSON document;
* a YAML document.

All of them are normalised into :class:`~sast.testing.model.TestSuite`
objects so that the runner does not care where a test came from.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from sast.core.config import Project
from sast.testing.model import TestCase, TestSuite

__all__ = [
    "load_suites_from_paths",
    "load_suite_from_path",
    "discover_suites",
    "make_suite",
    "SuiteLoadError",
]

PYTHON_SUFFIXES = (".py",)
DATA_SUFFIXES = (".json", ".yaml", ".yml")


class SuiteLoadError(Exception):
    """Raised when a suite definition cannot be loaded."""


def make_suite(name: str, tests: Iterable[TestCase]) -> TestSuite:
    """Build a suite called *name* holding *tests*."""
    return TestSuite(name=name, tests=list(tests))


def load_suites_from_paths(paths: Sequence[str | Path]) -> list[TestSuite]:
    """Load every suite found in *paths*."""
    suites: list[TestSuite] = []
    for path in paths or []:
        suites.extend(load_suite_from_path(path))
    return suites


def load_suite_from_path(path: str | Path) -> list[TestSuite]:
    """Load the suite(s) stored in *path*."""
    candidate = Path(path)
    if not candidate.exists():
        raise SuiteLoadError(f"test suite file not found: {candidate}")
    suffix = candidate.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return _load_python_suite(candidate)
    if suffix in DATA_SUFFIXES:
        return _load_data_suite(candidate)
    raise SuiteLoadError(f"unsupported test suite file: {candidate}")


def _load_python_suite(path: Path) -> list[TestSuite]:
    module_name = f"codeshield_suite_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise SuiteLoadError(f"cannot import the test suite module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise SuiteLoadError(f"cannot import the test suite module {path}: {error}") from error
    suites: list[TestSuite] = []
    candidates: list[Any] = []
    factory = getattr(module, "suite", None)
    if callable(factory):
        try:
            candidates.append(factory())
        except Exception as error:
            raise SuiteLoadError(f"the suite() factory of {path} failed: {error}") from error
    exported = getattr(module, "SUITES", None)
    if exported:
        candidates.append(exported)
    if not candidates:
        raise SuiteLoadError(
            f"the module {path} exposes neither a suite() function nor a SUITES list"
        )
    for candidate in candidates:
        suites.extend(_coerce_suites(candidate, path))
    return suites


def _coerce_suites(candidate: Any, path: Path) -> list[TestSuite]:
    suites: list[TestSuite] = []
    if candidate is None:
        return suites
    if isinstance(candidate, TestSuite):
        return [candidate]
    if isinstance(candidate, dict):
        return [TestSuite.from_dict(candidate)]
    if isinstance(candidate, (list, tuple)):
        for item in candidate:
            suites.extend(_coerce_suites(item, path))
        return suites
    raise SuiteLoadError(f"unsupported suite definition in {path}: {type(candidate).__name__}")


def _load_data_suite(path: Path) -> list[TestSuite]:
    text = path.read_text(encoding="utf-8")
    data: Any
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise SuiteLoadError(f"invalid JSON in {path}: {error}") from error
    else:
        try:
            import yaml
        except ImportError as error:
            raise SuiteLoadError("PyYAML is required to read YAML suites") from error
        try:
            data = yaml.safe_load(text)
        except Exception as error:
            raise SuiteLoadError(f"invalid YAML in {path}: {error}") from error
    if data is None:
        return []
    if isinstance(data, dict):
        if "suites" in data and isinstance(data["suites"], list):
            return [TestSuite.from_dict(item) for item in data["suites"]]
        return [TestSuite.from_dict(data)]
    if isinstance(data, list):
        return [TestSuite.from_dict(item) for item in data]
    raise SuiteLoadError(f"unsupported suite definition in {path}")


def discover_suites(project: Project) -> list[TestSuite]:
    """Find every suite stored below the test directories of *project*."""
    suites: list[TestSuite] = []
    seen: set[str] = set()
    for directory in project.config.test_dirs:
        root = project.resolve(directory)
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix not in PYTHON_SUFFIXES and suffix not in DATA_SUFFIXES:
                continue
            if suffix in PYTHON_SUFFIXES and not path.name.startswith("test_"):
                continue
            if suffix in DATA_SUFFIXES and not (
                path.name.endswith("_test.json")
                or path.name.endswith("_test.yaml")
                or path.name.endswith("_test.yml")
            ):
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            try:
                suites.extend(load_suite_from_path(path))
            except SuiteLoadError:
                continue
    return suites
