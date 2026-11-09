"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXAMPLE_PROJECT = ROOT / "examples" / "sample_project"


@pytest.fixture(scope="session")
def example_project_path() -> Path:
    return EXAMPLE_PROJECT


@pytest.fixture(scope="session")
def c_source() -> str:
    return (EXAMPLE_PROJECT / "src" / "utils.c").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def cpp_source() -> str:
    return (EXAMPLE_PROJECT / "src" / "buffer.cpp").read_text(encoding="utf-8")


@pytest.fixture()
def project(tmp_path: Path):
    from sast.core.config import AnalysisConfig, Project

    return Project(root=tmp_path, config=AnalysisConfig())
