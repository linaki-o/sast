"""The analysis engines the benchmark can drive."""

from __future__ import annotations

from benchmarks.engines.base import Engine, EngineResult, Finding
from benchmarks.engines.clangtidy import ClangTidyEngine
from benchmarks.engines.cppcheck import CppcheckEngine
from benchmarks.engines.codeshield import CodeShieldEngine

__all__ = [
    "Engine",
    "EngineResult",
    "Finding",
    "CodeShieldEngine",
    "CppcheckEngine",
    "ClangTidyEngine",
    "available_engines",
]


def available_engines(root) -> list[Engine]:
    """Every engine that can run on this machine."""
    return [
        CodeShieldEngine(root),
        CppcheckEngine(root),
        ClangTidyEngine(root),
    ]
