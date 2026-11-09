"""Unit testing and coverage subsystem of CodeShield.

The package offers three things:

``sast.testing.model``
    The data model: test cases, suites and results.
``sast.testing.interpreter`` / ``sast.testing.native``
    The two test engines: a portable C interpreter and a native gcc/clang
    pipeline.
``sast.testing.coverage`` / ``sast.testing.runtime`` / ``sast.testing.suites``
    The coverage model, the runner that ties everything together and the
    suite discovery.
"""

from __future__ import annotations

from sast.testing.coverage import (
    ConditionObservation,
    CoverageCollector,
    CoverageRecord,
    CoverageReport,
    DecisionCoverage,
    FileCoverage,
)
from sast.testing.interpreter import (
    AbortSignal,
    AssertionFailure,
    Buffer,
    CInterpreter,
    ExitSignal,
    InterpreterError,
    InterpreterLimit,
    InterpreterTimeout,
    MemoryFault,
    OutParameter,
)
from sast.testing.model import TestCase, TestResult, TestRunResult, TestSuite
from sast.testing.native import native_available
from sast.testing.runtime import TestRunner
from sast.testing.suites import (
    SuiteLoadError,
    discover_suites,
    load_suites_from_paths,
    make_suite,
)

__all__ = [
    "TestCase",
    "TestSuite",
    "TestResult",
    "TestRunResult",
    "CoverageCollector",
    "CoverageReport",
    "CoverageRecord",
    "ConditionObservation",
    "DecisionCoverage",
    "FileCoverage",
    "TestRunner",
    "CInterpreter",
    "load_suites_from_paths",
    "discover_suites",
    "make_suite",
    "SuiteLoadError",
    "native_available",
    "InterpreterError",
    "InterpreterTimeout",
    "InterpreterLimit",
    "MemoryFault",
    "AbortSignal",
    "ExitSignal",
    "AssertionFailure",
    "OutParameter",
    "Buffer",
]
