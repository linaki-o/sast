"""The unit test runner.

The runner drives the portable interpreter (and, when a compiler is
available, the native engine) over a :class:`~sast.testing.model.TestSuite`.
Every test case gets a fresh interpreter so that a test can never observe
the state of its predecessor, while the coverage of all tests of a suite is
aggregated into a single report.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterable, Sequence

from sast.ast.parser import parse_file
from sast.core.config import Project
from sast.core.models import SourceLocation
from sast.testing.coverage import CoverageCollector
from sast.testing.interpreter import (
    AbortSignal,
    AssertionFailure,
    Buffer,
    CInterpreter,
    Environment,
    ExitSignal,
    InterpreterError,
    InterpreterLimit,
    InterpreterTimeout,
    MemoryFault,
    OutParameter,
)
from sast.testing.model import TestCase, TestResult, TestRunResult, TestSuite

__all__ = ["TestRunner", "TestExecutionError"]

_EXCEPTION_ALIASES: dict[str, set[str]] = {
    "abort": {"abort", "sigabrt", "abortsignal"},
    "exit": {"exit", "exitcode", "exitsignal"},
    "assert": {"assert", "assertion", "assertionfailure"},
    "memory": {"memory", "memoryfault", "segfault", "sigsegv", "outofbounds"},
    "timeout": {"timeout", "interpretertimeout"},
    "limit": {"limit", "interpreterlimit", "recursion", "stackoverflow"},
    "error": {"error", "interpretererror", "exception"},
}


class TestExecutionError(InterpreterError):
    """Raised when a test case cannot be executed at all."""


class TestRunner:
    """Runs test suites against the C sources of a project."""

    def __init__(self, project: Project, *, engine: str = "auto") -> None:
        self.project = project
        self.engine = (engine or "auto").strip().lower()
        if self.engine not in {"auto", "native", "interpreter"}:
            raise ValueError(
                f"unknown test engine {engine!r} (expected auto, native or interpreter)"
            )

    def run_suite(self, suite: TestSuite) -> TestRunResult:
        """Run every test of *suite*."""
        sources = self._resolve_sources(suite.source_files)
        return self._run(suite.tests, sources, suite.name)

    def run_file(self, path: str, *, sources: list[str]) -> TestRunResult:
        """Load the suites stored in *path* and run them against *sources*."""
        from sast.testing.suites import load_suites_from_paths

        suites = load_suites_from_paths([path])
        if not suites:
            raise TestExecutionError(f"no test suite found in {path}")
        tests: list[TestCase] = []
        for suite in suites:
            tests.extend(suite.tests)
        name = suites[0].name if len(suites) == 1 else Path(path).stem
        resolved = self._resolve_sources(sources)
        return self._run(tests, resolved, name)

    def run_tests(self, tests: list[TestCase], sources: list[str]) -> TestRunResult:
        """Run *tests* against *sources*."""
        resolved = self._resolve_sources(sources)
        return self._run(list(tests), resolved, "tests")

    def _run(
        self, tests: Sequence[TestCase], sources: list[str], name: str
    ) -> TestRunResult:
        started = time.perf_counter()
        results: list[TestResult] = []
        collector = CoverageCollector()
        native_results = self._try_native(tests, sources)
        coverage: Any = None
        if native_results is None:
            units, source_map = self._load_sources(sources)
            for test in tests:
                result, test_collector = self._run_one(test, units, source_map)
                results.append(result)
                collector.merge(test_collector)
            coverage = collector.report()
        else:
            results.extend(native_results)
            coverage = getattr(self, "_native_coverage", None)
            if coverage is None:
                coverage = collector.report()
        duration = (time.perf_counter() - started) * 1000.0
        return TestRunResult(
            suite_name=name, results=results, coverage=coverage, duration_ms=duration
        )

    def _try_native(
        self,
        tests: Sequence[TestCase],
        sources: list[str],
    ) -> list[TestResult] | None:
        if self.engine == "interpreter":
            return None
        try:
            from sast.testing import native

            if not native.native_available():
                return None
            return self._run_native(tests, sources, native)
        except Exception:
            return None

    def _run_native(
        self,
        tests: Sequence[TestCase],
        sources: list[str],
        native: Any,
    ) -> list[TestResult]:
        import tempfile

        units, _source_map = self._load_sources(sources)
        functions = {}
        for unit in units:
            for declaration in unit.declarations:
                name = getattr(declaration, "name", "")
                if name:
                    functions.setdefault(name, declaration)
        harness = native.generate_harness(tests, sources, functions)
        with tempfile.TemporaryDirectory(prefix="codeshield-tests-") as workdir:
            executable = native.compile_harness(harness, sources, workdir)
            if executable is None:
                raise native.NativeRunError("no compiler available")
            parsed, _stdout = native.run_harness(executable)
            native.run_gcov(workdir, sources)
            report = native.parse_gcov(workdir, sources)
        results: list[TestResult] = []
        for test in tests:
            outcome = parsed.get(test.id)
            passed = bool(outcome and outcome.get("passed"))
            message = "" if passed else (outcome.get("message") if outcome else "no result")
            results.append(
                TestResult(
                    test_id=test.id,
                    name=test.name,
                    passed=passed,
                    duration_ms=0.0,
                    message=message,
                    expected=test.expected,
                    actual=outcome.get("actual") if outcome else None,
                    requirement_ids=list(test.requirement_ids),
                )
            )
        self._native_coverage = report
        return results

    def _load_sources(self, sources: list[str]) -> tuple[list[Any], dict[str, str]]:
        units: list[Any] = []
        source_map: dict[str, str] = {}
        for path in sources:
            candidate = Path(path)
            if not candidate.is_file():
                continue
            unit, _errors = parse_file(str(candidate))
            units.append(unit)
            try:
                source_map[unit.path] = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                source_map[unit.path] = ""
        return units, source_map

    def _resolve_sources(self, paths: Iterable[str]) -> list[str]:
        resolved: list[str] = []
        for path in paths or []:
            candidate = Path(path)
            if not candidate.is_absolute():
                candidate = self.project.resolve(path)
            if candidate.is_file():
                resolved.append(str(candidate))
        return resolved

    def _run_one(
        self, test: TestCase, units: list[Any], sources: dict[str, str]
    ) -> tuple[TestResult, CoverageCollector]:
        started = time.perf_counter()
        collector = CoverageCollector()
        interpreter = CInterpreter(units, sources, collector=collector, stubs=test.stubs)
        message = ""
        passed = False
        actual: Any = None
        location: SourceLocation | None = None
        try:
            for statement in test.setup:
                interpreter.run_statements(statement, interpreter.globals)
            actual = self._call_target(interpreter, test)
            message = self._check_result(interpreter, test, actual)
            passed = not message
        except (AbortSignal, ExitSignal, AssertionFailure, MemoryFault) as error:
            location = error.location
            message = str(error)
            passed = self._matches_expected_exception(test, error)
            if passed:
                message = f"expected {test.expected_exception}: {error}"
        except (InterpreterTimeout, InterpreterLimit) as error:
            location = error.location
            message = str(error)
            passed = self._matches_expected_exception(test, error)
        except InterpreterError as error:
            location = error.location
            message = str(error)
            passed = self._matches_expected_exception(test, error)
        finally:
            try:
                for statement in test.teardown:
                    interpreter.run_statements(statement, interpreter.globals)
            except InterpreterError:
                pass
        duration = (time.perf_counter() - started) * 1000.0
        report = collector.report()
        delta = {
            "statements": round(report.statement_coverage, 2),
            "branches": round(report.branch_coverage, 2),
            "conditions": round(report.condition_coverage, 2),
            "mc_dc": round(report.mc_dc_coverage, 2),
        }
        result = TestResult(
            test_id=test.id,
            name=test.name,
            passed=passed,
            duration_ms=duration,
            message=message,
            expected=test.expected,
            actual=actual,
            stdout=interpreter.stdout.getvalue(),
            stderr=interpreter.stderr.getvalue(),
            failed_location=location,
            coverage_delta=delta,
            requirement_ids=list(test.requirement_ids),
        )
        return result, collector

    def _call_target(self, interpreter: CInterpreter, test: TestCase) -> Any:
        environment = Environment(interpreter.globals)
        arguments = [self._prepare_argument(interpreter, item, environment) for item in test.params]
        result = interpreter.run_function(test.target, arguments)
        return_type = interpreter.return_type(test.target)
        if (
            isinstance(result, int)
            and interpreter.is_string_pointer(return_type)
            and result
        ):
            return interpreter.read_cstring(result)
        return result

    def _prepare_argument(
        self, interpreter: CInterpreter, argument: Any, environment: Environment
    ) -> Any:
        if isinstance(argument, str) and argument.startswith("&"):
            name = argument[1:].strip()
            if not name:
                raise TestExecutionError(f"invalid argument {argument!r}")
            return interpreter.resolve_address(name, environment)
        if isinstance(argument, str) and argument.startswith("$"):
            name = argument[1:].strip()
            if not name:
                raise TestExecutionError(f"invalid argument {argument!r}")
            return interpreter.resolve_value(name, environment)
        return argument

    def _assert_environment(self, interpreter: CInterpreter, test: TestCase) -> Environment:
        environment = Environment(interpreter.globals)
        for argument in test.params:
            if isinstance(argument, OutParameter) and argument.name:
                environment.define(argument.name, argument.current(), None)
            elif isinstance(argument, Buffer) and argument.name:
                environment.define(argument.name, argument.address, None)
        return environment

    def _check_result(
        self, interpreter: CInterpreter, test: TestCase, actual: Any
    ) -> str:
        if test.expected is not None and not self._values_equal(actual, test.expected):
            return f"expected {test.expected!r} but the function returned {actual!r}"
        if test.assert_expr:
            environment = self._assert_environment(interpreter, test)
            try:
                value = interpreter.evaluate_expression(test.assert_expr, environment)
            except InterpreterError as error:
                return f"cannot evaluate the assertion {test.assert_expr!r}: {error}"
            if not interpreter.truth(value):
                return f"the assertion {test.assert_expr!r} evaluated to {value!r}"
        return ""

    def _values_equal(self, actual: Any, expected: Any) -> bool:
        if isinstance(actual, float) or isinstance(expected, float):
            try:
                return abs(float(actual) - float(expected)) < 1e-9
            except (TypeError, ValueError):
                return False
        if isinstance(actual, (bytes, bytearray)) and isinstance(expected, str):
            return actual.decode("utf-8", errors="replace") == expected
        if isinstance(actual, str) and isinstance(expected, (bytes, bytearray)):
            return actual == expected.decode("utf-8", errors="replace")
        return actual == expected

    def _matches_expected_exception(self, test: TestCase, error: Exception) -> bool:
        expected = (test.expected_exception or "").strip().lower()
        if not expected:
            return False
        name = type(error).__name__.lower()
        aliases: set[str] = set()
        for group in _EXCEPTION_ALIASES.values():
            if name in group:
                aliases |= group
        if expected in aliases:
            return True
        return expected in name or name in expected
