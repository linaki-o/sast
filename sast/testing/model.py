"""Data model of the unit testing subsystem.

The model is intentionally free of any execution logic: it describes what a
test *is*, not how it is run.  The dataclasses are round-trip friendly so a
suite can be stored as JSON/YAML, handed to a CI job and restored without
losing information.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sast.core.models import SourceLocation

__all__ = [
    "TestCase",
    "TestSuite",
    "TestResult",
    "TestRunResult",
]


def _jsonable(value: Any) -> Any:
    """Convert *value* into something that survives a JSON round trip."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return str(value)


def _as_str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a list of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must contain strings only")
        result.append(item)
    return result


@dataclass
class TestCase:
    """A single unit test.

    ``target`` names the C function under test.  ``params`` are the arguments
    handed to that function, ``expected`` the value it must return and
    ``assert_expr`` an additional C expression that must evaluate to a
    non-zero value once the call returned.
    """

    id: str
    name: str
    target: str
    description: str = ""
    params: list[Any] = field(default_factory=list)
    expected: Any = None
    assert_expr: str = ""
    setup: list[str] = field(default_factory=list)
    teardown: list[str] = field(default_factory=list)
    stubs: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    requirement_ids: list[str] = field(default_factory=list)
    timeout_ms: int = 5000
    expected_exception: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "description": self.description,
            "params": [_jsonable(item) for item in self.params],
            "expected": _jsonable(self.expected),
            "assert_expr": self.assert_expr,
            "setup": list(self.setup),
            "teardown": list(self.teardown),
            "stubs": {str(key): _jsonable(value) for key, value in self.stubs.items()},
            "tags": list(self.tags),
            "requirement_ids": list(self.requirement_ids),
            "timeout_ms": self.timeout_ms,
            "expected_exception": self.expected_exception,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TestCase":
        if not isinstance(data, dict):
            raise ValueError("a test case must be a mapping")
        name = str(data.get("name") or data.get("id") or "")
        if not name:
            raise ValueError("a test case needs at least a name")
        target = str(data.get("target") or "")
        if not target:
            raise ValueError(f"test case {name!r} has no target function")
        identifier = str(data.get("id") or name)
        params = data.get("params") or []
        if not isinstance(params, (list, tuple)):
            raise ValueError(f"test case {identifier!r}: params must be a list")
        stubs = data.get("stubs") or {}
        if not isinstance(stubs, dict):
            raise ValueError(f"test case {identifier!r}: stubs must be a mapping")
        timeout = data.get("timeout_ms", 5000)
        try:
            timeout_ms = int(timeout)
        except (TypeError, ValueError) as error:
            raise ValueError(f"test case {identifier!r}: invalid timeout_ms") from error
        return cls(
            id=identifier,
            name=name,
            target=target,
            description=str(data.get("description") or ""),
            params=list(params),
            expected=data.get("expected"),
            assert_expr=str(data.get("assert_expr") or ""),
            setup=_as_str_list(data.get("setup"), f"test case {identifier!r}: setup"),
            teardown=_as_str_list(data.get("teardown"), f"test case {identifier!r}: teardown"),
            stubs={str(key): value for key, value in stubs.items()},
            tags=_as_str_list(data.get("tags"), f"test case {identifier!r}: tags"),
            requirement_ids=_as_str_list(
                data.get("requirement_ids"), f"test case {identifier!r}: requirement_ids"
            ),
            timeout_ms=timeout_ms,
            expected_exception=str(data.get("expected_exception") or ""),
        )


@dataclass
class TestSuite:
    """An ordered group of test cases that share the same sources."""

    name: str
    description: str = ""
    tests: list[TestCase] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "tests": [test.to_dict() for test in self.tests],
            "source_files": list(self.source_files),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TestSuite":
        if not isinstance(data, dict):
            raise ValueError("a test suite must be a mapping")
        name = str(data.get("name") or "")
        if not name:
            raise ValueError("a test suite needs a name")
        raw_tests = data.get("tests") or []
        if not isinstance(raw_tests, (list, tuple)):
            raise ValueError(f"test suite {name!r}: tests must be a list")
        tests = [TestCase.from_dict(item) for item in raw_tests]
        return cls(
            name=name,
            description=str(data.get("description") or ""),
            tests=tests,
            source_files=_as_str_list(
                data.get("source_files"), f"test suite {name!r}: source_files"
            ),
        )


@dataclass
class TestResult:
    """The outcome of a single test case."""

    test_id: str
    name: str
    passed: bool
    duration_ms: float
    message: str = ""
    expected: Any = None
    actual: Any = None
    stdout: str = ""
    stderr: str = ""
    failed_location: SourceLocation | None = None
    coverage_delta: dict = field(default_factory=dict)
    requirement_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "passed": self.passed,
            "duration_ms": round(float(self.duration_ms), 4),
            "message": self.message,
            "expected": _jsonable(self.expected),
            "actual": _jsonable(self.actual),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "failed_location": self.failed_location.to_dict() if self.failed_location else None,
            "coverage_delta": dict(self.coverage_delta),
            "requirement_ids": list(self.requirement_ids),
        }


@dataclass
class TestRunResult:
    """The aggregated outcome of one or more suites."""

    suite_name: str
    results: list[TestResult] = field(default_factory=list)
    coverage: Any = None
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        succeeded = sum(1 for result in self.results if result.passed)
        return succeeded * 100.0 / len(self.results)

    @property
    def failed(self) -> list[TestResult]:
        return [result for result in self.results if not result.passed]

    def to_dict(self) -> dict:
        coverage = None
        if self.coverage is not None and hasattr(self.coverage, "to_dict"):
            coverage = self.coverage.to_dict()
        return {
            "suite_name": self.suite_name,
            "passed": self.passed,
            "pass_rate": round(self.pass_rate, 4),
            "duration_ms": round(float(self.duration_ms), 4),
            "total": len(self.results),
            "failed": len(self.failed),
            "results": [result.to_dict() for result in self.results],
            "coverage": coverage,
        }
