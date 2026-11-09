"""In-memory store for the CodeShield analysis runs.

The store keeps the most recent runs of the tool in memory so that the web
dashboard can offer a history, compare runs and download the reports of an
earlier run without touching the file system.

The store is deliberately simple: a dictionary keyed by the run id plus an
ordered list of the ids that keeps the insertion order.  Every public method
is protected by a lock because the FastAPI application serves the runs from
several worker threads.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = ["Run", "RunStore", "new_run_id", "utc_now"]


def new_run_id() -> str:
    """Return a fresh, URL safe identifier for a run."""
    return uuid.uuid4().hex


def utc_now() -> str:
    """Return the current UTC time as an ISO 8601 timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Run:
    """A single execution of the analyser, the test runner or the tracer."""

    id: str
    project: str
    created_at: str
    kind: str
    result: Any = None
    tests: Any = None
    trace: Any = None
    duration_s: float = 0.0

    # ------------------------------------------------------------------
    @property
    def day(self) -> str:
        """The calendar day the run belongs to."""
        return (self.created_at or "")[:10]

    def to_dict(self) -> dict[str, Any]:
        """A JSON friendly summary of the run."""
        data: dict[str, Any] = {
            "id": self.id,
            "project": self.project,
            "created_at": self.created_at,
            "day": self.day,
            "kind": self.kind,
            "duration_s": round(float(self.duration_s), 4),
        }
        result = self.result
        if result is not None:
            counts = result.count_by_severity()
            data["violations"] = len(result.violations)
            data["counts"] = counts
            data["total"] = len(result.violations)
            data["files_scanned"] = result.files_scanned
            data["lines_scanned"] = result.lines_scanned
            data["risk_score"] = result.risk_score
            data["health_score"] = max(0, 100 - result.risk_score // 2)
            data["passed"] = bool(result.passed)
            data["by_category"] = result.by_category()
            data["by_rule"] = result.by_rule()
        tests = self.tests
        if tests is not None:
            failed = len(tests.failed)
            data["total_tests"] = len(tests.results)
            data["failed_tests"] = failed
            data["pass_rate"] = round(float(tests.pass_rate), 2)
            data["passed"] = bool(tests.passed)
            data["suite"] = getattr(tests, "suite_name", "")
            coverage = getattr(tests, "coverage", None)
            if coverage is not None:
                data["coverage"] = {
                    "statement": round(coverage.statement_coverage, 2),
                    "branch": round(coverage.branch_coverage, 2),
                    "condition": round(coverage.condition_coverage, 2),
                    "mcdc": round(coverage.mc_dc_coverage, 2),
                }
        trace = self.trace
        if trace is not None:
            data["trace"] = _trace_summary(trace)
        return data

    def to_detail(self) -> dict[str, Any]:
        """The summary extended by the full payload of the run."""
        data = self.to_dict()
        if self.result is not None:
            data["result"] = self.result.to_dict()
        if self.tests is not None:
            data["tests"] = self.tests.to_dict()
        if self.trace is not None:
            data["trace_matrix"] = _trace_payload(self.trace)
        return data


def _trace_summary(trace: Any) -> dict[str, Any]:
    data = _trace_payload(trace)
    if isinstance(data, dict):
        totals = data.get("totals")
        if isinstance(totals, dict):
            return totals
    return {}


def _trace_payload(trace: Any) -> Any:
    if hasattr(trace, "to_dict"):
        try:
            return trace.to_dict()
        except Exception:
            return {}
    if isinstance(trace, dict):
        return trace
    return {}


class RunStore:
    """A bounded, thread safe collection of :class:`Run` objects."""

    def __init__(self, max_runs: int = 50) -> None:
        self.max_runs = max(1, int(max_runs))
        self._runs: dict[str, Run] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def add(self, run: Run) -> Run:
        """Store *run* and return it."""
        with self._lock:
            self._runs[run.id] = run
            if run.id in self._order:
                self._order.remove(run.id)
            self._order.append(run.id)
            while len(self._order) > self.max_runs:
                oldest = self._order.pop(0)
                self._runs.pop(oldest, None)
        return run

    def get(self, run_id: str) -> Run | None:
        """The run stored under *run_id* or ``None``."""
        with self._lock:
            return self._runs.get(run_id)

    def latest(self, kind: str | None = None) -> Run | None:
        """The most recent run, optionally restricted to one *kind*."""
        with self._lock:
            for run_id in reversed(self._order):
                run = self._runs.get(run_id)
                if run is None:
                    continue
                if kind is None or run.kind == kind:
                    return run
        return None

    def list(self, kind: str | None = None) -> list[Run]:
        """Every stored run, oldest first."""
        with self._lock:
            runs = [self._runs[run_id] for run_id in self._order if run_id in self._runs]
        if kind is None:
            return runs
        return [run for run in runs if run.kind == kind]

    def remove(self, run_id: str) -> bool:
        """Drop the run stored under *run_id*."""
        with self._lock:
            if run_id not in self._runs:
                return False
            self._runs.pop(run_id, None)
            if run_id in self._order:
                self._order.remove(run_id)
        return True

    def clear(self) -> None:
        """Forget every stored run."""
        with self._lock:
            self._runs.clear()
            self._order.clear()

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        with self._lock:
            return len(self._runs)

    def __contains__(self, run_id: object) -> bool:
        with self._lock:
            return run_id in self._runs
