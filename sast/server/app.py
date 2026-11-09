"""The FastAPI application behind the CodeShield web dashboard.

The application exposes the analyser, the unit test runner and the
traceability matrix over a small JSON API and renders a self contained
dashboard on top of it.  Everything the dashboard needs is served from the
local ``static`` folder, so the tool works without any network access.

Run it with::

    uvicorn sast.server.app:app --port 8765
"""

from __future__ import annotations

import json
import platform
import re
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from sast import __version__
from sast.core.config import Project, load_project
from sast.core.models import Severity
from sast.report import render_all
from sast.rules.base import rule_catalog
from sast.rules.engine import RuleEngine
from sast.server.store import Run, RunStore, new_run_id, utc_now

try:  # pragma: no cover - the built in rules register themselves on import
    import sast.rules.builtin  # noqa: F401
except Exception:  # pragma: no cover - defensive
    pass

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

REPORT_FORMATS = ("html", "json", "sarif", "xml")
REPORT_MEDIA_TYPES = {
    "html": "text/html; charset=utf-8",
    "json": "application/json",
    "sarif": "application/json",
    "xml": "application/xml",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

__all__ = ["create_app", "app"]


class AnalyzeRequest(BaseModel):
    """Body of ``POST /api/analyze``."""

    path: str | None = None
    formats: list[str] = Field(default_factory=lambda: ["html", "json"])
    baseline: bool = False


class TestRequest(BaseModel):
    """Body of ``POST /api/test``."""

    path: str | None = None
    suite: str | None = None


def create_app(project_root: str | None = None) -> FastAPI:
    """Build the CodeShield web application.

    *project_root* points at the project the dashboard analyses by default;
    it defaults to the current working directory.
    """
    root = Path(project_root).resolve() if project_root else Path.cwd().resolve()

    application = FastAPI(
        title="CodeShield",
        version=__version__,
        description="CodeShield - C/C++ static analysis, unit testing and traceability.",
    )
    application.state.project_root = root
    application.state.store = RunStore()
    application.state.report_root = Path(tempfile.gettempdir()) / "codeshield" / "reports"
    application.state.run_roots: dict[str, Path] = {}

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

    # ------------------------------------------------------------------
    def store() -> RunStore:
        return application.state.store

    def resolve_root(candidate: str | None) -> Path:
        base: Path = application.state.project_root
        if not candidate:
            return base
        text = str(candidate).strip()
        if not text:
            return base
        path = Path(text)
        if not path.is_absolute():
            path = base / path
        return path.resolve()

    def project_for(candidate: str | None) -> Project:
        target = resolve_root(candidate)
        if not target.exists():
            raise HTTPException(400, f"project path does not exist: {target}")
        if not target.is_dir():
            raise HTTPException(400, f"project path is not a directory: {target}")
        try:
            return load_project(target)
        except Exception as error:
            raise HTTPException(400, f"cannot load the project: {error}") from error

    def require_run(run_id: str) -> Run:
        run = store().get(run_id)
        if run is None:
            raise HTTPException(404, f"unknown run: {run_id}")
        return run

    def require_result(run_id: str) -> Run:
        run = require_run(run_id)
        if run.result is None:
            raise HTTPException(404, f"the run {run_id} does not hold an analysis result")
        return run

    # ------------------------------------------------------------------
    @application.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @application.get("/api/version")
    async def version() -> dict[str, Any]:
        return {
            "name": "CodeShield",
            "version": __version__,
            "python": platform.python_version(),
            "project_root": str(application.state.project_root),
        }

    @application.get("/api/rules")
    async def rules() -> dict[str, Any]:
        catalog = rule_catalog()
        by_category = Counter(info.category for info in catalog)
        by_severity = Counter(info.severity.value for info in catalog)
        return {
            "rules": [info.to_dict() for info in catalog],
            "total": len(catalog),
            "by_category": dict(sorted(by_category.items())),
            "by_severity": {
                name: by_severity.get(name, 0) for name in SEVERITY_ORDER
            },
        }

    @application.post("/api/analyze")
    async def analyze(payload: AnalyzeRequest) -> dict[str, Any]:
        project = project_for(payload.path)
        requested = [str(item).strip().lower() for item in (payload.formats or [])]
        requested = [item for item in requested if item]
        unsupported = [item for item in requested if item not in REPORT_FORMATS]
        if unsupported:
            raise HTTPException(
                400,
                "unsupported report format(s): "
                + ", ".join(unsupported)
                + " (expected one of: "
                + ", ".join(REPORT_FORMATS)
                + ")",
            )
        formats = requested or ["json"]
        started = time.perf_counter()
        result = await run_in_threadpool(
            _run_analysis, project, bool(payload.baseline)
        )
        duration = time.perf_counter() - started
        run = Run(
            id=new_run_id(),
            project=project.name,
            created_at=utc_now(),
            kind="analysis",
            result=result,
            duration_s=duration,
        )
        store().add(run)
        application.state.run_roots[run.id] = project.root
        reports = await run_in_threadpool(_render_reports, result, formats, run.id)
        return {
            "run": run.to_dict(),
            "result": result.to_dict(),
            "reports": [str(item) for item in reports],
        }

    @application.get("/api/runs")
    async def runs(kind: str | None = Query(default=None)) -> dict[str, Any]:
        entries = store().list(kind)
        return {
            "runs": [run.to_dict() for run in entries],
            "total": len(entries),
        }

    @application.get("/api/runs/{run_id}")
    async def run_detail(run_id: str) -> dict[str, Any]:
        run = require_run(run_id)
        detail = run.to_detail()
        detail["run"] = run.to_dict()
        return detail

    @application.delete("/api/runs/{run_id}")
    async def delete_run(run_id: str) -> dict[str, Any]:
        run = store().get(run_id)
        if run is None:
            raise HTTPException(404, f"unknown run: {run_id}")
        store().remove(run_id)
        application.state.run_roots.pop(run_id, None)
        return {"deleted": run_id}

    @application.get("/api/results/{run_id}")
    async def results(run_id: str) -> dict[str, Any]:
        run = require_result(run_id)
        return run.result.to_dict()

    @application.get("/api/results/{run_id}/violations")
    async def violations(
        run_id: str,
        severity: str | None = Query(default=None),
        category: str | None = Query(default=None),
        rule: str | None = Query(default=None),
        q: str | None = Query(default=None),
    ) -> dict[str, Any]:
        run = require_result(run_id)
        selected = _filter_violations(
            run.result.violations,
            severity=severity,
            category=category,
            rule=rule,
            text=q,
        )
        return {
            "run_id": run_id,
            "total": len(selected),
            "filters": {
                "severity": severity or "",
                "category": category or "",
                "rule": rule or "",
                "q": q or "",
            },
            "violations": [item.to_dict() for item in selected],
        }

    @application.get("/api/results/{run_id}/metrics")
    async def metrics(run_id: str) -> dict[str, Any]:
        run = require_result(run_id)
        entries = [item.to_dict() for item in run.result.file_metrics]
        return {
            "run_id": run_id,
            "total": len(entries),
            "metrics": entries,
            "files_scanned": run.result.files_scanned,
            "lines_scanned": run.result.lines_scanned,
        }

    @application.post("/api/test")
    async def run_tests(payload: TestRequest) -> dict[str, Any]:
        project = project_for(payload.path)
        suites = await run_in_threadpool(_discover_suites, project, payload.suite)
        if not suites:
            raise HTTPException(
                400,
                "no test suite found below "
                + ", ".join(project.config.test_dirs),
            )
        started = time.perf_counter()
        outcome = await run_in_threadpool(_run_suites, project, suites)
        duration = time.perf_counter() - started
        run = Run(
            id=new_run_id(),
            project=project.name,
            created_at=utc_now(),
            kind="test",
            tests=outcome,
            duration_s=duration,
        )
        store().add(run)
        application.state.run_roots[run.id] = project.root
        return {"run": run.to_dict(), "tests": outcome.to_dict()}

    @application.get("/api/test/{run_id}")
    async def test_detail(run_id: str) -> dict[str, Any]:
        run = require_run(run_id)
        if run.tests is None:
            raise HTTPException(404, f"the run {run_id} does not hold a test result")
        data = run.tests.to_dict()
        data["run_id"] = run_id
        data["run"] = run.to_dict()
        return data

    @application.get("/api/coverage/{run_id}")
    async def coverage(run_id: str) -> dict[str, Any]:
        run = require_run(run_id)
        if run.tests is None:
            raise HTTPException(404, f"the run {run_id} does not hold a test result")
        report = getattr(run.tests, "coverage", None)
        if report is None:
            return {
                "run_id": run_id,
                "statement_coverage": 0.0,
                "branch_coverage": 0.0,
                "condition_coverage": 0.0,
                "mc_dc_coverage": 0.0,
                "covered_lines": 0,
                "total_lines": 0,
                "files": {},
                "decisions": {},
            }
        data = report.to_dict()
        data["run_id"] = run_id
        return data

    @application.get("/api/traceability")
    async def traceability() -> dict[str, Any]:
        project = project_for(None)
        matrix = await run_in_threadpool(_build_traceability, project)
        run = Run(
            id=new_run_id(),
            project=project.name,
            created_at=utc_now(),
            kind="trace",
            trace=matrix,
        )
        store().add(run)
        application.state.run_roots[run.id] = project.root
        return {"run": run.to_dict(), "traceability": matrix}

    @application.get("/api/traceability/{run_id}")
    async def traceability_run(run_id: str) -> dict[str, Any]:
        run = require_run(run_id)
        if run.trace is None:
            raise HTTPException(404, f"the run {run_id} does not hold a matrix")
        data = run.trace if isinstance(run.trace, dict) else _as_dict(run.trace)
        return {"run": run.to_dict(), "traceability": data}

    @application.get("/api/report/{run_id}/{fmt}")
    async def report(run_id: str, fmt: str) -> FileResponse:
        key = str(fmt or "").strip().lower()
        if key not in REPORT_FORMATS:
            raise HTTPException(
                400,
                f"unsupported report format: {fmt!r} (expected one of: "
                + ", ".join(REPORT_FORMATS)
                + ")",
            )
        run = require_result(run_id)
        root = application.state.run_roots.get(run_id)
        project = None
        if root is not None:
            try:
                project = load_project(root)
            except Exception:
                project = None
        written = await run_in_threadpool(
            _render_reports, run.result, [key], run_id, project
        )
        if not written:
            raise HTTPException(500, f"the {key} report could not be rendered")
        path = written[0]
        if not path.is_file():
            raise HTTPException(500, f"the {key} report is missing: {path}")
        return FileResponse(
            path,
            media_type=REPORT_MEDIA_TYPES.get(key, "application/octet-stream"),
            filename=f"codeshield-{run_id[:8]}.{key}",
        )

    @application.get("/api/metrics/summary")
    async def metrics_summary() -> dict[str, Any]:
        return _aggregate_metrics(store().list())

    # ------------------------------------------------------------------
    @application.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        project = _safe_project(application.state.project_root)
        runs = store().list()
        latest = store().latest("analysis")
        catalog = rule_catalog()
        groups: dict[str, list[dict[str, Any]]] = {}
        for info in catalog:
            groups.setdefault(info.category, []).append(info.to_dict())
        bootstrap = {
            "version": __version__,
            "project": project.name if project else str(application.state.project_root),
            "project_root": str(application.state.project_root),
            "runs": [run.to_dict() for run in runs],
            "latest_run": latest.id if latest else "",
            "rules": [info.to_dict() for info in catalog],
            "severities": list(SEVERITY_ORDER),
        }
        context = {
            "version": __version__,
            "project": bootstrap["project"],
            "project_root": bootstrap["project_root"],
            "runs": bootstrap["runs"],
            "rules": bootstrap["rules"],
            "rule_groups": groups,
            "rule_categories": sorted(groups),
            "latest_run": latest.id if latest else "",
            "severities": list(SEVERITY_ORDER),
            "kpi": _kpi(latest),
            "bootstrap": bootstrap,
        }
        return templates.TemplateResponse(request, "index.html.j2", context)

    @application.get("/runs/{run_id}", response_class=HTMLResponse)
    async def run_page(request: Request, run_id: str) -> HTMLResponse:
        run = require_run(run_id)
        context = {
            "version": __version__,
            "run": run.to_dict(),
            "run_id": run.id,
            "result": run.result.to_dict() if run.result is not None else {},
            "tests": run.tests.to_dict() if run.tests is not None else {},
            "coverage": _coverage_payload(run),
            "trace": run.trace if isinstance(run.trace, dict) else {},
            "report_formats": list(REPORT_FORMATS),
            "bootstrap": {
                "version": __version__,
                "run_id": run.id,
                "kind": run.kind,
                "project": run.project,
                "runs": [],
                "rules": [],
            },
        }
        return templates.TemplateResponse(request, "results.html.j2", context)

    return application


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _safe_project(root: Path) -> Project | None:
    try:
        return load_project(root)
    except Exception:
        return None


def _kpi(run: Run | None) -> dict[str, Any]:
    """The key figures shown in the header of the dashboard."""
    counts = {name: 0 for name in SEVERITY_ORDER}
    categories: dict[str, int] = {}
    total = 0
    files = 0
    health = 100
    passed = True
    if run is not None and run.result is not None:
        result = run.result
        counts = {name: int(value) for name, value in result.count_by_severity().items()}
        counts.update({name: 0 for name in SEVERITY_ORDER if name not in counts})
        categories = result.by_category()
        total = len(result.violations)
        files = result.files_scanned
        health = max(0, 100 - result.risk_score // 2)
        passed = bool(result.passed)
    share = {
        name: (round(counts.get(name, 0) * 100.0 / total, 2) if total else 0.0)
        for name in SEVERITY_ORDER
    }
    biggest = max(categories.values()) if categories else 0
    share_category = {
        name: (round(value * 100.0 / biggest, 2) if biggest else 0.0)
        for name, value in categories.items()
    }
    return {
        "total": total,
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "health": health,
        "files": files,
        "counts": counts,
        "categories": categories,
        "share": share,
        "share_category": share_category,
        "passed": passed,
    }


def _run_analysis(project: Project, baseline: bool) -> Any:
    engine = RuleEngine(project)
    result = engine.analyze()
    result.tool_version = __version__
    if baseline:
        known = _load_baseline(project)
        before = len(result.violations)
        result.violations = [
            item for item in result.violations if item.fingerprint not in known
        ]
        result.baseline_suppressed = before - len(result.violations)
        result.new_violations = len(result.violations)
        _save_baseline(project, result)
    return result


def _baseline_path(project: Project) -> Path:
    return project.resolve(project.config.baseline_file)


def _load_baseline(project: Project) -> set[str]:
    path = _baseline_path(project)
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if isinstance(payload, dict):
        entries = payload.get("fingerprints") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []
    return {str(item) for item in entries}


def _save_baseline(project: Project, result: Any) -> None:
    path = _baseline_path(project)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": utc_now(),
            "project": project.name,
            "fingerprints": sorted(item.fingerprint for item in result.violations),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _render_reports(
    result: Any, formats: Iterable[str], run_id: str, project: Project | None = None
) -> list[Path]:
    if result is None:
        return []
    output = Path(tempfile.gettempdir()) / "codeshield" / "reports" / run_id
    try:
        return list(render_all(result, formats, output, project=project))
    except Exception:
        return []


def _discover_suites(project: Project, selector: str | None) -> list[Any]:
    from sast.testing import discover_suites, load_suites_from_paths

    suites = list(discover_suites(project))
    text = (selector or "").strip()
    if not text:
        return suites
    matched = [item for item in suites if item.name.lower() == text.lower()]
    if matched:
        return matched
    path = project.resolve(text)
    if path.is_file():
        try:
            return list(load_suites_from_paths([path]))
        except Exception:
            return []
    return [item for item in suites if text.lower() in item.name.lower()]


def _run_suites(project: Project, suites: list[Any]) -> Any:
    from sast.testing import TestRunner

    runner = TestRunner(project, engine=project.config.test_framework)
    merged = None
    for suite in suites:
        outcome = runner.run_suite(suite)
        if merged is None:
            merged = outcome
            continue
        merged.results.extend(outcome.results)
        merged.duration_ms = float(merged.duration_ms) + float(outcome.duration_ms)
        if outcome.coverage is not None:
            if merged.coverage is None:
                merged.coverage = outcome.coverage
            else:
                try:
                    merged.coverage.merge(outcome.coverage)
                except Exception:
                    pass
    return merged


def _filter_violations(
    violations: Iterable[Any],
    severity: str | None = None,
    category: str | None = None,
    rule: str | None = None,
    text: str | None = None,
) -> list[Any]:
    severities = _split(severity)
    categories = _split(category)
    rules = _split(rule)
    query = (text or "").strip().lower()
    selected: list[Any] = []
    for item in violations:
        if severities and item.severity.value not in severities:
            continue
        if categories and item.category not in categories:
            continue
        if rules and item.rule_id not in rules:
            continue
        if query:
            haystack = " ".join(
                str(part)
                for part in (
                    item.rule_id,
                    item.rule_name,
                    item.message,
                    item.category,
                    item.function,
                    item.location.file,
                )
            ).lower()
            if query not in haystack:
                continue
        selected.append(item)
    return selected


def _split(value: str | None) -> set[str]:
    if not value:
        return set()
    return {
        part.strip().lower()
        for part in str(value).replace(";", ",").split(",")
        if part.strip()
    }


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:
            return {}
    if isinstance(value, dict):
        return value
    return {}


def _coverage_payload(run: Run) -> dict[str, Any]:
    if run.tests is None:
        return {}
    report = getattr(run.tests, "coverage", None)
    if report is None:
        return {}
    return report.to_dict()


def _aggregate_metrics(runs: list[Run]) -> dict[str, Any]:
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    by_day: dict[str, dict[str, Any]] = {}
    by_rule: Counter[str] = Counter()
    by_file: Counter[str] = Counter()
    rule_names: dict[str, str] = {}
    total_findings = 0
    total_files = 0
    total_lines = 0
    for run in runs:
        result = run.result
        if result is None:
            continue
        total_findings += len(result.violations)
        total_files += result.files_scanned
        total_lines += result.lines_scanned
        for name, count in result.count_by_severity().items():
            by_severity[name] = by_severity.get(name, 0) + count
        day = by_day.setdefault(
            run.day,
            {"day": run.day, "runs": 0, "findings": 0, "by_severity": {}},
        )
        day["runs"] += 1
        day["findings"] += len(result.violations)
        for name, count in result.count_by_severity().items():
            day["by_severity"][name] = day["by_severity"].get(name, 0) + count
        for rule_id, count in result.by_rule().items():
            by_rule[rule_id] += count
        for violation in result.violations:
            by_file[violation.location.file] += 1
            rule_names.setdefault(violation.rule_id, violation.rule_name)
    top_rules = [
        {"rule_id": rule_id, "name": rule_names.get(rule_id, rule_id), "count": count}
        for rule_id, count in by_rule.most_common(15)
    ]
    top_files = [
        {"file": path, "count": count} for path, count in by_file.most_common(15)
    ]
    days = sorted(by_day.values(), key=lambda item: item["day"])
    risk = 0
    for name, count in by_severity.items():
        try:
            risk += count * Severity.parse(name).weight
        except ValueError:
            continue
    return {
        "runs": len(runs),
        "analysis_runs": len([run for run in runs if run.result is not None]),
        "total_findings": total_findings,
        "files_scanned": total_files,
        "lines_scanned": total_lines,
        "by_severity": by_severity,
        "by_day": days,
        "top_rules": top_rules,
        "top_files": top_files,
        "risk_score": risk,
        "health_score": max(0, 100 - risk // 2),
    }


# ----------------------------------------------------------------------
# traceability
# ----------------------------------------------------------------------

_REQUIREMENT_PATTERN = re.compile(r"\b([A-Z][A-Z0-9]{1,10}-\d+(?:\.\d+)?)\b")


def _traceability_module() -> Any:
    try:
        from sast import traceability
    except Exception:
        return None
    return traceability


def _build_traceability(project: Project) -> dict[str, Any]:
    module = _traceability_module()
    if module is not None:
        try:
            requirements = _call_requirements(module, project)
            matrix = _call_matrix(module, project, requirements)
            payload = _as_dict(matrix)
            return {
                "available": True,
                "source": "sast.traceability",
                "requirements": _as_dict(requirements),
                "matrix": payload,
            }
        except Exception as error:
            fallback = _fallback_traceability(project)
            fallback["error"] = str(error)
            return fallback
    return _fallback_traceability(project)


def _call_requirements(module: Any, project: Project) -> Any:
    try:
        return module.load_requirements(project)
    except TypeError:
        return module.load_requirements(project.config.requirements_files)


def _call_matrix(module: Any, project: Project, requirements: Any) -> Any:
    try:
        return module.build_matrix(project, requirements)
    except TypeError:
        return module.build_matrix(requirements)


def _fallback_traceability(project: Project) -> dict[str, Any]:
    requirements: list[dict[str, Any]] = []
    files: list[str] = []
    for entry in project.config.requirements_files:
        path = project.resolve(entry)
        files.append(str(path))
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _REQUIREMENT_PATTERN.search(stripped)
            if match is None:
                continue
            identifier = match.group(1)
            title = stripped.split(":", 1)[-1].strip() or stripped
            requirements.append(
                {
                    "id": identifier,
                    "title": title,
                    "source": str(path),
                    "line": number,
                }
            )
    linked: dict[str, list[str]] = {}
    try:
        from sast.testing import discover_suites

        for suite in discover_suites(project):
            for case in suite.tests:
                for identifier in case.requirement_ids:
                    linked.setdefault(identifier, []).append(case.id)
    except Exception:
        linked = {}
    entries: dict[str, Any] = {}
    covered = 0
    for requirement in requirements:
        identifier = requirement["id"]
        tests = linked.get(identifier, [])
        if tests:
            covered += 1
        entries[identifier] = {
            "requirement": requirement,
            "tests": tests,
            "covered": bool(tests),
            "status": "covered" if tests else "uncovered",
        }
    return {
        "available": False,
        "source": "fallback",
        "requirements": requirements,
        "matrix": entries,
        "files": files,
        "totals": {
            "requirements": len(requirements),
            "covered": covered,
            "uncovered": len(requirements) - covered,
        },
    }


app = create_app()
