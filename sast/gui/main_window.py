"""The main window of the CodeShield desktop application.

The window offers the same functionality as the web dashboard:

* a project selector,
* the *Analyze*, *Run tests* and *Traceability* actions,
* a rule catalogue dock with check boxes,
* a findings table in the central area,
* a detail dock showing the selected finding,
* a status bar with the counters of the last run.

The analysis runs in a worker thread so that the window stays responsive on
large projects.
"""

from __future__ import annotations

import argparse
import html
import sys
import time
from pathlib import Path
from typing import Any

try:
    from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
    from PySide6.QtGui import QAction, QKeySequence
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QDockWidget,
        QFileDialog,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QPushButton,
        QTableView,
        QTextBrowser,
        QToolBar,
        QTreeView,
        QVBoxLayout,
        QWidget,
    )
except ImportError as error:  # pragma: no cover - depends on the machine
    raise ImportError(
        "PySide6 is required for the CodeShield desktop GUI. "
        "Install it with 'pip install PySide6' or 'pip install sast[gui]'."
    ) from error

from sast import __version__
from sast.core.config import Project, load_project
from sast.core.models import Severity
from sast.rules.base import RULE_REGISTRY, rule_catalog
from sast.rules.engine import RuleEngine

try:  # pragma: no cover - the built in rules register themselves on import
    import sast.rules.builtin  # noqa: F401
except Exception:  # pragma: no cover - defensive
    pass

from sast.gui.widgets import (
    SEVERITY_ORDER,
    CoverageGauge,
    MetricCard,
    RuleTreeModel,
    SeverityBadge,
    ViolationTableModel,
)

__all__ = ["MainWindow", "run_gui", "main"]

_STYLE = """
QMainWindow, QWidget { background: #0d1017; color: #e8ecf3; }
QToolBar { background: #161b27; border: 0; border-bottom: 1px solid #2f3748; spacing: 6px; padding: 4px; }
QToolBar QToolButton { color: #e8ecf3; padding: 4px 9px; border-radius: 5px; }
QToolBar QToolButton:hover { background: #232a3a; }
QLineEdit, QComboBox { background: #141926; color: #e8ecf3; border: 1px solid #2f3748;
    border-radius: 5px; padding: 4px 7px; }
QPushButton { background: #212736; color: #e8ecf3; border: 1px solid #2f3748;
    border-radius: 5px; padding: 4px 10px; }
QPushButton:hover { border-color: #5b8dff; }
QTableView, QTreeView { background: #141926; alternate-background-color: #171d2b;
    border: 1px solid #2f3748; border-radius: 6px; gridline-color: #242c3d; }
QHeaderView::section { background: #1b2130; color: #94a0b4; border: 0;
    border-bottom: 1px solid #2f3748; padding: 5px 7px; }
QDockWidget { titlebar-close-icon: none; }
QDockWidget::title { background: #161b27; padding: 6px 9px; border-bottom: 1px solid #2f3748; }
QStatusBar { background: #161b27; color: #b6c0d1; }
QTextBrowser { background: #141926; border: 1px solid #2f3748; border-radius: 6px; }
QScrollBar:vertical { background: #141926; width: 10px; }
QScrollBar::handle:vertical { background: #2f3748; border-radius: 5px; }
"""


class AnalysisWorker(QObject):
    """Runs the rule engine outside of the GUI thread."""

    finished = Signal(object, float)
    failed = Signal(str)

    def __init__(self, project: Project, rule_ids: list[str]) -> None:
        super().__init__()
        self._project = project
        self._rule_ids = list(rule_ids)

    def _rules(self) -> list[Any]:
        """The rules the user kept checked, filtered by the project config."""
        config = self._project.config
        disabled = set(config.disabled_rules)
        allowed = set(config.enabled_rules)
        categories = set(config.categories)
        try:
            threshold = Severity.parse(config.severity_threshold)
        except ValueError:
            threshold = Severity.INFO
        selected: list[Any] = []
        for rule_id in self._rule_ids:
            rule = RULE_REGISTRY.get(rule_id)
            if rule is None or rule_id in disabled:
                continue
            if categories and rule.category not in categories:
                continue
            if allowed and rule_id not in allowed and rule.category not in categories:
                continue
            if not rule.enabled_by_default and rule_id not in allowed:
                continue
            if rule.severity.rank > threshold.rank and rule_id not in allowed:
                continue
            selected.append(rule)
        return selected

    @Slot()
    def run(self) -> None:
        started = time.perf_counter()
        try:
            engine = RuleEngine(self._project, rules=self._rules())
            result = engine.analyze()
            result.tool_version = __version__
        except Exception as error:
            self.failed.emit(str(error))
            return
        self.finished.emit(result, time.perf_counter() - started)


class MainWindow(QMainWindow):
    """The CodeShield main window."""

    def __init__(self, project_root: str | Path | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"CodeShield {__version__}")
        self.resize(1440, 900)
        self.setStyleSheet(_STYLE)
        self._project_root = Path(project_root).resolve() if project_root else Path.cwd()
        self._result: Any = None
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._busy = False
        self._build_actions()
        self._build_toolbar()
        self._build_docks()
        self._build_central()
        self._build_status_bar()
        self._load_rules()
        self._refresh_status()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    def _build_actions(self) -> None:
        self.analyze_action = QAction("Analyze", self)
        self.analyze_action.setShortcut(QKeySequence.StandardKey.Refresh)
        self.analyze_action.setToolTip("Run the static analysis on the current project")
        self.analyze_action.triggered.connect(self.analyze)

        self.test_action = QAction("Run tests", self)
        self.test_action.setToolTip("Discover and run the unit test suites")
        self.test_action.triggered.connect(self.run_tests)

        self.trace_action = QAction("Traceability", self)
        self.trace_action.setToolTip("Show the requirement traceability matrix")
        self.trace_action.triggered.connect(self.show_traceability)

        self.quit_action = QAction("Quit", self)
        self.quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        self.quit_action.triggered.connect(self.close)

        menu = self.menuBar().addMenu("&File")
        menu.addAction(self.analyze_action)
        menu.addAction(self.test_action)
        menu.addAction(self.trace_action)
        menu.addSeparator()
        menu.addAction(self.quit_action)

        view = self.menuBar().addMenu("&View")
        self.rules_action = QAction("Rule catalogue", self)
        self.rules_action.setCheckable(True)
        self.rules_action.setChecked(True)
        self.rules_action.triggered.connect(self._toggle_rules_dock)
        view.addAction(self.rules_action)
        self.details_action = QAction("Details", self)
        self.details_action.setCheckable(True)
        self.details_action.setChecked(True)
        self.details_action.triggered.connect(self._toggle_details_dock)
        view.addAction(self.details_action)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setObjectName("mainToolbar")
        toolbar.setMovable(False)
        toolbar.addAction(self.analyze_action)
        toolbar.addAction(self.test_action)
        toolbar.addAction(self.trace_action)
        toolbar.addSeparator()

        toolbar.addWidget(QLabel(" Project "))
        self.project_edit = QLineEdit(str(self._project_root))
        self.project_edit.setMinimumWidth(320)
        self.project_edit.setToolTip("The root directory of the analysed project")
        self.project_edit.editingFinished.connect(self._on_project_edited)
        toolbar.addWidget(self.project_edit)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self._on_browse)
        toolbar.addWidget(self.browse_button)

        toolbar.addSeparator()
        toolbar.addWidget(QLabel(" Severity "))
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("All severities", "")
        for name in SEVERITY_ORDER:
            self.severity_combo.addItem(name, name)
        self.severity_combo.currentIndexChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self.severity_combo)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search findings…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setMinimumWidth(220)
        self.search_edit.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self.search_edit)

        self.addToolBar(toolbar)
        self.toolbar = toolbar

    def _build_docks(self) -> None:
        self.rules_dock = QDockWidget("Rule catalogue", self)
        self.rules_dock.setObjectName("rulesDock")
        self.rules_widget = QWidget()
        rules_layout = QVBoxLayout(self.rules_widget)
        rules_layout.setContentsMargins(6, 6, 6, 6)
        self.rule_filter = QLineEdit()
        self.rule_filter.setPlaceholderText("Filter rules…")
        self.rule_filter.textChanged.connect(self._on_rule_filter)
        rules_layout.addWidget(self.rule_filter)
        self.rule_model = RuleTreeModel()
        self.rule_view = QTreeView()
        self.rule_view.setModel(self.rule_model)
        self.rule_view.setHeaderHidden(True)
        self.rule_view.setUniformRowHeights(True)
        self.rule_view.expandAll()
        rules_layout.addWidget(self.rule_view)
        self.rules_dock.setWidget(self.rules_widget)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.rules_dock)

        self.details_dock = QDockWidget("Details", self)
        self.details_dock.setObjectName("detailsDock")
        self.details_widget = QWidget()
        details_layout = QVBoxLayout(self.details_widget)
        details_layout.setContentsMargins(8, 8, 8, 8)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)
        self.detail_badge = SeverityBadge("info", "—")
        self.detail_title = QLabel("Details")
        self.detail_title.setStyleSheet("color:#e8ecf3; font-weight: 600;")
        header_layout.addWidget(self.detail_badge)
        header_layout.addWidget(self.detail_title)
        header_layout.addStretch(1)
        details_layout.addWidget(header)

        self.cards_widget = QWidget()
        cards_layout = QHBoxLayout(self.cards_widget)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(8)
        self.card_total = MetricCard("Findings", "0", "#5b8dff")
        self.card_critical = MetricCard("Critical", "0", "#ff6b81")
        self.card_high = MetricCard("High", "0", "#ff9f45")
        self.card_health = MetricCard("Health", "100", "#3cc878")
        for card in (self.card_total, self.card_critical, self.card_high, self.card_health):
            cards_layout.addWidget(card)
        cards_layout.addStretch(1)
        details_layout.addWidget(self.cards_widget)

        lower = QWidget()
        lower_layout = QHBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        self.gauge = CoverageGauge()
        lower_layout.addWidget(self.gauge)
        self.details_browser = QTextBrowser()
        self.details_browser.setOpenExternalLinks(False)
        lower_layout.addWidget(self.details_browser, 1)
        details_layout.addWidget(lower, 1)

        self.details_dock.setWidget(self.details_widget)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.details_dock)
        self.details_browser.setHtml(
            "<p style='color:#94a0b4'>Select a finding to see its details.</p>"
        )

    def _build_central(self) -> None:
        self.violation_model = ViolationTableModel()
        self.table = QTableView()
        self.table.setModel(self.violation_model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(self.violation_model.SEVERITY_COLUMN, 100)
        self.table.setColumnWidth(self.violation_model.RULE_COLUMN, 160)
        self.table.setColumnWidth(self.violation_model.FILE_COLUMN, 200)
        self.table.setColumnWidth(self.violation_model.LINE_COLUMN, 60)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self.setCentralWidget(self.table)

    def _build_status_bar(self) -> None:
        bar = self.statusBar()
        self.status_files = QLabel("Files: 0")
        self.status_findings = QLabel("Findings: 0")
        self.status_duration = QLabel("Elapsed: 0.00 s")
        self.status_message = QLabel("")
        for widget in (self.status_files, self.status_findings, self.status_duration):
            bar.addWidget(widget)
        bar.addWidget(self.status_message, 1)

    def _load_rules(self) -> None:
        self.rule_model.set_rules(rule_catalog())
        self.rule_view.expandAll()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def project_root(self) -> Path:
        """The root directory of the analysed project."""
        return self._project_root

    def set_project_root(self, root: str | Path) -> None:
        """Point the window at another project."""
        self._project_root = Path(root).resolve()
        self.project_edit.setText(str(self._project_root))
        self._refresh_status()

    def current_project(self) -> Project:
        """The project built from the current root."""
        return load_project(self._project_root)

    def result(self) -> Any:
        """The result of the last analysis."""
        return self._result

    def _on_project_edited(self) -> None:
        text = self.project_edit.text().strip()
        if not text:
            return
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = self._project_root / candidate
        if candidate.is_dir():
            self._project_root = candidate.resolve()
            self.project_edit.setText(str(self._project_root))
            self._refresh_status()

    def _on_browse(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Select the project directory", str(self._project_root)
        )
        if selected:
            self.set_project_root(selected)

    def _on_rule_filter(self, text: str) -> None:
        self.rule_model.set_filter(text)
        self.rule_view.expandAll()

    def _on_filter_changed(self) -> None:
        severity = self.severity_combo.currentData() or ""
        self.violation_model.set_filter(severity, self.search_edit.text())

    def _on_selection_changed(self, selected: Any, deselected: Any) -> None:
        indexes = selected.indexes() if selected is not None else []
        if not indexes:
            return
        violation = self.violation_model.violation_at(indexes[0].row())
        if violation is None:
            return
        self.detail_badge.set_severity(violation.severity)
        self.detail_title.setText(
            f"{violation.rule_id} · {violation.rule_name}"
        )
        self.details_browser.setHtml(self._violation_html(violation))

    def _toggle_rules_dock(self, visible: bool) -> None:
        self.rules_dock.setVisible(bool(visible))

    def _toggle_details_dock(self, visible: bool) -> None:
        self.details_dock.setVisible(bool(visible))

    def _set_busy(self, busy: bool) -> None:
        self._busy = bool(busy)
        self.analyze_action.setEnabled(not busy)
        self.test_action.setEnabled(not busy)

    def _refresh_status(self, duration: float | None = None) -> None:
        result = self._result
        files = result.files_scanned if result is not None else 0
        findings = len(result.violations) if result is not None else 0
        self.status_files.setText(f"Files: {files}")
        self.status_findings.setText(f"Findings: {findings}")
        elapsed = duration if duration is not None else (
            result.duration_seconds if result is not None else 0.0
        )
        self.status_duration.setText(f"Elapsed: {float(elapsed):.2f} s")

    # ------------------------------------------------------------------
    # analysis
    # ------------------------------------------------------------------
    def analyze(self) -> None:
        """Run the analysis in a worker thread."""
        if self._busy:
            return
        self._set_busy(True)
        self.statusBar().showMessage("Analyzing…")
        try:
            project = self.current_project()
        except Exception as error:
            self._set_busy(False)
            self.statusBar().showMessage(f"Cannot open the project: {error}")
            return
        worker = AnalysisWorker(project, self.rule_model.enabled_rule_ids())
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_analysis_finished)
        worker.failed.connect(self._on_analysis_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    def analyze_sync(self) -> Any:
        """Run the analysis in the calling thread and return the result."""
        project = self.current_project()
        worker = AnalysisWorker(project, self.rule_model.enabled_rule_ids())
        result = None
        failure: list[str] = []

        def on_finished(value: Any, duration: float) -> None:
            nonlocal result
            result = value
            self._on_analysis_finished(value, duration)

        def on_failed(message: str) -> None:
            failure.append(message)

        worker.finished.connect(on_finished)
        worker.failed.connect(on_failed)
        worker.run()
        if failure:
            self._on_analysis_failed(failure[0])
        return result

    @Slot(object, float)
    def _on_analysis_finished(self, result: Any, duration: float) -> None:
        self._result = result
        self._set_busy(False)
        self.violation_model.set_violations(result.violations)
        self._on_filter_changed()
        counts = result.count_by_severity()
        risk = result.risk_score
        self.card_total.set_value(len(result.violations))
        self.card_critical.set_value(counts.get("critical", 0))
        self.card_high.set_value(counts.get("high", 0))
        self.card_health.set_value(max(0, 100 - risk // 2))
        self._refresh_status(duration)
        summary = (
            f"Analysis finished: {len(result.violations)} findings in "
            f"{result.files_scanned} files ({duration:.2f} s)"
        )
        if not result.rules_executed:
            summary = "No rule enabled, nothing was analysed. " + summary
        if not result.passed:
            serious = counts.get("critical", 0) + counts.get("high", 0)
            summary = f"Quality gate FAILED: {serious} critical/high findings. " + summary
        self.status_message.setText(summary)
        self.statusBar().showMessage(summary, 15000)
        self.details_browser.setHtml(
            f"<h3>Analysis summary</h3><ul>"
            f"<li>Findings: {len(result.violations)}</li>"
            f"<li>Files scanned: {result.files_scanned}</li>"
            f"<li>Lines scanned: {result.lines_scanned}</li>"
            f"<li>Rules executed: {result.rules_executed}</li>"
            f"<li>Risk score: {risk}</li>"
            f"<li>Quality gate: {'PASS' if result.passed else 'FAIL'}</li>"
            f"</ul>"
        )

    @Slot(str)
    def _on_analysis_failed(self, message: str) -> None:
        self._set_busy(False)
        self.status_message.setText(f"Analysis failed: {message}")
        self.statusBar().showMessage(f"Analysis failed: {message}", 15000)

    # ------------------------------------------------------------------
    # tests
    # ------------------------------------------------------------------
    def run_tests(self) -> None:
        """Discover and run the test suites of the project."""
        if self._busy:
            return
        self._set_busy(True)
        self.statusBar().showMessage("Running the unit tests…")
        try:
            from sast.testing import TestRunner, discover_suites

            project = self.current_project()
            suites = discover_suites(project)
            if not suites:
                self._set_busy(False)
                self.statusBar().showMessage(
                    "No test suite found below "
                    + ", ".join(project.config.test_dirs),
                    10000,
                )
                return
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
        except Exception as error:
            self._set_busy(False)
            self.statusBar().showMessage(f"Testing failed: {error}", 10000)
            return
        self._set_busy(False)
        if merged is None:
            self.statusBar().showMessage("No test result", 10000)
            return
        coverage = getattr(merged, "coverage", None)
        if coverage is not None:
            self.gauge.set_value(coverage.statement_coverage, "statement")
        message = (
            f"Tests finished: {len(merged.results)} cases, "
            f"{len(merged.failed)} failed ({merged.pass_rate:.0f}% passed)"
        )
        self.status_message.setText(message)
        self.statusBar().showMessage(message, 15000)
        rows = []
        for item in merged.results:
            badge = (
                '<span style="color:#3cc878">PASS</span>'
                if item.passed
                else '<span style="color:#ff6b81">FAIL</span>'
            )
            rows.append(
                f"<tr><td>{html.escape(item.name)}</td><td>{badge}</td>"
                f"<td>{item.duration_ms:.1f} ms</td>"
                f"<td>{html.escape(item.message or '')}</td></tr>"
            )
        body = (
            "<table width='100%' cellspacing='0' cellpadding='4'>"
            "<tr><th align='left'>Case</th><th align='left'>Result</th>"
            "<th align='left'>Duration</th><th align='left'>Message</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        self.details_browser.setHtml(
            f"<h3>Test results · {html.escape(merged.suite_name)}</h3>{body}"
        )

    # ------------------------------------------------------------------
    # traceability
    # ------------------------------------------------------------------
    def show_traceability(self) -> None:
        """Show the requirements of the project and their test coverage."""
        try:
            project = self.current_project()
            requirements = self._collect_requirements(project)
            linked = self._collect_linked_tests(project)
            rows = []
            covered = 0
            for requirement in requirements:
                tests = linked.get(requirement["id"], [])
                if tests:
                    covered += 1
                rows.append(
                    "<tr><td>{rid}</td><td>{title}</td><td>{tests}</td></tr>".format(
                        rid=html.escape(requirement["id"]),
                        title=html.escape(requirement["title"]),
                        tests=html.escape(", ".join(tests) or "—"),
                    )
                )
            body = (
                "<table width='100%' cellspacing='0' cellpadding='4'>"
                "<tr><th align='left'>Requirement</th><th align='left'>Title</th>"
                "<th align='left'>Tests</th></tr>"
                + ("".join(rows) or "<tr><td colspan='3'>No requirement file configured</td></tr>")
                + "</table>"
            )
            summary = (
                f"<h3>Traceability</h3><p>{len(requirements)} requirements, "
                f"{covered} covered by a test.</p>{body}"
            )
            self.details_browser.setHtml(summary)
            self.statusBar().showMessage(
                f"Traceability: {len(requirements)} requirements, {covered} covered",
                10000,
            )
        except Exception as error:
            self.statusBar().showMessage(f"Traceability failed: {error}", 10000)

    def _collect_requirements(self, project: Project) -> list[dict[str, str]]:
        import re

        pattern = re.compile(r"\b([A-Z][A-Z0-9]{1,10}-\d+(?:\.\d+)?)\b")
        found: list[dict[str, str]] = []
        for entry in project.config.requirements_files:
            path = project.resolve(entry)
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
                match = pattern.search(stripped)
                if match is None:
                    continue
                found.append(
                    {
                        "id": match.group(1),
                        "title": stripped.split(":", 1)[-1].strip() or stripped,
                        "source": f"{path}:{number}",
                    }
                )
        return found

    def _collect_linked_tests(self, project: Project) -> dict[str, list[str]]:
        linked: dict[str, list[str]] = {}
        try:
            from sast.testing import discover_suites

            for suite in discover_suites(project):
                for case in suite.tests:
                    for identifier in case.requirement_ids:
                        linked.setdefault(identifier, []).append(case.id)
        except Exception:
            return {}
        return linked

    # ------------------------------------------------------------------
    def _violation_html(self, violation: Any) -> str:
        location = violation.location
        parts = [
            "<h3>",
            html.escape(str(violation.rule_id)),
            " · ",
            html.escape(str(violation.rule_name)),
            "</h3>",
            f"<p><b>{html.escape(str(violation.message))}</b></p>",
            "<p style='color:#94a0b4'>"
            f"{html.escape(str(location.file))}:{location.line}:{location.column}"
            f" · {html.escape(str(violation.function or '—'))}"
            f" · {html.escape(str(violation.category))}</p>",
        ]
        if violation.snippet:
            parts.append(
                "<pre style='background:#10141d;border:1px solid #2f3748;padding:8px;"
                "border-radius:6px;color:#cfe3ff'>"
                + html.escape(str(violation.snippet))
                + "</pre>"
            )
        if violation.recommendation:
            parts.append(f"<p><b>Recommendation:</b> {html.escape(str(violation.recommendation))}</p>")
        if violation.cwe:
            parts.append(f"<p><b>CWE:</b> {html.escape(', '.join(str(item) for item in violation.cwe))}</p>")
        if violation.owasp:
            parts.append(f"<p><b>OWASP:</b> {html.escape(', '.join(violation.owasp))}</p>")
        if violation.standards:
            parts.append(f"<p><b>Standards:</b> {html.escape(', '.join(violation.standards))}</p>")
        if violation.trace:
            steps = "".join(
                f"<li>{html.escape(str(step.file))}:{step.line}:{step.column}</li>"
                for step in violation.trace
            )
            parts.append(f"<p><b>Data flow</b></p><ol>{steps}</ol>")
        parts.append(
            f"<p style='color:#94a0b4'>Fingerprint: {html.escape(str(violation.fingerprint))}</p>"
        )
        return "".join(parts)

    def severity_badge(self, severity: str) -> SeverityBadge:
        """A badge showing *severity*, handy for custom views."""
        return SeverityBadge(severity, self)


def run_gui(project_root: str | Path | None = None) -> int:
    """Start the desktop application and run its event loop."""
    application = QApplication.instance()
    owns = application is None
    if application is None:
        application = QApplication(sys.argv)
    window = MainWindow(project_root)
    window.show()
    if owns:
        return int(application.exec())
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command line entry point of the desktop application."""
    parser = argparse.ArgumentParser(
        prog="codeshield-gui", description="CodeShield desktop application"
    )
    parser.add_argument("project", nargs="?", default=None, help="project directory")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    arguments = parser.parse_args(argv)
    if arguments.version:
        print(__version__)
        return 0
    return run_gui(arguments.project)


if __name__ == "__main__":
    sys.exit(main())
