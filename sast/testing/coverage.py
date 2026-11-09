"""Coverage model for the CodeShield testing subsystem.

Three granularities are tracked:

``statement``
    Every executable statement node of the analysed translation unit is a
    coverable statement.
``branch``
    Every decision outcome (``if`` true/false, loop body/exit, every
    ``switch`` label, short circuit of ``&&``/``||``) is a branch.
``condition``
    Every atomic condition of a decision gets a unique identifier and the
    outcome that was observed for it is recorded.  The condition records also
    drive the MC/DC computation: a condition counts as MC/DC covered when it
    was seen taking both values while every other condition of the same
    decision stayed constant and the decision outcome flipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "CoverageRecord",
    "ConditionObservation",
    "DecisionCoverage",
    "FileCoverage",
    "CoverageCollector",
    "CoverageReport",
]

STATEMENT = "statement"
BRANCH = "branch"
CONDITION = "condition"


@dataclass
class CoverageRecord:
    """A single coverable location."""

    file: str
    line: int
    kind: str
    label: str = ""
    hits: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)

    @property
    def covered(self) -> bool:
        return self.hits > 0

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "label": self.label,
            "hits": self.hits,
            "covered": self.covered,
            "outcomes": dict(self.outcomes),
        }


@dataclass
class ConditionObservation:
    """One evaluation of a decision."""

    outcomes: dict[str, bool] = field(default_factory=dict)
    result: bool = False

    def to_dict(self) -> dict:
        return {"outcomes": dict(self.outcomes), "result": self.result}


@dataclass
class DecisionCoverage:
    """All observations collected for a single decision point."""

    file: str
    line: int
    decision_id: str
    condition_ids: list[str] = field(default_factory=list)
    observations: list[ConditionObservation] = field(default_factory=list)

    def merge(self, other: "DecisionCoverage") -> None:
        known = set(self.condition_ids)
        for condition_id in other.condition_ids:
            if condition_id not in known:
                self.condition_ids.append(condition_id)
                known.add(condition_id)
        self.observations.extend(other.observations)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "decision_id": self.decision_id,
            "condition_ids": list(self.condition_ids),
            "observations": [item.to_dict() for item in self.observations],
        }


@dataclass
class FileCoverage:
    """The coverage collected for one source file."""

    path: str
    statements: list[CoverageRecord] = field(default_factory=list)
    branches: list[CoverageRecord] = field(default_factory=list)
    conditions: list[CoverageRecord] = field(default_factory=list)

    @property
    def statement_coverage(self) -> float:
        return _percentage(
            sum(1 for record in self.statements if record.covered), len(self.statements)
        )

    @property
    def branch_coverage(self) -> float:
        return _percentage(
            sum(1 for record in self.branches if record.covered), len(self.branches)
        )

    @property
    def condition_coverage(self) -> float:
        return _percentage(
            sum(1 for record in self.conditions if _both_outcomes(record)),
            len(self.conditions),
        )

    @property
    def covered_lines(self) -> int:
        return len({record.line for record in self.statements if record.covered})

    @property
    def total_lines(self) -> int:
        return len({record.line for record in self.statements})

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "statement_coverage": round(self.statement_coverage, 2),
            "branch_coverage": round(self.branch_coverage, 2),
            "condition_coverage": round(self.condition_coverage, 2),
            "covered_lines": self.covered_lines,
            "total_lines": self.total_lines,
            "statements": [record.to_dict() for record in self.statements],
            "branches": [record.to_dict() for record in self.branches],
            "conditions": [record.to_dict() for record in self.conditions],
        }


def _percentage(covered: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return covered * 100.0 / total


def _both_outcomes(record: CoverageRecord) -> bool:
    outcomes = record.outcomes or {}
    return outcomes.get("true", 0) > 0 and outcomes.get("false", 0) > 0


class CoverageCollector:
    """Receives coverage events coming out of the interpreter.

    The collector also keeps the bookkeeping needed for MC/DC: every
    evaluation of a decision is stored together with the outcome of each of
    its atomic conditions so that the independence check can be performed
    later on.
    """

    def __init__(self) -> None:
        self._statements: dict[tuple[str, int], CoverageRecord] = {}
        self._branches: dict[tuple[str, int, str], CoverageRecord] = {}
        self._conditions: dict[tuple[str, int, str], CoverageRecord] = {}
        self._decisions: dict[str, DecisionCoverage] = {}

    def declare_statement(self, file: str, line: int) -> CoverageRecord:
        key = (file, line)
        record = self._statements.get(key)
        if record is None:
            record = CoverageRecord(file=file, line=line, kind=STATEMENT)
            self._statements[key] = record
        return record

    def declare_branch(self, file: str, line: int, branch_id: str) -> CoverageRecord:
        key = (file, line, branch_id)
        record = self._branches.get(key)
        if record is None:
            record = CoverageRecord(file=file, line=line, kind=BRANCH, label=branch_id)
            self._branches[key] = record
        return record

    def declare_condition(self, file: str, line: int, condition_id: str) -> CoverageRecord:
        key = (file, line, condition_id)
        record = self._conditions.get(key)
        if record is None:
            record = CoverageRecord(file=file, line=line, kind=CONDITION, label=condition_id)
            self._conditions[key] = record
        return record

    def hit_statement(self, file: str, line: int) -> None:
        record = self.declare_statement(file, line)
        record.hits += 1

    def hit_branch(self, file: str, line: int, branch_id: str) -> None:
        record = self.declare_branch(file, line, branch_id)
        record.hits += 1

    def hit_condition(self, file: str, line: int, condition_id: str, outcome: bool) -> None:
        record = self.declare_condition(file, line, condition_id)
        record.hits += 1
        key = "true" if outcome else "false"
        record.outcomes[key] = record.outcomes.get(key, 0) + 1

    def record_decision(
        self,
        file: str,
        line: int,
        decision_id: str,
        outcomes: dict[str, bool],
        result: bool,
    ) -> None:
        """Record one evaluation of a decision and of its conditions."""
        decision = self._decisions.get(decision_id)
        if decision is None:
            decision = DecisionCoverage(
                file=file, line=line, decision_id=decision_id, condition_ids=list(outcomes)
            )
            self._decisions[decision_id] = decision
        else:
            for condition_id in outcomes:
                if condition_id not in decision.condition_ids:
                    decision.condition_ids.append(condition_id)
        decision.observations.append(
            ConditionObservation(outcomes=dict(outcomes), result=bool(result))
        )
        for condition_id, outcome in outcomes.items():
            self.hit_condition(file, line, condition_id, outcome)

    def merge(self, other: "CoverageCollector") -> None:
        for record in other._statements.values():
            mine = self.declare_statement(record.file, record.line)
            mine.hits += record.hits
        for record in other._branches.values():
            mine = self.declare_branch(record.file, record.line, record.label)
            mine.hits += record.hits
        for record in other._conditions.values():
            mine = self.declare_condition(record.file, record.line, record.label)
            mine.hits += record.hits
            for key, value in record.outcomes.items():
                mine.outcomes[key] = mine.outcomes.get(key, 0) + value
        for decision in other._decisions.values():
            mine = self._decisions.get(decision.decision_id)
            if mine is None:
                self._decisions[decision.decision_id] = DecisionCoverage(
                    file=decision.file,
                    line=decision.line,
                    decision_id=decision.decision_id,
                    condition_ids=list(decision.condition_ids),
                    observations=list(decision.observations),
                )
            else:
                mine.merge(decision)

    def records(self) -> list[CoverageRecord]:
        result = list(self._statements.values())
        result.extend(self._branches.values())
        result.extend(self._conditions.values())
        result.sort(key=lambda record: (record.file, record.line, record.kind, record.label))
        return result

    def decisions(self) -> list[DecisionCoverage]:
        return sorted(self._decisions.values(), key=lambda item: (item.file, item.line, item.decision_id))

    def report(self) -> "CoverageReport":
        report = CoverageReport()
        files: dict[str, FileCoverage] = {}
        for record in self._statements.values():
            files.setdefault(record.file, FileCoverage(path=record.file)).statements.append(record)
        for record in self._branches.values():
            files.setdefault(record.file, FileCoverage(path=record.file)).branches.append(record)
        for record in self._conditions.values():
            files.setdefault(record.file, FileCoverage(path=record.file)).conditions.append(record)
        for path, coverage in files.items():
            coverage.statements.sort(key=lambda item: item.line)
            coverage.branches.sort(key=lambda item: (item.line, item.label))
            coverage.conditions.sort(key=lambda item: (item.line, item.label))
            report.files[path] = coverage
        for decision in self._decisions.values():
            report.decisions[decision.decision_id] = decision
        report.mcdc = compute_mcdc(report.decisions)
        return report


def compute_mcdc(decisions: dict[str, DecisionCoverage]) -> dict[str, bool]:
    """Decide which conditions are MC/DC covered.

    A condition is MC/DC covered when two evaluations of the same decision
    exist in which the condition took different values while every other
    condition of that decision kept the same value and the overall decision
    outcome changed.
    """
    covered: dict[str, bool] = {}
    for decision in decisions.values():
        condition_ids = list(decision.condition_ids)
        for condition_id in condition_ids:
            covered.setdefault(condition_id, False)
        observations = decision.observations
        for condition_id in condition_ids:
            others = [other for other in condition_ids if other != condition_id]
            for first in observations:
                for second in observations:
                    if first is second:
                        continue
                    if first.outcomes.get(condition_id) is None:
                        continue
                    if second.outcomes.get(condition_id) is None:
                        continue
                    if first.outcomes.get(condition_id) == second.outcomes.get(condition_id):
                        continue
                    if first.result == second.result:
                        continue
                    masked = True
                    for other in others:
                        left = first.outcomes.get(other)
                        right = second.outcomes.get(other)
                        if left is None or right is None or left != right:
                            masked = False
                            break
                    if masked:
                        covered[condition_id] = True
                        break
                if covered.get(condition_id):
                    break
    return covered


class CoverageReport:
    """The aggregated coverage of a test run."""

    def __init__(
        self,
        files: dict[str, FileCoverage] | None = None,
        decisions: dict[str, DecisionCoverage] | None = None,
        mcdc: dict[str, bool] | None = None,
    ) -> None:
        self.files: dict[str, FileCoverage] = files if files is not None else {}
        self.decisions: dict[str, DecisionCoverage] = decisions if decisions is not None else {}
        self.mcdc: dict[str, bool] = mcdc if mcdc is not None else {}

    @property
    def statement_coverage(self) -> float:
        covered = sum(
            sum(1 for record in file.statements if record.covered)
            for file in self.files.values()
        )
        total = sum(len(file.statements) for file in self.files.values())
        return _percentage(covered, total)

    @property
    def branch_coverage(self) -> float:
        covered = sum(
            sum(1 for record in file.branches if record.covered)
            for file in self.files.values()
        )
        total = sum(len(file.branches) for file in self.files.values())
        return _percentage(covered, total)

    @property
    def condition_coverage(self) -> float:
        covered = sum(
            sum(1 for record in file.conditions if _both_outcomes(record))
            for file in self.files.values()
        )
        total = sum(len(file.conditions) for file in self.files.values())
        return _percentage(covered, total)

    @property
    def mc_dc_coverage(self) -> float:
        covered = 0
        total = 0
        for file in self.files.values():
            for record in file.conditions:
                total += 1
                if self.mcdc.get(record.label, False):
                    covered += 1
        return _percentage(covered, total)

    @property
    def covered_lines(self) -> int:
        return sum(file.covered_lines for file in self.files.values())

    @property
    def total_lines(self) -> int:
        return sum(file.total_lines for file in self.files.values())

    def uncovered(self, kind: str | None = None) -> list[CoverageRecord]:
        result: list[CoverageRecord] = []
        for file in self.files.values():
            if kind in (None, STATEMENT):
                result.extend(record for record in file.statements if not record.covered)
            if kind in (None, BRANCH):
                result.extend(record for record in file.branches if not record.covered)
            if kind in (None, CONDITION):
                result.extend(
                    record for record in file.conditions if not _both_outcomes(record)
                )
        result.sort(key=lambda record: (record.file, record.line, record.kind, record.label))
        return result

    def records(self) -> list[CoverageRecord]:
        result: list[CoverageRecord] = []
        for file in self.files.values():
            result.extend(file.statements)
            result.extend(file.branches)
            result.extend(file.conditions)
        result.sort(key=lambda record: (record.file, record.line, record.kind, record.label))
        return result

    def merge(self, other: "CoverageReport") -> None:
        for path, coverage in other.files.items():
            mine = self.files.get(path)
            if mine is None:
                mine = FileCoverage(path=path)
                self.files[path] = mine
            _merge_records(mine.statements, coverage.statements)
            _merge_records(mine.branches, coverage.branches)
            _merge_records(mine.conditions, coverage.conditions)
        for decision_id, decision in other.decisions.items():
            mine = self.decisions.get(decision_id)
            if mine is None:
                self.decisions[decision_id] = DecisionCoverage(
                    file=decision.file,
                    line=decision.line,
                    decision_id=decision.decision_id,
                    condition_ids=list(decision.condition_ids),
                    observations=list(decision.observations),
                )
            else:
                mine.merge(decision)
        self.mcdc = compute_mcdc(self.decisions)

    def to_dict(self) -> dict:
        return {
            "statement_coverage": round(self.statement_coverage, 2),
            "branch_coverage": round(self.branch_coverage, 2),
            "condition_coverage": round(self.condition_coverage, 2),
            "mc_dc_coverage": round(self.mc_dc_coverage, 2),
            "covered_lines": self.covered_lines,
            "total_lines": self.total_lines,
            "files": {path: file.to_dict() for path, file in sorted(self.files.items())},
            "decisions": {
                key: decision.to_dict() for key, decision in sorted(self.decisions.items())
            },
        }

    def to_html(self) -> str:
        """Render the report as a self contained HTML fragment."""
        rows = []
        for path, file in sorted(self.files.items()):
            rows.append(
                "<tr><td><code>{path}</code></td>"
                "<td class='num'>{sc}%</td>"
                "<td class='num'>{bc}%</td>"
                "<td class='num'>{cc}%</td>"
                "<td class='num'>{mc}%</td>"
                "<td class='num'>{cl}/{tl}</td></tr>".format(
                    path=_escape(path),
                    sc=round(file.statement_coverage, 2),
                    bc=round(file.branch_coverage, 2),
                    cc=round(file.condition_coverage, 2),
                    mc=round(self._file_mcdc(file), 2),
                    cl=file.covered_lines,
                    tl=file.total_lines,
                )
            )
        body = "".join(rows) or "<tr><td colspan='6'>no data</td></tr>"
        return (
            "<div class='coverage-report'>"
            "<h3>Coverage</h3>"
            "<table class='coverage-table'>"
            "<thead><tr><th>File</th><th>Statements</th><th>Branches</th>"
            "<th>Conditions</th><th>MC/DC</th><th>Lines</th></tr></thead>"
            "<tbody>" + body + "</tbody>"
            "</table>"
            "<p class='coverage-summary'>"
            "Statements {sc}% | Branches {bc}% | Conditions {cc}% | MC/DC {mc}% | "
            "Lines {cl}/{tl}</p>"
            "</div>"
        ).format(
            sc=round(self.statement_coverage, 2),
            bc=round(self.branch_coverage, 2),
            cc=round(self.condition_coverage, 2),
            mc=round(self.mc_dc_coverage, 2),
            cl=self.covered_lines,
            tl=self.total_lines,
        )

    def _file_mcdc(self, file: FileCoverage) -> float:
        total = len(file.conditions)
        if total <= 0:
            return 0.0
        covered = sum(1 for record in file.conditions if self.mcdc.get(record.label, False))
        return covered * 100.0 / total

    def __repr__(self) -> str:
        return (
            "<CoverageReport statements={0:.1f}% branches={1:.1f}% "
            "conditions={2:.1f}% mcdc={3:.1f}%>".format(
                self.statement_coverage,
                self.branch_coverage,
                self.condition_coverage,
                self.mc_dc_coverage,
            )
        )


def _merge_records(mine: list[CoverageRecord], theirs: list[CoverageRecord]) -> None:
    index = {(record.line, record.label): record for record in mine}
    for record in theirs:
        key = (record.line, record.label)
        existing = index.get(key)
        if existing is None:
            index[key] = record
            mine.append(record)
            continue
        existing.hits += record.hits
        for name, value in (record.outcomes or {}).items():
            existing.outcomes[name] = existing.outcomes.get(name, 0) + value


def _escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
