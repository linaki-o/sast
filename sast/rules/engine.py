"""Rule execution engine.

The engine is responsible for

* discovering the files to analyse,
* parsing them and building the semantic context,
* running the selected rules against every file,
* applying the suppression mechanisms,
* aggregating everything into an :class:`~sast.core.models.AnalysisResult`.
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from sast.analysis.context import FileContext
from sast.analysis.scope import SymbolTable
from sast.ast.parser import Parser, ParseError
from sast.ast.nodes import TranslationUnit
from sast.core.config import AnalysisConfig, Project
from sast.core.models import AnalysisResult, Severity, SourceLocation, Violation
from sast.lexer.clexer import Lexer
from sast.rules.base import RULE_REGISTRY, Rule

#: Source file extensions understood by the toolchain.
SOURCE_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".tcc"}

#: Extensions that are usually generated and therefore excluded by default.
GENERATED_EXTENSIONS = {".pb.cc", ".pb.h", "_pb2.py"}


@dataclass
class AnalysisOptions:
    """Runtime options that are not part of the persisted configuration."""

    changed_files_only: bool = False
    changed_files: set[str] | None = None
    verbose: bool = False


class RuleEngine:
    """Runs the configured rules over a project."""

    def __init__(
        self,
        project: Project,
        *,
        rules: Sequence[type[Rule]] | None = None,
        options: AnalysisOptions | None = None,
    ) -> None:
        self.project = project
        self.config = project.config
        self.options = options or AnalysisOptions()
        self._rules: list[type[Rule]] = list(rules) if rules is not None else self._select_rules()
        self._suppressions: list[tuple[str, str, int]] = []  # (file, rule_id, line)
        self._file_suppressions: list[tuple[str, str]] = []  # (file, rule_id)
        #: Seconds spent in each phase of the last run.
        self.phase_timings: dict[str, float] = {
            "read": 0.0,
            "lex": 0.0,
            "parse": 0.0,
            "symbols": 0.0,
            "metrics": 0.0,
            "rules": 0.0,
        }
        #: Seconds spent in each rule during the last run.
        self.rule_timings: dict[str, float] = {}

    # ------------------------------------------------------------------
    def _select_rules(self) -> list[type[Rule]]:
        config = self.config
        enabled = set(config.enabled_rules)
        disabled = set(config.disabled_rules)
        threshold = Severity.parse(config.severity_threshold)
        categories = set(config.categories)

        selected: list[type[Rule]] = []
        for rule in RULE_REGISTRY.values():
            if rule.id in disabled:
                continue
            if enabled and rule.id not in enabled:
                # an explicit allow list wins over the default
                if not _matches_pack(rule, config.rule_packs):
                    continue
            if categories and rule.category not in categories:
                continue
            if not rule.enabled_by_default and rule.id not in enabled:
                continue
            if rule.severity.rank > threshold.rank and rule.id not in enabled:
                continue
            selected.append(rule)
        return selected

    # ------------------------------------------------------------------
    # file discovery
    # ------------------------------------------------------------------
    def discover_files(self) -> list[Path]:
        config = self.config
        roots = self.project.source_roots()
        files: list[Path] = []

        if config.files:
            for entry in config.files:
                candidate = self.project.resolve(entry)
                if candidate.is_file():
                    files.append(candidate)
                elif candidate.is_dir():
                    files.extend(self._walk(candidate))
        else:
            for root in roots:
                files.extend(self._walk(root))

        unique: list[Path] = []
        seen: set[Path] = set()
        for path in files:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            unique.append(resolved)
        return unique

    def _walk(self, root: Path) -> Iterator[Path]:
        excludes = self.config.excludes
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            relative = self.project.relative(path)
            if self._is_excluded(relative, excludes):
                continue
            if not self.config.analyse_tests and self._looks_like_test(relative):
                continue
            yield path

    def _is_excluded(self, relative: str, patterns: Sequence[str]) -> bool:
        for pattern in patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            # ``**/build/**`` style patterns
            if pattern.startswith("**/") and pattern.endswith("/**"):
                middle = pattern[3:-3]
                if f"/{middle}/" in f"/{relative}" or relative.startswith(f"{middle}/"):
                    return True
            if fnmatch.fnmatch(relative, f"*/{pattern}"):
                return True
        return False

    def _looks_like_test(self, relative: str) -> bool:
        lowered = relative.lower()
        name = Path(lowered).stem
        return (
            name.startswith("test")
            or name.endswith("_test")
            or name.endswith("test")
            or "/test/" in f"/{lowered}"
            or "/tests/" in f"/{lowered}"
            or "/unittest/" in f"/{lowered}"
        )

    # ------------------------------------------------------------------
    # analysis
    # ------------------------------------------------------------------
    def analyze(self) -> AnalysisResult:
        started = time.perf_counter()
        result = AnalysisResult(project=self.project.name)

        files = self.discover_files()
        if self.options.changed_files_only and self.options.changed_files is not None:
            wanted = set(self.options.changed_files)
            files = [path for path in files if self.project.relative(path) in wanted]

        for path in files:
            try:
                context = self.build_context(path)
            except Exception as error:  # pragma: no cover - defensive
                result.warnings.append(f"{path}: failed to parse ({error})")
                continue
            if context is None:
                continue

            result.files_scanned += 1
            result.lines_scanned += len(context.lines)
            result.file_metrics.extend(self._collect_metrics(context))

            rules_started = time.perf_counter()
            for rule_cls in self._rules:
                if not rule_cls().applies_to(context.language):
                    continue
                rule = rule_cls(context)
                rule_started = time.perf_counter()
                try:
                    for violation in rule.check(context) or ():
                        if violation is None:
                            continue
                        if self._is_suppressed(context, violation):
                            continue
                        result.violations.append(violation)
                except Exception as error:  # pragma: no cover - defensive
                    result.warnings.append(
                        f"{rule_cls.id} failed on {self.project.relative(path)}: {error}"
                    )
                elapsed = time.perf_counter() - rule_started
                self.rule_timings[rule_cls.id] = self.rule_timings.get(rule_cls.id, 0.0) + elapsed
            self.phase_timings["rules"] += time.perf_counter() - rules_started

        result.rules_executed = len(self._rules)
        result.duration_seconds = time.perf_counter() - started
        return result

    def build_context(self, path: Path) -> FileContext | None:
        """Parse *path* and build the context handed to the rules."""
        started = time.perf_counter()
        data = path.read_bytes()
        try:
            source = data.decode(self.config.encoding)
        except UnicodeDecodeError:
            source = data.decode("utf-8", errors="replace")
        self.phase_timings["read"] += time.perf_counter() - started

        relative = self.project.relative(path)
        language = "c++" if path.suffix.lower() in {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh"} else "c"

        started = time.perf_counter()
        lexed = Lexer(source, relative, language=language).tokenize()
        self.phase_timings["lex"] += time.perf_counter() - started

        started = time.perf_counter()
        parser = Parser(lexed.tokens, path=relative, language=language)
        unit = parser.parse()
        self.phase_timings["parse"] += time.perf_counter() - started

        unit.path = relative
        unit.language = language
        unit.includes = list(lexed.includes)

        started = time.perf_counter()
        symbols = SymbolTable(unit)
        self.phase_timings["symbols"] += time.perf_counter() - started

        return FileContext(
            unit,
            path=relative,
            source=source,
            symbols=symbols,
            macros=lexed.macros,
            comments=lexed.comments,
            directives=lexed.directives,
            config=self.config,
            language=language,
        )

    # ------------------------------------------------------------------
    def _collect_metrics(self, context: FileContext) -> list:
        from sast.analysis.metrics import collect_metrics

        started = time.perf_counter()
        metrics = collect_metrics(context)
        self.phase_timings["metrics"] += time.perf_counter() - started
        return metrics

    # ------------------------------------------------------------------
    # suppression
    # ------------------------------------------------------------------
    def _is_suppressed(self, context: FileContext, violation: Violation) -> bool:
        if not self.config.suppress_via_comments:
            return False
        for comment in context.comments:
            text = comment.text.lower()
            if not any(pattern.lower() in text for pattern in self.config.ignore_pattern):
                continue
            if not _mentions_rule(text, violation.rule_id):
                continue
            # the suppression applies to the line of the comment or the next line
            if comment.location.line in {
                violation.location.line,
                violation.location.line - 1,
            }:
                return True
        return False


def _mentions_rule(text: str, rule_id: str) -> bool:
    """Does the suppression comment mention this rule?"""
    if rule_id.lower() in text:
        return True
    # ``sast:ignore`` without a rule id suppresses every rule on that line
    for marker in ("sast:ignore", "coverity[", "codescan["):
        if marker in text:
            if "[" not in text.split(marker, 1)[1][:20]:
                return True
    return False


def _matches_pack(rule: type[Rule], packs: Sequence[str]) -> bool:
    if not packs:
        return False
    for pack in packs:
        if pack.lower() == rule.category.lower():
            return True
        if pack.lower() in rule.tags:
            return True
    return False
