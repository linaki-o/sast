"""Rule base classes and the global rule registry.

A rule is a class that implements :meth:`Rule.check`.  It receives a
:class:`~sast.analysis.context.FileContext` and yields
:class:`~sast.core.models.Violation` objects.

Example
-------
::

    @register
    class DivisionByZero(Rule):
        id = "SEC-DIV-001"
        name = "Division by zero"
        category = "security"
        severity = Severity.HIGH

        def check(self, ctx):
            for call in ctx.find_calls("div"):
                if ctx.is_literal_zero(call.arguments[0]):
                    yield ctx.report(self, call, "division by zero")
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any, Iterable, Iterator

from sast.core.models import RuleInfo, Severity, Violation

if TYPE_CHECKING:  # pragma: no cover
    from sast.analysis.context import FileContext

#: Global registry of every known rule, keyed by rule id.
RULE_REGISTRY: dict[str, type["Rule"]] = {}


class Rule(abc.ABC):
    """Base class of every analysis rule."""

    #: Unique identifier, e.g. ``SEC-BUF-001``.
    id: str = ""
    #: Human readable name.
    name: str = ""
    #: Category: ``security``, ``quality``, ``standards``, ``performance``.
    category: str = "quality"
    #: Default severity.
    severity: Severity = Severity.MEDIUM
    #: Long description shown in the documentation.
    description: str = ""
    #: Why the rule matters.
    rationale: str = ""
    #: How to fix the finding.
    recommendation: str = ""
    #: Related CWE identifiers.
    cwe: tuple[int, ...] = ()
    #: Related OWASP categories.
    owasp: tuple[str, ...] = ()
    #: Related coding standards (MISRA C:2012 rule numbers, CERT IDs ...).
    standards: tuple[str, ...] = ()
    #: Languages the rule applies to.
    languages: tuple[str, ...] = ("c", "c++")
    #: External references.
    references: tuple[str, ...] = ()
    #: Tags used for rule selection.
    tags: tuple[str, ...] = ()
    #: Whether the rule is enabled when no explicit configuration is given.
    enabled_by_default: bool = True
    #: Optional configuration knobs read from ``sast.yaml``.
    options: dict[str, Any] = {}

    def __init__(self, context: "FileContext | None" = None) -> None:
        self.ctx = context

    # ------------------------------------------------------------------
    def applies_to(self, language: str) -> bool:
        return language in self.languages

    @abc.abstractmethod
    def check(self, ctx: "FileContext") -> Iterable[Violation]:
        """Yield the violations found in *ctx*."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    def info(self) -> RuleInfo:
        """Metadata describing this rule."""
        return RuleInfo(
            rule_id=self.id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=self.description,
            rationale=self.rationale,
            recommendation=self.recommendation,
            cwe=self.cwe,
            owasp=self.owasp,
            standards=self.standards,
            languages=self.languages,
            references=self.references,
            enabled_by_default=self.enabled_by_default,
            tags=self.tags,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<Rule {self.id}>"


class RuleGroup:
    """A named collection of rules that can be enabled as a unit."""

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description

    def rules(self) -> list[type[Rule]]:
        return [rule for rule in RULE_REGISTRY.values() if rule.category == self.name]


def register(rule_cls: type[Rule]) -> type[Rule]:
    """Class decorator that adds a rule to the global registry."""
    if not rule_cls.id:
        raise ValueError(f"rule {rule_cls.__name__} has no id")
    if rule_cls.id in RULE_REGISTRY and RULE_REGISTRY[rule_cls.id] is not rule_cls:
        raise ValueError(f"duplicate rule id: {rule_cls.id}")
    RULE_REGISTRY[rule_cls.id] = rule_cls
    return rule_cls


def unregister(rule_id: str) -> None:
    RULE_REGISTRY.pop(rule_id, None)


def get_rule(rule_id: str) -> type[Rule] | None:
    return RULE_REGISTRY.get(rule_id)


def all_rules() -> list[type[Rule]]:
    return list(RULE_REGISTRY.values())


def rules_by_category() -> dict[str, list[type[Rule]]]:
    grouped: dict[str, list[type[Rule]]] = {}
    for rule in RULE_REGISTRY.values():
        grouped.setdefault(rule.category, []).append(rule)
    return grouped


def rule_catalog() -> list[RuleInfo]:
    """Metadata for every registered rule."""
    return [rule().info() for rule in RULE_REGISTRY.values()]
