"""Reusable widgets of the CodeShield desktop application.

The module hosts the small building blocks the main window is made of:

* :class:`SeverityBadge` -- a coloured label showing the severity of a finding,
* :class:`ViolationTableModel` -- the table model behind the findings view,
* :class:`RuleTreeModel` -- the tree model behind the rule catalogue,
* :class:`CoverageGauge` -- a donut gauge painted with ``QPainter``,
* :class:`MetricCard` -- a small KPI card.

Importing the module requires PySide6; a missing installation produces a
readable :class:`ImportError` instead of a bare ``ModuleNotFoundError``.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

try:
    from PySide6.QtCore import (
        QAbstractItemModel,
        QAbstractTableModel,
        QModelIndex,
        QRectF,
        Qt,
    )
    from PySide6.QtGui import QBrush, QColor, QPainter, QPen
    from PySide6.QtWidgets import (
        QFrame,
        QLabel,
        QSizePolicy,
        QVBoxLayout,
        QWidget,
    )
except ImportError as error:  # pragma: no cover - depends on the machine
    raise ImportError(
        "PySide6 is required for the CodeShield desktop GUI. "
        "Install it with 'pip install PySide6' or 'pip install sast[gui]'."
    ) from error

__all__ = [
    "SEVERITY_COLOURS",
    "SEVERITY_ORDER",
    "SeverityBadge",
    "ViolationTableModel",
    "RuleTreeModel",
    "CoverageGauge",
    "MetricCard",
]

SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#ff6b81",
    "high": "#ff9f45",
    "medium": "#ffd166",
    "low": "#4cc9f0",
    "info": "#9aa4b2",
}

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_RULE_STRIDE = 1000

_PANEL = "#212736"
_BORDER = "#2f3748"
_TEXT = "#e8ecf3"
_MUTED = "#94a0b4"


def _colour(name: str) -> QColor:
    return QColor(SEVERITY_COLOURS.get(str(name or "").lower(), SEVERITY_COLOURS["info"]))


def _rgba(colour: QColor, alpha: int) -> QColor:
    result = QColor(colour)
    result.setAlpha(alpha)
    return result


def _severity_of(value: Any) -> str:
    text = str(getattr(value, "value", value) or "info").lower()
    return text if text in SEVERITY_COLOURS else "info"


def _rank(value: Any) -> int:
    text = _severity_of(value)
    try:
        return SEVERITY_ORDER.index(text)
    except ValueError:
        return len(SEVERITY_ORDER)


class SeverityBadge(QLabel):
    """A small coloured label showing a severity."""

    def __init__(
        self,
        severity: Any = "info",
        text: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setObjectName("severityBadge")
        self.set_severity(severity, text)

    def set_severity(self, severity: Any, text: str | None = None) -> None:
        """Show *severity* with the matching colour."""
        name = _severity_of(severity)
        colour = _colour(name)
        self.setText(str(text if text is not None else name).upper())
        self.setStyleSheet(
            "background: rgba({}, {}, {}, 0.16);"
            "color: {};"
            "border: 1px solid rgba({}, {}, {}, 0.45);"
            "border-radius: 9px;"
            "padding: 1px 9px;"
            "font-size: 11px;"
            "font-weight: 700;".format(
                colour.red(),
                colour.green(),
                colour.blue(),
                colour.name(),
                colour.red(),
                colour.green(),
                colour.blue(),
            )
        )
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

    def severity(self) -> str:
        """The severity the badge currently shows."""
        return _severity_of(self.text().lower())


class ViolationTableModel(QAbstractTableModel):
    """The findings of an analysis run shown in the central table."""

    HEADERS: tuple[str, ...] = ("Severity", "Rule", "File", "Line", "Message")
    SEVERITY_COLUMN = 0
    RULE_COLUMN = 1
    FILE_COLUMN = 2
    LINE_COLUMN = 3
    MESSAGE_COLUMN = 4

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._all: list[Any] = []
        self._visible: list[Any] = []
        self._severity = ""
        self._text = ""
        self._sort_column = self.SEVERITY_COLUMN
        self._sort_order = Qt.SortOrder.AscendingOrder

    # -- population ----------------------------------------------------
    def set_violations(self, violations: Iterable[Any]) -> None:
        """Replace the findings of the model."""
        self.beginResetModel()
        self._all = list(violations or [])
        self._refresh()
        self.endResetModel()

    def clear(self) -> None:
        """Drop every finding."""
        self.set_violations([])

    def violations(self) -> list[Any]:
        """Every finding of the model, not only the visible ones."""
        return list(self._all)

    def visible_violations(self) -> list[Any]:
        """The findings currently shown."""
        return list(self._visible)

    def violation_at(self, row: int) -> Any | None:
        """The finding shown in *row*."""
        if 0 <= row < len(self._visible):
            return self._visible[row]
        return None

    # -- filtering -----------------------------------------------------
    def set_filter(self, severity: str | None = None, text: str | None = None) -> None:
        """Restrict the visible findings to one severity and a search term."""
        self.beginResetModel()
        self._severity = (severity or "").strip().lower()
        self._text = (text or "").strip().lower()
        self._refresh()
        self.endResetModel()

    def filter(self) -> tuple[str, str]:
        """The active severity and text filter."""
        return self._severity, self._text

    def _refresh(self) -> None:
        selected = []
        for violation in self._all:
            if self._severity and _severity_of(violation.severity) != self._severity:
                continue
            if self._text and self._text not in self._haystack(violation):
                continue
            selected.append(violation)
        self._visible = self._sorted(selected)

    def _haystack(self, violation: Any) -> str:
        location = getattr(violation, "location", None)
        path = getattr(location, "file", "")
        return " ".join(
            str(part).lower()
            for part in (
                getattr(violation, "rule_id", ""),
                getattr(violation, "rule_name", ""),
                getattr(violation, "message", ""),
                getattr(violation, "category", ""),
                getattr(violation, "function", ""),
                path,
            )
        )

    # -- sorting -------------------------------------------------------
    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Sort the visible findings by *column*."""
        self.layoutAboutToBeChanged.emit()
        self._sort_column = column
        self._sort_order = order
        self._visible = self._sorted(self._visible)
        self.layoutChanged.emit()

    def _sorted(self, items: list[Any]) -> list[Any]:
        column = self._sort_column
        reverse = self._sort_order == Qt.SortOrder.DescendingOrder
        if column == self.SEVERITY_COLUMN:
            key = lambda item: _rank(getattr(item, "severity", "info"))  # noqa: E731
        elif column == self.RULE_COLUMN:
            key = lambda item: str(getattr(item, "rule_id", ""))  # noqa: E731
        elif column == self.FILE_COLUMN:
            key = lambda item: str(getattr(getattr(item, "location", None), "file", ""))  # noqa: E731
        elif column == self.LINE_COLUMN:
            key = lambda item: int(getattr(getattr(item, "location", None), "line", 0) or 0)  # noqa: E731
        else:
            key = lambda item: str(getattr(item, "message", ""))  # noqa: E731
        return sorted(items, key=key, reverse=reverse)

    # -- Qt interface --------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._visible)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
            return None
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        violation = self.violation_at(index.row())
        if violation is None:
            return None
        location = getattr(violation, "location", None)
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == self.SEVERITY_COLUMN:
                return _severity_of(getattr(violation, "severity", "info"))
            if column == self.RULE_COLUMN:
                return str(getattr(violation, "rule_id", ""))
            if column == self.FILE_COLUMN:
                return str(getattr(location, "file", ""))
            if column == self.LINE_COLUMN:
                return int(getattr(location, "line", 0) or 0)
            return str(getattr(violation, "message", ""))
        if role == Qt.ItemDataRole.BackgroundRole:
            return QBrush(_rgba(_colour(getattr(violation, "severity", "info")), 28))
        if role == Qt.ItemDataRole.ForegroundRole:
            if column == self.SEVERITY_COLUMN:
                return QBrush(_colour(getattr(violation, "severity", "info")))
            if column == self.LINE_COLUMN:
                return QBrush(QColor(_TEXT))
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column == self.LINE_COLUMN:
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            return str(getattr(violation, "message", ""))
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable


class RuleTreeModel(QAbstractItemModel):
    """The rule catalogue grouped by category with check boxes."""

    def __init__(self, rules: Sequence[Any] | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._categories: list[str] = []
        self._rules: dict[str, list[dict[str, Any]]] = {}
        self._visible: dict[str, list[dict[str, Any]]] = {}
        self._enabled: set[str] = set()
        self._filter = ""
        if rules:
            self.set_rules(rules)

    # -- population ----------------------------------------------------
    def set_rules(self, rules: Sequence[Any]) -> None:
        """Replace the catalogue with *rules*."""
        self.beginResetModel()
        self._categories = []
        self._rules = {}
        self._enabled = set()
        for rule in rules or []:
            data = rule.to_dict() if hasattr(rule, "to_dict") else dict(rule)
            category = str(data.get("category") or "other")
            if category not in self._rules:
                self._rules[category] = []
                self._categories.append(category)
            self._rules[category].append(data)
            if data.get("enabled_by_default", True):
                self._enabled.add(str(data.get("rule_id")))
        self._visible = {name: list(items) for name, items in self._rules.items()}
        self.endResetModel()

    def set_filter(self, text: str | None) -> None:
        """Only show the rules matching *text*."""
        self.beginResetModel()
        self._filter = (text or "").strip().lower()
        self._visible = {}
        for category, items in self._rules.items():
            if not self._filter:
                self._visible[category] = list(items)
                continue
            matched = [
                item
                for item in items
                if self._filter in str(item.get("rule_id", "")).lower()
                or self._filter in str(item.get("name", "")).lower()
                or self._filter in str(item.get("category", "")).lower()
            ]
            if matched:
                self._visible[category] = matched
        self.endResetModel()

    def categories(self) -> list[str]:
        """The categories of the catalogue."""
        return list(self._categories)

    def rule_id(self, index: QModelIndex) -> str:
        """The rule identifier behind *index*."""
        data = self._entry(index)
        if data is None:
            return ""
        return str(data.get("rule_id", ""))

    def enabled_rule_ids(self) -> list[str]:
        """The identifiers of every checked rule."""
        enabled: list[str] = []
        for category in self._categories:
            for item in self._rules.get(category, []):
                if str(item.get("rule_id")) in self._enabled:
                    enabled.append(str(item.get("rule_id")))
        return enabled

    def is_enabled(self, rule_id: str) -> bool:
        """Is *rule_id* checked?"""
        return str(rule_id) in self._enabled

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        """Check or uncheck a single rule."""
        if enabled:
            self._enabled.add(str(rule_id))
        else:
            self._enabled.discard(str(rule_id))

    # -- internals -----------------------------------------------------
    def _entry(self, index: QModelIndex) -> dict[str, Any] | None:
        if not index.isValid():
            return None
        pointer = int(index.internalId())
        if pointer <= 0 or pointer % _RULE_STRIDE == 0:
            return None
        category = pointer // _RULE_STRIDE - 1
        position = pointer % _RULE_STRIDE - 1
        items = self._visible.get(self._categories[category], []) if 0 <= category < len(self._categories) else []
        if 0 <= position < len(items):
            return items[position]
        return None

    # -- Qt interface --------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if not parent.isValid():
            return len(self._categories)
        pointer = int(parent.internalId())
        if pointer > 0 and pointer % _RULE_STRIDE == 0:
            category = pointer - 1
            if 0 <= category < len(self._categories):
                return len(self._visible.get(self._categories[category], []))
        return 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 1

    def index(
        self, row: int, column: int, parent: QModelIndex = QModelIndex()
    ) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if not parent.isValid():
            return self.createIndex(row, column, row + 1)
        pointer = int(parent.internalId())
        if pointer > 0 and pointer % _RULE_STRIDE == 0:
            return self.createIndex(row, column, pointer * _RULE_STRIDE + row + 1)
        return QModelIndex()

    def parent(self, index: QModelIndex = QModelIndex()) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        pointer = int(index.internalId())
        if pointer > 0 and pointer % _RULE_STRIDE != 0:
            category = pointer // _RULE_STRIDE - 1
            return self.createIndex(category, 0, category + 1)
        return QModelIndex()

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return "Rules"
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        pointer = int(index.internalId())
        if pointer <= 0:
            return None
        if pointer % _RULE_STRIDE == 0:
            position = pointer - 1
            category = self._categories[position] if position < len(self._categories) else ""
            items = self._visible.get(category, [])
            if role == Qt.ItemDataRole.DisplayRole:
                return f"{category} ({len(items)})"
            if role == Qt.ItemDataRole.CheckStateRole:
                checked = [str(item.get("rule_id")) in self._enabled for item in items]
                if not checked:
                    return Qt.CheckState.Unchecked
                if all(checked):
                    return Qt.CheckState.Checked
                return Qt.CheckState.PartiallyChecked
            if role == Qt.ItemDataRole.ToolTipRole:
                return f"{len(items)} rules"
            return None
        entry = self._entry(index)
        if entry is None:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return str(entry.get("name") or entry.get("rule_id"))
        if role == Qt.ItemDataRole.CheckStateRole:
            if str(entry.get("rule_id")) in self._enabled:
                return Qt.CheckState.Checked
            return Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.ToolTipRole:
            parts = [str(entry.get("rule_id")), str(entry.get("name"))]
            if entry.get("description"):
                parts.append(str(entry.get("description")))
            return "\n".join(parts)
        if role == Qt.ItemDataRole.UserRole:
            return str(entry.get("rule_id"))
        if role == Qt.ItemDataRole.ForegroundRole:
            severity = str(entry.get("severity") or "info")
            return QBrush(_colour(severity))
        return None

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if role != Qt.ItemDataRole.CheckStateRole or not index.isValid():
            return False
        pointer = int(index.internalId())
        if pointer <= 0:
            return False
        if pointer % _RULE_STRIDE == 0:
            position = pointer - 1
            category = self._categories[position] if position < len(self._categories) else ""
            items = self._visible.get(category, [])
            checked = int(value) == int(Qt.CheckState.Checked.value)
            for item in items:
                self.set_enabled(str(item.get("rule_id")), checked)
            self.dataChanged.emit(
                self.index(position, 0),
                self.index(position, 0),
                [Qt.ItemDataRole.CheckStateRole],
            )
            return True
        entry = self._entry(index)
        if entry is None:
            return False
        self.set_enabled(
            str(entry.get("rule_id")), int(value) == int(Qt.CheckState.Checked.value)
        )
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return (
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )


class CoverageGauge(QWidget):
    """A donut gauge showing a coverage percentage."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value = 0.0
        self._label = ""
        self._colour = QColor("#3cc878")
        self.setMinimumSize(150, 150)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def set_value(self, value: float, label: str | None = None) -> None:
        """Show *value* (a percentage) on the gauge."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0
        self._value = max(0.0, min(100.0, number))
        if label is not None:
            self._label = label
        self.update()

    def value(self) -> float:
        """The percentage currently shown."""
        return self._value

    def set_colour(self, colour: str | QColor) -> None:
        """Set the colour of the gauge arc."""
        self._colour = QColor(colour) if isinstance(colour, str) else colour
        self.update()

    def paintEvent(self, event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = max(40.0, float(min(self.width(), self.height())) - 22.0)
        left = (self.width() - width) / 2.0
        top = (self.height() - width) / 2.0
        rect = QRectF(left, top, width, width)
        thickness = 13.0
        painter.setPen(QPen(QColor(_BORDER), thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        if self._value > 0:
            colour = QColor(self._colour)
            if self._value < 50:
                colour = QColor("#ff9f45")
            elif self._value < 80:
                colour = QColor("#ffd166")
            painter.setPen(
                QPen(colour, thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            )
            painter.drawArc(rect, 90 * 16, int(-360 * 16 * self._value / 100.0))
        painter.setPen(QColor(_TEXT))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(13)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self._value:.1f}%")
        if self._label:
            painter.setPen(QColor(_MUTED))
            font.setBold(False)
            font.setPointSize(9)
            painter.setFont(font)
            painter.drawText(
                QRectF(left, top + width - 4.0, width, 18.0),
                Qt.AlignmentFlag.AlignCenter,
                self._label,
            )


class MetricCard(QFrame):
    """A small card showing a single KPI."""

    def __init__(
        self,
        title: str = "",
        value: Any = "0",
        accent: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            "QFrame {{ background: {}; border: 1px solid {}; border-left: 3px solid {};"
            "border-radius: 6px; }}".format(
                _PANEL, _BORDER, accent or "#5b8dff"
            )
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(1)
        self._title = QLabel(str(title))
        self._title.setStyleSheet(f"color: {_MUTED}; font-size: 11px; border: none;")
        self._value = QLabel(str(value))
        self._value.setStyleSheet(f"color: {_TEXT}; font-size: 19px; font-weight: 700; border: none;")
        layout.addWidget(self._title)
        layout.addWidget(self._value)

    def set_value(self, value: Any) -> None:
        """Update the number of the card."""
        self._value.setText(str(value))

    def set_title(self, title: str) -> None:
        """Update the caption of the card."""
        self._title.setText(str(title))

    def value_text(self) -> str:
        """The text currently shown."""
        return self._value.text()
