"""The CodeShield desktop application.

The package exposes the PySide6 based GUI of the tool::

    python -m sast.gui.main_window D:\\path\\to\\project

Importing the package requires PySide6.  When the library is missing a
readable :class:`ImportError` is raised instead of a bare
``ModuleNotFoundError``.
"""

from __future__ import annotations

from typing import Any

__all__ = ["main", "run_gui", "MainWindow"]

_MESSAGE = (
    "PySide6 is required for the CodeShield desktop GUI. "
    "Install it with 'pip install PySide6' or 'pip install sast[gui]'."
)

try:
    import PySide6  # noqa: F401
except ImportError as error:  # pragma: no cover - depends on the machine
    raise ImportError(_MESSAGE) from error


def __getattr__(name: str) -> Any:
    if name in {"main", "run_gui", "MainWindow"}:
        from sast.gui import main_window

        return getattr(main_window, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
