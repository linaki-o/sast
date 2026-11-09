"""The CodeShield web dashboard.

The package exposes the FastAPI application of the dashboard::

    uvicorn sast.server.app:app --port 8765

``create_app`` is imported lazily so that importing the package does not
pull FastAPI into the process.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from sast.server.app import create_app as factory

        return factory
    if name == "app":
        return importlib.import_module("sast.server.app")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
