"""CLI module for IMETA."""

from typing import Any


def __getattr__(name: str) -> Any:
    if name in ("main", "build_parser"):
        from . import main as main_mod

        return getattr(main_mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["main", "build_parser"]

