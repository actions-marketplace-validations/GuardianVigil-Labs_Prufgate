"""Trusted commands used while inspecting an untrusted workspace."""

from __future__ import annotations

import sys
from pathlib import Path

GIT_SAFE = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")


def git_command(*args: str) -> list[str]:
    """Disable repository-configured executable hooks for every git operation."""
    return ["git", *GIT_SAFE, *args]


def cli_command(*args: str) -> list[str]:
    """Launch this installation, without cwd, PYTHONPATH or user-site imports.

    A zipapp is itself executable; a checkout/wheel contains cli.py. Never use
    `-m` from the workspace: a package planted there would win module lookup.
    """
    root = Path(__file__).resolve().parent.parent
    entry = root if root.is_file() else root / "prufgate" / "cli.py"
    return [sys.executable, "-I", str(entry), *args]
