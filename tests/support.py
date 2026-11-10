"""Helpers shared by test modules (not collected: the name does not start with test)."""
from __future__ import annotations

import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def installed_python(root: Path) -> Path:
    """An editable test installation in a venv, visible even under Python -I."""
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(root)
    site = root / ("Lib/site-packages" if sys.platform == "win32" else
                   f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
    (site / "prufgate-fixture.pth").write_text(str(ROOT) + "\n", encoding="utf-8")
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
