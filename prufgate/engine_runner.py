"""Run a shipped Python engine while measuring its successful source reads."""
from __future__ import annotations

import json
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from prufgate.coverage import Coverage, recording  # noqa: E402
from prufgate.safe_fs import safe_write_text  # noqa: E402


def main() -> int:
    output, engine, script, *args = sys.argv[1:]
    path = Path(script).resolve()
    if not path.is_relative_to(ROOT / "prufgate"):
        raise ValueError("only shipped engine scripts can be executed")
    trace = Coverage(Path(os.environ.get("WORKSPACE", os.getcwd())), "battery")
    trace.step(engine)
    code = 2
    try:
        sys.argv = [str(path), *args]
        with recording(trace):
            try:
                runpy.run_path(str(path), run_name="__main__")
                code = 0
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 2 if exc.code else 0
        trace.engines[-1].update(status="completed" if code in (0, 1) else "error", reason="" if code in (0, 1) else f"Engine exited {code}.")
    finally:
        safe_write_text(Path(output), json.dumps(trace.to_dict()))
    return code


if __name__ == "__main__":
    sys.exit(main())
