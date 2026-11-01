"""Output that never crashes on the characters PrufGate prints (box drawing, check marks).

On Windows, output sent to a pipe or a file (CI logs, `> report.txt`) defaults to the
ANSI code page, cp1252, which cannot encode them: printing the summary table raised
UnicodeEncodeError and the run ended as a crash. A stream that cannot encode them is
switched to UTF-8, with unencodable characters replaced, never raised.
"""
from __future__ import annotations

import sys

_SAMPLE = "╔═✔✖—…"  # ╔═✔✖—…


def utf8_output() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        encoding = getattr(stream, "encoding", None)
        reconfigure = getattr(stream, "reconfigure", None)
        if stream is None or reconfigure is None:
            continue
        try:
            _SAMPLE.encode(encoding or "ascii")
        except (LookupError, UnicodeEncodeError):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
