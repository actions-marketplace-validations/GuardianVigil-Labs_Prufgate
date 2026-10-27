"""String-literal awareness for line rules.

A rule that looks for code (`onClick={() => {}}`, `# noqa`, `` exec(`... ${x}`) ``)
must not fire on a string that only describes that code: a help text, a list of
examples, a marketing page. `search_code` returns the first match that starts
outside every quoted string on the line.
"""

from __future__ import annotations

import re

_STRING_PREFIXES = frozenset({"r", "u", "b", "f", "fr", "rf", "br", "rb"})


def string_spans(line: str) -> list[tuple[int, int]]:
    """(start, end) of each '...', "..." and `...` literal closed on this line,
    quotes included. An unclosed quote (an apostrophe in prose or a comment, a
    template that continues on the next line) opens nothing."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "#" or (c == "/" and i + 1 < n and line[i + 1] == "/"):
            break
        if c == "/" and i + 1 < n and line[i + 1] == "*":
            end = line.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        if c in "\"'`":
            if c == "'" and i > 0 and (line[i - 1].isalnum() or line[i - 1] == "_"):
                k = i - 1
                while k > 0 and (line[k - 1].isalnum() or line[k - 1] == "_"):
                    k -= 1
                if line[k:i].lower() not in _STRING_PREFIXES:
                    i += 1
                    continue
            j = i + 1
            while j < n and line[j] != c:
                j += 2 if line[j] == "\\" else 1
            if j < n:
                spans.append((i, j + 1))
                i = j + 1
                continue
        i += 1
    return spans


def in_string(spans: list[tuple[int, int]], pos: int) -> bool:
    return any(a <= pos < b for a, b in spans)


def search_code(pattern: re.Pattern[str], line: str) -> re.Match[str] | None:
    """The first match of `pattern` in `line` that starts outside a string literal."""
    spans = string_spans(line)
    for m in pattern.finditer(line):
        if not in_string(spans, m.start()):
            return m
    return None
