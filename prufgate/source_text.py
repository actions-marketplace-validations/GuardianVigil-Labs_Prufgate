"""Offset-preserving views of source comments and quoted literals."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# Languages whose single-delimiter ' and " strings cannot span a line. A stray
# quote there (an apostrophe in JSX text) must not mask the rest of the file.
_LINE_STRINGS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
    ".py", ".go", ".java", ".kt", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift",
}
# A Rust char literal; any other ' starts a lifetime or label ('a, 'static).
_RUST_CHAR = re.compile(r"'(?:\\(?:u\{[0-9A-Fa-f]{1,6}\}|x[0-9A-Fa-f]{2}|.)|[^\\'\r\n])'")


@lru_cache(maxsize=64)
def views(text: str, path: str = "") -> tuple[str, str, tuple[tuple[int, int], ...]]:
    """Return comments masked, comments/literals masked, and comment spans.

    Quoted URLs and comment markers inside literals are data. Offsets and line
    endings stay intact, so callers can report locations in the original text.
    """
    suffix = Path(path).suffix.lower()
    hashes = not suffix or suffix in {".py", ".rb", ".sh", ".yaml", ".yml", ".toml", ".php"}
    slashes = suffix not in {".py", ".rb", ".sh", ".yaml", ".yml", ".toml"}
    dashes = not suffix or suffix == ".sql"
    line_strings = suffix in _LINE_STRINGS
    rust = suffix == ".rs"
    comments, literals = [], []
    i = 0
    while i < len(text):
        start = i
        if text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            i = len(text) if end < 0 else end + 3
            comments.append((start, i))
        elif slashes and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            comments.append((start, i))
        elif (slashes and text.startswith("//", i)) or (hashes and text[i] == "#") or (dashes and text.startswith("--", i)):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            comments.append((start, i))
        elif slashes and text[i] == "/" and (
            not text[:i].rstrip() or text[:i].rstrip()[-1] in "=(:,[!&|?{;"
            or text[:i].rstrip().endswith("return")
        ):
            # JS regex literals can contain [//] without starting a comment.
            i += 1
            in_class = False
            while i < len(text) and text[i] not in "\r\n":
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "[":
                    in_class = True
                elif text[i] == "]":
                    in_class = False
                elif text[i] == "/" and not in_class:
                    i += 1
                    break
                i += 1
            literals.append((start, min(i, len(text))))
        elif rust and text[i] == "'" and not _RUST_CHAR.match(text, i):
            i += 1
        elif text[i] in "\"'`":
            quote = text[i]
            delimiter = quote * 3 if text.startswith(quote * 3, i) else quote
            i += len(delimiter)
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text.startswith(delimiter, i):
                    i += len(delimiter)
                    break
                elif line_strings and delimiter in "'\"" and text[i] in "\r\n":
                    break
                else:
                    i += 1
            literals.append((start, min(i, len(text))))
        else:
            i += 1

    def mask(spans: list[tuple[int, int]]) -> str:
        out = list(text)
        for start, end in spans:
            for n in range(start, end):
                if out[n] not in "\r\n":
                    out[n] = " "
        return "".join(out)

    return mask(comments), mask(comments + literals), tuple(comments)


def comment_text(text: str, path: str = "") -> str:
    return "\n".join(text[a:b] for a, b in views(text, path)[2])
