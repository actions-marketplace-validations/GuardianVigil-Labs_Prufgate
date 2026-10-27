#!/usr/bin/env python3
"""The lines a change touched, for changed-files scans (`check --changed`, `prufgate.sh fast`).

A pull request is judged on what it changed. Every engine still reads whole files
(a rule may need context), but a finding is kept only when its location overlaps
a line the diff added or modified. A finding on a line that opens a block (a
function, a test, an `if` or `catch` body) covers the whole block, so deleting the
assertions of a test or rewriting the body of an error branch is still in scope. The diff is the working tree against the merge
base with the base ref (else HEAD), untracked files included as wholly new.

Kept whatever their line: rules about the diff itself (`DIFF_ANCHORED_*`), such as
a deleted test file or a weakened assertion, which point at removed code; gitleaks
findings from the scanned commit range (`Commit` set), already limited to the
change by the runner. A full scan (no `--changed`) applies no scope at all.

Run as a script, it writes `{path: [[start, end], ...]}` as JSON and prints the
changed paths that exist, one per line, for the shell runners.
"""

from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from prufgate.config import GitDiffError, _diff_base, _git  # noqa: E402

Ranges = Dict[str, List[Tuple[int, int]]]
WHOLE_FILE = (1, 10**9)

# Engines and rules whose findings are about the diff itself, often its removed lines.
DIFF_ANCHORED_TOOLS = frozenset({"diff-guard", "pr-reviewer", "prufgate-gate", "config"})
DIFF_ANCHORED_RULES = frozenset({"test-input-special-casing", "prufgate-config-self-exemption", "debt-ceiling-breached"})

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _unquote_git_path(raw: str, prefix: str = "") -> Optional[str]:
    """Parse a path from a `+++ ` or `rename to ` diff header, handling trailing tabs
    (appended by git when a filename contains spaces) and C-style quoting (`"b/..."`)."""
    s = raw.rstrip("\t")
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        inner = s[1:-1]
        out_bytes = bytearray()
        i = 0
        esc = {"n": 10, "t": 9, "r": 13, "b": 8, "f": 12, "a": 7, "v": 11, '"': 34, "\\": 92}
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt in "01234567":
                    m = re.match(r"^[0-7]{1,3}", inner[i + 1 : i + 4])
                    if m:
                        out_bytes.append(int(m.group(0), 8) & 0xFF)
                        i += 1 + len(m.group(0))
                        continue
                if nxt in esc:
                    out_bytes.append(esc[nxt])
                    i += 2
                    continue
                out_bytes.extend(nxt.encode("utf-8"))
                i += 2
            else:
                out_bytes.extend(inner[i].encode("utf-8"))
                i += 1
        s = out_bytes.decode("utf-8", errors="replace")
    else:
        s = s.split("\t", 1)[0]
    if prefix:
        return s[len(prefix):] if s.startswith(prefix) else None
    return s or None


def parse_diff(diff: str) -> Ranges:
    """{path: [(first, last)]} of the added lines of a `-U0` diff. A pure deletion
    marks the two lines around it, so code that now joins across it is in scope."""
    ranges: Ranges = {}
    current: Optional[List[Tuple[int, int]]] = None
    old_left = 0
    new_left = 0
    for line in diff.splitlines():
        if old_left > 0 or new_left > 0:
            if line.startswith("-") and old_left > 0:
                old_left -= 1
                continue
            if line.startswith("+") and new_left > 0:
                new_left -= 1
                continue
            if line.startswith(" ") and old_left > 0 and new_left > 0:
                old_left -= 1
                new_left -= 1
                continue
            if line.startswith("\\"):
                continue
        if line.startswith("diff --git "):
            current = None
            old_left = new_left = 0
        elif line.startswith("rename to ") and old_left == 0 and new_left == 0:
            rel = _unquote_git_path(line[len("rename to "):])
            if rel:
                current = ranges.setdefault(rel, [WHOLE_FILE])
        elif line.startswith("--- ") and old_left == 0:
            new_left = 0
        elif line.startswith("+++ ") and new_left == 0:
            rel = _unquote_git_path(line[4:], prefix="b/")
            current = ranges.setdefault(rel, []) if rel else None
            old_left = 0
        elif current is not None and (m := _HUNK_RE.match(line)):
            old_left = int(m.group(2) or "1")
            start, count = int(m.group(3)), int(m.group(4) or "1")
            new_left = count
            if current == [WHOLE_FILE]:
                current.clear()
            current.append((start, start + count - 1) if count else (max(1, start), start + 1))
    return ranges


def changed_lines(base_ref: Optional[str], cwd: Path | str) -> Ranges:
    """The changed lines under `cwd`, paths relative to it. Raises GitDiffError
    when git cannot produce the diff: a scope that cannot be computed must fail."""
    _masked_lines.cache_clear()  # a long-lived process (MCP, API) must not see old file text
    commit = _diff_base(base_ref or None, cwd)
    diff = _git(
        ["-c", "core.quotePath=false", "diff", "-U0", "-M", "--text", "--no-color", "--no-ext-diff",
         "--no-textconv", "--relative", "--end-of-options", commit],
        cwd,
    )
    ranges = parse_diff(diff)
    for rel in _git(["ls-files", "-z", "--others", "--exclude-standard"], cwd).split("\0"):
        if rel:
            ranges[rel] = [WHOLE_FILE]
    return ranges


def norm_path(path: str, workspace: Optional[Path] = None) -> str:
    p = str(path or "").replace("\\", "/")
    if workspace is not None:
        prefix = str(workspace.resolve()).rstrip("/") + "/"
        if p.startswith(prefix):
            p = p[len(prefix):]
    return re.sub(r"^(?:/workspace/|\./)+", "", p)


_MAX_BLOCK = 300
_RUBY_OPEN_RE = re.compile(r"\b(?:do|def)\b")
_RUBY_END_RE = re.compile(r"\bend\b")


@lru_cache(maxsize=256)
def _masked_lines(path: str) -> Tuple[str, ...]:
    from prufgate.anti_reward_hacking.test_integrity import (
        _strip_comments_and_strings_Preserve_len as mask,
    )

    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ()
    return tuple(mask(text).splitlines())


def block_end(lines: Tuple[str, ...], line: int) -> int:
    """The last line of the block that `line` (1-based) opens: braces, a Python
    `:` header and its indented body, or a Ruby `do`/`def` ... `end` block.
    Walks past leading `@decorator` lines and multi-line `(...)` parameter lists."""
    if not 1 <= line <= len(lines):
        return line
    idx = line - 1
    limit = min(len(lines), idx + _MAX_BLOCK)
    while idx < limit and lines[idx].lstrip().startswith("@"):
        pdepth = lines[idx].count("(") - lines[idx].count(")")
        idx += 1
        while idx < limit and pdepth > 0:
            pdepth += lines[idx].count("(") - lines[idx].count(")")
            idx += 1
        while idx < limit and not lines[idx].strip():
            idx += 1
    if idx >= limit:
        return min(len(lines), line + _MAX_BLOCK)

    hdr_idx = idx
    pdepth = lines[hdr_idx].count("(") - lines[hdr_idx].count(")")
    while pdepth > 0 and hdr_idx + 1 < limit:
        if lines[hdr_idx].count("{") > lines[hdr_idx].count("}"):
            break
        hdr_idx += 1
        pdepth += lines[hdr_idx].count("(") - lines[hdr_idx].count(")")

    hdr_open = lines[hdr_idx].lstrip().lstrip("}")
    depth = hdr_open.count("{") - hdr_open.count("}")
    brace_start = hdr_idx
    if depth <= 0 and hdr_idx + 1 < limit and lines[hdr_idx + 1].lstrip().startswith("{"):
        brace_start = hdr_idx + 1
        depth = lines[brace_start].count("{") - lines[brace_start].count("}")
    if depth > 0:
        for n in range(brace_start + 1, limit):
            depth += lines[n].count("{") - lines[n].count("}")
            if depth <= 0:
                return n + 1
        return limit

    if lines[hdr_idx].rstrip().endswith(":"):
        indent = len(lines[idx]) - len(lines[idx].lstrip())
        end = hdr_idx + 1
        for n in range(hdr_idx + 1, limit):
            if not lines[n].strip():
                continue
            if len(lines[n]) - len(lines[n].lstrip()) <= indent:
                break
            end = n + 1
        return end

    rdepth = len(_RUBY_OPEN_RE.findall(lines[hdr_idx])) - len(_RUBY_END_RE.findall(lines[hdr_idx]))
    if rdepth > 0:
        for n in range(hdr_idx + 1, limit):
            rdepth += len(_RUBY_OPEN_RE.findall(lines[n])) - len(_RUBY_END_RE.findall(lines[n]))
            if rdepth <= 0:
                return n + 1
        return limit

    if hdr_idx > line - 1:
        return hdr_idx + 1
    return line


def in_scope(
    ranges: Ranges,
    tool: str,
    rule: str,
    path: str,
    spans: List[Tuple[int, int]],
    workspace: Optional[Path] = None,
) -> bool:
    """Whether a finding at `spans` (inclusive line ranges) of `path` is part of the change."""
    if (
        tool in DIFF_ANCHORED_TOOLS
        or rule in DIFF_ANCHORED_RULES
        or rule.startswith("diff-")
        or rule.endswith("debt-ceiling-breached")
    ):
        return True
    rel = norm_path(path, workspace)
    touched = ranges.get(rel)
    if not touched:
        return False
    if any(a <= end and start <= b for start, end in spans for a, b in touched):
        return True
    lines = _masked_lines(str((workspace or Path.cwd()) / rel))
    return any(a <= block_end(lines, start) and start <= b for start, _ in spans for a, b in touched)


def load(path: Path) -> Optional[Ranges]:
    """Ranges written by `main`, or None when the file is absent (a full scan)."""
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): [(int(a), int(b)) for a, b in v] for k, v in data.items()}


def main(argv: Optional[List[str]] = None) -> int:
    base, out = None, None
    for a in argv if argv is not None else sys.argv[1:]:
        if a.startswith("--base="):
            base = a.split("=", 1)[1] or None
        elif a.startswith("--json-out="):
            out = a.split("=", 1)[1]
        else:
            print(f"usage: {sys.argv[0]} [--base=REF] --json-out=PATH", file=sys.stderr)
            return 2
    if not out:
        print("diff_scope: --json-out is required", file=sys.stderr)
        return 2
    try:
        ranges = changed_lines(base, Path.cwd())
    except GitDiffError as e:
        print(f"diff_scope: cannot compute the changed lines: {e}", file=sys.stderr)
        return 2
    Path(out).write_text(json.dumps(ranges, sort_keys=True), encoding="utf-8")
    for rel in sorted(ranges):
        if Path(rel).is_file():
            print(rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
