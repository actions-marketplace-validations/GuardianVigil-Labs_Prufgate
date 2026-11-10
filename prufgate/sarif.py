"""Stable SARIF `partialFingerprints`, so code scanning tracks an alert across commits.

`primaryLocationLineHash` is computed exactly as GitHub's upload action does it
(github/codeql-action, `src/fingerprints.ts`): a rolling hash over the next 100
non-whitespace characters starting at the line, so inserting unrelated lines above a
finding does not change it, plus an occurrence counter (`:1`, `:2`, ...) for identical
content. Because the value matches the action's own, switching to PrufGate's
fingerprints does not reopen alerts the action already fingerprinted.

`prufgateFindingHash/v1` folds the rule into that hash, so two rules on the same line
never share a fingerprint. A result whose file cannot be read (a dynamic target, a file
outside the root, a line past the end) still gets a deterministic fallback built from
its rule, path and message.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Optional

from prufgate.safe_fs import safe_read_bytes

_BLOCK_SIZE = 100
_MOD = 37
_MASK = (1 << 64) - 1
_FIRST_MOD = pow(_MOD, _BLOCK_SIZE, 1 << 64)
_EOF = 65535
_MAX_FILE_BYTES = 4 * 1024 * 1024


def line_hashes(text: str) -> dict[int, str]:
    """Map each 1-based line number to GitHub's `primaryLocationLineHash` for it."""
    window = [0] * _BLOCK_SIZE
    starts = [-1] * _BLOCK_SIZE  # the line number that starts at each window slot, or -1
    counts: dict[str, int] = {}
    out: dict[int, str] = {}
    state = {"hash": 0, "index": 0}

    def emit() -> None:
        value = format(state["hash"], "x")
        counts[value] = counts.get(value, 0) + 1
        out[starts[state["index"]]] = f"{value}:{counts[value]}"
        starts[state["index"]] = -1

    def update(code: int) -> None:
        i = state["index"]
        state["hash"] = (_MOD * state["hash"] + code - _FIRST_MOD * window[i]) & _MASK
        window[i] = code
        state["index"] = (i + 1) % _BLOCK_SIZE

    # JavaScript's charCodeAt works on UTF-16 code units, so hash those.
    units = memoryview(text.encode("utf-16-le")).cast("H").tolist()
    line_no = 0
    line_start = True
    prev_cr = False
    for code in units + [_EOF]:
        if code in (32, 9) or (prev_cr and code == 10):
            prev_cr = False
            continue
        prev_cr = code == 13
        if prev_cr:
            code = 10
        if starts[state["index"]] != -1:
            emit()
        if line_start:
            line_start = False
            line_no += 1
            starts[state["index"]] = line_no
        if code == 10:
            line_start = True
        update(code)
    for _ in range(_BLOCK_SIZE):
        if starts[state["index"]] != -1:
            emit()
        update(0)
    return out


def _read_hashes(root: Path, uri: str) -> Optional[dict[int, str]]:
    """Line hashes for `uri` under `root`, or None when it is not a readable file inside it."""
    try:
        base = root.resolve()
        path = (base / uri).resolve()
        if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return line_hashes(safe_read_bytes(path).decode("utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _sha(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def add_partial_fingerprints(results: list[dict[str, Any]], root: Optional[Path]) -> None:
    """Set `partialFingerprints` on every SARIF result in place.

    `root` is the directory that result URIs are relative to; None skips file reads and
    gives every result the fallback fingerprint.
    """
    cache: dict[str, Optional[dict[int, str]]] = {}
    fallback_counts: dict[str, int] = {}
    for result in results:
        rule = str(result.get("ruleId", ""))
        location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
        uri = str(location.get("artifactLocation", {}).get("uri", ""))
        line = int(location.get("region", {}).get("startLine", 1) or 1)

        if root is not None and uri and uri not in cache:
            cache[uri] = _read_hashes(root, uri)
        line_hash = (cache.get(uri) or {}).get(line)
        if line_hash is None:
            # The line number is left out so the fallback survives line shifts too.
            base = _sha(rule, uri, str(result.get("message", {}).get("text", "")))[:16]
            fallback_counts[base] = fallback_counts.get(base, 0) + 1
            line_hash = f"{base}:{fallback_counts[base]}"

        fingerprints = result.setdefault("partialFingerprints", {})
        fingerprints["primaryLocationLineHash"] = line_hash
        fingerprints["prufgateFindingHash/v1"] = _sha(rule, line_hash)[:32]
