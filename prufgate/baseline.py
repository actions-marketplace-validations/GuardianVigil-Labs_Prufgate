"""The PrufGate baseline: findings a project already had, which are not reported.

`.prufgate/baseline.yaml` (or `.yml`, `.json`) holds a list of entries, either at
the top level or under `baseline`, `ignore` or `ignored`. An entry names a `file`
and a `rule` (`file_path` and `rule_id` are accepted too; `"*"` in one of them
matches anything) and, when `prufgate baseline` wrote it, a `fingerprint`: a hash
of the rule and the finding's line (whitespace removed), with a counter for
findings of that rule on identical lines in the file (`<hash>:1`, `<hash>:2`).
Lines moving, or code changing elsewhere in the file, do not change it. An entry
with a fingerprint hides one finding, so a new finding of the same rule in the
same file is still reported, and so is one whose line is edited. `line` is
informational. Rule IDs match case-insensitively, through aliases, with or
without the gate's `anti-fabrication-` prefix.

With a base ref the baseline is read as it is at the merge base, never from the
working tree, so a change cannot baseline its own findings. Rules that guard the
gate itself are never hidden.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from prufgate.config import _diff_base, expand_rule_aliases, git_blob, repo_prefix

BASELINE_FILES = (".prufgate/baseline.yaml", ".prufgate/baseline.yml", ".prufgate/baseline.json")
DEFAULT_FILE = BASELINE_FILES[0]
# Findings about the gate's own integrity: a baseline entry must never hide them.
PROTECTED_RULES = frozenset({
    "prufgate-config-self-exemption", "prufgate-config-not-applied", "debt-ceiling-breached",
})
_PREFIX = "anti-fabrication-"
_LEAD_RE = re.compile(r"^(?:/workspace/|\./|/)+")
_MAX_FILE_BYTES = 4 * 1024 * 1024

HEADER = """\
# PrufGate baseline: findings that already existed when `prufgate baseline` wrote this file.
# They are not reported and do not block. A new finding still is reported, and so is
# one whose line is edited. Delete entries as you fix them, or run `prufgate baseline`
# again. In a pull request the baseline is read from the base branch, so a change to
# this file applies only after merge.
"""


class BaselineError(Exception):
    """The baseline file exists but cannot be read or parsed."""


@dataclass(frozen=True)
class Entry:
    file: str  # normalized path, or "*"
    rule: str  # canonical rule, or "*"
    fingerprint: Optional[str] = None


def norm_path(path: object) -> str:
    return _LEAD_RE.sub("", str(path).strip().replace("\\", "/"))


def canonical_rule(rule: object) -> str:
    """One spelling per rule: lower case, no `anti-fabrication-` prefix, the first alias."""
    r = str(rule).strip()
    if r.lower().startswith(_PREFIX):
        r = r[len(_PREFIX):]
    return min(a.lower() for a in expand_rule_aliases(r))


def read_baseline(workspace: Path, ref: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """(path, text) of the first baseline file, or None. With `ref` it is read as it
    is at the merge base with that ref. Raises GitDiffError when git cannot read it."""
    if ref is None:
        for rel in BASELINE_FILES:
            p = workspace / rel
            if p.is_file():
                try:
                    return rel, p.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    return rel, ""
        return None
    commit = _diff_base(ref, workspace)
    prefix = repo_prefix(workspace)
    for rel in BASELINE_FILES:
        text = git_blob(commit, prefix + rel, workspace)
        if text is not None:
            return rel, text
    return None


def parse_entries(baseline: Optional[Tuple[str, str]]) -> List[Entry]:
    """The entries of a baseline from `read_baseline`. Raises BaselineError when the
    file does not parse; an entry that names neither a file nor a rule is skipped."""
    if baseline is None:
        return []
    rel, text = baseline
    try:
        if rel.endswith((".yaml", ".yml")):
            import yaml

            data = yaml.safe_load(text) if text.strip() else None
        else:
            data = json.loads(text) if text.strip() else None
    except ImportError as exc:
        raise BaselineError(f"{rel}: PyYAML is not installed, so the baseline cannot be read") from exc
    except Exception as exc:  # yaml.YAMLError, ValueError
        raise BaselineError(f"{rel} does not parse: {exc.__class__.__name__}") from exc
    if data is None:
        return []
    if isinstance(data, dict):
        items = data.get("baseline") or data.get("ignore") or data.get("ignored") or []
    else:
        items = data
    if not isinstance(items, list):
        raise BaselineError(f"{rel}: expected a list of entries")
    entries: List[Entry] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_file = item.get("file", item.get("file_path"))
        raw_rule = item.get("rule", item.get("rule_id"))
        if raw_file is None and raw_rule is None:
            continue
        e_file = "*" if raw_file in (None, "*") else norm_path(raw_file)
        e_rule = "*" if raw_rule in (None, "*") else canonical_rule(raw_rule)
        if not e_file or not e_rule or (e_file == "*" and e_rule == "*"):
            continue
        fp = item.get("fingerprint")
        entries.append(Entry(e_file, e_rule, str(fp) if fp else None))
    return entries


class _Lines:
    """Whitespace-free text of each line of files under `root`, read once."""

    def __init__(self, root: Optional[Path]):
        self.root = root.resolve() if root is not None else None
        self._files: Dict[str, Optional[List[str]]] = {}

    def get(self, file: str, line: int) -> str:
        if self.root is None:
            return ""
        if file not in self._files:
            self._files[file] = None
            try:
                path = (self.root / file).resolve()
                if path.is_relative_to(self.root) and path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
                    text = path.read_bytes().decode("utf-8", errors="replace")
                    self._files[file] = ["".join(ln.split()) for ln in text.splitlines()]
            except (OSError, ValueError):
                pass
        lines = self._files[file] or []
        return lines[line - 1] if 0 < line <= len(lines) else ""


Item = Tuple[object, object, object]  # (file, rule, line) of a finding


def fingerprints(items: List[Item], root: Optional[Path]) -> List[Tuple[str, str, str]]:
    """(file, rule, fingerprint) of each finding, normalized. The counter numbers the
    findings of one rule on identical lines of one file in line order."""
    lines = _Lines(root)
    keyed = []
    for file, rule, line in items:
        n_file, c_rule, n_line = norm_path(file or "workspace"), canonical_rule(rule), int(line or 1)
        digest = hashlib.sha256(f"{c_rule}\0{lines.get(n_file, n_line)}".encode("utf-8")).hexdigest()[:16]
        keyed.append((n_file, c_rule, digest, n_line))
    order = sorted(range(len(keyed)), key=lambda i: (keyed[i][0], keyed[i][1], keyed[i][3]))
    counts: Dict[Tuple[str, str, str], int] = {}
    out: List[Tuple[str, str, str]] = [("", "", "")] * len(keyed)
    for i in order:
        n_file, c_rule, digest, _ = keyed[i]
        counts[(n_file, c_rule, digest)] = counts.get((n_file, c_rule, digest), 0) + 1
        out[i] = (n_file, c_rule, f"{digest}:{counts[(n_file, c_rule, digest)]}")
    return out


class Matcher:
    """Matches findings against baseline entries and remembers which entries matched."""

    def __init__(self, entries: Iterable[Entry], root: Optional[Path]):
        self.entries = list(entries)
        self.root = root
        self.used: set = set()

    def match_all(self, items: List[Item]) -> List[bool]:
        """Whether the baseline lists each finding. Pass all findings of a scan at once:
        the fingerprint counters are numbered across them."""
        exact = {(e.file, e.rule, e.fingerprint): e for e in self.entries if e.fingerprint is not None}
        loose = [e for e in self.entries if e.fingerprint is None]
        out = []
        for key in fingerprints(items, self.root):
            n_file, c_rule, _ = key
            hit = None
            if c_rule not in PROTECTED_RULES:
                hit = exact.get(key) or next(
                    (e for e in loose if e.rule in ("*", c_rule) and e.file in ("*", n_file)), None
                )
            if hit is not None:
                self.used.add(hit)
            out.append(hit is not None)
        return out

    def stale(self) -> List[Entry]:
        return [e for e in self.entries if e not in self.used]


def entries_for(items: List[Item], root: Path) -> List[Dict[str, object]]:
    """The baseline entries `prufgate baseline` writes, sorted by file and line."""
    out = []
    for (file, rule, fp), (_, shown, line) in zip(fingerprints(items, root), items):
        if rule in PROTECTED_RULES:
            continue
        # The rule as reports name it; matching goes through canonical_rule.
        name = str(shown).strip()
        name = name[len(_PREFIX):] if name.lower().startswith(_PREFIX) else name
        out.append({"rule": name, "file": file, "fingerprint": fp, "line": int(line or 1)})
    out.sort(key=lambda e: (e["file"], e["line"], e["rule"]))
    return out


def render(entries: List[Dict[str, object]], as_json: bool) -> str:
    if as_json:
        return json.dumps({"version": 1, "baseline": entries}, indent=2) + "\n"
    # Flow mappings with JSON-quoted strings: valid YAML, one finding per line.
    lines = [HEADER, "version: 1", "baseline:" if entries else "baseline: []"]
    for e in entries:
        pairs = ", ".join(f"{k}: {json.dumps(v)}" for k, v in e.items())
        lines.append(f"  - {{{pairs}}}")
    return "\n".join(lines) + "\n"


def write(path: Path, text: str) -> None:
    """Write without following a symlink: the file lives in the scanned repository."""
    if path.parent.is_symlink() or path.is_symlink():
        raise OSError(f"refusing to write through a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
