"""Deterministic auto-fixes for safe cases (`prufgate fix`).

Only lines the branch adds against the base are touched, each fix must match the
expected text exactly, and each one is checked: the rule it answers must stop firing
once it is applied. Anything else is reported as "no safe fix".

Fixes: a focus filter (`.only`, `fit`, `fdescribe`) loses its focus; an unjustified
skip is removed; an assertion hunk that only deletes or weakens assertions gets the
base lines back; a suppression comment without a reason is removed (a reason is never
invented); `|| true` and `continue-on-error: true` in a CI workflow are removed.

Files are written only with `--apply`, never through a symlink and never outside the
repository.
"""

from __future__ import annotations

import difflib
import errno
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from prufgate import inline_ignore
from prufgate.anti_reward_hacking.test_integrity import (
    DIFF_ASSERTION_LINE_RE,
    scan_diff_for_reward_hacking,
)
from prufgate.diff_guard import tamper_detector as td
from prufgate.review.reviewer import PRComment, format_review_github

ASSERTION_RULE = "diff-assertion-weakening"
SKIP_RULE = "test-skip-smuggling"
SUPPRESSION_RULE = "suppression-comment-smuggling"
CI_RULE = "linter-or-ci-config-weakening"
IGNORE_RULE = inline_ignore.MISSING_REASON_RULE


class FixError(RuntimeError):
    """The fix plan could not be computed (bad ref, not a repository)."""


@dataclass
class Edit:
    """Replace new-file line `line` (1-based, `old` with its line ending) by `new` (empty: delete it)."""

    line: int
    old: str
    new: list[str]


@dataclass
class Fix:
    rule: str
    path: str
    title: str
    edits: list[Edit] = field(default_factory=list)


@dataclass
class NoFix:
    rule: str
    path: str
    line: int
    why: str


@dataclass
class FileState:
    base: list[str]  # lines with endings; empty for a new file
    head: list[str]


@dataclass
class Plan:
    fixes: list[Fix]
    skipped: list[NoFix]
    files: dict[str, FileState]


# --- git -------------------------------------------------------------------


def _git(root: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    # Repository hooks and fsmonitor are code from the repository: never run them.
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=root, capture_output=True, text=text, check=False,
    )


def _blob(root: Path, rev: str, path: str) -> list[str] | None:
    res = _git(root, "show", f"{rev}:{path}", text=False)
    if res.returncode != 0:
        return None
    try:
        return res.stdout.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


def _changed_files(root: Path, base: str) -> list[str]:
    """Regular files (not symlinks, not submodules) the branch adds or modifies."""
    res = _git(root, "diff", "--raw", "-z", "--no-renames", "--diff-filter=AM", "--end-of-options", base, "HEAD")
    if res.returncode != 0:
        raise FixError("git diff failed")
    parts = res.stdout.split("\0")
    out = []
    for meta, path in zip(parts[0::2], parts[1::2]):
        new_mode = meta.split()[1] if meta.startswith(":") and len(meta.split()) > 1 else ""
        if new_mode in ("100644", "100755"):
            out.append(path)
    return out


def merge_base(root: Path, base_ref: str) -> str:
    if not base_ref or base_ref.startswith("-"):
        raise FixError(f"invalid base ref: {base_ref!r}")
    res = _git(root, "merge-base", "--end-of-options", base_ref, "HEAD")
    if res.returncode != 0 or not res.stdout.strip():
        raise FixError(f"base ref {base_ref!r} has no merge base with HEAD in this repository")
    return res.stdout.strip()


# --- diffs and rule checks -------------------------------------------------


def _strip(line: str) -> str:
    return line.rstrip("\r\n")


def file_diff(path: str, base: list[str], new: list[str]) -> str:
    """A git-style unified diff of one file, the shape the engines parse."""
    a = f"a/{path}" if base else "/dev/null"
    body = list(difflib.unified_diff([_strip(x) for x in base], [_strip(x) for x in new], a, f"b/{path}", lineterm=""))
    return "\n".join([f"diff --git a/{path} b/{path}", *body]) + "\n" if body else ""


def _findings(diff_text: str) -> list:
    out = list(td.scan_diff_for_tampering(diff_text))
    out += [f for f in scan_diff_for_reward_hacking(diff_text) if f.rule == ASSERTION_RULE]
    return out


def _reasonless_ignores(path: str, base: list[str], head: list[str]) -> list[int]:
    """New-file line numbers of added `prufgate-ignore` comments without a reason."""
    out = []
    for h in td.parse_unified_diff(file_diff(path, base, head)):
        for ln, text in h.added_lines:
            parsed = inline_ignore.parse(text)
            if parsed is not None and not parsed[1]:
                out.append(ln)
    return out


def _count(rule: str, path: str, base: list[str], lines: list[str]) -> int:
    if rule == IGNORE_RULE:
        return len(_reasonless_ignores(path, base, lines))
    return sum(1 for f in _findings(file_diff(path, base, lines)) if f.rule == rule and f.path == path)


def apply_edits(lines: list[str], edits: list[Edit]) -> list[str] | None:
    """`lines` with `edits` applied, or None when any edit no longer matches exactly."""
    out = list(lines)
    for e in sorted(edits, key=lambda e: e.line, reverse=True):
        if not 1 <= e.line <= len(out) or out[e.line - 1] != e.old:
            return None
        out[e.line - 1 : e.line] = e.new
    return out


# --- single-line transforms --------------------------------------------------

_FOCUS_RE = re.compile(r"\b(it|test|describe|context)\.only(\s*\()|\bf(it|describe)(\s*\()")
_SKIP_CALL_RE = re.compile(r"\b(it|test|describe|context|suite|specify)\.skip(\s*\()|\bx(it|describe|test|context|specify)\b(\s*\(|\s+[\"'])")
# Whole-line skips with no reason: removing the line restores the base.
_SKIP_LINE_RE = re.compile(r"^(?:@pytest\.mark\.skip(?:\(\s*\))?|t\.(?:Skip|SkipNow)\(\s*\))\s*;?$")
_CI_LINE_RE = re.compile(r"^continue-on-error\s*:\s*true\s*(?:#.*)?$")
_OR_TRUE_RE = re.compile(r"^(.*\S)\s*\|\|\s*true\s*$")
_DIRECTIVE = r"(?:@ts-ignore|@ts-expect-error|eslint-disable[\w-]*|biome-ignore|noqa|type:\s*ignore|nolint|prufgate-ignore)\b"
_TRAILING_IGNORE_RE = re.compile(r"^(.*?\S)[ \t]*(?:#|//)[ \t]*" + _DIRECTIVE + r"(.*)$")
_WHOLE_IGNORE_RE = re.compile(r"^\s*(?:#(?![!\[])|//)\s*" + _DIRECTIVE)


def _one(regex: re.Pattern[str], text: str) -> re.Match[str] | None:
    """The only match of `regex` in `text`; None when there is none or more than one (ambiguous)."""
    found = list(regex.finditer(text))
    return found[0] if len(found) == 1 else None


def _focus_fix(text: str) -> str | None:
    m = _one(_FOCUS_RE, text)
    if not m:
        return None
    repl = m.group(1) + m.group(2) if m.group(1) else m.group(3) + m.group(4)
    return text[: m.start()] + repl + text[m.end() :]


def _skip_fix(text: str) -> str | None:
    if _SKIP_LINE_RE.match(text.strip()):
        return ""  # delete the line
    m = _one(_SKIP_CALL_RE, text)
    if not m:
        return None
    repl = m.group(1) + m.group(2) if m.group(1) else m.group(3) + m.group(4)
    return text[: m.start()] + repl + text[m.end() :]


def _balanced_quotes(code: str) -> bool:
    return all(code.count(q) % 2 == 0 for q in ("'", '"', "`"))


def _ignore_fix(text: str) -> str | None:
    """Remove a suppression comment: the whole line when it is only the comment, else the trailing comment."""
    if _WHOLE_IGNORE_RE.match(text):
        return ""
    m = _TRAILING_IGNORE_RE.match(text)
    if not m:
        return None
    code, tail = m.group(1), m.group(2)
    # A comment marker in the code or after the directive could be inside a string, or a
    # second comment we would delete with it: ambiguous.
    if "#" in code or "//" in code or "#" in tail or "//" in tail or "/*" in text or not _balanced_quotes(code):
        return None
    return code


def _ci_fix(text: str) -> str | None:
    if _CI_LINE_RE.match(text.strip()):
        return ""
    m = _OR_TRUE_RE.match(text)
    if m and "||" not in m.group(1) and "#" not in m.group(1):
        return m.group(1)
    return None


def _line_fix(rule: str, path: str, text: str) -> tuple[str | None, str]:
    """(replacement or None, title) for one added line; "" deletes the line."""
    if rule == SKIP_RULE:
        new = _focus_fix(text)
        if new is not None:
            return new, "Remove the focus filter"
        return _skip_fix(text), "Remove the unjustified skip"
    if rule in (SUPPRESSION_RULE, IGNORE_RULE):
        return _ignore_fix(text), "Remove the suppression comment without a reason"
    if rule == CI_RULE and td._is_ci_workflow_file(path):
        return _ci_fix(text), "Remove the ignored CI failure"
    return None, ""


# --- assertion hunks ---------------------------------------------------------


def _is_assertion(text: str) -> bool:
    s = text.strip()
    return bool(s) and not s.startswith(("#", "//", "/*", "*")) and bool(DIFF_ASSERTION_LINE_RE.search(s))


def _assertion_fix(path: str, line: int, st: FileState) -> tuple[list[Edit] | None, str]:
    """Restore the base lines of a hunk that only deletes or weakens assertions, 1:1."""
    for h in td.parse_unified_diff(file_diff(path, st.base, st.head)):
        added_nums = [ln for ln, _ in h.added_lines]
        if line not in added_nums and not (not added_nums and h.new_start <= line <= h.new_start + len(h.context_lines)):
            continue
        tags = "".join(r[:1] for r in h.raw_lines[1:])
        if not re.fullmatch(r" *-+\+* *", tags):
            return None, "the hunk mixes several changes"
        removed = [st.base[ln - 1] for ln, _ in h.removed_lines]
        added = h.added_lines
        if not all(_is_assertion(r) for r in removed) or not all(_is_assertion(t) for _, t in added):
            return None, "the hunk changes lines other than assertions"
        if added and len(added) != len(removed):
            return None, "the weakened assertions do not map 1:1 to the base"
        if added:
            return [Edit(ln, st.head[ln - 1], [r]) for (ln, _), r in zip(added, removed)], ""
        # Pure deletion: re-insert next to a context line of the hunk.
        lead = len(tags) - len(tags.lstrip(" "))
        if lead:
            at = h.new_start + lead - 1
            return [Edit(at, st.head[at - 1], [st.head[at - 1], *removed])], ""
        if len(tags) > len(tags.rstrip(" ")):
            at = h.new_start
            return [Edit(at, st.head[at - 1], [*removed, st.head[at - 1]])], ""
        return None, "no context line to anchor the restored assertions"
    return None, "the hunk was not found"


# --- planning ----------------------------------------------------------------


def _verify(fix: Fix, st: FileState) -> str:
    """Empty when the fix applies exactly and its rule stops firing; else why not."""
    fixed = apply_edits(st.head, fix.edits)
    if fixed is None:
        return "the expected text does not match"
    if _count(fix.rule, fix.path, st.base, fixed) >= _count(fix.rule, fix.path, st.base, st.head):
        return "the rule still fires after the fix"
    return ""


def _rule_counts(path: str, base: list[str], lines: list[str]) -> Counter:
    counts = Counter(f.rule for f in _findings(file_diff(path, base, lines)) if f.path == path)
    counts[IGNORE_RULE] += len(_reasonless_ignores(path, base, lines))
    return counts


def _combined_ok(path: str, base: list[str], before: list[str], after: list[str], rules: set[str]) -> bool:
    """Every fixed rule fires less after the edits, and no rule fires more."""
    was, now = _rule_counts(path, base, before), _rule_counts(path, base, after)
    return all(now[r] < was[r] for r in rules) and all(now[r] <= was[r] for r in now)


def plan_fixes(root: Path, base_ref: str) -> Plan:
    mb = merge_base(root, base_ref)
    files: dict[str, FileState] = {}
    targets: list[tuple[str, str, int]] = []  # (rule, path, line)
    for path in _changed_files(root, mb):
        head = _blob(root, "HEAD", path)
        if head is None:
            continue  # binary or unreadable
        base = _blob(root, mb, path) or []
        st = files[path] = FileState(base, head)
        diff = file_diff(path, base, head)
        targets += [(f.rule, f.path, f.line) for f in _findings(diff) if f.path == path]
        targets += [(IGNORE_RULE, path, ln) for ln in _reasonless_ignores(path, base, head)]

    fixes: list[Fix] = []
    skipped: list[NoFix] = []
    taken: dict[str, dict[int, tuple]] = {}
    seen: set[tuple] = set()
    for rule, path, line in sorted(set(targets), key=lambda t: (t[1], t[2], t[0])):
        st = files.get(path)
        if st is None:
            skipped.append(NoFix(rule, path, line, "file not readable"))
            continue
        fix, why = _make_fix(rule, path, line, st)
        if fix is not None:
            why = _verify(fix, st)
        if fix is None or why:
            skipped.append(NoFix(rule, path, line, why or "no safe fix for this rule"))
            continue
        key = tuple((e.line, tuple(e.new)) for e in fix.edits)
        if (path, key) in seen:
            continue  # the same edit already answers another finding on this line
        used = taken.setdefault(path, {})
        if any(e.line in used for e in fix.edits):
            skipped.append(NoFix(rule, path, line, "overlaps another fix"))
            continue
        seen.add((path, key))
        used.update({e.line: key for e in fix.edits})
        fixes.append(fix)
    # Fixes checked one by one can still interact: check each file's fixes together.
    for path in sorted({f.path for f in fixes}):
        mine = [f for f in fixes if f.path == path]
        st = files[path]
        new = apply_edits(st.head, [e for f in mine for e in f.edits])
        if new is None or not _combined_ok(path, st.base, st.head, new, {f.rule for f in mine}):
            fixes = [f for f in fixes if f.path != path]
            skipped += [NoFix(f.rule, path, f.edits[0].line, "the fixes in this file do not check out together") for f in mine]
    return Plan(fixes, skipped, files)


def _make_fix(rule: str, path: str, line: int, st: FileState) -> tuple[Fix | None, str]:
    if rule == ASSERTION_RULE:
        edits, why = _assertion_fix(path, line, st)
        return (Fix(rule, path, "Restore the base assertions", edits) if edits else None), why
    added = {ln for h in td.parse_unified_diff(file_diff(path, st.base, st.head)) for ln, _ in h.added_lines}
    if line not in added:
        return None, "the line is not added by this branch"
    old = st.head[line - 1]
    text = _strip(old)
    new, title = _line_fix(rule, path, text)
    if new is None:
        return None, "no safe fix for this line"
    ending = old[len(text) :]
    return Fix(rule, path, title, [Edit(line, old, [new + ending] if new else [])]), ""


def fixed_files(plan: Plan) -> dict[str, list[str]]:
    by_path: dict[str, list[Edit]] = {}
    for f in plan.fixes:
        by_path.setdefault(f.path, []).extend(f.edits)
    out = {}
    for path, edits in by_path.items():
        new = apply_edits(plan.files[path].head, edits)
        if new is not None:
            out[path] = new
    return out


# --- outputs -----------------------------------------------------------------


def format_patch(plan: Plan) -> str:
    """A unified diff from HEAD to the fixed files, for `git apply`."""
    out = []
    for path, new in sorted(fixed_files(plan).items()):
        head = plan.files[path].head
        body = difflib.unified_diff(head, new, f"a/{path}", f"b/{path}")
        out.append(f"diff --git a/{path} b/{path}\n" + "".join(x if x.endswith("\n") else x + "\n\\ No newline at end of file\n" for x in body))
    return "".join(out)


def suggestion_comments(plan: Plan) -> list[PRComment]:
    """One review comment per edited line, its suggestion replacing that line."""
    out = []
    for f in plan.fixes:
        for e in f.edits:
            out.append(
                PRComment(
                    file_path=f.path,
                    line=e.line,
                    severity="P2",
                    title=f"Auto-fix ({f.rule})",
                    message=f"{f.title}. Deterministic and checked: `{f.rule}` no longer fires once applied.",
                    suggestion="".join(_strip(x) + "\n" for x in e.new).rstrip("\n") if e.new else "",
                    exact_fix=True,
                )
            )
    return out


def format_github_suggestions(plan: Plan) -> str:
    return format_review_github(suggestion_comments(plan))


# --- writing -------------------------------------------------------------------


class ApplyRefused(RuntimeError):
    """`--apply` will not write this file."""


def _safe_target(root: Path, rel: str) -> Path:
    """`root/rel`, refusing absolute paths, `..`, and any symlink on the way."""
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ApplyRefused(f"{rel}: path outside the repository")
    cur = root
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            raise ApplyRefused(f"{rel}: refusing to follow a symlink")
    if not cur.resolve().is_relative_to(root.resolve()):
        raise ApplyRefused(f"{rel}: path outside the repository")
    return cur


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# Directories can be opened relative to each other without following links (not on Windows).
_DIR_FD = os.open in os.supports_dir_fd and bool(_NOFOLLOW) and hasattr(os, "O_DIRECTORY")


def _open_by_path_checked(root: Path, rel: str, target: Path) -> int:
    """Without dir_fd (Windows): open by path, then check that the descriptor is the very
    file at the resolved path, inside the repository. A directory swapped for a link
    before the open redirects it outside (refused), and one swapped and swapped back
    leaves a descriptor that is not the file now at that path (refused)."""
    fd = os.open(target, os.O_RDWR | _NOFOLLOW)
    try:
        real = Path(target).resolve(strict=True)
        opened, there = os.fstat(fd), os.stat(real)
        if not real.is_relative_to(root.resolve()) or (opened.st_dev, opened.st_ino) != (there.st_dev, there.st_ino):
            raise ApplyRefused(f"{rel}: refusing to follow a symlink")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_target(root: Path, rel: str) -> int:
    """A read-write descriptor for `root/rel`. Each directory on the way is opened
    relative to the one before with O_NOFOLLOW, so a directory swapped for a symlink
    after the check cannot redirect the write; the file is then read and rewritten
    through this one descriptor."""
    target = _safe_target(root, rel)
    if not _DIR_FD:
        return _open_by_path_checked(root, rel, target)
    parts = Path(rel).parts
    fd = os.open(root.resolve(), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(parts[-1], os.O_RDWR | _NOFOLLOW, dir_fd=fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ApplyRefused(f"{rel}: refusing to follow a symlink") from exc
        raise
    finally:
        os.close(fd)


def _read(fd: int) -> list[str]:
    chunks = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8").splitlines(keepends=True)


def _write(fd: int, lines: list[str]) -> None:
    data = "".join(lines).encode("utf-8")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    while data:
        data = data[os.write(fd, data):]


def _relocate(head: list[str], current: list[str], edits: list[Edit]) -> list[Edit] | None:
    """`edits` (HEAD line numbers) moved onto the working tree's lines; None when an edited
    line is not in an unchanged stretch of the working tree."""
    blocks = difflib.SequenceMatcher(None, head, current, autojunk=False).get_matching_blocks()
    out = []
    for e in edits:
        at = next((b + e.line - 1 - a for a, b, n in blocks if a < e.line <= a + n), None)
        if at is None:
            return None
        out.append(Edit(at + 1, e.old, e.new))
    return out


def apply_plan(root: Path, plan: Plan, force: bool = False) -> tuple[list[str], list[str]]:
    """Write the fixes. Returns (written paths, refusal messages)."""
    written, refused = [], []
    edits: dict[str, list[Edit]] = {}
    rules: dict[str, set[str]] = {}
    for f in plan.fixes:
        edits.setdefault(f.path, []).extend(f.edits)
        rules.setdefault(f.path, set()).add(f.rule)
    for path, new in sorted(fixed_files(plan).items()):
        try:
            fd = _open_target(root, path)
        except (ApplyRefused, OSError) as exc:
            refused.append(str(exc))
            continue
        try:
            current = _read(fd)
            if current == new:
                continue  # already applied
            st = plan.files[path]
            if current != st.head:
                if not force:
                    refused.append(f"{path}: has uncommitted changes; commit or stash them, or pass --force")
                    continue
                moved = _relocate(st.head, current, edits[path])
                new = apply_edits(current, moved) if moved is not None else None
                if new is None or not _combined_ok(path, st.base, current, new, rules[path]):
                    refused.append(f"{path}: the expected text no longer matches the working tree")
                    continue
            _write(fd, new)
            written.append(path)
        except (OSError, UnicodeDecodeError) as exc:
            refused.append(f"{path}: {exc}")
        finally:
            os.close(fd)
    return written, refused
