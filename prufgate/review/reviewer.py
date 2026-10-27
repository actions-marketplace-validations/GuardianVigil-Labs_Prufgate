#!/usr/bin/env python3
"""PrufGate Hybrid Diff & PR Reviewer (Engine 6 — `prufgate/review/reviewer.py`).

Combines:
1. Deterministic Diff Gate (Default, zero LLM cost):
   - High-precision security & engineering diff patterns (SQL injection, command injection,
     hardcoded credentials, disabled TLS verification, DOM XSS, ignored Go errors,
     unbounded goroutines, credential logging, unguarded Server Actions).
   - Diff-scoped agent tampering rules from Engine 3 (`diff_guard`).
   - Strict suggestion validation: in GitHub (`--format github`) mode, only emits
     ````suggestion` blocks when the replacement is syntactically valid executable code
     (never a comment-only placeholder that would delete the user's code).
2. Optional `--ai` BYO-Agent / LLM Reviewer (`prufgate/review/ai_adapter.py`):
   - Delegates semantic diff review to local agent CLIs (`claude`, `opencode`, `codex`,
     `gemini`) or standard API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST`).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import __version__, inline_ignore  # noqa: E402
from prufgate.anti_fabrication.literals import search_code  # noqa: E402
from prufgate.bola.bola_engine import INTERNAL_SCANNER_PATHS, is_self_scan, is_test_path  # noqa: E402
from prufgate.config import ConfigError  # noqa: E402
from prufgate.diff_guard.tamper_detector import scan_diff_for_tampering  # noqa: E402
from prufgate.report_formats import gitlab_code_quality, junit_xml  # noqa: E402
from prufgate.review.ai_adapter import review_diff_with_ai  # noqa: E402
from prufgate.rules import low_confidence_enabled, review_rule_id, visible  # noqa: E402
from prufgate.sarif import add_partial_fingerprints  # noqa: E402


class PRComment:
    """A single pull-request review comment with optional replacement suggestion."""

    def __init__(
        self,
        file_path: str,
        line: int,
        severity: str,  # P0, P1, P2, P3
        title: str,
        message: str,
        suggestion: str | None = None,
        ai: bool = False,
        exact_fix: bool = False,
    ):
        self.file_path = file_path
        self.line = line
        self.severity = severity
        self.title = title
        self.message = message
        self.suggestion = suggestion
        self.ai = ai
        # A checked deterministic fix from `prufgate fix`: its suggestion is emitted as
        # is, and an empty one deletes the line.
        self.exact_fix = exact_fix

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "file": self.file_path,
            "line": self.line,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
        }
        if self.suggestion:
            data["suggestion"] = self.suggestion
        if self.ai:
            data["ai"] = True  # never AI-adjudicated (`check --ai-adjudicate`)
        return data


def is_valid_code_suggestion(suggestion: str | None) -> bool:
    """Return True only if `suggestion` contains executable replacement code (not just comments)."""
    if not suggestion or not suggestion.strip():
        return False
    code_lines: list[str] = []
    for raw in suggestion.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith(("//", "#", "/*", "*", "--")):
            continue
        code_lines.append(s)
    if not code_lines:
        return False
    joined = "\n".join(code_lines)
    # Check balanced delimiters so malformed snippets are never emitted as GitHub suggestions
    for open_ch, close_ch in (("(", ")"), ("[", "]"), ("{", "}")):
        if joined.count(open_ch) != joined.count(close_ch):
            return False
    return True


class DiffUnavailableError(RuntimeError):
    """The requested diff could not be computed (bad ref, not a repository)."""


def _git_diff(args: list[str], cwd: str | None) -> str | None:
    res = subprocess.run(["git", "diff", "--text", "--no-ext-diff", "--no-textconv", *args], capture_output=True, text=True, errors="replace", check=False, cwd=cwd)
    return res.stdout if res.returncode == 0 else None


DEFAULT_BASE = "origin/main"


def get_git_diff(base_ref: str = DEFAULT_BASE, cwd: Path | None = None, strict: bool = False) -> str:
    """Diff of the branch against `base_ref`, falling back to the working tree.

    With `strict`, a base ref that does not resolve raises DiffUnavailableError instead
    of silently reviewing something else. A ref starting with `-` is always refused
    (it would be read as a git option).
    """
    if not base_ref or base_ref.startswith("-"):
        raise DiffUnavailableError(f"invalid base ref: {base_ref!r}")
    run_cwd = str(cwd) if cwd else None
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD"], capture_output=True, text=True, check=False, cwd=run_cwd
    )
    if probe.returncode != 0:
        raise DiffUnavailableError("not a git repository with commits; pass --diff-file to review a diff")
    candidates = [base_ref] if base_ref.startswith("origin/") else [base_ref, f"origin/{base_ref}"]
    resolved = False
    for ref in candidates:
        out = _git_diff(["--end-of-options", f"{ref}...HEAD"], run_cwd)
        if out is not None:
            resolved = True
            if out.strip():
                return out
    if strict and not resolved:
        raise DiffUnavailableError(f"base ref {base_ref!r} does not resolve in this repository")
    out = _git_diff(["HEAD"], run_cwd)
    if out is None:
        raise DiffUnavailableError("git diff HEAD failed")
    return out


def parse_diff_hunks(diff_text: str) -> list[dict[str, Any]]:
    """Parse a unified git diff into file-scoped added lines with new-file line numbers."""
    from prufgate.diff_scope import _HUNK_RE, _unquote_git_path

    hunks: list[dict[str, Any]] = []
    current_file: str | None = None
    current_line = 0
    in_header = False  # between `diff --git` and the first `@@`
    old_left = 0
    new_left = 0
    ctx_lines: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file, in_header = None, True
            old_left = new_left = 0
            ctx_lines = []
        elif in_header and line.startswith("+++ "):
            raw = line[4:]
            current_file = None if raw.strip() == "/dev/null" or raw.strip().startswith("/dev/null\t") else _unquote_git_path(raw, "b/")
        elif line.startswith("@@ "):
            in_header = False
            ctx_lines = []
            m = _HUNK_RE.match(line)
            if m:
                old_left = int(m.group(2)) if m.group(2) is not None else 1
                current_line = int(m.group(3)) - 1
                new_left = int(m.group(4)) if m.group(4) is not None else 1
        elif in_header or current_file is None or line.startswith("\\"):
            continue
        elif line.startswith("+"):
            current_line += 1
            new_left = max(0, new_left - 1)
            hunks.append(
                {
                    "file": current_file,
                    "line": current_line,
                    "content": line[1:],
                    "prev_ctx": list(ctx_lines[-3:]),
                }
            )
            ctx_lines = []
        elif line.startswith("-"):
            old_left = max(0, old_left - 1)
        else:
            current_line += 1
            old_left = max(0, old_left - 1)
            new_left = max(0, new_left - 1)
            ctx_lines.append(line[1:] if line.startswith(" ") else line)

    return hunks


_GENERATED_SEGMENTS = {"dist", "build", ".next", "node_modules", "vendor", "out", "coverage", "target"}


def _skip_review_path(file: str, skip_internal: bool) -> bool:
    parts = file.split("/")
    if any(seg in _GENERATED_SEGMENTS for seg in parts[:-1]) or is_test_path(file):
        return True
    return skip_internal and file.startswith(INTERNAL_SCANNER_PATHS)


# A query whose first argument is a template literal with `${...}` in it. `${}` in a
# later argument (the bind parameters) is a value, not SQL; in '...' or "..." it is text.
_SQL_CALL = r"""\b(?:query|execute|rawQuery|Exec|Query|QueryRow)\s*\(\s*"""
SQL_TEMPLATE_RE = re.compile(_SQL_CALL + r"""`[^`]*?\$\{[^}]+\}""", re.IGNORECASE)
SQL_SPRINTF_RE = re.compile(_SQL_CALL + r"""fmt\.Sprintf\(["'][^"']*?%[sv]""", re.IGNORECASE)
SQL_FSTRING_RE = re.compile(r"""\b(?:cursor\.execute|session\.execute)\s*\(\s*f["'][^"']*?\{[^}]+\}""", re.IGNORECASE)
SQL_CALL_OPEN_RE = re.compile(_SQL_CALL + r"""(`[^`]*)?(?:\s*(?://|#).*)?$""", re.IGNORECASE)
SHELL_TEMPLATE_RE = re.compile(r"""\bexec(?:Sync)?\s*\(\s*`[^`]*?\$\{[^}]+\}""")


def _multiline_sql_template(content: str, hunks: list[dict[str, Any]], idx: int) -> bool:
    """`db.query(` or ``db.query(`SELECT ...`` at the end of a line, with the template
    literal that follows (on the next added lines) interpolating `${...}` before it closes."""
    if "${" in content and any(search_code(SQL_CALL_OPEN_RE, c.strip()) for c in hunks[idx].get("prev_ctx") or ()):
        return True
    m = search_code(SQL_CALL_OPEN_RE, content)
    if not m:
        return False
    text = m.group(1) or ""
    file, line_no = hunks[idx]["file"], hunks[idx]["line"]
    for k, h in enumerate(hunks[idx + 1 : idx + 16], start=1):
        if h["file"] != file or h["line"] != line_no + k:
            return False
        nxt = h["content"].strip()
        if not text:
            if not nxt.startswith("`"):
                return False
            text, nxt = "`", nxt[1:]
        close = nxt.find("`")
        part = nxt if close < 0 else nxt[:close]
        if "${" in part:
            return True
        if close >= 0:
            return False
    return False


def analyze_diff(hunks: list[dict[str, Any]], skip_internal: bool = False) -> list[PRComment]:
    """Deterministic rules over added lines. `skip_internal` skips PrufGate's own engine sources."""
    comments: list[PRComment] = []

    for idx, item in enumerate(hunks):
        file = item["file"]
        line_no = item["line"]
        raw_line = item["content"]
        content = raw_line.strip()

        if _skip_review_path(file, skip_internal):
            continue

        if not content or content.startswith(("//", "#", "/*", "*")):
            continue

        window_lines = [
            h["content"]
            for h in hunks[idx : min(len(hunks), idx + 15)]
            if h["file"] == file and h["line"] - line_no < 25
        ]
        window_text = "\n".join(window_lines)

        # 1. SQL Injection / String concatenation in queries
        if (
            search_code(SQL_TEMPLATE_RE, content)
            or search_code(SQL_SPRINTF_RE, content)
            or search_code(SQL_FSTRING_RE, content)
            or _multiline_sql_template(content, hunks, idx)
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P0",
                    title="SQL Injection Vector",
                    message="Detected string interpolation / format string inside database query execution. Always use parameterized queries ($1, $2 or ?) to prevent SQL injection.",
                )
            )

        # 2. Hardcoded Credentials / Secrets in Diff
        if re.search(
            r"""\b(?:api[_-]?key|secret|password|access[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["'][a-zA-Z0-9_\-\.]{16,}["']""",
            content,
            re.IGNORECASE,
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P0",
                    title="Hardcoded Credential in Code",
                    message="Detected high-entropy hardcoded secret or token assignment in added code. Move this credential to an environment variable or a secrets manager.",
                )
            )

        # 3. Command Injection / Unsafe Shell Execution
        if (
            re.search(r"""\bsubprocess\.(?:run|Popen|call|check_output)\s*\(.*?\bshell\s*=\s*True\b""", content)
            or search_code(SHELL_TEMPLATE_RE, content)
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P0",
                    title="Shell Command Injection Risk",
                    message="Executing shell commands with `shell=True` or interpolated template strings allows arbitrary command injection if user input reaches the command. Pass an argument array without invoking a shell.",
                )
            )

        # 4. Disabled TLS Certificate Verification
        if (
            re.search(r"""\bInsecureSkipVerify\s*:\s*true\b""", content)
            or re.search(r"""\brejectUnauthorized\s*:\s*false\b""", content)
            or re.search(r"""\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(.*?\bverify\s*=\s*False\b""", content)
        ):
            replaced_line = None
            if "rejectUnauthorized: false" in raw_line:
                replaced_line = raw_line.replace("rejectUnauthorized: false", "rejectUnauthorized: true")
            elif "InsecureSkipVerify: true" in raw_line:
                replaced_line = raw_line.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P1",
                    title="Disabled TLS Certificate Verification",
                    message="Disabling TLS certificate verification exposes outbound connections to man-in-the-middle (MitM) interception. Keep certificate validation enabled.",
                    suggestion=replaced_line,
                )
            )

        # 5. Unsafe DOM XSS (dangerouslySetInnerHTML / innerHTML without sanitization)
        if (
            ("dangerouslySetInnerHTML" in content or re.search(r"""\.innerHTML\s*=(?!=)""", content))
            # ponytail: sanitisation is checked on the same line only; a value sanitised
            # on an earlier line is reported (P1, easy to dismiss) rather than missed.
            and "DOMPurify" not in content
            and "sanitize" not in content.lower()
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P1",
                    title="Unsanitized HTML Injection (XSS)",
                    message="Assigning raw HTML via `dangerouslySetInnerHTML` or `.innerHTML` without sanitization (e.g. `DOMPurify.sanitize()`) enables Cross-Site Scripting (XSS).",
                )
            )

        # 6. Missing error handling in Go (ignoring errors with _)
        if file.endswith(".go") and re.search(r""",\s*_\s*:?=\s*[\w.]+\(""", content):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P2",
                    title="Ignored Error Return in Go",
                    message="Blank identifier `_` is used to discard an error return value. Handle or propagate this error to prevent silent runtime failures.",
                )
            )

        # 7. Unbounded goroutine leak
        if (
            file.endswith(".go")
            and re.search(r"""\bgo\s+func\s*\(.*?\)\s*\{""", content)
            and not re.search(r"""\b(?:wg\.Done|errgroup|ctx\.Done|semaphore)\b""", window_text)
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P2",
                    title="Unbounded Goroutine Spawn",
                    message="Spawning goroutines directly without a worker pool, WaitGroup, errgroup, or context cancellation risks memory exhaustion and goroutine leaks under load.",
                )
            )

        # 8. Sensitive data in console.log
        if re.search(
            r"""console\.(?:log|debug|info|warn|error)\(.*?\b(?:password|token|secret|apiKey|bearer|privateKey)\b""",
            content,
            re.IGNORECASE,
        ):
            comments.append(
                PRComment(
                    file_path=file,
                    line=line_no,
                    severity="P1",
                    title="Credential Logging in Console",
                    message="Do not log sensitive credentials, authentication tokens, or secrets to stdout/stderr. Strip or mask these attributes before logging.",
                )
            )

        # 9. Next.js Server Action missing auth guard
        if ("actions/" in file or "app/actions" in file) and content.startswith("export async function"):
            has_auth = bool(
                re.search(
                    r"\b(?:assert[A-Z]\w*|verifySession|verify[A-Z]\w*|requireAuth|require[A-Z]\w*|auth\(\)|authCheck|getSession|getCurrentUser|protect[A-Z]\w*|checkPermission)\b",
                    window_text,
                )
            )
            if not has_auth:
                comments.append(
                    PRComment(
                        file_path=file,
                        line=line_no,
                        severity="P1",
                        title="Server Action Missing Authorization Guard",
                        message="Ensure this Server Action verifies caller permissions at the start of the function (e.g. `auth()`, `requireAuth()`, `verifySession()`) before mutating state.",
                    )
                )

    added = {(h["file"], h["line"]): h["content"] for h in hunks}
    return [
        c for c in comments
        if not inline_ignore.suppressed(
            inline_ignore.context([added.get((c.file_path, c.line - 1), ""), added.get((c.file_path, c.line), "")], 2),
            review_rule_id(c.title), engine="pr-reviewer", path=c.file_path, line=c.line,
            severity=c.severity, message=f"{c.title}: {c.message}",
        )
    ]


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean_ai_text(value: str, limit: int) -> str:
    """Model output is untrusted: strip control characters and bound its length."""
    return _CONTROL_CHARS_RE.sub("", value)[:limit]


def run_hybrid_review(
    diff_text: str,
    include_diff_guard: bool = False,
    enable_ai: bool = False,
    ai_provider: str = "auto",
    skip_internal: bool = False,
) -> list[PRComment]:
    """Run deterministic diff analysis plus optional diff_guard and BYO-AI review."""
    hunks = parse_diff_hunks(diff_text)
    comments = analyze_diff(hunks, skip_internal=skip_internal)

    if include_diff_guard:
        for dg in scan_diff_for_tampering(diff_text):
            comments.append(
                PRComment(
                    file_path=dg.path,
                    line=dg.line,
                    severity=dg.severity,
                    title=dg.rule,
                    message=dg.message,
                )
            )

    if enable_ai:
        added = {(h["file"], h["line"]) for h in hunks}
        ai_res = review_diff_with_ai(diff_text, provider=ai_provider)
        if ai_res.status != "executed":
            # --ai was asked for: say plainly when it did not run, never look like a clean AI pass.
            print(f"prufgate review: AI review {ai_res.status} ({ai_res.provider}): {ai_res.note}", file=sys.stderr)
        for item in ai_res.comments:
            # Keep only comments pinned to a line this diff adds; drop anything else the model invents.
            if (item.get("file"), item.get("line")) not in added:
                continue
            suggestion = item.get("suggestion")
            comments.append(
                PRComment(
                    file_path=item["file"],
                    line=item["line"],
                    severity=item["severity"] if item.get("severity") in ("P0", "P1", "P2", "P3") else "P2",
                    title=_clean_ai_text(str(item["title"]), 200),
                    message=_clean_ai_text(str(item["message"]), 2000),
                    suggestion=suggestion if is_valid_code_suggestion(suggestion) else None,
                    ai=True,
                )
            )

    return comments


def format_review_markdown(comments: list[PRComment], strict_suggestions: bool = True) -> str:
    """Format PR comments as Markdown.

    Suggestion blocks replace the commented line when applied, so only valid code is
    ever emitted; `strict_suggestions` is kept for API compatibility and cannot be relaxed.
    """
    md_lines = ["# PrufGate PR Review\n"]
    if comments:
        md_lines.append(f"Found **{len(comments)}** potential code improvement(s) in this pull request.\n")
        for c in comments:
            md_lines.append(f"### [{c.severity}] {c.title}")
            md_lines.append(f"**Location:** `{c.file_path}:{c.line}`\n")
            md_lines.append(f"{c.message}\n")
            if c.exact_fix and c.suggestion is not None:
                md_lines.append("```suggestion\n" + c.suggestion + ("\n" if c.suggestion else "") + "```\n")
            elif is_valid_code_suggestion(c.suggestion):
                md_lines.append("```suggestion\n" + str(c.suggestion) + "\n```\n")
    else:
        md_lines.append("✔ Diff analysis completed. No security anti-patterns or quality defects detected in this PR.")
    return "\n".join(md_lines)


def _escape_gh_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_gh_property(value: str) -> str:
    return _escape_gh_data(value).replace(":", "%3A").replace(",", "%2C")


def format_review_github(comments: list[PRComment]) -> str:
    """GitHub Actions annotations plus the Markdown review.

    Annotation fields are escaped per the workflow-command spec, and the free-text
    Markdown is wrapped in `::stop-commands::` so no line of it (which may quote code or
    model output) can be read as a workflow command.
    """
    lines: list[str] = []
    for c in comments:
        level = "error" if c.severity in ("P0", "P1") else "warning"
        lines.append(
            f"::{level} file={_escape_gh_property(c.file_path)},line={int(c.line)},"
            f"title={_escape_gh_property(f'[{c.severity}] {c.title}')}::{_escape_gh_data(c.message)}"
        )
    token = secrets.token_hex(16)
    lines.append(f"::stop-commands::{token}")
    lines.append(format_review_markdown(comments))
    lines.append(f"::{token}::")
    return "\n".join(lines)


def format_review_sarif(comments: list[PRComment], root: Path | None = None) -> str:
    """Format PR comments as a SARIF 2.1.0 JSON string; `root` is the repository the paths are relative to."""
    return json.dumps(review_sarif_doc(comments, root), indent=2)


def format_review_other(fmt: str, comments: list[PRComment], root: Path | None = None) -> str:
    """The `gitlab` or `junit` report, built from the same SARIF document."""
    doc = review_sarif_doc(comments, root)
    return gitlab_code_quality(doc) if fmt == "gitlab" else junit_xml(doc)


def review_sarif_doc(comments: list[PRComment], root: Path | None = None) -> dict:
    results = []
    for c in comments:
        level = "error" if c.severity in ("P0", "P1") else "warning"
        results.append(
            {
                "ruleId": review_rule_id(c.title),
                "level": level,
                "message": {"text": f"[{c.severity}] {c.title}: {c.message}"},
                "properties": {"severity": c.severity},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": c.file_path},
                            "region": {"startLine": c.line},
                        }
                    }
                ],
            }
        )
    add_partial_fingerprints(results, root)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "prufgate-review",
                        "version": __version__,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def format_review_reviewdog(comments: list[PRComment]) -> str:
    """Format PR comments as Reviewdog Diagnostic Format (`rdjson`)."""
    diagnostics = []
    for c in comments:
        sev = "ERROR" if c.severity in ("P0", "P1") else "WARNING"
        diag: dict[str, Any] = {
            "message": f"[{c.severity}] {c.title}: {c.message}",
            "location": {
                "path": c.file_path,
                "range": {"start": {"line": c.line, "column": 1}},
            },
            "severity": sev,
        }
        if is_valid_code_suggestion(c.suggestion):
            diag["suggestions"] = [
                {
                    "range": {
                        "start": {"line": c.line, "column": 1},
                        "end": {"line": c.line, "column": 1},
                    },
                    "text": c.suggestion,
                }
            ]
        diagnostics.append(diag)
    return json.dumps({"source": {"name": "prufgate-review"}, "diagnostics": diagnostics}, indent=2)


def run_self_check() -> int:
    sample_diff = (
        "diff --git a/src/db.ts b/src/db.ts\n"
        "--- a/src/db.ts\n"
        "+++ b/src/db.ts\n"
        "@@ -1,2 +1,4 @@\n"
        "+const q = db.query(`SELECT * FROM users WHERE id = '${userId}'`);\n"
        "+const agent = new https.Agent({ rejectUnauthorized: false });\n"
        "+console.log('user secret token:', secretToken);\n"
    )
    comments = run_hybrid_review(sample_diff)
    if len(comments) != 3:
        print(f"reviewer self-check FAILED: expected 3 comments, got {len(comments)}", file=sys.stderr)
        return 1
    gh_out = format_review_github(comments)
    # Only the TLS replacement is valid executable code; the console.log comment placeholder must NOT emit a suggestion block in github mode
    if gh_out.count("```suggestion") != 1:
        print("reviewer self-check FAILED: expected exactly 1 valid ```suggestion block in github format", file=sys.stderr)
        return 1
    print("reviewer self-check: 3 diff review & suggestion validation case(s) ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in raw_args:
        return run_self_check()

    ws_env = os.environ.get(
        "WORKSPACE",
        "/workspace" if Path("/workspace").exists() and os.access("/workspace", os.W_OK) else str(Path.cwd()),
    )
    parser = argparse.ArgumentParser(description="PrufGate Diff-Scoped Semantic PR Reviewer")
    parser.add_argument("--workspace", default=ws_env, help="Workspace directory path")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Base git ref for diff analysis")
    parser.add_argument("--diff-file", help="Explicit path to diff file")
    parser.add_argument("--output", help="Alias for --output-json")
    parser.add_argument("--output-json", default=None)
    parser.add_argument("--output-md", default=None)
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "sarif", "github", "reviewdog", "gitlab", "junit"),
        default=None,
        help="Stdout output format when running interactively via `prufgate review`",
    )
    parser.add_argument("--ai", action="store_true", help="Enable optional BYO-Agent / LLM diff review")
    parser.add_argument("--ai-provider", default="auto", help="AI provider: auto, claude, opencode, codex, gemini, openai, anthropic, ollama")
    args = parser.parse_args(raw_args)

    ws_path = Path(args.workspace).resolve()
    # Read at the base like every other setting: a branch must not turn its own
    # findings off. The default base may be absent; its diff falls back to HEAD.
    cfg_ref = None if args.diff_file else args.base
    if cfg_ref == DEFAULT_BASE and subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "--end-of-options", f"{DEFAULT_BASE}^{{commit}}"],
        cwd=ws_path if ws_path.exists() else None, capture_output=True, check=False,
    ).returncode != 0:
        cfg_ref = "HEAD"
    try:
        enable_low = low_confidence_enabled(ws_path, ref=cfg_ref)
    except ConfigError as exc:
        print(f"reviewer: {exc}", file=sys.stderr)
        return 2
    reports_dir = Path(os.environ.get("PRUFGATE_REPORTS_DIR", str(ws_path / "reports")))
    output_json = args.output or args.output_json or str(reports_dir / "raw" / "pr_review.json")
    output_md = args.output_md or str(reports_dir / "raw" / "pr_review.md")

    try:
        if args.diff_file:
            diff_text = Path(args.diff_file).read_text(encoding="utf-8", errors="replace")
        else:
            # The default base may be absent (a local-only repository); any other base must resolve.
            diff_text = get_git_diff(
                args.base, cwd=ws_path if ws_path.exists() else None, strict=args.base != DEFAULT_BASE
            )
    except (OSError, DiffUnavailableError) as exc:
        print(f"reviewer: cannot read the diff: {exc}", file=sys.stderr)
        return 2

    if not diff_text:
        if not args.format:
            print("  [PR Reviewer] No git diff found. Clean branch or uncommitted changes.")
        Path(output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(output_json).write_text("[]", encoding="utf-8")
        Path(output_md).parent.mkdir(parents=True, exist_ok=True)
        Path(output_md).write_text("# PR Review\n\nNo changed lines to review.\n", encoding="utf-8")
        if args.format == "json":
            print("[]")
        elif args.format == "sarif":
            print(format_review_sarif([]))
        elif args.format == "reviewdog":
            print(format_review_reviewdog([]))
        elif args.format in ("gitlab", "junit"):
            print(format_review_other(args.format, []))
        elif args.format in ("markdown", "github"):
            print("# PR Review\n\nNo changed lines to review.")
        return 0

    try:
        comments = run_hybrid_review(
            diff_text,
            include_diff_guard=bool(args.format),
            enable_ai=args.ai,
            ai_provider=args.ai_provider,
            skip_internal=is_self_scan(ws_path),
        )
    except Exception as exc:  # fail closed: a crash is never a pass
        print(f"reviewer: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    comments = visible(comments, enable_low)

    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(output_json).write_text(json.dumps([c.to_dict() for c in comments], indent=2), encoding="utf-8")

    md_text = format_review_markdown(comments)
    Path(output_md).parent.mkdir(parents=True, exist_ok=True)
    Path(output_md).write_text(md_text, encoding="utf-8")

    if args.format == "json":
        print(json.dumps([c.to_dict() for c in comments], indent=2))
    elif args.format == "sarif":
        print(format_review_sarif(comments, ws_path))
    elif args.format == "github":
        print(format_review_github(comments))
    elif args.format == "reviewdog":
        print(format_review_reviewdog(comments))
    elif args.format in ("gitlab", "junit"):
        print(format_review_other(args.format, comments, ws_path))
    elif args.format == "markdown":
        print(format_review_markdown(comments))
    else:
        print(f"✔ PR Review completed: {len(comments)} comment(s) written to {output_json}")

    # Exit 0: no P0/P1. 1: a P0/P1 comment. 2: the diff could not be read.
    return 1 if any(c.severity in ("P0", "P1") for c in comments) else 0


if __name__ == "__main__":
    sys.exit(main())
