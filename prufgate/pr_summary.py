"""`prufgate pr-summary`: one short Markdown summary of a gate run, for a pull request.

It reads the SARIF report the gate wrote (`reports/prufgate.sarif`) and the change
itself, and prints the verdict, the findings (most severe first) and a few facts
about the change: production and test lines changed, assertion lines added and
removed in tests, dependency manifests and CI, lint, test or coverage
configuration touched. The GitHub Action appends it to the job summary and, with
`pr_comment: true`, keeps it as one pull-request comment that each run updates.

Paths and messages come from the repository under review, so they are shown only
as inline code (no mention, link or HTML can come through) after the same
redaction AI adjudication applies. A result's `details` (where a secret
scanner's match is kept) is never read.

The summary reports; it never decides. The gate's verdict and exit code stay
with `prufgate.sh` and the synthesizer.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from prufgate import PROJECT_URL, __version__  # noqa: E402
from prufgate.anti_reward_hacking.test_integrity import (  # noqa: E402
    DIFF_ASSERTION_LINE_RE,
    is_test_file,
)
from prufgate.config import GitDiffError, _diff_base, _git  # noqa: E402
from prufgate.diff_guard.tamper_detector import (  # noqa: E402
    COVERAGE_FILE_RE,
    _is_ci_workflow_file,
    _is_linter_config_file,
)
from prufgate.diff_scope import _HUNK_RE, _unquote_git_path  # noqa: E402
from prufgate.review.adjudicate import redact  # noqa: E402
from prufgate.safe_fs import safe_read_text  # noqa: E402
from prufgate.scan_result import metadata_from_sarif  # noqa: E402

MARKER = "<!-- prufgate:pr-summary -->"
# GitHub refuses comment bodies over 65,536 characters.
MAX_BODY = 60000
MAX_LISTED_FILES = 10
SEVERITIES = ("P0", "P1", "P2", "P3")
_LEVEL_SEVERITY = {"error": "P1", "warning": "P2", "note": "P3", "none": "P3"}
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BINARY_RE = re.compile(r"^Binary files (?:a/(.+?)|/dev/null) and (?:b/(.+?)|/dev/null) differ$")

MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg", "go.mod", "Cargo.toml",
    "Gemfile", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts", "packages.config",
    "deno.json", "deno.jsonc",
})
GUARDRAIL_NAMES = frozenset({
    ".pre-commit-config.yaml", "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml",
    ".gitleaks.toml", "CODEOWNERS", "action.yml", "action.yaml",
})
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".txt")


class SummaryError(Exception):
    """The summary could not be built or posted (exit 2)."""


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    fingerprint: str = ""
    blocking: Optional[bool] = None


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    ignored: int = 0  # honoured inline ignores (SARIF suppression kind inSource)
    dismissed: int = 0  # AI-dismissed (kind external)
    baselined: int = 0
    reviewed: int = 0
    metadata: dict = field(default_factory=dict)

    def count(self, *severities: str) -> int:
        return sum(1 for f in self.findings if f.severity in severities)


@dataclass
class FileChange:
    path: str
    added: int = 0
    removed: int = 0
    asserts_added: int = 0
    asserts_removed: int = 0


# --- the report -------------------------------------------------------------


def read_sarif(path: Path) -> Report:
    """The findings of a SARIF 2.1.0 report. A result with a suppression is counted,
    not listed. Raises SummaryError when the file is missing or not SARIF."""
    try:
        doc = json.loads(safe_read_text(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SummaryError(f"cannot read the SARIF report {path}: {exc}") from exc
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not isinstance(runs, list) or not runs or not all(isinstance(run, dict) for run in runs):
        raise SummaryError(f"{path} is not a SARIF report: it has no runs")
    report = Report()
    try:
        report.metadata = metadata_from_sarif(doc)
    except ValueError as exc:
        raise SummaryError("invalid versioned scan metadata") from exc
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        for res in results if isinstance(results, list) else []:
            if not isinstance(res, dict):
                continue
            sups = [s for s in res.get("suppressions") or [] if isinstance(s, dict) and s.get("status", "accepted") == "accepted"]
            if sups:
                if (res.get("properties") or {}).get("dismissal"):
                    report.reviewed += 1
                elif any(s.get("justification", "").lower().startswith("in the prufgate baseline") for s in sups):
                    report.baselined += 1
                elif any(s.get("kind") == "external" for s in sups):
                    report.dismissed += 1
                else:
                    report.ignored += 1
                continue
            props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
            severity = props.get("severity")
            if severity not in SEVERITIES:
                severity = _LEVEL_SEVERITY.get(str(res.get("level") or "warning"), "P2")
            uri, line = "", 1
            locs = res.get("locations")
            if isinstance(locs, list) and locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation") or {}
                uri = str(((phys.get("artifactLocation") or {}).get("uri")) or "")
                try:
                    line = max(1, int((phys.get("region") or {}).get("startLine") or 1))
                except (TypeError, ValueError):
                    line = 1
            message = res.get("message")
            text = message.get("text") if isinstance(message, dict) else ""
            fingerprint = str((res.get("partialFingerprints") or {}).get("prufgateFindingHash/v1", ""))
            report.findings.append(Finding(str(res.get("ruleId") or "unknown-rule"), severity, uri, line, str(text or ""), fingerprint,
                                          props.get("blocking") if type(props.get("blocking")) is bool else None))
    report.findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.path, f.line, f.rule))
    return report


# --- the change -------------------------------------------------------------


def parse_changes(diff: str) -> List[FileChange]:
    """Lines added and removed per file, and assertion lines among them, from a
    `git diff -U0` (renames detected). A rename with no edit is a file with no lines."""
    files: List[FileChange] = []
    cur: Optional[FileChange] = None
    old_path: Optional[str] = None
    old_left = new_left = 0
    for line in diff.splitlines():
        if cur is not None and (old_left > 0 or new_left > 0):
            if line.startswith("-") and old_left > 0:
                old_left -= 1
                cur.removed += 1
                cur.asserts_removed += bool(DIFF_ASSERTION_LINE_RE.search(line[1:]))
                continue
            if line.startswith("+") and new_left > 0:
                new_left -= 1
                cur.added += 1
                cur.asserts_added += bool(DIFF_ASSERTION_LINE_RE.search(line[1:]))
                continue
            if line.startswith("\\"):
                continue
        if line.startswith("diff --git "):
            cur, old_path, old_left, new_left = None, None, 0, 0
        elif line.startswith("rename to ") and cur is None:
            rel = _unquote_git_path(line[len("rename to "):])
            if rel:
                cur = FileChange(rel)
                files.append(cur)
        elif line.startswith("--- "):
            old_path = _unquote_git_path(line[4:], prefix="a/")
        elif line.startswith("+++ "):
            rel = _unquote_git_path(line[4:], prefix="b/") or old_path
            if rel and (cur is None or cur.path != rel):
                cur = FileChange(rel)
                files.append(cur)
        elif (m := _BINARY_RE.match(line)) and cur is None:
            rel = m.group(2) or m.group(1)
            if rel:
                cur = FileChange(rel)
                files.append(cur)
        elif cur is not None and (m := _HUNK_RE.match(line)):
            old_left = int(m.group(2) or "1")
            new_left = int(m.group(4) or "1")
    return files


def change_facts(workspace: Path, base_ref: str) -> List[FileChange]:
    """The change against the merge base with `base_ref`. Raises GitDiffError."""
    commit = _diff_base(base_ref, workspace)
    diff = _git(
        ["-c", "core.quotePath=false", "diff", "-U0", "-M", "--no-color", "--no-ext-diff", "--no-textconv",
         "--relative", "--end-of-options", commit],
        workspace,
    )
    return parse_changes(diff)


def is_manifest(path: str) -> bool:
    name = Path(path).name
    return (
        name in MANIFEST_NAMES
        or name.endswith(".csproj")
        or (name.startswith("requirements") and name.endswith((".txt", ".in")))
    )


def is_guardrail(path: str) -> bool:
    """CI, lint, test or coverage configuration, or PrufGate's own."""
    norm = path.replace("\\", "/")
    name = Path(norm).name
    return (
        norm.startswith(".prufgate/")
        or name in GUARDRAIL_NAMES
        or _is_ci_workflow_file(norm)
        or _is_linter_config_file(norm)
        or bool(COVERAGE_FILE_RE.search(norm))
    )


def category(path: str) -> str:
    if is_test_file(path):
        return "tests"
    if is_manifest(path) or is_guardrail(path):
        return "config"
    norm = path.replace("\\", "/")
    if norm.lower().endswith(DOC_SUFFIXES) or norm.split("/", 1)[0] in ("docs", "doc"):
        return "docs"
    return "production"


# --- rendering --------------------------------------------------------------


def code(text: object, limit: int = 160, scrub: bool = True) -> str:
    """`text` as one inline code span: on one line, at most `limit` characters,
    with no backtick that could close the span early, and redacted when `scrub`
    (messages; not paths and rule IDs, where a long path would read as a key)."""
    s = str(text)
    s = " ".join((redact(s) if scrub else s).split()).replace("`", "'")
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return f"`{s}`" if s else "`-`"


def _file_list(paths: List[str]) -> str:
    shown = ", ".join(code(p, 100, scrub=False) for p in paths[:MAX_LISTED_FILES])
    more = len(paths) - MAX_LISTED_FILES
    return shown + (f" and {more} more" if more > 0 else "")


def _plural(n: int, word: str, plural: str = "") -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def render(
    report: Report,
    changes: Optional[List[FileChange]] = None,
    base_ref: Optional[str] = None,
    exit_code: Optional[int] = None,
    max_findings: int = 10,
    changes_note: str = "",
) -> str:
    blocking = sum(f.blocking if f.blocking is not None else f.severity in ("P0", "P1") for f in report.findings)
    warnings = report.count("P2")
    notes = report.count("P3")
    if exit_code is None:
        exit_code = report.metadata.get("exit_code", 1 if blocking else 0)
    if report.metadata.get("scan_status") in ("incomplete", "error"):
        exit_code = 2
    if exit_code == 0:
        title = "PrufGate: no blocking findings"
    elif exit_code == 1:
        title = f"PrufGate: {_plural(blocking, 'blocking finding') if blocking else 'blocking findings'}"
    else:
        title = "PrufGate could not finish the check"
    out = [MARKER, f"### {title}", ""]
    if exit_code not in (0, 1):
        out += [
            f"The gate exited with code {int(exit_code)}: an engine failed or the configuration or base ref "
            "is unusable, so this run is not a pass. The job log names the cause.",
            "",
        ]
    counts = [f"**{blocking}** blocking (P0/P1)", f"**{warnings}** {'warning' if warnings == 1 else 'warnings'} (P2)",
              f"**{notes}** {'note' if notes == 1 else 'notes'} (P3)"]
    advisory_high = sum(f.severity in ("P0", "P1") and f.blocking is False for f in report.findings)
    if advisory_high:
        counts.append(f"**{advisory_high}** advisory under policy (P0/P1)")
    if report.ignored:
        counts.append(f"{report.ignored} ignored with a reason")
    if report.dismissed:
        counts.append(f"{report.dismissed} dismissed by AI adjudication")
    out += [" · ".join(counts), ""]

    if report.findings:
        listed = report.findings[: max(0, max_findings)]
        head = "**Findings**, most severe first"
        if len(listed) < len(report.findings):
            head += f" (the first {len(listed)} of {len(report.findings)}; all of them are in the SARIF report)"
        out += [head + ":", ""]
        for f in listed:
            where = f"{f.path}:{f.line}" if f.path else "the repository"
            out.append(
                f"- **{f.severity}** {code(f.rule, 80, scrub=False)} at {code(where, 120, scrub=False)}: {code(f.message)}"
            )
        out.append("")

    if changes is not None:
        out += _render_changes(changes, base_ref)
    elif changes_note:
        out += [f"_About this change: {changes_note}_", ""]

    out.append(
        f"<sub>PrufGate {__version__} · [what each rule means]({PROJECT_URL}/blob/main/docs/ENGINES.md)</sub>"
    )
    body = "\n".join(out) + "\n"
    if len(body) > MAX_BODY:
        cut = body.rfind("\n- ", 0, MAX_BODY - 200)
        body = body[: cut if cut > 0 else MAX_BODY - 200] + "\n\n_The summary was cut to fit; the SARIF report has every finding._\n"
    return body


def workflow_summary(result: dict, comparison: Optional[dict] = None) -> str:
    """PR-facing facts and next actions; every repository-derived string is escaped."""
    status = result.get("scan_status", "unknown")
    cov, gov = result.get("coverage", {}), result.get("governance", {})
    counts = result.get("summary", {})
    out = ["", "**Review workflow**", "", f"Scan status: {code(status)}; enforcement: {code(result.get('enforcement', {}).get('mode', 'strict'))}."]
    if comparison is None:
        out.append("New versus existing findings: not measured; supply a previous SARIF report for a stable-fingerprint comparison.")
    elif comparison.get("available"):
        out.append(f"New findings: **{comparison['new']}**; existing active findings: **{comparison['existing']}**; no longer reported: **{comparison['resolved']}**.")
    else:
        out.append("New versus existing findings: unknown — " + code(comparison.get("reason", "Stable fingerprints are missing.")) + ".")
    out.append(f"Existing debt: **{gov.get('baselined_findings', 'unknown')}** findings matched the baseline; **{gov.get('registered_known_debt_entries', 'unknown')}** registered known-debt entries.")
    if gov.get("known_debt_ceilings"):
        out.append("Numeric debt allowances (not measured counts): " + ", ".join(code(f"{rule}: {limit}") for rule, limit in sorted(gov["known_debt_ceilings"].items())) + ".")
    out.append(f"Reviewed dismissals applied: **{len(gov.get('dismissed', []))}**; pending ledger changes: **{gov.get('pending_changes', 0)}**.")
    attention = [entry for entry in gov.get("states", []) if entry.get("state") in ("pending", "expired")]
    for entry in attention[:10]:
        out.append(f"- Dismissal {code(entry.get('dismissal_id', 'unknown'), 50)}: {code(entry.get('state'))}; owner {code(entry.get('owner', 'unassigned'))}; expires {code(entry.get('expires') or 'not set')}.")
    if len(attention) > 10:
        out.append(f"- {len(attention) - 10} more dismissal records are in the local ledger and result artifact.")
    out.append(f"Coverage: {code(cov.get('files_checked') if cov.get('files_checked') is not None else 'unknown')} files; {code(cov.get('lines_checked') if cov.get('lines_checked') is not None else 'unknown')} input lines.")
    reasons = result.get("errors", []) + result.get("incomplete_reasons", [])
    skips = [entry for entry in cov.get("engines", []) if entry.get("status") in ("skipped", "error", "incomplete")]
    out += ["", "**Incomplete, failed or skipped checks**", ""]
    out += ["- " + code(reason, 400) for reason in reasons]
    out += [f"- {code(entry.get('engine', 'check'))}: {code(entry.get('status'))} — {code(entry.get('reason') or 'No reason supplied', 240)}" for entry in skips]
    if not reasons and not skips:
        out.append("- None reported within the selected scan profile.")
    actions = []
    if status in ("incomplete", "error"):
        actions.append("Repair the failed inputs or checks and rerun. This scan cannot establish a pass.")
    if counts.get("blockers", 0):
        actions.append(f"Fix or request review of {counts['blockers']} policy blocker(s); use prufgate explain RULE for rule-specific guidance.")
    if counts.get("advisories", 0):
        actions.append("Triage the advisory findings. Promote selected rules only after validating their precision in this codebase.")
    if gov.get("pending_changes"):
        actions.append("Have a maintainer review the dismissal ledger changes; approvals added by this PR do not apply to its scan.")
    expired = [s for s in gov.get("states", []) if s.get("state") == "expired"]
    if expired:
        actions.append("Review expired dismissals and fix the restored findings or submit a new reviewed request.")
    if gov.get("baselined_findings") or gov.get("registered_known_debt_entries"):
        actions.append("Reduce recorded debt as fixes land; refresh the baseline through normal review.")
    if not actions:
        actions.append("Review the reported coverage and change facts; no policy blocker was reported in completed checks.")
    out += ["", "**Recommended next actions**", "", *["- " + action for action in actions]]
    return "\n".join(out) + "\n"


def compare_reports(report: Report, previous: Report) -> dict:
    if report.metadata and previous.metadata:
        if report.metadata.get("profile") != previous.metadata.get("profile") or report.metadata.get("coverage", {}).get("scope") != previous.metadata.get("coverage", {}).get("scope"):
            return {"available": False, "reason": "Reports cover different profiles or scopes."}
    if any(not f.fingerprint for f in report.findings + previous.findings):
        return {"available": False}
    current = {(f.rule, f.path, f.fingerprint) for f in report.findings}
    old = {(f.rule, f.path, f.fingerprint) for f in previous.findings}
    return {"available": True, "new": len(current - old), "existing": len(current & old), "resolved": len(old - current)}


def _render_changes(changes: List[FileChange], base_ref: Optional[str]) -> List[str]:
    rows = {"production": [0, 0, 0], "tests": [0, 0, 0], "config": [0, 0, 0], "docs": [0, 0, 0]}
    asserts_added = asserts_removed = 0
    for c in changes:
        cat = category(c.path)
        rows[cat][0] += 1
        rows[cat][1] += c.added
        rows[cat][2] += c.removed
        if cat == "tests":
            asserts_added += c.asserts_added
            asserts_removed += c.asserts_removed
    against = f" (compared with {code(base_ref, 80, scrub=False)})" if base_ref else ""
    out = [f"**About this change**{against}", "", "| | Files | Lines added | Lines removed |", "|---|---:|---:|---:|"]
    labels = {"production": "Production code", "tests": "Tests", "config": "Build, CI and configuration",
              "docs": "Documentation"}
    for key, label in labels.items():
        n, a, r = rows[key]
        out.append(f"| {label} | {n} | {a} | {r} |")
    out.append("")
    out.append(f"- Assertion lines in tests: {asserts_added} added, {asserts_removed} removed")
    manifests = [c.path for c in changes if is_manifest(c.path)]
    guardrails = [c.path for c in changes if is_guardrail(c.path)]
    if manifests:
        out.append(f"- Dependency manifests changed: {_file_list(manifests)}")
    if guardrails:
        out.append(f"- CI, lint, test or coverage configuration changed: {_file_list(guardrails)}")
    if rows["production"][1] + rows["production"][2] and not rows["tests"][0]:
        out.append("- Production code changed and no test file did")
    out.append("")
    return out


# --- the pull-request comment ----------------------------------------------

Opener = Callable[[urllib.request.Request, float], Any]


def _default_opener(req: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (https only, checked below)


def _call(opener: Opener, method: str, url: str, token: str, body: Optional[Dict[str, Any]] = None) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", f"prufgate/{__version__}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with opener(req, 20.0) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        hint = ""
        if exc.code in (403, 404):
            hint = (" (the token needs `pull-requests: write`; a pull request from a fork gets a read-only token, "
                    "so no comment can be posted there)")
        raise SummaryError(f"GitHub API {method} returned HTTP {exc.code}{hint}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SummaryError(f"GitHub API {method} failed: {exc.__class__.__name__}") from None
    try:
        return json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        raise SummaryError(f"GitHub API {method} returned a reply that is not JSON") from None


def post_comment(
    body: str,
    repo: str,
    pr: int,
    token: str,
    api_url: str = "https://api.github.com",
    author: str = "github-actions[bot]",
    opener: Opener = _default_opener,
    max_pages: int = 10,
) -> str:
    """Create the summary comment, or update the one `author` posted before (found
    by MARKER). Returns "created" or "updated". Raises SummaryError."""
    if not _REPO_RE.match(repo or "") or ".." in repo:
        raise SummaryError(f"not an owner/name repository: {repo!r}")
    if not isinstance(pr, int) or pr <= 0:
        raise SummaryError(f"not a pull request number: {pr!r}")
    if not token:
        raise SummaryError("no token: set PRUFGATE_GITHUB_TOKEN or GITHUB_TOKEN")
    api = api_url.rstrip("/")
    if not api.startswith("https://"):
        raise SummaryError("the GitHub API URL must use https://")
    existing = None
    for page in range(1, max_pages + 1):
        items = _call(opener, "GET", f"{api}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token)
        if not isinstance(items, list):
            raise SummaryError("GitHub API GET returned something other than a list of comments")
        for item in items:
            if (
                isinstance(item, dict)
                and str(item.get("body") or "").startswith(MARKER)
                and (item.get("user") or {}).get("login") == author
                and isinstance(item.get("id"), int)
            ):
                existing = item["id"]
                break
        if existing is not None or len(items) < 100:
            break
    if existing is not None:
        _call(opener, "PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
        return "updated"
    _call(opener, "POST", f"{api}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
    return "created"


def pr_number_from_event(path: Optional[str]) -> Optional[int]:
    """The pull request number in a GitHub event payload (GITHUB_EVENT_PATH), if any."""
    if not path:
        return None
    try:
        event = json.loads(safe_read_text(Path(path), encoding="utf-8"))
    except (OSError, ValueError):
        return None
    number = (event.get("pull_request") or {}).get("number") if isinstance(event, dict) else None
    return number if isinstance(number, int) and number > 0 else None


# --- command ----------------------------------------------------------------


def resolve_base(reports_dir: Path, explicit: Optional[str]) -> Optional[str]:
    """--base, then the base ref the gate used (reports/raw/base_ref), then
    PRUFGATE_BASE_REF, then origin/$GITHUB_BASE_REF in a pull request."""
    if explicit:
        return explicit
    try:
        recorded = safe_read_text(reports_dir / "raw" / "base_ref", encoding="utf-8").strip()
    except OSError:
        recorded = ""
    if recorded:
        return recorded
    if os.environ.get("PRUFGATE_BASE_REF"):
        return os.environ["PRUFGATE_BASE_REF"]
    if os.environ.get("GITHUB_BASE_REF"):
        return f"origin/{os.environ['GITHUB_BASE_REF']}"
    return None


def main(
    workspace: str = ".",
    sarif: Optional[str] = None,
    base: Optional[str] = None,
    exit_code: Optional[int] = None,
    max_findings: int = 10,
    post: bool = False,
    repo: Optional[str] = None,
    pr: Optional[int] = None,
    opener: Opener = _default_opener,
    previous_sarif: Optional[str] = None,
) -> int:
    root = Path(workspace).resolve()
    reports_dir = Path(os.environ.get("PRUFGATE_REPORTS_DIR") or root / "reports")
    sarif_path = Path(sarif) if sarif else reports_dir / "prufgate.sarif"
    try:
        report = read_sarif(sarif_path)
    except SummaryError as exc:
        print(f"prufgate pr-summary: {exc}", file=sys.stderr)
        return 2
    base_ref = resolve_base(reports_dir, base)
    changes: Optional[List[FileChange]] = None
    note = ""
    if base_ref:
        try:
            changes = change_facts(root, base_ref)
        except GitDiffError as exc:
            note = f"git could not compare with the base ref ({exc})"
    else:
        note = "no base ref, so there is nothing to compare"
    body = render(report, changes, base_ref, exit_code, max_findings, note)
    comparison = None
    if previous_sarif:
        try:
            comparison = compare_reports(report, read_sarif(Path(previous_sarif)))
        except SummaryError as exc:
            print(f"prufgate pr-summary: previous report could not be read: {exc}", file=sys.stderr)
            return 2
    metadata = report.metadata
    if not metadata:
        blockers = sum(f.blocking if f.blocking is not None else f.severity in ("P0", "P1") for f in report.findings)
        metadata = {"scan_status": "error" if exit_code not in (None, 0, 1) else "findings" if report.findings else "clean",
                    "summary": {"blockers": blockers, "advisories": len(report.findings) - blockers},
                    "errors": ["The gate could not finish; inspect its execution log."] if exit_code not in (None, 0, 1) else [],
                    "coverage": {}, "governance": {}, "enforcement": {"mode": "not reported"}}
    body += workflow_summary(metadata, comparison)
    body = body[:MAX_BODY] if len(body) > MAX_BODY else body
    sys.stdout.write(body)
    sys.stdout.flush()
    if not post:
        return 0
    repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
    pr = pr or pr_number_from_event(os.environ.get("GITHUB_EVENT_PATH"))
    token = os.environ.get("PRUFGATE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    try:
        if pr is None:
            raise SummaryError("no pull request number: pass --pr, or run on a pull_request event")
        what = post_comment(
            body, repo, pr, token,
            api_url=os.environ.get("GITHUB_API_URL") or "https://api.github.com",
            author=os.environ.get("PRUFGATE_COMMENT_AUTHOR") or "github-actions[bot]",
            opener=opener,
        )
    except SummaryError as exc:
        print(f"prufgate pr-summary: the comment was not posted: {exc}", file=sys.stderr)
        return 2
    print(f"prufgate pr-summary: pull request comment {what}", file=sys.stderr)
    return 0

