#!/usr/bin/env python3
"""
PrufGate Review Synthesizer & Unified SARIF/Markdown Reporter
Ingests PrufGate's 6 core engine outputs + optional ast-grep/gitleaks/zizmor outputs,
normalizes into P0-P3 severities, generates reports/prufgate.sarif, reports/prufgate-review.md,
reports/gl-code-quality-report.json and reports/prufgate-junit.xml,
prints an ANSI summary table, and exits 1 if P0/P1 findings are detected.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from prufgate import PROJECT_URL, __version__, diff_scope, inline_ignore  # noqa: E402
from prufgate.config import (  # noqa: E402
    ConfigError,
    GitDiffError,
    PrufGateConfig,
    _diff_base,
    git_blob,
    repo_prefix,
)
from prufgate.report_formats import gitlab_code_quality, junit_xml  # noqa: E402
from prufgate.review.adjudicate import adjudicate  # noqa: E402
from prufgate.rules import SARIF_RANK, confidence, visible  # noqa: E402
from prufgate.sarif import add_partial_fingerprints  # noqa: E402

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"


class Finding:
    def __init__(
        self,
        tool: str,
        rule_id: str,
        severity: str,  # P0, P1, P2, P3
        message: str,
        file_path: str = "workspace",
        line: int = 1,
        details: str = "",
        origin: str = "",
        spans: Optional[List[tuple]] = None,
        anchored: bool = False,
    ):
        self.tool = tool
        self.origin = origin or tool  # "ai-review" for an AI review comment
        self.rule_id = rule_id
        self.severity = severity
        self.message = message.strip().replace("\n", " ")
        self.file_path = file_path
        self.line = line
        self.details = details.strip()
        # Line ranges the finding covers, for the changed-lines scope (diff_scope).
        self.spans = spans or [(line, line)]
        # Already limited to the change by the runner (gitleaks over the PR's commits).
        self.anchored = anchored

    @property
    def confidence(self) -> str:
        return confidence(self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "details": self.details,
        }


def safe_write_text(path: Path, text: str) -> None:
    """Write `path` without following a symlink: the reports folder lives in the
    scanned repository, which may plant `reports/prufgate.sarif -> elsewhere`."""
    if path.parent.is_symlink():
        raise OSError(f"refusing to write into a symlinked directory: {path.parent}")
    if path.is_symlink():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def get_git_info() -> tuple[str, str]:
    workspace = Path(os.environ.get("WORKSPACE", "/workspace")).resolve().name or "workspace"
    commit = "unknown"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        pass
    return workspace, commit


def parse_raw_results(raw_dir: Path) -> List[Finding]:
    findings: List[Finding] = []

    # 1. Engine 1: Production Anti-Fabrication Engine (anti_fabrication.json)
    af_file = raw_dir / "anti_fabrication.json"
    if af_file.exists() and af_file.stat().st_size > 0:
        try:
            af_data = json.loads(af_file.read_text(encoding="utf-8"))
            if isinstance(af_data, list):
                for item in af_data:
                    ln = int(item.get("line", 1))
                    end_ln = int(item.get("end_line") or ln)
                    findings.append(
                        Finding(
                            tool="anti-fabrication",
                            rule_id=f"anti-fabrication-{item.get('rule', 'violation')}",
                            severity="P0",
                            message=f"Zero-fabrication invariant breached: {item.get('rule')}",
                            file_path=item.get("file", "unknown"),
                            line=ln,
                            details=item.get("snippet", "")[:200],
                            spans=[(ln, max(ln, end_ln))],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 2. Engine 2: Test Integrity & Anti-Reward-Hacking Engine (test_integrity.json)
    ti_file = raw_dir / "test_integrity.json"
    if ti_file.exists() and ti_file.stat().st_size > 0:
        try:
            ti_data = json.loads(ti_file.read_text(encoding="utf-8"))
            if isinstance(ti_data, list):
                for item in ti_data:
                    rule_name = item.get("rule", "test-integrity-violation")
                    sev = item.get("severity", "P0")
                    if sev not in ("P0", "P1", "P2", "P3"):
                        sev = "P0"
                    ln = int(item.get("line", 1))
                    end_ln = int(item.get("end_line") or ln)
                    findings.append(
                        Finding(
                            tool="test-integrity",
                            rule_id=rule_name,
                            severity=sev,
                            message=item.get("message") or f"Test integrity invariant breached: {rule_name}",
                            file_path=item.get("file", "unknown"),
                            line=ln,
                            details=item.get("snippet", "")[:200],
                            spans=[(ln, max(ln, end_ln))],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 3. Engine 3: Diff-Scoped Agent Tampering Guard (diff_guard.json)
    dg_file = raw_dir / "diff_guard.json"
    if dg_file.exists() and dg_file.stat().st_size > 0:
        try:
            dg_data = json.loads(dg_file.read_text(encoding="utf-8"))
            if isinstance(dg_data, list):
                for item in dg_data:
                    rule_name = item.get("rule", "diff-tampering-violation")
                    sev = item.get("severity", "P0")
                    if sev not in ("P0", "P1", "P2", "P3"):
                        sev = "P0"
                    findings.append(
                        Finding(
                            tool="diff-guard",
                            rule_id=rule_name,
                            severity=sev,
                            message=item.get("message") or f"Diff guardrail tampering detected: {rule_name}",
                            file_path=item.get("file", "unknown"),
                            line=int(item.get("line", 1)),
                            details=item.get("snippet", "")[:200],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 4. Engine 4: Ghost Dependency, API Contract & Environment Drift Guard (contract_guard.json)
    cg_file = raw_dir / "contract_guard.json"
    if cg_file.exists() and cg_file.stat().st_size > 0:
        try:
            cg_data = json.loads(cg_file.read_text(encoding="utf-8"))
            cg_items = cg_data.get("findings", []) if isinstance(cg_data, dict) else cg_data
            if isinstance(cg_items, list):
                for item in cg_items:
                    rule_name = item.get("rule") or item.get("rule_id") or "contract-guard-violation"
                    sev = item.get("severity", "P1")
                    if sev not in ("P0", "P1", "P2", "P3"):
                        sev = "P1"
                    ln = int(item.get("line", 1))
                    end_ln = int(item.get("end_line") or ln)
                    findings.append(
                        Finding(
                            tool="contract-guard",
                            rule_id=rule_name,
                            severity=sev,
                            message=item.get("message") or f"Contract or dependency drift detected: {rule_name}",
                            file_path=item.get("file", "unknown"),
                            line=ln,
                            details=item.get("snippet", "")[:200],
                            spans=[(ln, max(ln, end_ln))],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 5. Engine 5: Universal Multi-Tenant BOLA / IDOR Engine (bola_matrix.json)
    bola_file = raw_dir / "bola_matrix.json"
    if bola_file.exists() and bola_file.stat().st_size > 0:
        try:
            bola_data = json.loads(bola_file.read_text(encoding="utf-8"))
            if isinstance(bola_data, list):
                for item in bola_data:
                    b_line = int(item.get("line", 1))
                    findings.append(
                        Finding(
                            tool="bola-matrix",
                            rule_id=item.get("rule_id", "BOLA-VIOLATION"),
                            severity=item.get("severity", "P0"),
                            message=item.get("message", "Cross-tenant authorization boundary broken"),
                            file_path=item.get("target", "target"),
                            line=b_line,
                            details=f"{item.get('details', '')} {item.get('curl_poc', '')}"[:300],
                            # The whole handler: removing its guard is a change to the route.
                            spans=[(b_line, max(b_line, int(item.get("end_line") or b_line)))],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 6. Engine 6: Hybrid Semantic Diff Reviewer (pr_review.json)
    pr_file = raw_dir / "pr_review.json"
    if pr_file.exists() and pr_file.stat().st_size > 0:
        try:
            pr_data = json.loads(pr_file.read_text(encoding="utf-8"))
            if isinstance(pr_data, list):
                for item in pr_data:
                    findings.append(
                        Finding(
                            tool="pr-reviewer",
                            rule_id=inline_ignore.review_rule_id(str(item.get("title") or "review")),
                            origin="ai-review" if item.get("ai") is True else "",
                            severity=item.get("severity", "P2"),
                            message=f"{item.get('title')}: {item.get('message')}",
                            file_path=item.get("file", "unknown"),
                            line=int(item.get("line", 1)),
                            details=item.get("suggestion", "")[:200],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 7. Optional Accelerator: Gitleaks (gitleaks.json)
    # gitleaks_worktree.json: uncommitted edits in a changed-files run.
    for gl_file in (raw_dir / "gitleaks.json", raw_dir / "gitleaks_worktree.json"):
        if gl_file.exists() and gl_file.stat().st_size > 0:
            try:
                data = json.loads(gl_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        findings.append(
                            Finding(
                                tool="gitleaks",
                                rule_id=item.get("RuleID", "secret-detected"),
                                severity="P0",
                                message=f"Secret detected: {item.get('Description', 'Hardcoded secret')}",
                                file_path=item.get("File", "unknown"),
                                line=item.get("StartLine", 1),
                                details=f"Match: {item.get('Match', '')[:80]}",
                                # Found in a commit of the scanned range: the change added it.
                                anchored=bool(item.get("Commit")),
                            )
                        )
            except (json.JSONDecodeError, OSError):
                pass

    # 8. Optional Accelerator: ast-grep (ast_grep.json)
    ast_file = raw_dir / "ast_grep.json"
    if ast_file.exists() and ast_file.stat().st_size > 0:
        try:
            data = json.loads(ast_file.read_text(encoding="utf-8"))
            for item in data:
                # ast-grep lines are 0-based.
                rng = item.get("range", {})
                start = int(rng.get("start", {}).get("line", 0)) + 1
                end = int(rng.get("end", {}).get("line", start - 1)) + 1
                findings.append(
                    Finding(
                        tool="ast-grep",
                        rule_id=item.get("ruleId", "ast-rule"),
                        severity="P1",
                        message=item.get("message", item.get("text", "AST violation")),
                        file_path=item.get("file", "unknown"),
                        line=start,
                        spans=[(start, max(start, end))],
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 9. Optional Accelerator: Zizmor (zizmor.json)
    zizmor_file = raw_dir / "zizmor.json"
    if zizmor_file.exists() and zizmor_file.stat().st_size > 0:
        try:
            data = json.loads(zizmor_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    findings.append(zizmor_finding(item))
        except (json.JSONDecodeError, OSError):
            pass

    # 10. Custom gate & hook failures (*.fail)
    for fail_file in raw_dir.glob("*.fail"):
        gate_name = fail_file.stem
        log_file = raw_dir / f"{gate_name}.log"
        details = log_file.read_text(errors="ignore") if log_file.exists() else "Gate exited non-zero"
        tail_lines = [line for line in details.splitlines() if line.strip()][-5:]
        summary_details = " | ".join(tail_lines) if tail_lines else "Verification failed"
        findings.append(
            Finding(
                tool="prufgate-gate",
                rule_id=f"gate-failed-{gate_name}",
                severity="P1",
                message=f"Custom audit hook '{gate_name}' failed verification",
                file_path=f"reports/raw/{gate_name}.log",
                line=1,
                details=summary_details[:200],
            )
        )

    # 11. Inline prufgate-ignore comments without a reason: they suppressed nothing.
    for e in inline_ignore.load(raw_dir / SUPPRESSIONS_FILE):
        if e["kind"] == "missing-reason":
            findings.append(
                Finding(
                    tool=str(e.get("engine") or "prufgate"),
                    rule_id=inline_ignore.MISSING_REASON_RULE,
                    severity="P2",
                    message=f"{inline_ignore.MISSING_REASON_MESSAGE} It names `{e.get('rule')}`, which is still reported.",
                    file_path=str(e.get("file") or "unknown"),
                    line=int(e.get("line") or 1),
                )
            )

    return deduplicate_findings(findings)


def zizmor_severity(rule_id: str, severity: str, conf: str) -> str:
    """P0-P3 from zizmor's own severity and confidence. Only a High-severity finding
    blocks (P0 for a confident template injection); Medium is advisory, and a
    Low-confidence Medium, Low or Informational one is a note. `unpinned-uses` is
    hygiene, never blocking."""
    severity, conf = severity.upper(), conf.upper()
    if rule_id == "unpinned-uses":
        return "P2"
    if severity == "HIGH":
        return "P0" if rule_id == "template-injection" and conf == "HIGH" else "P1"
    if severity == "MEDIUM":
        return "P3" if conf == "LOW" else "P2"
    if severity in ("LOW", "INFORMATIONAL"):
        return "P3"
    return "P2"


def zizmor_finding(item: Dict[str, Any]) -> Finding:
    """One zizmor JSON result. Its line is the primary location's (zizmor rows are
    0-based); every location in that file counts for the changed-lines scope."""
    determ = item.get("determinations") or {}
    rule_id = item.get("ident", item.get("rule", "ci-security"))
    sev = zizmor_severity(
        rule_id, str(determ.get("severity") or item.get("severity") or "Medium"), str(determ.get("confidence") or "Medium")
    )
    file_path, line, spans = ".github/workflows", 1, []
    locs = [loc for loc in item.get("locations") or [] if isinstance(loc, dict)]
    primary = next((loc for loc in locs if (loc.get("symbolic") or {}).get("kind") == "Primary"), locs[0] if locs else None)

    def path_of(loc: Dict[str, Any]) -> str:
        local = ((loc.get("symbolic") or {}).get("key") or {}).get("Local") or {}
        return str(local.get("given_path") or local.get("verbatim_path") or ".github/workflows")

    def rows(loc: Dict[str, Any]) -> tuple:
        where = (loc.get("concrete") or {}).get("location") or {}
        start = int((where.get("start_point") or {}).get("row", 0)) + 1
        end = int((where.get("end_point") or {}).get("row", start - 1)) + 1
        return start, max(start, end)

    if primary is not None:
        file_path = path_of(primary)
        line = rows(primary)[0]
        spans = [rows(loc) for loc in locs if path_of(loc) == file_path]
    return Finding(
        tool="zizmor",
        rule_id=rule_id,
        severity=sev,
        message=item.get("desc", item.get("message", "CI workflow issue")),
        file_path=file_path,
        line=line,
        spans=spans,
    )


def scope_to_change(findings: List[Finding], ranges: Optional[diff_scope.Ranges], workspace_dir: Path) -> List[Finding]:
    """In a changed-files run (the runner wrote the changed lines), only findings on
    lines the change touched; a full run (no file) keeps everything."""
    if ranges is None:
        return findings
    kept = [
        f for f in findings
        if f.anchored or diff_scope.in_scope(ranges, f.tool, f.rule_id, f.file_path, f.spans, workspace_dir)
    ]
    if len(kept) < len(findings):
        print(f"prufgate: {len(findings) - len(kept)} finding(s) on lines this change did not touch were not reported "
              "(changed-files scan; a full scan reports them).", file=sys.stderr)
    return kept


SUPPRESSIONS_FILE = "suppressions.jsonl"
CHANGED_LINES_FILE = "changed_lines.json"
# The engines that report a rule under a prefixed ID (see the parsers above).
_RULE_PREFIX = {"anti-fabrication": "anti-fabrication-"}


def load_suppressions(raw_dir: Path) -> List[tuple[Finding, str]]:
    """Every inline ignore the engines honoured, as (the finding it hid, the reason)."""
    out: List[tuple[Finding, str]] = []
    for e in inline_ignore.load(raw_dir / SUPPRESSIONS_FILE):
        if e["kind"] != "honoured":
            continue
        tool = str(e.get("engine") or "prufgate")
        sev = e.get("severity") if e.get("severity") in SEVERITY_RANK else "P2"
        out.append(
            (
                Finding(
                    tool=tool,
                    rule_id=_RULE_PREFIX.get(tool, "") + str(e.get("rule") or "unknown"),
                    severity=sev,
                    message=str(e.get("message") or e.get("rule") or "suppressed finding"),
                    file_path=str(e.get("file") or "unknown"),
                    line=int(e.get("line") or 1),
                ),
                # The reason comes from the scanned repository: one line, no Markdown code breaks.
                str(e.get("reason") or "").replace("`", "'").replace("|", "/")[:200],
            )
        )
    return out


SEVERITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate identical findings reported across overlapping scanners while preserving highest severity."""
    dedup_map: Dict[tuple, Finding] = {}
    for f in findings:
        norm_file = re.sub(r"^(?:/workspace/|\./|/)+", "", f.file_path or "workspace")
        norm_rule = f.rule_id.strip().lower()
        if norm_rule.upper().startswith(("CVE-", "GHSA-")):
            key: tuple = ("vuln_id", norm_rule.upper())
        elif f.tool == "gitleaks" or "secret" in norm_rule:
            key = ("secret", norm_file, max(1, f.line))
        elif "action" in norm_rule and ("auth" in norm_rule or "guard" in norm_rule):
            key = ("action_guard", norm_file, max(1, f.line))
        else:
            key = (norm_file, max(1, f.line), norm_rule)

        if key not in dedup_map:
            dedup_map[key] = f
        else:
            existing = dedup_map[key]
            if existing.file_path in ("workspace", "unknown") and f.file_path not in ("workspace", "unknown"):
                existing.file_path = f.file_path
            if SEVERITY_RANK.get(f.severity, 9) < SEVERITY_RANK.get(existing.severity, 9):
                existing.severity = f.severity
            existing.anchored = existing.anchored or f.anchored or (f.tool in diff_scope.DIFF_ANCHORED_TOOLS)
            existing.spans = list(
                dict.fromkeys((existing.spans or [(existing.line, existing.line)]) + (f.spans or [(f.line, f.line)]))
            )
            if f.tool != existing.tool and f.tool not in existing.details:
                suffix = f"Also detected by: {f.tool}"
                existing.details = f"{existing.details} | {suffix}".strip(" |")
    return list(dedup_map.values())


BASELINE_FILES = (".prufgate/baseline.yaml", ".prufgate/baseline.yml", ".prufgate/baseline.json")
# Written by runners/run_fast.sh in a changed-files run: the base ref it diffed against.
BASE_REF_FILE = "base_ref"


def read_baseline(workspace_dir: Path, ref: Optional[str] = None) -> Optional[tuple]:
    """(path, text) of the first baseline file, or None. With `ref` it is read as
    it is at the merge base with that ref, never from the working tree, so a
    change cannot baseline its own findings. Raises GitDiffError when git cannot
    read the base: the gate then fails closed."""
    if ref is None:
        for rel in BASELINE_FILES:
            p = workspace_dir / rel
            if p.is_file():
                try:
                    return rel, p.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    return rel, ""
        return None
    commit = _diff_base(ref, workspace_dir)
    prefix = repo_prefix(workspace_dir)
    for rel in BASELINE_FILES:
        text = git_blob(commit, prefix + rel, workspace_dir)
        if text is not None:
            return rel, text
    return None


def filter_confidence(findings: List[Finding], enable_low_confidence: bool) -> List[Finding]:
    """Drop findings of low-confidence rules unless the config turns them on."""
    return visible(findings, enable_low_confidence)


def baseline_keys(baseline: Optional[tuple]) -> set:
    """The (file, rule) pairs a baseline from `read_baseline` ignores ("*" for any)."""
    if baseline is None:
        return set()
    try:
        rel, raw_text = baseline
        if rel.endswith((".yaml", ".yml")):
            import yaml

            data = yaml.safe_load(raw_text) or {}
        else:
            data = json.loads(raw_text)

        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = (
                data.get("ignore")
                or data.get("ignored")
                or data.get("baseline")
                or []
            )
        else:
            return set()

        ignored_keys = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw_file = entry.get("file") if "file" in entry else entry.get("file_path")
            raw_rule = entry.get("rule_id") if "rule_id" in entry else entry.get("rule")
            if raw_file is None and raw_rule is None:
                continue
            e_file = re.sub(r"^(?:/workspace/|\./|/)+", "", str(raw_file).strip()) if raw_file is not None else None
            e_rule = str(raw_rule).strip().lower() if raw_rule is not None else None
            if e_file and e_rule:
                ignored_keys.add((e_file, e_rule))
            elif e_rule and raw_file == "*":
                ignored_keys.add(("*", e_rule))
            elif e_file and raw_rule == "*":
                ignored_keys.add((e_file, "*"))
        return ignored_keys
    except Exception:
        return set()


def filter_baseline_findings(findings: List[Finding], workspace_dir: Path, ref: Optional[str] = None) -> List[Finding]:
    """Filter out findings matching entries in .prufgate/baseline.yaml or .prufgate/baseline.json if present
    (at the base ref when one is given)."""
    ignored_keys = baseline_keys(read_baseline(workspace_dir, ref))
    if not ignored_keys:
        return findings
    filtered = []
    for f in findings:
        norm_file = re.sub(r"^(?:/workspace/|\./|/)+", "", f.file_path or "workspace")
        norm_rule = f.rule_id.lower()
        if (norm_file, norm_rule) in ignored_keys or ("*", norm_rule) in ignored_keys or (norm_file, "*") in ignored_keys:
            continue
        filtered.append(f)
    return filtered


# Raw output each runner step writes. An executed step whose output is missing
# or unreadable did not finish: that is an error, never a clean pass.
ENGINE_OUTPUTS = {
    "anti-fabrication": "anti_fabrication.json",
    "test-integrity": "test_integrity.json",
    "diff-guard": "diff_guard.json",
    "contract-guard": "contract_guard.json",
    "bola-matrix": "bola_matrix.json",
    "pr-reviewer": "pr_review.json",
    "gitleaks": "gitleaks.json",
    "gitleaks-worktree": "gitleaks_worktree.json",
    "ast-grep": "ast_grep.json",
    "zizmor": "zizmor.json",
}
# PrufGate's own engines exit 0 (clean), 1 (findings) or 2 (error).
CORE_ENGINES = {"anti-fabrication", "test-integrity", "diff-guard", "contract-guard", "bola-matrix", "pr-reviewer"}


def engine_errors(raw_dir: Path, manifest: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    """Return {tool: reason} for every step that crashed or left no readable output."""
    errors: Dict[str, str] = {}
    if not manifest:
        return {"prufgate": "no execution manifest: no engine is known to have run"}
    for tool, info in manifest.items():
        status = str(info.get("status", "")).lower()
        if status == "error":
            errors[tool] = str(info.get("detail") or "failed")
            continue
        if status != "executed":
            continue
        code = int(info.get("exit_code", 0) or 0)
        if tool in CORE_ENGINES and code >= 2:
            errors[tool] = f"exited {code}"
            continue
        out = ENGINE_OUTPUTS.get(tool)
        if out is None:
            continue
        path = raw_dir / out
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            errors[tool] = f"exited {code} and wrote no {out}"
        except (OSError, ValueError):
            errors[tool] = f"exited {code} and wrote an unreadable {out}"
    # Every core engine must report, even if only as skipped with a reason: a
    # gate killed half way, or a lost manifest line, is not a clean run.
    for tool in sorted(CORE_ENGINES - set(manifest)):
        errors[tool] = "did not run (no entry in the execution manifest)"
    for tool, out in ENGINE_OUTPUTS.items():
        path = raw_dir / out
        if tool not in errors and path.exists():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                errors[tool] = f"{out} is not valid JSON"
    return errors


def load_execution_manifest(raw_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Read execution_manifest.jsonl recorded by runners to show complete engine status."""
    manifest: Dict[str, Dict[str, Any]] = {}
    manifest_file = raw_dir / "execution_manifest.jsonl"
    if not manifest_file.is_file():
        return manifest
    try:
        for line in manifest_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            tool = obj.get("tool")
            if tool:
                detail = obj.get("detail") if obj.get("detail") is not None else obj.get("note", "")
                exit_code = int(obj.get("exit_code", 0) or 0)
                duration_s = float(obj.get("duration_seconds", 0.0) or 0.0)
                status = obj.get("status", "executed")
                manifest[tool] = {
                    "status": status,
                    "detail": str(detail or "").strip(),
                    "exit_code": exit_code,
                    "duration_seconds": duration_s,
                }
    except Exception:
        pass
    return manifest


def _normalize_sarif_uri(file_path: str, workspace_dir: Optional[Path] = None) -> str:
    """Normalize artifact URI for strict GitHub Code Scanning SARIF 2.1.0 compatibility."""
    raw = (file_path or "").strip()
    if not raw or raw in ("workspace", "target", "unknown"):
        return "PRUFGATE_AUDIT_TARGET"
    if raw.startswith(("http://", "https://")):
        return "PRUFGATE_DYNAMIC_TARGET"
    if workspace_dir:
        ws_prefix = str(workspace_dir.resolve()) + "/"
        if raw.startswith(ws_prefix):
            raw = raw[len(ws_prefix) :]
    raw = re.sub(r"^(?:/workspace/|\./|/)+", "", raw)
    return raw or "PRUFGATE_AUDIT_TARGET"


SARIF_SECURITY_SEVERITY = {
    "P0": "9.5",
    "P1": "7.5",
    "P2": "5.0",
    "P3": "2.0",
}


def generate_sarif(
    findings: List[Finding],
    output_path: Path,
    workspace_dir: Optional[Path] = None,
    suppressed: Optional[List[tuple[Finding, str]]] = None,
    ai_dismissed: Optional[List[tuple[Finding, str]]] = None,
) -> Dict[str, Any]:
    """Honoured inline ignores are written as results carrying an in-source
    `suppressions` entry, which code scanning shows as dismissed with the reason;
    AI-dismissed findings carry an `external` one. Returns the SARIF document,
    which the GitLab and JUnit reports are built from."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results = []

    entries = (
        [(f, None, None) for f in findings]
        + [(f, reason, "inSource") for f, reason in (suppressed or [])]
        + [(f, f"AI-dismissed: {reason}", "external") for f, reason in (ai_dismissed or [])]
    )
    for f, reason, kind in entries:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message[:100]},
                "defaultConfiguration": {
                    "level": "error" if f.severity in ("P0", "P1") else "warning",
                    "rank": SARIF_RANK[f.confidence],
                },
                "properties": {
                    "tags": ["security", "quality", f.tool],
                    "security-severity": SARIF_SECURITY_SEVERITY.get(f.severity, "5.0"),
                    "precision": f.confidence,
                },
            }

        level = "error" if f.severity in ("P0", "P1") else "warning"
        if f.severity == "P3":
            level = "note"

        norm_uri = _normalize_sarif_uri(f.file_path, workspace_dir)

        result: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": norm_uri
                        },
                        "region": {"startLine": max(1, int(f.line or 1))},
                    }
                }
            ],
            "properties": {
                "tool": f.tool,
                "severity": f.severity,
                "confidence": f.confidence,
                "rawTarget": f.file_path,
                "details": f.details,
            },
        }
        if reason is not None:
            result["suppressions"] = [{"kind": kind, "justification": reason}]
        results.append(result)

    add_partial_fingerprints(results, workspace_dir)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": os.environ.get("PRUFGATE_PRODUCT_NAME", "PrufGate"),
                        "semanticVersion": __version__,
                        "informationUri": os.environ.get("PRUFGATE_INFO_URI", PROJECT_URL),
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    safe_write_text(output_path, json.dumps(sarif, indent=2))
    return sarif


def generate_markdown(
    findings: List[Finding],
    template_path: Optional[Path],
    output_path: Path,
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    errors: Optional[Dict[str, str]] = None,
    suppressed: Optional[List[tuple[Finding, str]]] = None,
    ai_dismissed: Optional[List[tuple[Finding, str]]] = None,
) -> None:
    workspace, commit = get_git_info()
    suppressed = suppressed or []
    ai_dismissed = ai_dismissed or []
    errors = errors or {}
    p0 = [f for f in findings if f.severity == "P0"]
    p1 = [f for f in findings if f.severity == "P1"]
    p2 = [f for f in findings if f.severity == "P2"]
    p3 = [f for f in findings if f.severity == "P3"]

    if errors:
        verdict_badge = "⚠️ **ERROR (an engine did not finish)**"
        verdict_text = "ERROR — " + "; ".join(f"{t}: {r}" for t, r in sorted(errors.items())) + ". The scan is incomplete, so it cannot pass."
    elif p0 or p1:
        verdict_badge = "🔴 **FAIL (Blockers Detected)**"
        verdict_text = "FAILED — Resolve all P0 and P1 issues before merging."
    else:
        verdict_badge = "🟢 **PASS (Clean)**"
        verdict_text = "PASSED — All gates and invariant checks verified cleanly."

    manifest = manifest or {}
    all_tools = sorted(set(f.tool for f in findings) | set(manifest.keys()) | set(errors))
    scanner_rows = []
    if not all_tools:
        scanner_rows.append("| All Active Engines | 0 | 0 | 0 | 0 | 🟢 PASS |")
    else:
        for t in all_tools:
            tf = [f for f in findings if f.tool == t]
            tp0 = sum(1 for f in tf if f.severity == "P0")
            tp1 = sum(1 for f in tf if f.severity == "P1")
            tp2 = sum(1 for f in tf if f.severity == "P2")
            tp3 = sum(1 for f in tf if f.severity == "P3")
            m_info = manifest.get(t, {})
            m_status = str(m_info.get("status", "executed")).lower()
            m_exit = int(m_info.get("exit_code", 0) or 0)
            m_detail = str(m_info.get("detail") or "").strip()
            m_dur = float(m_info.get("duration_seconds", 0.0) or 0.0)
            dur_str = f" ({int(m_dur)}s)" if m_dur > 0 else ""
            detail_with_dur = f"{m_detail}{dur_str}" if m_detail else (f"{int(m_dur)}s" if m_dur > 0 else "")
            if t in errors:
                status = f"⚠️ ERROR ({errors[t]})"
            elif tp0 > 0 or tp1 > 0:
                status = "🔴 FAIL"
            elif tp2 > 0:
                status = "🟡 WARN"
            elif m_status.startswith("skipped") and len(tf) == 0:
                status = f"⚪ SKIPPED ({detail_with_dur or 'not applicable'})"
            elif (m_status in ("error", "failed") or m_exit >= 2) and len(tf) == 0:
                if m_exit >= 2 and detail_with_dur:
                    reason = f"exit {m_exit}: {detail_with_dur}"
                else:
                    reason = detail_with_dur or f"exit code {m_exit}"
                status = f"⚠️ ERROR ({reason})"
            else:
                status = f"🟢 PASS ({detail_with_dur})" if detail_with_dur else "🟢 PASS"
            scanner_rows.append(f"| `{t}` | {tp0} | {tp1} | {tp2} | {tp3} | {status} |")

    critical_findings = p0 + p1
    if not critical_findings:
        crit_sec = "✨ **Zero Critical (P0) or High (P1) issues found.** Codebase conforms to all PrufGate invariants."
    else:
        rows = []
        for f in critical_findings:
            rows.append(
                f"### [{f.severity}] `{f.rule_id}` in `{f.file_path}:{f.line}`\n"
                f"- **Engine:** `{f.tool}`\n"
                f"- **Confidence:** {f.confidence}\n"
                f"- **Finding:** {f.message}\n"
                + (f"- **Details:** `{f.details}`\n" if f.details else "")
                + "- **Action:** Immediate remediation required.\n"
            )
        crit_sec = "\n".join(rows)

    advisory_findings = p2 + p3
    if not advisory_findings:
        adv_sec = "✨ **No medium or low advisory notices.**"
    else:
        rows = []
        for f in advisory_findings[:30]:
            rows.append(
                f"- **[{f.severity}, {f.confidence} confidence]** `{f.file_path}:{f.line}` — {f.message} (`{f.rule_id}` via `{f.tool}`)"
            )
        if len(advisory_findings) > 30:
            rows.append(f"\n_... and {len(advisory_findings) - 30} more advisories (see reports/prufgate.sarif)_")
        adv_sec = "\n".join(rows)

    if not suppressed:
        ign_sec = "No inline `prufgate-ignore` comments suppressed a finding."
    else:
        rows = [
            f"- `{f.file_path}:{f.line}` `{f.rule_id}` [{f.severity}, {f.confidence} confidence] via `{f.tool}` — {reason}"
            for f, reason in suppressed[:50]
        ]
        if len(suppressed) > 50:
            rows.append(f"\n_... and {len(suppressed) - 50} more (see reports/prufgate.sarif)_")
        ign_sec = "\n".join(rows)

    if not ai_dismissed:
        ai_sec = "AI adjudication dismissed no finding."
    else:
        rows = [
            f"- `{f.file_path}:{f.line}` `{f.rule_id}` [{f.severity}, {f.confidence} confidence] via `{f.tool}` — AI: {reason}"
            for f, reason in ai_dismissed[:50]
        ]
        if len(ai_dismissed) > 50:
            rows.append(f"\n_... and {len(ai_dismissed) - 50} more (see reports/prufgate.sarif)_")
        ai_sec = "\n".join(rows)

    default_template = """# PrufGate Verification Report

**Status:** {VERDICT_BADGE}<br>
**Date:** {GENERATED_AT}<br>
**Target Workspace:** `{WORKSPACE_NAME}`<br>
**Commit/Ref:** `{GIT_COMMIT}`

---

## 1. Executive Summary

PrufGate audited `{WORKSPACE_NAME}` across its 6 core verification engines (Production Anti-Fabrication, Test Integrity & Anti-Reward-Hacking, Diff Tampering Guard, Contract & Dependency Guard, Multi-Tenant BOLA/IDOR, and Hybrid Semantic Diff Review).

| Severity | Count | Blockers |
| :--- | :--- | :--- |
| **P0 (Critical)** | {COUNT_P0} | {BLOCKER_P0} |
| **P1 (High)** | {COUNT_P1} | {BLOCKER_P1} |
| **P2 (Medium)** | {COUNT_P2} | Non-blocking |
| **P3 (Low / Info)** | {COUNT_P3} | Non-blocking |
| **Inline ignores** | {COUNT_IGNORED} | Suppressed with a reason (section 5) |
| **AI-dismissed** | {COUNT_AI_DISMISSED} | Judged not real by AI adjudication (section 6) |

---

## 2. Verification Engine Matrix

| Engine / Scanner | P0 | P1 | P2 | P3 | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
{SCANNER_ROWS}

---

## 3. High & Critical Findings (P0 & P1)

{CRITICAL_FINDINGS_SECTION}

---

## 4. Medium & Low Advisory Notices (P2 & P3)

{ADVISORY_FINDINGS_SECTION}

---

## 5. Inline Ignores

{IGNORED_SECTION}

---

## 6. AI-dismissed

Findings an AI provider judged not real (`ai_adjudicate`). They do not block; high-confidence findings are never sent.

{AI_DISMISSED_SECTION}

---

## 7. Audit Sign-off

- **SARIF Specification:** SARIF 2.1.0 emitted to `reports/prufgate.sarif`
- **Verdict:** {VERDICT_TEXT}
"""

    template = default_template
    if template_path and template_path.is_file():
        template = template_path.read_text(encoding="utf-8")

    content = template.format(
        VERDICT_BADGE=verdict_badge,
        GENERATED_AT=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        WORKSPACE_NAME=workspace,
        GIT_COMMIT=commit,
        COUNT_P0=len(p0),
        COUNT_P1=len(p1),
        COUNT_P2=len(p2),
        COUNT_P3=len(p3),
        BLOCKER_P0="🔴 Immediate Blocker" if p0 else "None",
        BLOCKER_P1="🔴 Merge Blocker" if p1 else "None",
        SCANNER_ROWS="\n".join(scanner_rows) if scanner_rows else "| `All Engines` | 0 | 0 | 0 | 0 | 🟢 PASS |",
        CRITICAL_FINDINGS_SECTION=crit_sec,
        ADVISORY_FINDINGS_SECTION=adv_sec,
        COUNT_IGNORED=len(suppressed),
        IGNORED_SECTION=ign_sec,
        COUNT_AI_DISMISSED=len(ai_dismissed),
        AI_DISMISSED_SECTION=ai_sec,
        VERDICT_TEXT=verdict_text,
    )

    safe_write_text(output_path, content)


def print_ansi_table(
    findings: List[Finding],
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    errors: Optional[Dict[str, str]] = None,
) -> None:
    errors = errors or {}
    p0 = sum(1 for f in findings if f.severity == "P0")
    p1 = sum(1 for f in findings if f.severity == "P1")
    p2 = sum(1 for f in findings if f.severity == "P2")
    p3 = sum(1 for f in findings if f.severity == "P3")

    manifest = manifest or {}
    executed_tools = {t for t, info in manifest.items() if info.get("status") == "executed"}
    tools = sorted(set(f.tool for f in findings) | executed_tools | set(errors))

    print()
    print(f"{BOLD}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║                           PRUFGATE AUDIT REPORT                                 ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════╦══════╦══════╦══════╦══════╦═══════════════════╣{RESET}")
    print(f"{BOLD}║ Engine / Scanner             ║  P0  ║  P1  ║  P2  ║  P3  ║ Status            ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════╬══════╬══════╬══════╬══════╬═══════════════════╣{RESET}")

    if not tools:
        print(f"║ {GREEN}All Engines (Clean){RESET}          ║   0  ║   0  ║   0  ║   0  ║ {GREEN}✔ ALL PASSED{RESET}      ║")
    else:
        for t in tools:
            tf = [f for f in findings if f.tool == t]
            tp0 = sum(1 for f in tf if f.severity == "P0")
            tp1 = sum(1 for f in tf if f.severity == "P1")
            tp2 = sum(1 for f in tf if f.severity == "P2")
            tp3 = sum(1 for f in tf if f.severity == "P3")
            status = f"{RED}✘ ERROR{RESET}   " if t in errors else f"{RED}✘ FAILED{RESET}" if (tp0 > 0 or tp1 > 0) else (f"{YELLOW}⚠ WARN{RESET}  " if tp2 > 0 else f"{GREEN}✔ PASS{RESET}  ")
            print(f"║ {t[:28]:<28} ║ {tp0:>4} ║ {tp1:>4} ║ {tp2:>4} ║ {tp3:>4} ║ {status:<17} ║")

    print(f"{BOLD}╠══════════════════════════════╩══════╩══════╩══════╩══════╩═══════════════════╣{RESET}")
    print(f"║ {BOLD}TOTALS:{RESET} P0={RED}{p0}{RESET} | P1={RED}{p1}{RESET} | P2={YELLOW}{p2}{RESET} | P3={BLUE}{p3}{RESET}                                           ║")
    if errors:
        print(f"║ {RED}{BOLD}VERDICT: ERROR (an engine did not finish; the scan is incomplete){RESET}          ║")
        for t, reason in sorted(errors.items()):
            print(f"║   {t}: {reason}")
    elif p0 > 0 or p1 > 0:
        print(f"║ {RED}{BOLD}VERDICT: FAILED (P0/P1 Blockers Detected){RESET}                                  ║")
    else:
        print(f"║ {GREEN}{BOLD}VERDICT: PASSED (Zero Critical Blockers){RESET}                                    ║")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print()


def main() -> None:
    workspace_env = os.environ.get("WORKSPACE")
    if workspace_env:
        workspace_dir = Path(workspace_env)
    elif Path("/workspace").exists() and os.access("/workspace", os.W_OK):
        workspace_dir = Path("/workspace")
    else:
        workspace_dir = Path.cwd()

    reports_dir = Path(os.environ.get("PRUFGATE_REPORTS_DIR", str(workspace_dir / "reports")))
    raw_dir = reports_dir / "raw"

    if reports_dir.is_symlink() or raw_dir.is_symlink():
        print(f"prufgate: {reports_dir} or its raw/ folder is a symlink; refusing to write reports through it.", file=sys.stderr)
        sys.exit(2)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # A config that does not load is an error (the run cannot pass), reported like a crashed engine.
    ref_file = raw_dir / BASE_REF_FILE
    base_ref = (ref_file.read_text(encoding="utf-8").strip() if ref_file.is_file() else "") or None
    if ref_file.is_file() and base_ref is None:
        # A changed scan of the working-tree diff: it compares with HEAD, so an
        # uncommitted baseline or config edit must not apply to it either.
        base_ref = "HEAD"
    config_error = ""
    try:
        cfg = PrufGateConfig.load(workspace_dir, ref=base_ref)
    except ConfigError as exc:
        config_error, cfg = str(exc), PrufGateConfig()
    enable_low = cfg.enable_low_confidence

    findings = parse_raw_results(raw_dir)
    try:
        ranges = diff_scope.load(raw_dir / CHANGED_LINES_FILE)
    except (OSError, ValueError, TypeError) as e:
        print(f"prufgate: cannot read {CHANGED_LINES_FILE}: {e}", file=sys.stderr)
        sys.exit(2)
    findings = scope_to_change(findings, ranges, workspace_dir)
    try:
        head_baseline = read_baseline(workspace_dir) if base_ref else None
        base_baseline = read_baseline(workspace_dir, base_ref) if base_ref else None
        if head_baseline != base_baseline:
            findings.append(
                Finding(
                    tool="prufgate-gate",
                    rule_id="prufgate-config-not-applied",
                    severity="P2",
                    message="This change edits the PrufGate baseline. This run applied the baseline at the base ref "
                    "and ignored the branch's: baseline changes take effect after merge.",
                    file_path=(head_baseline or base_baseline)[0],
                )
            )
        # Like a configuration exemption: an entry the branch adds silences a
        # finding once merged, so it needs a maintainer's review.
        for e_file, e_rule in sorted(baseline_keys(head_baseline) - baseline_keys(base_baseline)):
            findings.append(
                Finding(
                    tool="prufgate-gate",
                    rule_id="prufgate-config-self-exemption",
                    severity="P1",
                    message=f"This change adds `{e_rule}` in `{e_file}` to the PrufGate baseline. "
                    "A change that silences PrufGate needs a maintainer's review.",
                    file_path=head_baseline[0],
                )
            )
        findings = filter_confidence(findings, enable_low)
        findings = filter_baseline_findings(findings, workspace_dir, base_ref)
    except GitDiffError as e:
        print(f"prufgate: cannot read the baseline at base ref {base_ref!r}: {e}", file=sys.stderr)
        sys.exit(2)
    manifest = load_execution_manifest(raw_dir)
    errors = engine_errors(raw_dir, manifest)
    if config_error:
        errors["config"] = config_error

    suppressed = load_suppressions(raw_dir)
    if ranges is not None:
        suppressed = [(f, r) for f, r in suppressed if diff_scope.in_scope(ranges, f.tool, f.rule_id, f.file_path, f.spans, workspace_dir)]

    # Only the configuration in effect (at the base ref) turns it on: it can dismiss
    # findings, so no environment variable or flag a change could set may.
    ai_dismissed: List[tuple[Finding, str]] = []
    # The MCP server, the REST API and the agent hooks set PRUFGATE_NO_AI_ADJUDICATE.
    if not config_error and cfg.ai_adjudicate.enabled and not os.environ.get("PRUFGATE_NO_AI_ADJUDICATE"):
        verdicts, note = adjudicate(
            [(f.rule_id, f.file_path, f.line, f.message, f.origin) for f in findings],
            workspace_dir,
            cfg.ai_adjudicate,
            provider=os.environ.get("PRUFGATE_AI_PROVIDER") or "auto",
        )
        print(f"prufgate: {note}", file=sys.stderr)
        ai_dismissed = [(findings[i], reason) for i, reason in verdicts.items()]
        findings = [f for i, f in enumerate(findings) if i not in verdicts]

    sarif = generate_sarif(
        findings, reports_dir / "prufgate.sarif", workspace_dir=workspace_dir, suppressed=suppressed, ai_dismissed=ai_dismissed
    )
    safe_write_text(reports_dir / "gl-code-quality-report.json", gitlab_code_quality(sarif, errors))
    safe_write_text(reports_dir / "prufgate-junit.xml", junit_xml(sarif, errors))
    generate_markdown(
        findings, None, reports_dir / "prufgate-review.md", manifest=manifest, errors=errors, suppressed=suppressed,
        ai_dismissed=ai_dismissed,
    )
    print_ansi_table(findings, manifest=manifest, errors=errors)

    if errors:
        sys.exit(2)
    has_blockers = any(f.severity in ("P0", "P1") for f in findings)
    sys.exit(1 if has_blockers else 0)


if __name__ == "__main__":
    main()
