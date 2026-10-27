#!/usr/bin/env python3
"""PrufGate Unified CLI (`prufgate`).

Subcommands:
  - `prufgate check [path] [--changed] [--base REF] [--format text|json|sarif|gitlab|junit|agent-hook] [--ai-adjudicate]`
  - `prufgate test-audit [path] [--changed] [--format text|json]`
  - `prufgate bola [path] [--url URL] [--token-a ...] [--token-b ...] [--routes-from FILE] [--roles FILE] [--max-routes N] [--static-only] [--base REF]`
  - `prufgate review [--base REF] [--diff-file PATH] [--format markdown|json|sarif|github|reviewdog|gitlab|junit] [--ai]`
  - `prufgate fix [path] [--base REF] [--format patch|github-suggestions] [--apply] [--force]`
  - `prufgate verify --differential [path] [--base REF] [--test-cmd CMD] [--allow-run-tests]` (runs repository tests: opt-in only)
  - `prufgate verify --mutation [path] [--base REF] [--tool NAME] [--max-mutants N] [--allow-run-tests]` (runs repository tests: opt-in only)
  - `prufgate init [path] [--hooks] [--agent NAME ...] [--agents-md] [--bugbot] [--overwrite]`
  - `prufgate shell-guard` (Claude Code PreToolUse hook: payload on stdin, exit 2 blocks)
  - `prufgate hook <agent> <event>` (fail-closed coding-agent hook adapters, docs/AGENT_HOOKS.md)
  - `prufgate transcript FILE [--format text|json|sarif] [--format-in claude|codex|text]` (suspicious commands an agent ran)
  - `prufgate bench [--cases DIR] [--format text|json|markdown] [--rule RULE] [--min-precision X] [--min-recall Y]`
  - `prufgate export-rules [--format semgrep] [--out FILE] [--pack cti]`
  - `prufgate mcp`
  - `prufgate api [--host 127.0.0.1] [--port 8000]`
  - `prufgate fast` / `prufgate full` (shortcuts for `check --changed` / `check`)
  - `prufgate --self-check`

Exit codes: 0 clean, 1 blocking findings (P0/P1), 2 usage, configuration or engine error.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent))

import prufgate.contract_guard as cg_engine  # noqa: E402
from prufgate import PROJECT_URL, __version__, diff_scope, inline_ignore  # noqa: E402
from prufgate.anti_fabrication import detector as af_detector  # noqa: E402
from prufgate.anti_reward_hacking import test_integrity as ti_engine  # noqa: E402
from prufgate.bola import bola_engine  # noqa: E402
from prufgate.config import (  # noqa: E402
    AiAdjudicate,
    ConfigError,
    GitDiffError,
    PrufGateConfig,
    expand_rule_aliases,
    rules_match,
)
from prufgate.diff_guard import tamper_detector as dg_engine  # noqa: E402
from prufgate.hooks.adapters import AGENTS, EVENTS  # noqa: E402
from prufgate.hooks.agent_hooks import AGENT_CHOICES, HookConfigError, init_workspace  # noqa: E402
from prufgate.report_formats import gitlab_code_quality, junit_xml  # noqa: E402
from prufgate.review import reviewer as rev_engine  # noqa: E402
from prufgate.review.adjudicate import adjudicate as ai_adjudicate  # noqa: E402
from prufgate.rules import SARIF_RANK, visible  # noqa: E402
from prufgate.rules import confidence as rule_confidence  # noqa: E402
from prufgate.sarif import add_partial_fingerprints  # noqa: E402


def run_all_self_checks() -> int:
    """Execute built-in fixture verification across all 6 PrufGate core engines."""
    checks = [
        ("anti-fabrication", af_detector.self_check),
        ("test-integrity", ti_engine.run_self_check),
        ("diff-guard", dg_engine.run_self_check),
        ("contract-guard", cg_engine.run_self_check),
        ("bola-engine", bola_engine.run_self_check),
        ("review-engine", rev_engine.run_self_check),
    ]
    failed = 0
    for name, fn in checks:
        rc = fn()
        if rc != 0:
            print(f"[FAIL] {name} self-check exited with {rc}", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print("prufgate self-check: all 6 core engines passed.")
    return 0


def _collect_unified_findings(
    target_path: Path,
    changed_only: bool = False,
    base_ref: str | None = None,
    config_path: str | None = None,
    honoured: list[dict[str, Any]] | None = None,
    ai_dismissed: list[dict[str, Any]] | None = None,
    ai_provider: str | None = None,
) -> list[dict[str, Any]]:
    """Run Engines 1-5 on `target_path` and return normalized finding dicts.

    A reasonless inline ignore is returned as an `ignore-without-reason` finding;
    the ignores the engines honoured are appended to `honoured` when it is given.

    With `ai_dismissed` given, AI adjudication runs when `ai_provider` is set (the
    `--ai-adjudicate` flag) or the configuration in effect turns it on; the findings
    it dismisses move from the result to `ai_dismissed`.

    The engines read git and relative paths from the current directory, so the
    scan runs from the workspace root whatever directory `prufgate` was started in.
    """
    target_path = target_path.resolve()
    workspace = target_path if target_path.is_dir() else target_path.parent
    previous_cwd = Path.cwd()
    os.chdir(workspace)
    try:
        with inline_ignore.recording() as records:
            found = _collect_in_workspace(
                workspace, target_path, changed_only, base_ref, config_path, ai_dismissed, ai_provider,
                records=records, honoured=honoured,
            )
    finally:
        os.chdir(previous_cwd)
    return found


def _is_internal(engine: Any, path: str) -> bool:
    """PrufGate's own engine files, matched by whole path segments so a user's
    tests/test_cli.py is never skipped."""
    fn = getattr(engine, "is_internal_path", None)
    if fn is not None:
        return bool(fn(path))
    # Only PrufGate's own repository has these files; elsewhere nothing is internal.
    if not (Path("prufgate/cli.py").is_file() and Path("prufgate/anti_reward_hacking/test_integrity.py").is_file()):
        return False
    norm = "/" + str(path).replace("\\", "/").lstrip("./")
    return any(("/" + p.strip("/") + "/") in norm + "/" for p in getattr(engine, "INTERNAL_SCANNER_PATHS", ()) if "/" in p.strip("/"))


def _git_ok(*args: str) -> str | None:
    try:
        # Repository hooks and fsmonitor are commands from the repository under review: never run them.
        res = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return res.stdout


class BaseRefError(ConfigError):
    """No usable base ref: a changed-files scan would compare against nothing."""


def _commit(ref: str) -> str | None:
    out = _git_ok("rev-parse", "--verify", "-q", "--end-of-options", f"{ref}^{{commit}}")
    return out.strip() if out else None


def resolve_base_ref(explicit: str | None = None, committed: bool = False) -> str | None:
    """The base ref a changed-files scan diffs against, run from the workspace.

    Order: `explicit`, PRUFGATE_BASE_REF, origin/$GITHUB_BASE_REF; then
    origin/HEAD, and HEAD~1 only when the working tree has no changes, skipping a
    candidate that HEAD is not ahead of (so a clean default branch never
    compares with itself). An untracked file must not hide a branch's commits
    from the scan. Returns None when the working tree has changes and no base
    applies: the working-tree diff is scanned. Raises BaseRefError
    when there is nothing to compare: never an empty diff that reads as a pass.
    `committed` (a comparison of the committed HEAD only) treats the working tree as clean.
    """
    head = _commit("HEAD")
    if head is None:
        raise BaseRefError("not a git repository with at least one commit: --changed has nothing to compare")
    ref = explicit or os.environ.get("PRUFGATE_BASE_REF") or (
        f"origin/{os.environ['GITHUB_BASE_REF']}" if os.environ.get("GITHUB_BASE_REF") else None
    )
    if ref:
        if ref.startswith("-") or _commit(ref) is None:
            raise BaseRefError(f"base ref {ref!r} is not a commit in this repository (shallow clone? fetch it first)")
        return ref
    dirty = not committed and (
        _git_ok("diff", "--quiet", "HEAD") is None or bool(_git_ok("ls-files", "--others", "--exclude-standard"))
    )
    for candidate in ("origin/HEAD",) if dirty else ("origin/HEAD", "HEAD~1"):
        if _commit(candidate) is None:
            continue
        merge_base = _git_ok("merge-base", candidate, "HEAD")
        if merge_base and merge_base.strip() != head:
            return candidate
    if dirty:
        return None
    raise BaseRefError(
        "the working tree is clean and no base ref is usable (set --base or PRUFGATE_BASE_REF; "
        "a shallow CI clone needs fetch-depth: 0)"
    )


def _collect_in_workspace(
    workspace: Path,
    target_path: Path,
    changed_only: bool,
    base_ref: str | None,
    config_path: str | None,
    ai_dismissed: list[dict[str, Any]] | None = None,
    ai_provider: str | None = None,
    records: list[dict[str, Any]] | None = None,
    honoured: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    # A changed scan judges only the lines the change touched (prufgate/diff_scope.py).
    ranges: diff_scope.Ranges | None = None
    if changed_only:
        base_ref = resolve_base_ref(base_ref)
        ranges = diff_scope.changed_lines(base_ref, workspace)
    # With a base ref every engine applies the configuration at the base: the
    # branch's own edits take effect after merge. Engine 3 compares the two.
    head_cfg = PrufGateConfig.load(workspace, config_path)
    # A changed scan with no base compares the working tree with HEAD, so an
    # uncommitted configuration edit does not apply to it either.
    cfg_ref = base_ref or ("HEAD" if changed_only else None)
    cfg = PrufGateConfig.load(workspace, config_path, ref=cfg_ref) if cfg_ref else head_cfg

    unified: list[dict[str, Any]] = []

    # 1. Engine 1: Anti-Fabrication Detector
    af_settings = cfg.to_detector_settings()
    af_detector.apply_settings(af_settings)
    if changed_only:
        rel_targets = [f for f in af_detector.changed_files(base_ref) if Path(f).exists()]
        af_files = af_detector.collect(rel_targets) if rel_targets else []
    else:
        af_files = af_detector.collect([os.path.relpath(target_path, workspace)])

    for fpath in af_files:
        rel_f = os.path.normpath(str(fpath)).replace("\\", "/")
        if cfg.is_excluded(rel_f):
            continue
        for f in af_detector.scan_file(Path(rel_f)):
            if cfg.is_exempt(rel_f, f.rule):
                continue
            unified.append(
                {
                    "engine": "anti-fabrication",
                    "rule": f.rule,
                    "severity": "P0",
                    "file": rel_f,
                    "line": f.line,
                    "end_line": f.end_line,
                    "message": f"Fabrication pattern '{f.rule}': {f.text}",
                    "snippet": f.text,
                }
            )

    # 2. Engine 2: Anti-Reward-Hacking & Test Integrity
    if changed_only:
        diff_text = ti_engine._get_git_diff(base_ref, cwd=workspace)
        if diff_text:
            for df in ti_engine.scan_diff_for_reward_hacking(diff_text, repo_root=workspace, config=cfg):
                if not _is_internal(ti_engine, df.path):
                    unified.append(
                        {
                            "engine": "test-integrity",
                            "rule": df.rule,
                            "severity": df.severity,
                            "file": df.path,
                            "line": df.line,
                            "end_line": df.end_line,
                            "message": df.message,
                            "snippet": df.text,
                        }
                    )
        test_files = [
            p
            for p in ti_engine._changed_files(base_ref, cwd=workspace)
            if p.is_file() and ti_engine.is_test_file(p)
        ]
    else:
        if target_path.is_file():
            test_files = [target_path] if ti_engine.is_test_file(target_path) else []
        else:
            test_files = ti_engine._iter_test_files([target_path])

    for tf in test_files:
        try:
            rel_tf = str(tf.resolve().relative_to(workspace)).replace("\\", "/")
        except ValueError:
            rel_tf = str(tf).replace("\\", "/")
        if _is_internal(ti_engine, rel_tf):
            continue
        try:
            content = tf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for tf_finding in ti_engine.scan_test_file(tf, content, cfg):
            unified.append(
                {
                    "engine": "test-integrity",
                    "rule": tf_finding.rule,
                    "severity": tf_finding.severity,
                    "file": rel_tf,
                    "line": tf_finding.line,
                    "end_line": tf_finding.end_line,
                    "message": tf_finding.message,
                    "snippet": tf_finding.text,
                }
            )

    # 3. Engine 3: Diff-Scoped Tampering Guard (when git diff is available)
    diff_for_dg = dg_engine._get_git_diff(base_ref, cwd=workspace)
    dg_findings = dg_engine.scan_diff_for_tampering(diff_for_dg, config=cfg) if diff_for_dg else []
    # Linter configs and the PrufGate configuration, compared by value with the base.
    dg_findings = dg_engine.with_linter_drift(dg_findings, diff_for_dg, workspace, base_ref, cfg)
    dg_findings = dg_engine.with_config_drift(dg_findings, head_cfg, workspace, cfg_ref, config_path)
    if dg_findings:
        for dgf in dg_findings:
            if not _is_internal(dg_engine, dgf.path):
                unified.append(
                    {
                        "engine": "diff-guard",
                        "rule": dgf.rule,
                        "severity": dgf.severity,
                        "file": dgf.path,
                        "line": dgf.line,
                        "message": dgf.message,
                        "snippet": dgf.text,
                    }
                )

    # 4. Engine 4: Ghost Dependency, API Contract & Env Drift Guard
    if target_path.is_dir():
        for cgf in cg_engine.scan_contract_guard(workspace, changed_only=changed_only, config=cfg, base=base_ref or None):
            unified.append(
                {
                    "engine": "contract-guard",
                    "rule": cgf.rule,
                    "severity": cgf.severity,
                    "file": cgf.path,
                    "line": cgf.line,
                    "message": cgf.message,
                    "snippet": cgf.text,
                }
            )

    # 5. Engine 5: Static Multi-Tenant BOLA Verification
    if target_path.is_dir():
        with redirect_stdout(io.StringIO()):
            bola_findings = bola_engine.run_static_matrix_audit(
                workspace, config=cfg, changed_files=set(ranges) if ranges is not None else None
            )
        for bf in bola_findings:
            unified.append(
                {
                    "engine": "bola",
                    "rule": bf.rule_id,
                    "severity": bf.severity,
                    "file": bf.endpoint_or_file,
                    "line": bf.line,
                    "end_line": bf.end_line,
                    "message": bf.message,
                    "snippet": bf.details,
                }
            )

    if ranges is not None:
        unified = [
            f for f in unified
            if diff_scope.in_scope(
                ranges, str(f["engine"]), str(f["rule"]), str(f["file"]),
                [(int(f["line"]), int(f.get("end_line") or f["line"]))], workspace,
            )
        ]

    # Deduplicate by (file, line, rule)
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in unified:
        # Aliases of one rule (old and new IDs) are one finding.
        key = (str(item["file"]), int(item["line"]), min(expand_rule_aliases(str(item["rule"]))))
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    # Low-confidence rules are off unless the config turns them on: not reported, not blocking.
    for item in deduped:
        item["confidence"] = rule_confidence(str(item["rule"]))
    deduped = visible(deduped, cfg.enable_low_confidence)

    # known_debt ceilings: a breach is a blocker; findings within a ceiling are tracked debt.
    violations, advisories = cfg.check_debt_ratchet(deduped)
    for adv in advisories:
        print(f"notice: {adv}", file=sys.stderr)
    if violations:
        for v in violations:
            deduped.append(
                {
                    "engine": "config",
                    "rule": "debt-ceiling-breached",
                    "severity": "P0",
                    "file": str(cfg.source_path.relative_to(workspace)) if cfg.source_path else ".prufgate/config.yaml",
                    "line": 1,
                    "message": v,
                    "snippet": "",
                    "confidence": rule_confidence("debt-ceiling-breached"),
                }
            )
    elif cfg.known_debt_ceilings and not changed_only:
        # A loosened configuration is never debt: the configuration under review sets the ceilings.
        # In a changed scan, only changed lines were counted, so a repo-wide numeric ceiling
        # cannot excuse brand-new findings on changed lines.
        deduped = [
            f
            for f in deduped
            if f["rule"] == "prufgate-config-self-exemption"
            or not any(rules_match(str(f["rule"]), r) for r in cfg.known_debt_ceilings)
        ]

    for e in records or ():
        if ranges is not None and not diff_scope.in_scope(
            ranges, str(e.get("engine") or ""), str(e.get("rule") or ""), str(e.get("file") or ""),
            [(int(e.get("line") or 1), int(e.get("line") or 1))], workspace,
        ):
            continue
        if e["kind"] == "missing-reason":
            deduped.append(
                {
                    "engine": e["engine"],
                    "rule": inline_ignore.MISSING_REASON_RULE,
                    "severity": "P2",
                    "file": e["file"],
                    "line": e["line"],
                    "message": f"{inline_ignore.MISSING_REASON_MESSAGE} It names `{e['rule']}`, which is still reported.",
                    "snippet": "",
                    "confidence": rule_confidence(inline_ignore.MISSING_REASON_RULE),
                }
            )
        elif honoured is not None:
            honoured.append(e)
    # After the debt ratchet, so a dismissal never lowers a known_debt count.
    # AI adjudication only loosens the gate, so only the configuration in effect (read at
    # the base ref) turns it on; `--ai-adjudicate` alone is a request, never enough.
    adj = _trusted_adjudication(workspace, config_path, cfg, cfg_ref) if ai_dismissed is not None else cfg.ai_adjudicate
    if ai_dismissed is not None and ai_provider is not None and not adj.enabled:
        print(
            "notice: --ai-adjudicate ignored: the configuration in effect does not enable `ai_adjudicate`; "
            "running without AI.",
            file=sys.stderr,
        )
    elif ai_dismissed is not None and adj.enabled:
        provider = ai_provider or os.environ.get("PRUFGATE_AI_PROVIDER") or "auto"
        verdicts, note = ai_adjudicate(
            [(str(f["rule"]), str(f["file"]), int(f["line"]), str(f["message"]), str(f.get("engine") or ""))
             for f in deduped],
            workspace,
            adj,
            provider=provider,
        )
        print(f"notice: {note}", file=sys.stderr)
        for i, reason in verdicts.items():
            ai_dismissed.append({**deduped[i], "kind": "ai-dismissed", "reason": reason})
        deduped = [f for i, f in enumerate(deduped) if i not in verdicts]
    return deduped


def _trusted_adjudication(workspace: Path, config_path: str | None, cfg: PrufGateConfig, cfg_ref: str | None) -> AiAdjudicate:
    """The `ai_adjudicate` settings a run may use. A full scan with no base applies the
    working tree's configuration, but adjudication only loosens the gate: in a git
    repository it must also be on where a changed scan would read it (the base, else HEAD)."""
    if cfg_ref is not None or _commit("HEAD") is None or not cfg.ai_adjudicate.enabled:
        return cfg.ai_adjudicate
    try:
        ref = resolve_base_ref() or "HEAD"
    except BaseRefError:
        ref = "HEAD"
    try:
        trusted = PrufGateConfig.load(workspace, config_path, ref=ref).ai_adjudicate
    except ConfigError:
        return AiAdjudicate()
    return trusted if trusted.enabled else AiAdjudicate()


def _format_sarif_findings(
    findings: list[dict[str, Any]],
    root: Path | None = None,
    honoured: list[dict[str, Any]] | None = None,
) -> str:
    return json.dumps(_sarif_findings_doc(findings, root, honoured), indent=2)


def _sarif_findings_doc(
    findings: list[dict[str, Any]],
    root: Path | None = None,
    honoured: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Honoured inline ignores become results with an in-source `suppressions` entry."""
    results = []
    rules: dict[str, dict[str, Any]] = {}
    for f in findings + (honoured or []):
        sev = str(f.get("severity", "P1")).upper()
        level = "error" if sev in ("P0", "P1") else "warning"
        rule_id = str(f.get("rule", "prufgate-finding"))
        conf = rule_confidence(rule_id)
        rules.setdefault(rule_id, _sarif_rule(rule_id))
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"[{sev}] ({f.get('engine', 'prufgate')}) {f.get('message', '')}"},
                "properties": {"severity": sev, "engine": str(f.get("engine", "prufgate")), "confidence": conf},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.get("file", "workspace"))},
                            "region": {"startLine": max(1, int(f.get("line", 1)))},
                        }
                    }
                ],
            }
        )
        if f.get("kind") == "honoured":
            results[-1]["suppressions"] = [{"kind": "inSource", "justification": str(f.get("reason", ""))}]
        elif f.get("kind") == "ai-dismissed":
            results[-1]["suppressions"] = [{"kind": "external", "justification": f"AI-dismissed: {f.get('reason', '')}"}]
    add_partial_fingerprints(results, root)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "prufgate",
                        "version": __version__,
                        "informationUri": os.environ.get("PRUFGATE_INFO_URI", PROJECT_URL),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def _sarif_rule(rule_id: str) -> dict[str, Any]:
    """SARIF rule metadata: `precision` is the rule's confidence, as code scanning reads it."""
    conf = rule_confidence(rule_id)
    return {
        "id": rule_id,
        "defaultConfiguration": {"rank": SARIF_RANK[conf]},
        "properties": {"precision": conf},
    }


def _stop_hook_active() -> bool:
    """True when a coding agent's Stop hook input says it is already continuing
    because of a stop hook (the documented loop guard)."""
    if sys.stdin is None or sys.stdin.isatty():
        return False
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except (ValueError, OSError):
        return False
    return isinstance(data, dict) and data.get("stop_hook_active") is True


def _cmd_check(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"prufgate check: path does not exist: {args.path}", file=sys.stderr)
        return 2

    honoured: list[dict[str, Any]] = []
    dismissed: list[dict[str, Any]] = []
    try:
        findings = _collect_unified_findings(
            target,
            changed_only=args.changed,
            base_ref=args.base,
            config_path=args.config,
            honoured=honoured,
            # The agent hooks (and the MCP server and REST API, which set the variable)
            # never call AI adjudication: an agent must not get a judge to iterate against.
            ai_dismissed=None if args.format == "agent-hook" or os.environ.get("PRUFGATE_NO_AI_ADJUDICATE") else dismissed,
            ai_provider=(args.ai_provider or os.environ.get("PRUFGATE_AI_PROVIDER") or "auto") if args.ai_adjudicate else None,
        )
    except (ConfigError, af_detector.SettingsError) as exc:
        print(f"prufgate check: {exc}", file=sys.stderr)
        return 2
    except SystemExit as exc:
        # An engine gave up (for example --changed outside a git repository).
        print(f"prufgate check: an engine stopped the scan (exit {exc.code})", file=sys.stderr)
        return 2
    except Exception as exc:  # an engine crash must never read as a pass
        print(f"prufgate check: engine error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2

    blockers = [f for f in findings if f["severity"] in ("P0", "P1")]

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif args.format == "sarif":
        # Finding paths are relative to the scanned directory, or to the file's directory for one file.
        print(_format_sarif_findings(findings, target if target.is_dir() else target.parent, honoured + dismissed))
    elif args.format in ("gitlab", "junit"):
        doc = _sarif_findings_doc(findings, target if target.is_dir() else target.parent, honoured + dismissed)
        print(gitlab_code_quality(doc) if args.format == "gitlab" else junit_xml(doc))
    elif args.format == "agent-hook":
        if blockers:
            print(
                f"PrufGate Agent Guardrail blocked completion ({len(blockers)} blocker finding(s)):",
                file=sys.stderr,
            )
            for b in blockers:
                print(
                    f"  - [{b['severity']}] {b['file']}:{b['line']} ({b['rule']}): {b['message']}",
                    file=sys.stderr,
                )
            print(
                "Fix the fabricated logic, hollow test, or unscoped BOLA query above before finishing.",
                file=sys.stderr,
            )
            return 2
        return 0
    else:
        if honoured:
            print(f"{len(honoured)} finding(s) suppressed by an inline prufgate-ignore:")
            for e in honoured:
                print(f"  [{e['engine']}:{e['rule']}] {e['file']}:{e['line']} — {e['reason']}")
        if dismissed:
            print(f"AI-dismissed: {len(dismissed)} finding(s) an AI judged not real (not blocking):")
            for e in dismissed:
                print(f"  [{e['severity']}] [{e['engine']}:{e['rule']}] {e['file']}:{e['line']} — AI: {e['reason']}")
        if not findings:
            print("✔ PrufGate check passed: 0 findings across Engines 1-5.")
            return 0
        print(f"✖ PrufGate check detected {len(findings)} finding(s) ({len(blockers)} blocker(s)):")
        for f in findings:
            print(f"  [{f['severity']}] [{f['engine']}:{f['rule']}] {f['file']}:{f['line']} — {f['message']}")

    return 1 if blockers else 0


def _cmd_test_audit(args: argparse.Namespace) -> int:
    cli_args: list[str] = []
    if args.changed:
        cli_args.append(f"--changed={args.base}" if args.base else "--changed")
    if args.config:
        cli_args.append(f"--config={args.config}")
    if args.json_out:
        cli_args.append(f"--json-out={args.json_out}")
    # The engine reads git and the config from the current directory: run it
    # from the workspace so `prufgate test-audit /path --changed` works anywhere.
    target = Path(args.path or ".").resolve()
    workspace = target if target.is_dir() else target.parent
    if args.path:
        cli_args.append(os.path.relpath(target, workspace))
    previous = Path.cwd()
    os.chdir(workspace)
    try:
        return ti_engine.main(cli_args)
    finally:
        os.chdir(previous)


def _cmd_bola(args: argparse.Namespace) -> int:
    old_env: dict[str, str | None] = {}
    env_overrides = {
        "PRUFGATE_TEST_PROBE_TOKEN_A": args.token_a,
        "PRUFGATE_TEST_PROBE_TOKEN_B": args.token_b,
        "PRUFGATE_TEST_PROBE_TENANT_A_ID": args.tenant_a,
        "PRUFGATE_TEST_PROBE_TENANT_B_ID": args.tenant_b,
    }
    for k, val in env_overrides.items():
        if val is not None:
            old_env[k] = os.environ.get(k)
            os.environ[k] = val

    try:
        ws = Path(args.path).resolve()
        base_ref = args.base
        if args.changed and ws.is_dir():
            prev_cwd = Path.cwd()
            os.chdir(ws)
            try:
                base_ref = resolve_base_ref(args.base)
            finally:
                os.chdir(prev_cwd)
        cfg_ref = base_ref or ("HEAD" if args.changed else None)
        cfg = PrufGateConfig.load(ws, args.config, ref=cfg_ref)
        findings: list[bola_engine.BolaFinding] = []
        extra_paths: list[str] = []
        if args.max_routes < 0:
            print("prufgate bola: --max-routes must be 0 or more", file=sys.stderr)
            return 2
        if args.routes_from:
            from prufgate.bola.route_sources import RouteSourceError, load_route_paths

            skipped = 0
            try:
                for route_file in args.routes_from:
                    paths, n_skipped = load_route_paths(route_file)
                    extra_paths += paths
                    skipped += n_skipped
            except RouteSourceError as exc:
                print(f"prufgate bola: {exc}", file=sys.stderr)
                return 2
            print(
                f"prufgate bola: --routes-from read {len(extra_paths)} GET/HEAD path(s), skipped {skipped} other-method entr(ies).",
                file=sys.stderr,
            )
        roles_matrix = None
        if args.roles:
            from prufgate.bola.role_matrix import RoleMatrixError, load_role_matrix

            if args.static_only or not args.url:
                print("prufgate bola: --roles needs --url and cannot be combined with --static-only", file=sys.stderr)
                return 2
            try:
                roles_matrix = load_role_matrix(args.roles)
            except RoleMatrixError as exc:
                print(f"prufgate bola: {exc}", file=sys.stderr)
                return 2
            if len(roles_matrix[1]) > args.max_routes:
                print(f"prufgate bola: {args.roles} lists {len(roles_matrix[1])} routes, over --max-routes {args.max_routes}", file=sys.stderr)
                return 2
        if not args.static_only and args.url:
            from prufgate.netguard import target_url_error

            url_error = target_url_error(args.url)
            if url_error:
                print(f"prufgate bola: {url_error}", file=sys.stderr)
                return 2
            if not bola_engine.check_server_active(args.url):
                print(f"prufgate bola: {args.url} is not reachable; the live probe did not run.", file=sys.stderr)
                return 2
            if roles_matrix:
                from prufgate.bola.role_matrix import RoleMatrixError, run_role_matrix

                try:
                    findings.extend(run_role_matrix(args.url, *roles_matrix))
                except RoleMatrixError as exc:
                    print(f"prufgate bola: {exc}", file=sys.stderr)
                    return 2
            else:
                with redirect_stdout(sys.stderr):
                    findings.extend(bola_engine.run_dynamic_matrix(
                        args.url, workspace=ws, config=cfg, extra_paths=extra_paths, max_extra_paths=args.max_routes,
                    ))
        if ws.exists():
            with redirect_stdout(io.StringIO()):
                ranges = diff_scope.changed_lines(base_ref, ws) if args.changed else None
                changed = set(ranges) if ranges is not None else None
                static_findings = bola_engine.run_static_matrix_audit(ws, config=cfg, changed_files=changed)
                if ranges is not None:
                    static_findings = [
                        f for f in static_findings
                        if diff_scope.in_scope(ranges, "bola", f.rule_id, f.endpoint_or_file, [(f.line, f.end_line)], ws)
                    ]
                findings.extend(static_findings)
        findings = visible(findings, cfg.enable_low_confidence)

        if args.format == "json":
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            if not findings:
                print("✔ PrufGate BOLA verification passed: 0 findings.")
            else:
                print(f"✖ PrufGate BOLA verification found {len(findings)} issue(s):")
                for f in findings:
                    print(f"  [{f.severity}] [{f.rule_id}] {f.endpoint_or_file}:{f.line} — {f.message}")
        return 1 if any(f.severity in ("P0", "P1") for f in findings) else 0
    except (ConfigError, GitDiffError) as exc:
        print(f"prufgate bola: {exc}", file=sys.stderr)
        return 2
    finally:
        for k, prev in old_env.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def _cmd_review(args: argparse.Namespace) -> int:
    rev_args = [f"--workspace={args.workspace}", f"--format={args.format}"]
    if args.base:
        rev_args.append(f"--base={args.base}")
    if args.diff_file:
        rev_args.append(f"--diff-file={args.diff_file}")
    if args.ai:
        rev_args.append("--ai")
        rev_args.append(f"--ai-provider={args.ai_provider}")
    return rev_engine.main(rev_args)


def _cmd_fix(args: argparse.Namespace) -> int:
    from prufgate.review import autofix

    repo = Path(args.path).resolve()
    prev = Path.cwd()
    try:
        os.chdir(repo)
        base = resolve_base_ref(args.base, committed=True)
        if base is None:
            raise BaseRefError("no base ref to compare with: pass --base or set PRUFGATE_BASE_REF")
        top = _git_ok("rev-parse", "--show-toplevel")
        root = Path(top.strip()).resolve() if top else repo
        plan = autofix.plan_fixes(root, base)
    except (OSError, ConfigError, autofix.FixError) as exc:
        print(f"prufgate fix: {exc}", file=sys.stderr)
        return 2
    finally:
        os.chdir(prev)

    for s in plan.skipped:
        print(f"no safe fix: {s.path}:{s.line} [{s.rule}] {s.why}", file=sys.stderr)
    if args.apply:
        written, refused = autofix.apply_plan(root, plan, force=args.force)
        for msg in refused:
            print(f"prufgate fix: not written: {msg}", file=sys.stderr)
        for path in written:
            print(f"fixed {path}")
        if not written and not refused:
            print(f"prufgate fix: nothing to write ({len(plan.fixes)} fix(es), already applied or none)")
        return 2 if refused else 0
    if args.format == "github-suggestions":
        print(autofix.format_github_suggestions(plan))
    else:
        sys.stdout.write(autofix.format_patch(plan))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from prufgate import differential, mutation, repo_runner

    if args.differential == args.mutation:
        print("prufgate verify: name one mode (--differential or --mutation)", file=sys.stderr)
        return 2
    mode = "--differential" if args.differential else "--mutation"
    if not repo_runner.opted_in(args.allow_run_tests):
        print(
            f"prufgate verify {mode} runs the repository's tests, which is code from the repository "
            f"under review. Run it only in a sandbox or CI, and opt in with --allow-run-tests or {repo_runner.OPT_IN_ENV}=1.",
            file=sys.stderr,
        )
        return 2
    timeout = args.timeout
    if timeout is None:
        timeout = differential.DEFAULT_TIMEOUT if args.differential else mutation.DEFAULT_TIMEOUT
    if timeout <= 0 or args.max_mutants <= 0:
        print("prufgate verify: --timeout and --max-mutants must be positive numbers", file=sys.stderr)
        return 2
    if args.differential and args.tool:
        print("prufgate verify: --tool applies to --mutation only", file=sys.stderr)
        return 2
    repo = Path(args.path).resolve()
    prev = Path.cwd()
    try:
        os.chdir(repo)
        base = resolve_base_ref(args.base, committed=True)
        if base is None:
            raise BaseRefError("no base ref to compare with: pass --base or set PRUFGATE_BASE_REF")
        if repo_runner.git(repo, "status", "--porcelain").strip():  # without the operator's tokens
            print("notice: uncommitted changes are not part of the run; it runs on the committed HEAD.", file=sys.stderr)
        if args.differential:
            result = differential.run(repo, base, args.test_cmd, timeout, args.pass_env)
        else:
            result = mutation.run(repo, base, args.tool, timeout, args.max_mutants, args.pass_env)
    except (OSError, ConfigError, repo_runner.RunError) as exc:
        print(f"prufgate verify: {exc}", file=sys.stderr)
        return 2
    finally:
        os.chdir(prev)

    findings = result.findings
    for f in findings:
        f["confidence"] = rule_confidence(f["rule"])
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif args.format == "sarif":
        print(_format_sarif_findings(findings, repo))
    elif args.mutation:
        _print_mutation(result)
    elif not findings:
        if result.overlaid or result.removed:
            print(f"✔ PrufGate differential passed: the base test run ({len(result.overlaid)} file(s) restored, "
                  f"{len(result.removed)} head-only file(s) removed) passes on the head code.")
        else:
            print("✔ PrufGate differential passed: no test file was deleted or changed against the base.")
    else:
        print(f"✖ PrufGate differential: base tests fail on the head code ({len(findings)} finding(s)):")
        for f in findings:
            print(f"  [{f['severity']}] [{f['rule']}] {f['file']}:{f['line']} — {f['message']}")
    return 1 if findings else 0


def _print_mutation(result: Any) -> None:
    if not result.files:
        print("✔ PrufGate mutation: no changed production lines to mutate.")
        return
    counts = ", ".join(f"{n} {status}" for status, n in sorted(result.summary.items())) or "no mutants"
    head = f"{len(result.files)} changed file(s), {', '.join(result.tools)}: {counts} on changed lines"
    if result.outside:
        head += f" ({result.outside} outside them, ignored)"
    if not result.findings:
        print(f"✔ PrufGate mutation passed: {head}.")
        return
    print(f"✖ PrufGate mutation: {head}:")
    for f in result.findings:
        print(f"  [{f['severity']}] [{f['rule']}] {f['file']}:{f['line']} — {f['message']}")


def _cmd_transcript(args: argparse.Namespace) -> int:
    from prufgate import transcript

    path = Path(args.file)
    try:
        fmt, checked, findings = transcript.scan(path, args.format_in)
    except transcript.TranscriptError as exc:
        print(f"prufgate transcript: {transcript.scrub_paths(str(exc))}", file=sys.stderr)
        return 2
    for f in findings:
        f["confidence"] = rule_confidence(f["rule"])
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif args.format == "sarif":
        print(_format_sarif_findings(findings, None))
    elif not findings:
        print(f"✔ PrufGate transcript: no suspicious commands ({fmt} transcript, {checked} command(s) checked).")
    else:
        print(f"✖ PrufGate transcript: {len(findings)} suspicious command(s) ({fmt} transcript, {checked} checked):")
        for f in findings:
            print(f"  [{f['severity']}] [{f['rule']}] line {f['line']} — {f['message']}")
    return 1 if findings else 0


def _cmd_init(args: argparse.Namespace) -> int:
    ws = Path(args.path).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    try:
        written = init_workspace(
            ws, install_hooks=args.hooks, overwrite=args.overwrite, agents=args.agent,
            agents_md=args.agents_md, bugbot=args.bugbot,
        )
    except HookConfigError as exc:
        print(f"prufgate init: {exc}", file=sys.stderr)
        return 2
    if written:
        print(f"✔ Initialized PrufGate workspace in {ws}:")
        for rel in written:
            print(f"  - {rel}")
    else:
        print(f"✔ PrufGate configuration already exists in {ws} (pass --overwrite to replace).")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    if "--self-check" in raw_args or (raw_args and raw_args[0] == "self-check"):
        return run_all_self_checks()
    # Internal: `prufgate base-ref [path]` prints the base ref ./prufgate.sh should use
    # (empty line: scan the working-tree diff) or exits 2 when there is none.
    if raw_args and raw_args[0] == "base-ref":
        prev = Path.cwd()
        try:
            os.chdir(raw_args[1] if len(raw_args) > 1 else ".")
            print(resolve_base_ref() or "")
            return 0
        except (OSError, BaseRefError) as exc:
            print(f"prufgate: {exc}", file=sys.stderr)
            return 2
        finally:
            os.chdir(prev)
    # Shortcuts matching ./prufgate.sh: `prufgate fast` = check --changed, `prufgate full` = check.
    if raw_args and raw_args[0] == "fast":
        raw_args = ["check", "--changed", *raw_args[1:]]
    elif raw_args and raw_args[0] == "full":
        raw_args = ["check", *raw_args[1:]]

    parser = argparse.ArgumentParser(
        prog="prufgate",
        description="PrufGate — checks code for fabricated logic, hollow tests, guardrail tampering and BOLA.",
        epilog="Exit codes: 0 clean, 1 blocking findings (P0/P1), 2 usage, configuration or engine error.",
        allow_abbrev=False,
    )
    parser.add_argument("--self-check", action="store_true", help="Run built-in fixture verification across all engines")
    parser.add_argument("--version", action="version", version=f"prufgate {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand")

    # 1. prufgate check
    p_check = subparsers.add_parser("check", help="Scan workspace or changed files across Engines 1-5")
    p_check.add_argument("path", nargs="?", default=".", help="Workspace or file path to scan")
    p_check.add_argument("--changed", action="store_true", help="Scan only uncommitted or branch-changed files")
    p_check.add_argument("--base", default=None, help="Base git ref when using --changed (e.g. origin/main)")
    p_check.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_check.add_argument(
        "--format",
        choices=("text", "json", "sarif", "gitlab", "junit", "agent-hook"),
        default="text",
        help="Output format (default: text)",
    )
    p_check.add_argument(
        "--ai-adjudicate",
        action="store_true",
        help="Ask an AI provider whether each low-confidence finding is real; a 'no' moves it to an AI-dismissed list. "
        "Takes effect only when the configuration in effect (at the base ref) enables ai_adjudicate",
    )
    p_check.add_argument(
        "--ai-provider",
        default=None,
        help="Provider for AI adjudication (auto, claude, opencode, codex, gemini, openai, anthropic, ollama; "
        "default PRUFGATE_AI_PROVIDER or auto)",
    )

    # 2. prufgate test-audit
    p_test = subparsers.add_parser("test-audit", help="Audit test suite integrity & anti-reward-hacking (Engine 2)")
    p_test.add_argument("path", nargs="?", default=None, help="Test file or directory to audit")
    p_test.add_argument("--changed", action="store_true", help="Scan only changed test files and diff hunks")
    p_test.add_argument("--base", default=None, help="Base git ref when using --changed")
    p_test.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_test.add_argument("--json-out", default=None, help="Write JSON findings to file")

    # 3. prufgate bola
    p_bola = subparsers.add_parser("bola", help="Run static + optional live 2-token BOLA verification (Engine 5)")
    p_bola.add_argument("path", nargs="?", default=".", help="Workspace path to scan")
    p_bola.add_argument("--url", default=None, help="Live target URL for 2-token differential HTTP probing")
    p_bola.add_argument("--token-a", default=None, help="Bearer token for Tenant A")
    p_bola.add_argument("--token-b", default=None, help="Bearer token for Tenant B")
    p_bola.add_argument("--tenant-a", default=None, help="Resource/Tenant ID for Tenant A")
    p_bola.add_argument("--tenant-b", default=None, help="Resource/Tenant ID for Tenant B")
    p_bola.add_argument("--static-only", action="store_true", help="Run only static route & query scoping checks")
    p_bola.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_bola.add_argument("--base", default=None, help="Read the PrufGate configuration as it is at this base ref (changed-files runs)")
    p_bola.add_argument("--changed", action="store_true",
                        help="Static checks report only files changed against --base (else HEAD), untracked files included")
    p_bola.add_argument("--format", choices=("text", "json"), default="text")
    p_bola.add_argument(
        "--routes-from", action="append", default=[], metavar="FILE",
        help="Extra GET/HEAD route paths from an OpenAPI/Swagger, Postman v2.1 or HAR file (repeatable); probed on --url only",
    )
    p_bola.add_argument("--max-routes", type=int, default=200, help="Cap on extra paths from --routes-from, and on routes in --roles (default 200)")
    p_bola.add_argument(
        "--roles", default=None, metavar="FILE",
        help="Role matrix (YAML): which of your test roles may GET/HEAD which routes; probed on --url instead of the two-token probe",
    )

    # 4. prufgate review
    p_rev = subparsers.add_parser("review", help="Run deterministic + optional BYO-AI PR diff review (Engine 6)")
    p_rev.add_argument("--workspace", default=".", help="Workspace path")
    p_rev.add_argument("--base", default=None, help="Base git ref for diff analysis (default: origin/main)")
    p_rev.add_argument("--diff-file", default=None, help="Explicit unified diff file to review")
    p_rev.add_argument(
        "--format",
        choices=("markdown", "json", "sarif", "github", "reviewdog", "gitlab", "junit"),
        default="markdown",
        help="Review output format",
    )
    p_rev.add_argument("--ai", action="store_true", help="Delegate semantic diff review to local agent CLI or LLM API")
    p_rev.add_argument("--ai-provider", default="auto", help="AI provider (auto, claude, opencode, codex, gemini, openai, anthropic, ollama)")

    # 4a. prufgate fix
    p_fix = subparsers.add_parser("fix", help="Deterministic fixes for safe findings: print a patch, or write it with --apply")
    p_fix.add_argument("path", nargs="?", default=".", help="Repository path")
    p_fix.add_argument("--base", default=None, help="Base git ref (default: as for check --changed)")
    p_fix.add_argument("--format", choices=("patch", "github-suggestions"), default="patch")
    p_fix.add_argument("--apply", action="store_true", help="Write the fixes to the working tree")
    p_fix.add_argument("--force", action="store_true", help="With --apply, write files that have uncommitted changes")

    # 4b. prufgate verify
    p_verify = subparsers.add_parser(
        "verify",
        help="Run the repository's tests: base tests on the head code, or a mutation smoke test "
        "(EXECUTES repository code: opt-in, sandbox or CI only)",
    )
    p_verify.add_argument("path", nargs="?", default=".", help="Repository path")
    p_verify.add_argument("--differential", action="store_true", help="Run the base ref's test files on the head code")
    p_verify.add_argument("--base", default=None, help="Base git ref (default: as for check --changed)")
    p_verify.add_argument("--test-cmd", default=None, help="Test command (default: detect pytest, npm test or go test)")
    p_verify.add_argument("--mutation", action="store_true",
                          help="Mutate the changed production lines with an installed mutation tool")
    p_verify.add_argument("--tool", choices=("mutmut", "stryker", "pit", "gremlins", "go-mutesting", "cargo-mutants"),
                          default=None, help="With --mutation: the tool to use (default: detect per language)")
    p_verify.add_argument("--max-mutants", type=int, default=200,
                          help="With --mutation: mutant cap, where the tool has one (PIT); --timeout bounds the rest")
    p_verify.add_argument("--timeout", type=int, default=None,
                          help="Seconds per test run, or for the whole mutation tool run (default 600 / 1800)")
    p_verify.add_argument(
        "--pass-env", action="append", default=[], metavar="NAME", help="Pass this environment variable to the tests; repeat"
    )
    p_verify.add_argument("--allow-run-tests", action="store_true", help="Opt in to running the repository's tests")
    p_verify.add_argument("--format", choices=("text", "json", "sarif"), default="text")

    # 5. prufgate init
    p_init = subparsers.add_parser("init", help="Initialize .prufgate/config.yaml and coding agent stop hooks")
    p_init.add_argument("path", nargs="?", default=".", help="Workspace directory to initialize")
    p_init.add_argument("--hooks", action="store_true", help="Generate coding-agent hooks (default: Claude Code and Cursor) and a pre-commit hook")
    p_init.add_argument(
        "--agent",
        action="append",
        choices=AGENT_CHOICES,
        default=None,
        help="Agent to write hooks for; repeat for several (implies --hooks)",
    )
    p_init.add_argument("--agents-md", action="store_true", help="Add or update the PrufGate section in AGENTS.md for coding agents and AI reviewers")
    p_init.add_argument("--bugbot", action="store_true", help="Add or update the same section in .cursor/BUGBOT.md (Cursor Bugbot review rules)")
    p_init.add_argument("--overwrite", action="store_true", help="Overwrite existing config/hook files")

    # 5b. prufgate shell-guard
    subparsers.add_parser(
        "shell-guard",
        help="Coding-agent PreToolUse hook: read the hook JSON on stdin, exit 2 to block hook-skipping, force pushes and test deletion",
    )

    # 5c. prufgate hook <agent> <event>
    p_hook = subparsers.add_parser(
        "hook",
        help="Fail-closed coding-agent hook adapter: read the agent's hook JSON on stdin and answer in its protocol",
    )
    p_hook.add_argument("agent", choices=AGENTS)
    p_hook.add_argument("event", choices=EVENTS, help="pre-tool (shell/edit guard), shell (Cursor beforeShellExecution), stop")

    # 5c2. prufgate transcript
    p_tr = subparsers.add_parser("transcript", help="Report git-history lookups, hook skipping and test tampering in an agent transcript")
    p_tr.add_argument("file", help="Claude Code or Codex CLI session JSONL, or a plain-text shell log")
    p_tr.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p_tr.add_argument("--format-in", choices=("claude", "codex", "text"), default=None, help="Transcript format (default: detect)")

    # 5d. prufgate bench
    p_bench = subparsers.add_parser("bench", help="Measure precision and recall of `check --changed` on a labelled corpus")
    p_bench.add_argument("--cases", default=None, help="Corpus directory (default: bench/cases, from a checkout)")
    p_bench.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    p_bench.add_argument("--rule", default=None, help="Score this rule only")
    p_bench.add_argument("--min-precision", type=float, default=None, help="Exit 1 when overall precision is below this")
    p_bench.add_argument("--min-recall", type=float, default=None, help="Exit 1 when overall recall is below this")

    # 5e. prufgate export-rules
    p_export = subparsers.add_parser(
        "export-rules", help="Export the single-line pattern rules as Semgrep / Opengrep rules YAML"
    )
    p_export.add_argument("--format", choices=("semgrep",), default="semgrep", help="Output format (default: semgrep)")
    p_export.add_argument("--out", default=None, metavar="FILE", help="Write to FILE instead of standard output")
    p_export.add_argument("--pack", action="append", choices=("cti",), default=[], help="Also export an opt-in pack's rules")

    # 6. prufgate mcp
    subparsers.add_parser("mcp", help="Start PrufGate Model Context Protocol (MCP) stdio server")

    # 7. prufgate api
    p_api = subparsers.add_parser("api", help="Start PrufGate REST API server")
    p_api.add_argument("--host", default=os.environ.get("PRUFGATE_API_HOST", "127.0.0.1"))
    p_api.add_argument("--port", type=int, default=8000)

    # No abbreviated options: `--ai-adj` must not slip past the check for `--ai-adjudicate`.
    for sub in subparsers.choices.values():
        sub.allow_abbrev = False
    args = parser.parse_args(raw_args)

    if args.subcommand == "check":
        if args.format != "agent-hook":
            return _cmd_check(args)
        # Coding-agent Stop hook: any failure blocks (exit 2, the code agents
        # treat as blocking), except when the agent is already continuing
        # because of this hook: then report and let it stop, never loop.
        active = _stop_hook_active()
        try:
            rc = _cmd_check(args)
        except Exception as exc:
            print(f"prufgate: the check could not run: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            rc = 2
        if rc == 0:
            return 0
        if active:
            print("prufgate: stop_hook_active is set; reporting without blocking a second time.", file=sys.stderr)
            return 0
        return 2
    if args.subcommand == "test-audit":
        return _cmd_test_audit(args)
    if args.subcommand == "bola":
        return _cmd_bola(args)
    if args.subcommand == "review":
        return _cmd_review(args)
    if args.subcommand == "fix":
        return _cmd_fix(args)
    if args.subcommand == "verify":
        return _cmd_verify(args)
    if args.subcommand == "init":
        return _cmd_init(args)
    if args.subcommand == "shell-guard":
        from prufgate.hooks.shell_guard import main as shell_guard_main

        return shell_guard_main()
    if args.subcommand == "hook":
        from prufgate.hooks.adapters import main as hook_main

        return hook_main(args.agent, args.event)
    if args.subcommand == "transcript":
        return _cmd_transcript(args)
    if args.subcommand == "bench":
        from prufgate.bench import main as bench_main

        return bench_main(args.cases, args.format, args.rule, args.min_precision, args.min_recall)
    if args.subcommand == "export-rules":
        from prufgate.export_rules import main as export_main

        return export_main(args.format, args.out, tuple(args.pack))
    if args.subcommand == "mcp":
        from prufgate.mcp.prufgate_mcp_server import main as mcp_main

        mcp_main()
        return 0
    if args.subcommand == "api":
        from prufgate.api.server import run_server

        run_server(host=args.host, port=args.port)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
