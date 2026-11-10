"""Versioned, integration-independent scan results and finding explanations."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from prufgate.coverage import unavailable
from prufgate.enforcement import DEFAULT as DEFAULT_ENFORCEMENT
from prufgate.enforcement import apply as enforce
from prufgate.explain import describe, lookup
from prufgate.privacy import redact, redact_data
from prufgate.rules import confidence, review_rule_id
from prufgate.safe_fs import safe_read_text

SCHEMA_VERSION = "1.0"
STATUSES = {"clean", "findings", "incomplete", "error"}


def redact_result(value):
    """Redact free text while preserving structural, Git-derived provenance IDs."""
    out = redact_data(value)
    if isinstance(value, dict) and value.get("schema_version") == SCHEMA_VERSION:
        revision = value.get("revision", {})
        if isinstance(revision, dict) and isinstance(revision.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision["commit"]):
            out["revision"]["commit"] = revision["commit"]
            ref = value.get("coverage", {}).get("base_ref")
            if isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ref) and value.get("governance", {}).get("applied_ref") == ref:
                out["coverage"]["base_ref"] = ref
                out["governance"]["applied_ref"] = ref
    return out


def ai_privacy(enabled: bool = False, provider: Optional[str] = None, purpose: str = "adjudication") -> dict:
    destination = None
    if enabled:
        from prufgate.review.ai_adapter import detect_ai_provider
        provider = detect_ai_provider(provider or "auto")
        if provider in ("openai", "anthropic", "ollama"):
            endpoint = {"openai": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions",
                        "anthropic": "https://api.anthropic.com/v1/messages",
                        "ollama": os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/api/chat"}[provider]
            parts = urlsplit(endpoint)
            destination = redact(urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", "")))
        elif provider:
            destination = f"Configured {provider} CLI; its downstream destination is not visible to PrufGate."
    return {"external_ai": {"enabled": enabled, "provider": provider if enabled else None,
                            "destination": destination, "purpose": purpose,
                            "content": "Redacted unified diff (up to 24000 characters)." if purpose == "review" else "Rule, finding message and a bounded source-code window.",
                            "redaction": "Known credential environment values, credential assignments and recognized token formats. Best effort; not a guarantee against all sensitive data.",
                            "consent": "Explicit --ai / --ai-adjudicate, or PRUFGATE_ALLOW_EXTERNAL_AI=1. Configuration alone is insufficient."}}


def _limitations(rule: str, engine: str) -> list[str]:
    if "BOLA" in rule or "bola" in engine.lower():
        return ["An authorization guard, tenant relationship or middleware may be outside the analyzed context.",
                "A live probe establishes only the tested identities, resource values and response comparisons."]
    if "test" in engine or "test" in rule:
        return ["Assertions or test setup may be provided by a helper or framework the static checker cannot resolve."]
    if "contract" in engine or "route" in rule:
        return ["Generated routes, dynamic imports or deployment-provided settings may be absent from the workspace."]
    return ["Static pattern matching may miss surrounding control flow or an intentional, documented special case. Review the cited code before changing it."]


def enrich(item: dict, root: Optional[Path] = None, include_code: bool = True) -> dict:
    finding = dict(item)
    if not include_code:
        finding.pop("snippet", None)
        finding.pop("details", None)
    engine = str(item.get("engine", item.get("tool", "prufgate")))
    rule = str(item.get("rule", item.get("rule_id", "")) or review_rule_id(str(item.get("title", "finding"))))
    finding.update(engine=engine, rule=rule, file=str(item.get("file", item.get("path", "workspace"))),
                   severity=item.get("severity", "P0"), line=max(1, int(item.get("line") or 1)))
    if not item.get("end_line"):
        finding.pop("end_line", None)
    finding["confidence"] = item.get("confidence") or confidence(rule)
    key = lookup(rule)
    explanation = describe(key) if key else None
    finding["explanation"] = {"reasoning": explanation["what"] if explanation else str(item.get("message", item.get("title", rule))),
                              "suggested_fix": explanation["fix"] if explanation else "Inspect the cited operation and enforce its documented correctness or authorization contract.",
                              "could_be_incorrect_when": _limitations(rule, engine)}
    secret_finding = engine in ("gitleaks", "gitleaks-worktree")
    code = str(item.get("snippet") or "")[:1200] if include_code and not secret_finding else ""
    start = finding["line"]
    reason = "Code evidence was disabled." if not include_code else "No safe source excerpt is available."
    if secret_finding:
        reason = "Secret-scanner source excerpts are deliberately omitted."
    if include_code and not secret_finding and root is not None:
        try:
            path = root / finding["file"]
            lines = safe_read_text(path, root=root).splitlines()
            start = max(1, finding["line"] - 2)
            code = "\n".join(lines[start - 1:finding["line"] + 2])[:1200]
        except (OSError, ValueError):
            pass
    finding["evidence"] = {"code": redact(code) if code else None, "start_line": start if code else None,
                           "reason": None if code else reason}
    return redact_data(finding)


def make_result(findings: list[dict], *, root: Optional[Path] = None, coverage: Optional[dict] = None,
                errors: Optional[list[str]] = None, incomplete: Optional[list[str]] = None,
                privacy: Optional[dict] = None, profile: str = "core", include_code: bool = True, enforcement: Optional[dict] = None,
                config_path: Optional[str] = None, revision: Optional[dict] = None) -> dict:
    """Build the versioned result. With `root` and no `enforcement`, the trusted
    policy and dismissals are applied once; a caller rebuilding a result from a
    completed scan passes that scan's `enforcement` (and `revision`) instead."""
    items = [enrich(item, root, include_code) for item in findings]
    errors, incomplete = errors or [], incomplete or []
    governance, revision = {}, revision or {}
    policy = enforcement or DEFAULT_ENFORCEMENT
    if root is not None and enforcement is None:
        from prufgate.workflow import apply as apply_workflow
        try:
            items, policy, governance, revision = apply_workflow(items, root, (coverage or {}).get("base_ref"), config_path)
            items = [enrich(item, root, include_code) for item in items]
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            errors = [*errors, f"Workflow policy or dismissal ledger is invalid ({exc.__class__.__name__}): {exc}"]
            from prufgate.workflow import revision as current_revision
            revision = current_revision(root)
    items = enforce(items, policy)
    state = "error" if errors else "incomplete" if incomplete else "findings" if items else "clean"
    blockers = sum(item["blocking"] for item in items)
    result = redact_result({"schema_version": SCHEMA_VERSION, "scan_status": state, "profile": profile,
                        "exit_code": 2 if errors or incomplete else 1 if blockers else 0,
                        "passed": state in ("clean", "findings") and blockers == 0,
                        "findings": items, "summary": {"blockers": blockers, "advisories": len(items) - blockers, "total_findings": len(items)},
                        "coverage": {**unavailable(), **coverage} if coverage is not None else unavailable(),
                        "errors": errors, "incomplete_reasons": incomplete, "privacy": privacy or ai_privacy(),
                        "enforcement": policy, "governance": governance, "revision": revision})
    # Restore only validated, structural Git provenance. Do not relax text redaction.
    result["revision"] = revision
    return result


def validate_result(value: Any) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION or value.get("scan_status") not in STATUSES:
        raise ValueError("unsupported scan result")
    from prufgate.result_validation import validate_findings
    findings = validate_findings(value.get("findings"), "unified")
    if not isinstance(value.get("coverage"), dict) or not isinstance(value.get("privacy"), dict):
        raise ValueError("missing scan metadata")
    if type(value.get("exit_code")) is not int or type(value.get("passed")) is not bool:
        raise ValueError("invalid scan decision types")
    if not isinstance(value.get("summary"), dict) or any(type(value["summary"].get(key)) is not int for key in ("blockers", "advisories", "total_findings")):
        raise ValueError("invalid finding counts")
    cov = value["coverage"]
    for key in ("files_checked", "lines_checked", "lines_in_scope"):
        if cov.get(key) is not None and (type(cov[key]) is not int or cov[key] < 0):
            raise ValueError("invalid coverage counts")
    if not isinstance(cov.get("files"), list) or not isinstance(cov.get("engines"), list) or not isinstance(cov.get("exclusions"), list):
        raise ValueError("invalid coverage entries")
    for entry in cov["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str) or type(entry.get("lines")) is not int or entry["lines"] < 0:
            raise ValueError("invalid coverage file")
    for key in ("errors", "incomplete_reasons"):
        if not isinstance(value.get(key), list) or not all(isinstance(v, str) for v in value[key]):
            raise ValueError("invalid scan reasons")
    policy = value.get("enforcement") or DEFAULT_ENFORCEMENT
    if not isinstance(policy, dict) or policy.get("mode") not in ("strict", "advisory", "selected") or policy.get("minimum_confidence") not in ("low", "medium", "high") or not isinstance(policy.get("blocking_rules"), list):
        raise ValueError("invalid enforcement policy")
    expected = make_result(findings, errors=value["errors"], incomplete=value["incomplete_reasons"], include_code=False, enforcement=policy)
    for actual, calculated in zip(findings, expected["findings"]):
        if "blocking" in actual and (type(actual["blocking"]) is not bool or actual["blocking"] != calculated["blocking"]):
            raise ValueError("finding blocking decision disagrees with enforcement policy")
    if any(value.get(key) != expected[key] for key in ("scan_status", "exit_code", "passed", "summary")):
        raise ValueError("scan status disagrees with findings or execution state")
    return value


def attach_sarif(doc: dict, result: dict) -> dict:
    doc["runs"][0].setdefault("properties", {})["prufgate"] = {k: v for k, v in result.items() if k != "findings"}
    # Suppressed results follow active findings in PrufGate's SARIF writers.
    for entry, finding in zip(doc["runs"][0]["results"], result["findings"]):
        entry.setdefault("properties", {})["explanation"] = finding["explanation"]
        entry["properties"]["evidence"] = finding["evidence"]
        entry["properties"]["blocking"] = finding["blocking"]
        entry["properties"]["fingerprint"] = finding.get("fingerprint")
    for finding in result.get("governance", {}).get("dismissed", []):
        doc["runs"][0]["results"].append({"ruleId": finding["rule"], "level": "note", "message": {"text": finding["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["file"]}, "region": {"startLine": finding["line"]}}}],
            "properties": {"severity": finding["severity"], "dismissal": finding, "blocking": False},
            "suppressions": [{"kind": "external", "status": "accepted", "justification": finding["reason"]}]})
    return doc


def metadata_from_sarif(doc: dict) -> dict:
    properties = doc.get("runs", [{}])[0].get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("invalid run properties")
    value = properties.get("prufgate", {})
    if not isinstance(value, dict):
        raise ValueError("invalid scan metadata")
    if value and (value.get("schema_version") != SCHEMA_VERSION or value.get("scan_status") not in STATUSES):
        raise ValueError("invalid scan metadata version or status")
    for key in ("errors", "incomplete_reasons"):
        if value and (not isinstance(value.get(key), list) or not all(isinstance(v, str) for v in value[key])):
            raise ValueError("invalid scan reasons")
    if value:
        if not isinstance(value.get("coverage"), dict) or not isinstance(value.get("privacy"), dict):
            raise ValueError("invalid coverage or privacy metadata")
        for key in ("files_checked", "lines_checked", "lines_in_scope"):
            count = value["coverage"].get(key)
            if count is not None and (type(count) is not int or count < 0):
                raise ValueError("invalid coverage count")
    return value


def markdown_summary(result: dict) -> str:
    cov = result["coverage"]
    files = "unknown" if cov.get("files_checked") is None else cov["files_checked"]
    count = "unknown" if cov.get("lines_checked") is None else cov["lines_checked"]
    lines = [f"Scan status: **{result['scan_status']}**", f"Profile: `{result['profile']}`",
             f"Files checked: {files}; lines read: {count}.",
             str(cov.get("measurement", "")), "", "Engine coverage:"]
    lines.insert(2, f"Enforcement: `{result.get('enforcement', DEFAULT_ENFORCEMENT)['mode']}`; blocking decisions preserve original risk severity.")
    lines += [f"- {e['engine']}: {e['status']}" + (f" — {e['reason']}" if e.get("reason") else "") for e in cov.get("engines", [])]
    lines += ["", "Exclusions:"] + [f"- {e.get('path', e.get('pattern', ''))}: {e['reason']}" for e in cov.get("exclusions", [])]
    lines += ["", "Failed or incomplete checks:"] + [f"- {reason}" for reason in result["errors"] + result["incomplete_reasons"]]
    ai = result["privacy"]["external_ai"]
    lines += ["", f"External AI enabled: {ai['enabled']}; destination: {ai['destination'] or 'none'}. "]
    if ai.get("outcome"):
        lines.append(str(ai["outcome"]))
    for finding in result["findings"]:
        e = finding["explanation"]
        lines += ["", f"`{finding['rule']}` at `{finding['file']}:{finding['line']}` ({finding['confidence']} confidence)",
                  f"Reasoning: {e['reasoning']}", f"Suggested fix: {e['suggested_fix']}",
                  "Could be incorrect when: " + " ".join(e["could_be_incorrect_when"])]
        if finding["evidence"]["code"]:
            # Indentation prevents source content from closing a fenced block.
            lines += ["", *["    " + line for line in finding["evidence"]["code"].splitlines()]]
    return redact("\n".join(lines) + "\n")
