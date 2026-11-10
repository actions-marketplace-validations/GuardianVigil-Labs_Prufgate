"""Effective policy, reviewed dismissals and scan provenance at a trusted base."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from prufgate import dismissals
from prufgate.baseline import fingerprints
from prufgate.config import GitDiffError, PrufGateConfig, _git
from prufgate.enforcement import apply as apply_enforcement


def trusted_ref(root: Path, ref: Optional[str]) -> Optional[str]:
    try:
        _git(["rev-parse", "--verify", "HEAD"], root)
    except GitDiffError:
        if ref:
            raise
        return None
    return ref or "HEAD"


def revision(root: Path) -> dict:
    try:
        commit = _git(["rev-parse", "--verify", "HEAD"], root).strip()
        names = _git(["diff", "--name-only", "-z", "HEAD"], root) + _git(["ls-files", "--others", "--exclude-standard", "-z"], root)
        dirty = any(path and not path.replace("\\", "/").startswith("reports/") for path in names.split("\0"))
        return {"commit": commit, "dirty": dirty}
    except (GitDiffError, OSError):
        return {"commit": None, "dirty": None}


def apply(items: list[dict], root: Path, ref: Optional[str],
          config_path: Optional[str] = None) -> tuple[list[dict], dict, dict, dict]:
    base = trusted_ref(root, ref)
    cfg = PrufGateConfig.load(root, config_path, ref=base)
    keys = fingerprints([(f["file"], f["rule"], f["line"]) for f in items], root)
    items = [{**item, "fingerprint": key[2]} for item, key in zip(items, keys)]
    items, governance = dismissals.apply(items, root, base)
    # A repository-level finding: once per result, even when a merged scan
    # (the MCP full scan) passes findings that already carry it.
    if governance["pending_changes"] and not any(i["rule"] == "prufgate-config-self-exemption" and i.get("engine") == "workflow"
                                                 for i in items):
        events, _ = dismissals.load(root)
        if any(event["action"] == "approved" for event in events[len(governance["audit"]):]):
            items.append({"rule": "prufgate-config-self-exemption", "engine": "workflow", "severity": "P1", "confidence": "high",
                          "file": dismissals.LEDGER, "line": 1, "message": "This change approves a dismissal. It requires maintainer review and applies only after merge."})
    governance["registered_exemptions"] = len(cfg.exempt)
    governance["registered_known_debt_entries"] = len(cfg.known_debt)
    governance["known_debt_ceilings"] = dict(cfg.known_debt_ceilings)
    return apply_enforcement(items, cfg.enforcement), cfg.enforcement, governance, revision(root)
