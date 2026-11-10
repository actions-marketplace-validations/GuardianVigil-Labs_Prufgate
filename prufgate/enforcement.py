"""Separate risk severity from the project's adoption policy."""
from __future__ import annotations

from typing import Any

from prufgate.baseline import PROTECTED_RULES, canonical_rule

DEFAULT = {"mode": "strict", "blocking_rules": [], "minimum_confidence": "low"}
RANK = {"low": 0, "medium": 1, "high": 2}


def blocking(finding: dict, policy: dict[str, Any]) -> bool:
    if finding.get("severity") not in ("P0", "P1"):
        return False
    rule = canonical_rule(finding.get("rule", finding.get("rule_id", "")))
    if rule in PROTECTED_RULES:
        return True
    if policy["mode"] == "advisory":
        return False
    if RANK.get(finding.get("confidence"), 1) < RANK[policy["minimum_confidence"]]:
        return False
    return policy["mode"] == "strict" or rule in {canonical_rule(r) for r in policy["blocking_rules"]}


def apply(findings: list[dict], policy: dict) -> list[dict]:
    return [{**item, "blocking": blocking(item, policy),
             "enforcement_reason": "Policy blocker" if blocking(item, policy) else "Advisory under the effective enforcement policy"}
            for item in findings]
