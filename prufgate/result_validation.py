"""Structural validation at scanner and service boundaries."""

from __future__ import annotations

import json
from typing import Any


class InvalidResult(ValueError):
    """An engine did not return its promised machine-readable result."""


def read_json(text: str) -> Any:
    """Reject non-JSON numbers and ambiguous duplicate fields at boundaries."""
    def constant(value: str) -> Any:
        raise InvalidResult("non-finite JSON number")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        out = {}
        for key, value in items:
            if key in out:
                raise InvalidResult("duplicate JSON field")
            out[key] = value
        return out

    return json.loads(text, parse_constant=constant, object_pairs_hook=pairs)


def validate_findings(data: Any, tool: str) -> list[dict]:
    if tool == "contract-guard" and isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        raise InvalidResult(f"{tool}: expected a findings array")
    for item in data:
        if not isinstance(item, dict) or not item:
            raise InvalidResult(f"{tool}: expected finding objects")
        for key in ("rule", "rule_id", "ruleId", "file", "target", "message", "snippet", "title", "details", "curl_poc", "text"):
            if key in item and not isinstance(item[key], str):
                raise InvalidResult(f"{tool}: invalid {key}")
        if item.get("suggestion") is not None and not isinstance(item["suggestion"], str):
            raise InvalidResult(f"{tool}: invalid suggestion")
        for key in ("line", "end_line", "StartLine"):
            if key in item and (type(item[key]) is not int or item[key] < 1):
                raise InvalidResult(f"{tool}: invalid {key}")
        if tool not in {"zizmor", "gitleaks", "gitleaks-worktree", "ast-grep"} and "severity" in item and item["severity"] not in ("P0", "P1", "P2", "P3"):
            raise InvalidResult(f"{tool}: invalid severity")
        if tool in {"anti-fabrication", "test-integrity", "diff-guard", "contract-guard", "bola-matrix", "unified"}:
            if not any(isinstance(item.get(k), str) and item[k] for k in ("rule", "rule_id")):
                raise InvalidResult(f"{tool}: missing rule")
        if tool == "pr-reviewer" and not all(item.get(k) for k in ("title", "message", "file")):
            raise InvalidResult("pr-reviewer: missing finding fields")
        if tool in {"gitleaks", "gitleaks-worktree"}:
            if not isinstance(item.get("File"), str) or not item["File"]:
                raise InvalidResult("gitleaks: missing File")
            for key in ("RuleID", "Description", "Match", "Secret", "Commit"):
                if key in item and not isinstance(item[key], str):
                    raise InvalidResult(f"gitleaks: invalid {key}")
        if tool == "ast-grep":
            if not item.get("file") or not isinstance(item.get("range"), dict):
                raise InvalidResult("ast-grep: missing file or range")
            for point in ("start", "end"):
                value = item["range"].get(point)
                if not isinstance(value, dict) or type(value.get("line")) is not int or value["line"] < 0:
                    raise InvalidResult("ast-grep: invalid range")
        if tool == "zizmor":
            if not isinstance(item.get("ident", item.get("rule")), str):
                raise InvalidResult("zizmor: missing rule")
            if not isinstance(item.get("determinations", {}), dict) or not isinstance(item.get("locations", []), list):
                raise InvalidResult("zizmor: invalid finding metadata")
            for location in item.get("locations", []):
                if not isinstance(location, dict):
                    raise InvalidResult("zizmor: invalid location")
                symbolic, concrete = location.get("symbolic", {}), location.get("concrete", {})
                if not isinstance(symbolic, dict) or not isinstance(concrete, dict):
                    raise InvalidResult("zizmor: invalid location metadata")
                key = symbolic.get("key", {})
                if not isinstance(key, dict) or not isinstance(key.get("Local", {}), dict):
                    raise InvalidResult("zizmor: invalid location path")
                value = concrete.get("location", {})
                if not isinstance(value, dict):
                    raise InvalidResult("zizmor: invalid location range")
                for point in ("start_point", "end_point"):
                    entry = value.get(point, {})
                    if not isinstance(entry, dict) or type(entry.get("row", 0)) is not int or entry.get("row", 0) < 0:
                        raise InvalidResult("zizmor: invalid location row")
    return data


def validate_sarif(data: Any) -> dict:
    if not isinstance(data, dict) or data.get("version") != "2.1.0":
        raise InvalidResult("expected SARIF version 2.1.0")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise InvalidResult("SARIF must contain a run")
    for run in runs:
        if not isinstance(run, dict):
            raise InvalidResult("invalid SARIF run")
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str) or not driver["name"]:
            raise InvalidResult("SARIF run needs tool.driver.name")
        results = run.get("results")
        if not isinstance(results, list):
            raise InvalidResult("SARIF run needs a results array")
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("message"), dict):
                raise InvalidResult("invalid SARIF result")
            message = result["message"]
            if not any(isinstance(message.get(k), str) and message[k] for k in ("text", "markdown", "id")):
                raise InvalidResult("SARIF result needs a message")
            if result.get("level", "warning") not in ("none", "note", "warning", "error"):
                raise InvalidResult("invalid SARIF level")
            suppressions = result.get("suppressions", [])
            if not isinstance(suppressions, list) or any(
                not isinstance(s, dict) or s.get("kind") not in ("inSource", "external")
                or s.get("status", "accepted") not in ("accepted", "underReview", "rejected")
                for s in suppressions
            ):
                raise InvalidResult("invalid SARIF suppressions")
            if not isinstance(result.get("properties", {}), dict):
                raise InvalidResult("invalid SARIF properties")
            severity = result.get("properties", {}).get("severity")
            if severity is not None and severity not in ("P0", "P1", "P2", "P3"):
                raise InvalidResult("invalid SARIF severity")
        if not isinstance(run.get("invocations", []), list):
            raise InvalidResult("invalid SARIF invocations")
        for invocation in run.get("invocations", []):
            if not isinstance(invocation, dict) or invocation.get("executionSuccessful") is False:
                raise InvalidResult("SARIF records an unsuccessful invocation")
    return data
