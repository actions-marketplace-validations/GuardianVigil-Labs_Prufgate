#!/usr/bin/env python3
"""PrufGate Model Context Protocol (MCP) server: JSON-RPC 2.0 over stdio, no dependencies.

Every tool runs an engine in a subprocess and reads its JSON output from a
temporary directory, so a scan never writes into the workspace. A tool result
is `passed: true` only when the engine finished and reported no P0/P1 finding:
an engine that crashed, timed out or left no readable output is `status: error`
and `passed: false`, and the MCP result carries `isError: true`.

The live two-token BOLA probe sends HTTP requests, so it runs only when the
caller passes an explicit `target_url`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

PRUFGATE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PRUFGATE_ROOT) not in sys.path:
    sys.path.insert(0, str(PRUFGATE_ROOT))

from prufgate import __version__  # noqa: E402
from prufgate.config import ConfigError  # noqa: E402
from prufgate.netguard import target_url_error  # noqa: E402
from prufgate.rules import low_confidence_enabled, visible  # noqa: E402

ENGINE_DIR = PRUFGATE_ROOT / "prufgate"
CLI = ENGINE_DIR / "cli.py"
SCRIPTS = {
    "anti_fabrication": ENGINE_DIR / "anti_fabrication" / "detector.py",
    "test_audit": ENGINE_DIR / "anti_reward_hacking" / "test_integrity.py",
    "diff_guard": ENGINE_DIR / "diff_guard" / "tamper_detector.py",
    "contract_check": ENGINE_DIR / "contract_guard" / "__init__.py",
    "review": ENGINE_DIR / "review" / "reviewer.py",
}
# Newest first. The server answers with the client's version when it knows it.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
TIMEOUT_SECONDS = int(os.environ.get("PRUFGATE_MCP_TIMEOUT", "300"))

class ToolInputError(ValueError):
    """Bad tool arguments: reported to the caller as a tool error."""


validate_target_url = target_url_error


def _workspace(path: Any) -> Path:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ToolInputError("workspace_path must be a non-empty path string")
    ws = Path(path).resolve()
    if not ws.is_dir():
        raise ToolInputError(f"Workspace does not exist: {path}")
    return ws


def _base_ref(ref: Any) -> Optional[str]:
    if ref in (None, ""):
        return None
    if not isinstance(ref, str) or ref.startswith("-") or any(c.isspace() for c in ref):
        raise ToolInputError("base_ref must be a git ref such as origin/main")
    return ref


def _resolve_base(ws: Path, ref: Optional[str]) -> tuple[str, Optional[str]]:
    """Return (base, error) for a diff-based engine. An empty base means "the
    working-tree diff". A ref that does not exist, or a clean tree with nothing
    to compare against, is an error: never an empty diff that reads as a pass."""
    if ref:
        proc = subprocess.run(["git", "rev-parse", "--verify", "-q", "--end-of-options", f"{ref}^{{commit}}"],
                              cwd=str(ws), capture_output=True, text=True)
        return (ref, None) if proc.returncode == 0 else ("", f"base ref {ref!r} is not a commit in this repository")
    proc = subprocess.run([sys.executable, str(CLI), "base-ref", str(ws)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    if proc.returncode != 0:
        return "", (proc.stderr.strip() or f"base-ref exited {proc.returncode}")
    return proc.stdout.strip(), None


def _run_json(cmd: List[str], ws: Path, out_flag: Optional[str] = None, stdout_json: bool = False) -> tuple[Optional[list], Optional[str]]:
    """Run one engine. Return (findings, None) or (None, error).

    Engines exit 0 (clean), 1 (findings) or 2 (error). Output is read from a
    file the engine must create (`out_flag=<path>`) or from stdout.
    """
    with tempfile.TemporaryDirectory(prefix="prufgate-mcp-") as tmp:
        out = Path(tmp) / "out.json"
        full = [sys.executable, *cmd] + ([f"{out_flag}={out}"] if out_flag else [])
        env = dict(os.environ, WORKSPACE=str(ws), PRUFGATE_REPORTS_DIR=str(Path(tmp) / "reports"), PRUFGATE_NO_AI_ADJUDICATE="1")
        try:
            proc = subprocess.run(
                full, cwd=str(ws), env=env, capture_output=True, text=True,
                errors="replace", timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return None, f"timed out after {TIMEOUT_SECONDS}s"
        except OSError as e:
            return None, f"could not start: {e}"
        tail = (proc.stderr or proc.stdout or "").strip()[-800:]
        if proc.returncode not in (0, 1):
            return None, f"exited {proc.returncode}: {tail}"
        try:
            data = json.loads(proc.stdout if stdout_json else out.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, f"exited {proc.returncode} without writing its JSON output: {tail}"
        except ValueError:
            return None, f"exited {proc.returncode} with unreadable JSON output: {tail}"
        items = data.get("findings", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return None, "JSON output is not a list of findings"
        return items, None


def _result(
    tool: str, ws: Path, findings: Optional[list], error: Optional[str], *, cfg_ref: Optional[str] = None, **extra: Any
) -> Dict[str, Any]:
    """`cfg_ref`: the base a diff-based tool compared with ("HEAD" for the
    working-tree diff), where the configuration is read, like the engines do."""
    findings = findings or []
    try:
        # Low-confidence rules are hidden and never block unless the config turns them on.
        findings = visible(findings, low_confidence_enabled(ws, ref=cfg_ref))
    except ConfigError as exc:
        error = "; ".join(filter(None, [error, f"config: {exc}"]))
    blockers = sum(1 for f in findings if str(f.get("severity", "P0")).upper() in ("P0", "P1"))
    res: Dict[str, Any] = {
        "tool": tool,
        "workspace": str(ws),
        "status": "error" if error else "ok",
        "passed": error is None and blockers == 0,
        "blockers": blockers,
        "total_findings": len(findings),
        "findings": findings,
        **extra,
    }
    if error:
        res["error"] = error
    return res


def _check_cmd(ws: Path, changed: bool, base: Optional[str]) -> List[str]:
    cmd = [str(CLI), "check", str(ws), "--format", "json"]
    if changed:
        cmd.append("--changed")
    if base:
        cmd += ["--base", base]
    return cmd


def _bola_cmd(ws: Path, target_url: Optional[str]) -> List[str]:
    cmd = [str(CLI), "bola", str(ws), "--format", "json"]
    return cmd + (["--url", target_url] if target_url else ["--static-only"])


def prufgate_fast_scan(workspace_path: str = ".", base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engines 1-5 on changed files (`prufgate check --changed`)."""
    ws, base = _workspace(workspace_path), _base_ref(base_ref)
    findings, err = _run_json(_check_cmd(ws, True, base), ws, stdout_json=True)
    resolved, base_err = _resolve_base(ws, base)
    return _result("prufgate_fast_scan", ws, findings, err, cfg_ref=None if base_err else resolved or "HEAD", base_ref=base)


def prufgate_full_scan(workspace_path: str = ".", base_ref: Optional[str] = None, target_url: Optional[str] = None) -> Dict[str, Any]:
    """Engines 1-5 on the whole workspace (static BOLA always), the diff reviewer,
    and the live BOLA probe when `target_url` is given."""
    ws, base = _workspace(workspace_path), _base_ref(base_ref)
    if target_url:
        url_err = validate_target_url(target_url)
        if url_err:
            raise ToolInputError(url_err)
    steps: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    def add(name: str, items: Optional[list], err: Optional[str]) -> None:
        steps[name] = {"status": "error" if err else "ok", "findings": len(items or [])}
        if err:
            errors.append(f"{name}: {err}")
        findings.extend(items or [])

    add("check", *_run_json(_check_cmd(ws, False, base), ws, stdout_json=True))
    review_base, base_err = _resolve_base(ws, base)
    if base_err:
        # The whole-workspace check ran; only the diff review has no input.
        steps["review"] = {"status": "skipped", "reason": base_err}
    else:
        add("review", *_run_json(_review_cmd(ws, review_base), ws, stdout_json=True))
    if target_url:
        add("bola_live", *_run_json(_bola_cmd(ws, target_url), ws, stdout_json=True))
    cfg_ref = None if base_err else review_base or "HEAD"
    return _result(
        "prufgate_full_scan", ws, findings, "; ".join(errors) or None, cfg_ref=cfg_ref, steps=steps, base_ref=base, target_url=target_url
    )


def _review_cmd(ws: Path, base: str) -> List[str]:
    # <base>...HEAD; with no base, HEAD...HEAD is empty and the reviewer falls
    # back to the working-tree diff.
    return [str(SCRIPTS["review"]), f"--workspace={ws}", "--format=json", f"--base={base or 'HEAD'}"]


def _diff_tool(tool: str, script: str, workspace_path: str, base_ref: Optional[str]) -> Dict[str, Any]:
    ws = _workspace(workspace_path)
    base, err = _resolve_base(ws, _base_ref(base_ref))
    if err:
        return _result(tool, ws, None, err)
    return _engine_tool(tool, script, str(ws), [f"--changed={base}" if base else "--changed"], base or "HEAD")


def _engine_tool(tool: str, script: str, workspace_path: str, args: List[str], cfg_ref: Optional[str] = None) -> Dict[str, Any]:
    ws = _workspace(workspace_path)
    findings, err = _run_json([str(SCRIPTS[script]), *args], ws, out_flag="--json-out")
    return _result(tool, ws, findings, err, cfg_ref=cfg_ref)


def prufgate_anti_fabrication(workspace_path: str = ".", changed_only: bool = False, base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engine 1: fabricated production logic."""
    if changed_only:
        return _diff_tool("prufgate_anti_fabrication", "anti_fabrication", workspace_path, base_ref)
    return _engine_tool("prufgate_anti_fabrication", "anti_fabrication", workspace_path, [])


def prufgate_test_audit(workspace_path: str = ".", changed_only: bool = False, base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engine 2: hollow tests and reward hacking."""
    if changed_only:
        return _diff_tool("prufgate_test_audit", "test_audit", workspace_path, base_ref)
    return _engine_tool("prufgate_test_audit", "test_audit", workspace_path, [])


def prufgate_diff_guard(workspace_path: str = ".", base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engine 3: guardrail tampering in the diff (working tree, or against base_ref)."""
    return _diff_tool("prufgate_diff_guard", "diff_guard", workspace_path, base_ref)


def prufgate_contract_check(workspace_path: str = ".", changed_only: bool = False, base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engine 4: ghost dependencies, env drift and route mismatches."""
    ws = _workspace(workspace_path)
    if not changed_only:
        return _engine_tool("prufgate_contract_check", "contract_check", str(ws), [f"--workspace={ws}"])
    base, err = _resolve_base(ws, _base_ref(base_ref))
    if err:
        return _result("prufgate_contract_check", ws, None, err)
    return _engine_tool(
        "prufgate_contract_check", "contract_check", str(ws), [f"--changed={base}" if base else "--changed", f"--workspace={ws}"], base or "HEAD"
    )


def prufgate_bola_check(workspace_path: str = ".", target_url: Optional[str] = None) -> Dict[str, Any]:
    """Engine 5: static BOLA checks, plus the live probe when target_url is given."""
    ws = _workspace(workspace_path)
    if target_url:
        url_err = validate_target_url(target_url)
        if url_err:
            raise ToolInputError(url_err)
    findings, err = _run_json(_bola_cmd(ws, target_url), ws, stdout_json=True)
    return _result("prufgate_bola_check", ws, findings, err, live_probe=bool(target_url))


def prufgate_review(workspace_path: str = ".", base_ref: Optional[str] = None) -> Dict[str, Any]:
    """Engine 6: deterministic diff review against base_ref (resolved like prufgate check --changed)."""
    ws = _workspace(workspace_path)
    base, err = _resolve_base(ws, _base_ref(base_ref))
    if err:
        return _result("prufgate_review", ws, None, err)
    findings, err = _run_json(_review_cmd(ws, base), ws, stdout_json=True)
    return _result("prufgate_review", ws, findings, err, cfg_ref=base or "HEAD", base_ref=base or "working tree")


def prufgate_summary(workspace_path: str = ".") -> Dict[str, Any]:
    """Read the last report written by ./prufgate.sh, without running a scan."""
    ws = _workspace(workspace_path)
    sarif, md = ws / "reports" / "prufgate.sarif", ws / "reports" / "prufgate-review.md"
    return {
        "tool": "prufgate_summary",
        "workspace": str(ws),
        "status": "found" if sarif.exists() or md.exists() else "not_found",
        "sarif_report": str(sarif) if sarif.exists() else None,
        "markdown_report": str(md) if md.exists() else None,
        "markdown_content": md.read_text(encoding="utf-8", errors="replace")[:4000] if md.exists() else None,
    }


def prufgate_explain(rule: Any = None) -> Dict[str, Any]:
    """What a rule catches and how to fix it (`prufgate explain`). Reads no workspace."""
    from prufgate.explain import describe, lookup, suggestions

    if not isinstance(rule, str) or not rule.strip():
        raise ToolInputError("rule must be a rule ID, as a finding names it")
    found = lookup(rule)
    if found is None:
        return {"tool": "prufgate_explain", "status": "error",
                "error": f"no PrufGate rule named {rule!r}", "did_you_mean": suggestions(rule)}
    return {"tool": "prufgate_explain", "status": "ok", **describe(found)}


def _tool(
    name: str, title: str, description: str, props: Dict[str, Any], open_world: bool = False,
    required: Optional[List[str]] = None, workspace: bool = True,
) -> Dict[str, Any]:
    hints = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": open_world}
    properties = {"workspace_path": WS_PROP, **props} if workspace else dict(props)
    schema: Dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema, "annotations": {"title": title, **hints}, **hints}


WS_PROP = {"type": "string", "description": "Path to the repository to scan", "default": "."}
BASE_PROP = {"type": "string", "description": "Base git ref to diff against, e.g. origin/main"}
CHANGED_PROP = {"type": "boolean", "description": "Scan only changed files", "default": False}
URL_PROP = {"type": "string", "description": "Live http(s) URL for the two-token BOLA probe. The probe runs only when this is set."}

MCP_TOOLS = [
    _tool("prufgate_fast_scan", "PrufGate Fast Scan", "Run engines 1-5 (anti-fabrication, test integrity, diff guard, contract guard, static BOLA) on changed files.", {"base_ref": BASE_PROP}),
    _tool("prufgate_full_scan", "PrufGate Full Scan", "Run engines 1-5 on the whole workspace plus the diff reviewer; adds the live BOLA probe only when target_url is set.", {"base_ref": BASE_PROP, "target_url": URL_PROP}, open_world=True),
    _tool("prufgate_anti_fabrication", "PrufGate Anti-Fabrication", "Engine 1: canned fallbacks, simulated return values, stub handlers and other fabricated production logic.", {"changed_only": CHANGED_PROP, "base_ref": BASE_PROP}),
    _tool("prufgate_test_audit", "PrufGate Test Integrity", "Engine 2: zero-assertion tests, tautologies, self-mocked units and weakened assertions.", {"changed_only": CHANGED_PROP, "base_ref": BASE_PROP}),
    _tool("prufgate_diff_guard", "PrufGate Diff Guard", "Engine 3: skipped tests, suppression comments, unsafe casts and weakened lint/CI config added in the diff.", {"base_ref": BASE_PROP}),
    _tool("prufgate_contract_check", "PrufGate Contract Guard", "Engine 4: undeclared or hallucinated imports, undocumented environment variables and frontend/backend route mismatches.", {"changed_only": CHANGED_PROP, "base_ref": BASE_PROP}),
    _tool("prufgate_bola_check", "PrufGate BOLA Check", "Engine 5: routes and queries without auth or tenant scoping; the live two-token probe runs only when target_url is set.", {"target_url": URL_PROP}, open_world=True),
    _tool("prufgate_review", "PrufGate Diff Review", "Engine 6: deterministic review of the diff against base_ref (default: resolved like prufgate check --changed).", {"base_ref": BASE_PROP}),
    _tool("prufgate_summary", "PrufGate Summary", "Read the last SARIF/Markdown report written by ./prufgate.sh without running a scan.", {}),
    _tool("prufgate_explain", "PrufGate Explain Rule", "What a rule catches, how to fix it, and how to record a false positive. Pass the rule ID a finding names.",
          {"rule": {"type": "string", "description": "Rule ID, e.g. canned-error-fallback or test-skip-smuggling"}},
          required=["rule"], workspace=False),
]

HANDLERS = {
    "prufgate_fast_scan": prufgate_fast_scan,
    "prufgate_full_scan": prufgate_full_scan,
    "prufgate_anti_fabrication": prufgate_anti_fabrication,
    "prufgate_test_audit": prufgate_test_audit,
    "prufgate_diff_guard": prufgate_diff_guard,
    "prufgate_contract_check": prufgate_contract_check,
    "prufgate_bola_check": prufgate_bola_check,
    "prufgate_review": prufgate_review,
    "prufgate_summary": prufgate_summary,
    "prufgate_explain": prufgate_explain,
}


def handle_tool_call(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a tools/call. Unknown tools and arguments raise ValueError."""
    fn = HANDLERS.get(name)
    if fn is None:
        raise ValueError(f"Unknown tool: {name}")
    if not isinstance(args, dict):
        raise ToolInputError("arguments must be an object")
    allowed = set(next(t for t in MCP_TOOLS if t["name"] == name)["inputSchema"]["properties"])
    unknown = set(args) - allowed
    if unknown:
        raise ToolInputError(f"unknown argument(s) for {name}: {', '.join(sorted(unknown))}")
    return fn(**args)


def handle_message(request: Any) -> Optional[Dict[str, Any]]:
    """Answer one JSON-RPC message; notifications (no id) get no answer."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request"}}
    req_id, method = request.get("id"), request["method"]
    params = request.get("params") or {}
    if "id" not in request:
        return None
    if method == "initialize":
        wanted = params.get("protocolVersion") if isinstance(params, dict) else None
        version = wanted if wanted in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        result: Dict[str, Any] = {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "prufgate-mcp-server", "version": __version__},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": MCP_TOOLS}
    elif method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "tools/call needs a tool name"}}
        if params["name"] not in HANDLERS:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown tool: {params['name']}"}}
        try:
            data = handle_tool_call(params["name"], params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(data, indent=2)}], "isError": data.get("status") == "error"}
        except (ToolInputError, TypeError) as e:
            result = {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def run_stdio_jsonrpc_loop() -> None:
    """Read newline-delimited JSON-RPC from stdin, answer on stdout, log to stderr."""
    sys.stderr.write(f"[PrufGate MCP Server {__version__}] listening on stdio.\n")
    sys.stderr.flush()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except ValueError:
            response: Optional[Dict[str, Any]] = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            try:
                response = handle_message(request)
            except Exception as e:  # never kill the server; report the failure
                rid = request.get("id") if isinstance(request, dict) else None
                response = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": f"Internal error: {e}"}}
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


def main() -> None:
    run_stdio_jsonrpc_loop()


if __name__ == "__main__":
    from prufgate.console import utf8_output  # Windows: piped output is cp1252

    utf8_output()
    main()
