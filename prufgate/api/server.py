#!/usr/bin/env python3
"""
PrufGate REST API & Webhook Service
Provides HTTP endpoints for triggering audits, querying scan statuses,
retrieving SARIF / Markdown reports, receiving CI webhooks, and browsing OpenAPI docs.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

PRUFGATE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PRUFGATE_ROOT) not in sys.path:
    sys.path.insert(0, str(PRUFGATE_ROOT))

from prufgate import __version__  # noqa: E402
from prufgate.config import ConfigError  # noqa: E402
from prufgate.netguard import target_url_error  # noqa: E402
from prufgate.privacy import redact  # noqa: E402
from prufgate.process import cli_command  # noqa: E402
from prufgate.result_validation import read_json, validate_sarif  # noqa: E402
from prufgate.rules import low_confidence_enabled, visible  # noqa: E402
from prufgate.safe_fs import safe_read_text, safe_remove_tree, safe_write_text  # noqa: E402
from prufgate.scan_result import (  # noqa: E402
    make_result,
    metadata_from_sarif,
    redact_result,
    validate_result,
)

# In-memory scan store and active subprocess map
SCANS: Dict[str, Dict[str, Any]] = {}
SCAN_PROCESSES: Dict[str, subprocess.Popen[str]] = {}
SCANS_LOCK = threading.Lock()

# The gate modes that produce a SARIF report: fast/check scan changed files,
# review/full the whole workspace.
BATTERIES = ("fast", "check", "review", "full")
SCAN_TIMEOUT = int(os.environ.get("PRUFGATE_API_SCAN_TIMEOUT", "600"))
MAX_BODY_BYTES = 1 << 20
MAX_SCAN_HISTORY = 200
REPORT_RETENTION_SECONDS = 24 * 60 * 60
HTTP_TIMEOUT = 30
MAX_CONNECTIONS = 16
PROCESS_GRACE_SECONDS = 1

# Set by run_server; module-level so the handler and the tests share them.
API_TOKEN = ""
WEBHOOK_SECRET = ""
MAX_RUNNING = 2


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def workspace_root() -> Path:
    """The only directory scans may run in. Every requested workspace must
    resolve inside it, so a caller cannot point a scan at /etc or $HOME."""
    configured = os.environ.get("PRUFGATE_WORKSPACE_ROOT")
    if configured:
        return Path(configured).resolve()
    if Path("/workspace").is_dir():
        return Path("/workspace").resolve()
    return Path.cwd().resolve()


def resolve_workspace(requested: Any) -> Path:
    if requested is None:
        requested = "."
    if not isinstance(requested, str) or "\x00" in requested:
        raise RequestError(400, "workspace must be a path string")
    root = workspace_root()
    candidate = Path(requested)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise RequestError(403, "workspace must be inside the configured workspace root")
    if not resolved.is_dir():
        raise RequestError(400, "workspace does not exist")
    return resolved


def validate_battery(battery: Any) -> str:
    if battery not in BATTERIES:
        raise RequestError(400, f"battery must be one of: {', '.join(BATTERIES)}")
    return battery


def validate_target_url(target_url: Any) -> Optional[str]:
    if target_url is None:
        return None
    err = target_url_error(target_url)
    if err:
        raise RequestError(400, f"target_url refused: {err}")
    return target_url


def bearer_ok(header: Optional[str]) -> bool:
    if not API_TOKEN or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):].encode(), API_TOKEN.encode())


def webhook_signature_ok(headers: Any, body: bytes) -> bool:
    """GitHub signs the raw body (X-Hub-Signature-256); GitLab sends the shared
    secret itself (X-Gitlab-Token). Either must match WEBHOOK_SECRET."""
    if not WEBHOOK_SECRET:
        return False
    sig = headers.get("X-Hub-Signature-256")
    if sig:
        expected = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig.encode(), expected.encode())
    token = headers.get("X-Gitlab-Token")
    if token:
        return hmac.compare_digest(token.encode(), WEBHOOK_SECRET.encode())
    return False


def _terminate_scan_process(scan_id: str) -> None:
    """Terminate, escalate and reap; the runner owns registration until cleanup."""
    with SCANS_LOCK:
        proc = SCAN_PROCESSES.get(scan_id)
    if proc is None:
        return
    _stop_process(proc)


def _signal_process(proc: subprocess.Popen[str], force: bool = False) -> None:
    try:
        if os.name == "posix":
            # The group ID is fixed at startup, even after the leader exits.
            os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
        elif proc.poll() is None:
            proc.kill() if force else proc.terminate()
    except ProcessLookupError:
        pass


def _stop_process(proc: subprocess.Popen[str]) -> None:
    _signal_process(proc)
    try:
        proc.wait(timeout=PROCESS_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # Descendants can survive after the group leader handles SIGTERM.
        _signal_process(proc, force=True)
        proc.wait()


def _remove_scan_artifacts(scan: Dict[str, Any]) -> None:
    scan_id, workspace = scan.get("scan_id"), scan.get("workspace")
    if not isinstance(scan_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", scan_id) or not workspace:
        return
    try:
        safe_remove_tree(Path(workspace) / "reports" / "scans" / scan_id)
    except OSError:
        # Never follow links or broaden cleanup after a refusal.
        print("prufgate api: could not safely remove scan artifacts", file=sys.stderr)


def prune_scan_history(workspace: Optional[Path] = None) -> None:
    """Bound finished history and artifacts, including orphaned reports after restart."""
    now = time.time()
    evicted = []
    with SCANS_LOCK:
        finished = [(sid, scan) for sid, scan in SCANS.items()
                    if scan.get("status") not in ("queued", "running") and sid not in SCAN_PROCESSES]
        for index, (sid, scan) in enumerate(reversed(finished)):
            try:
                stamp = datetime.datetime.fromisoformat(scan.get("completed_at", scan.get("created_at", ""))).timestamp()
            except (TypeError, ValueError):
                stamp = now
            if index >= MAX_SCAN_HISTORY or now - stamp > REPORT_RETENTION_SECONDS:
                evicted.append(SCANS.pop(sid))
        active = set(SCANS) | set(SCAN_PROCESSES)
        retained = sum(1 for scan in SCANS.values() if scan.get("workspace") == str(workspace)
                       and scan.get("status") not in ("queued", "running")) if workspace is not None else 0
    for scan in evicted:
        _remove_scan_artifacts(scan)
    if workspace is None:
        return
    parent = workspace / "reports" / "scans"
    # Refuse linked parents before listing. Each deletion is checked again.
    if any(p.is_symlink() for p in (workspace / "reports", parent)) or not parent.is_dir():
        return
    candidates = []
    try:
        for path in parent.iterdir():
            # Only service-generated UUIDs may be reclaimed without an in-memory record.
            if path.name not in active and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", path.name):
                candidates.append((path.lstat().st_mtime, path.name))
        for index, (stamp, sid) in enumerate(sorted(candidates, reverse=True)):
            if index >= max(0, MAX_SCAN_HISTORY - retained) or now - stamp > REPORT_RETENTION_SECONDS:
                _remove_scan_artifacts({"scan_id": sid, "workspace": str(workspace)})
    except OSError:
        print("prufgate api: could not inspect retained scan artifacts", file=sys.stderr)


def scan_command(battery: str, workspace: Path, profile: str = "battery", result_out: Optional[Path] = None) -> tuple[list[str], bool]:
    """The command for a battery, and whether its stdout is the SARIF report.

    From a source checkout or the container, ./prufgate.sh runs the full gate
    (engines plus optional gitleaks/ast-grep/zizmor) and writes SARIF and
    Markdown. A pip install has no prufgate.sh: `prufgate check` then writes SARIF to
    stdout (engines 1-5, no Markdown report).
    """
    if profile == "core":
        cmd = cli_command("check", str(workspace), "--format", "sarif")
        if battery in ("fast", "check"):
            cmd.append("--changed")
        if result_out:
            cmd.extend(("--result-out", str(result_out)))
        return cmd, True
    prufgate_script = PRUFGATE_ROOT / "prufgate.sh"
    if prufgate_script.is_file():
        return ["bash", str(prufgate_script), battery], False
    cmd = cli_command("check", str(workspace), "--format", "sarif")
    if battery in ("fast", "check"):
        cmd.insert(-2, "--changed")
    return cmd, True


def run_scan_process(scan_id: str, cmd: list[str], cwd: Path, env: Dict[str, str]) -> tuple[int, str, str]:
    """Run one scan in its own process group so DELETE can stop it."""
    with SCANS_LOCK:
        if scan_id not in SCANS:
            return 130, "", "Scan cancelled before process startup"
        # DELETE takes the same lock: startup and registration are one operation.
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            env=env, start_new_session=True,
        )
        SCAN_PROCESSES[scan_id] = proc
    try:
        stdout, stderr = proc.communicate(timeout=SCAN_TIMEOUT)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        _stop_process(proc)
        # Drain and close pipes after killing; never leave an unreaped Popen behind.
        try:
            proc.communicate(timeout=PROCESS_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return 124, "", f"Scan timed out after {SCAN_TIMEOUT} seconds"
    finally:
        _stop_process(proc)
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
        with SCANS_LOCK:
            SCAN_PROCESSES.pop(scan_id, None)


def execute_scan_worker(scan_id: str, battery: str, workspace: str, target_url: Optional[str]) -> None:
    """Run a scan with its own report directory and record the outcome.

    Only this scan's own SARIF counts: a missing or unreadable report is an
    error with no finding counts, never zero findings, and never an older
    report left in the workspace.
    """
    with SCANS_LOCK:
        if scan_id not in SCANS:
            return
        SCANS[scan_id]["status"] = "running"
        SCANS[scan_id]["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        profile = SCANS[scan_id].get("profile", "battery")

    start_time = time.time()
    ws_path = Path(workspace)
    reports_root = ws_path / "reports"
    isolated_reports_dir = reports_root / "scans" / scan_id
    sarif_path = isolated_reports_dir / "prufgate.sarif"
    markdown_path = isolated_reports_dir / "prufgate-review.md"
    try:
        # reports/ is inside the scanned repository: never follow a planted symlink.
        for p in (reports_root, reports_root / "scans", isolated_reports_dir):
            if p.is_symlink():
                raise OSError(f"{p} is a symlink; refusing to write reports through it")
        isolated_reports_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["WORKSPACE"] = str(ws_path)
        env["PRUFGATE_REPORTS_DIR"] = str(isolated_reports_dir)
        env["PRUFGATE_NO_AI_ADJUDICATE"] = "1"  # the REST API never calls AI adjudication
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(PRUFGATE_ROOT), env.get("PYTHONPATH")]))
        env.pop("TARGET_URL", None)
        if target_url:
            env["TARGET_URL"] = target_url
        cmd, sarif_on_stdout = scan_command(battery, ws_path, profile, isolated_reports_dir / "prufgate-result.json")
        exit_code, stdout, stderr = run_scan_process(scan_id, cmd, ws_path, env)
        if sarif_on_stdout and exit_code in (0, 1):
            safe_write_text(sarif_path, stdout, encoding="utf-8")
            stdout = ""
    except Exception as e:
        exit_code, stdout, stderr = 2, "", f"Execution error: {e}"

    elapsed = round(time.time() - start_time, 2)

    # Count findings from this scan's SARIF report.
    p0 = p1 = p2 = p3 = 0
    counted = False
    findings_error = None
    metadata, normalized = {}, []
    effective_blockers = 0
    # The base the battery compared with (its changed scope writes it; empty means
    # HEAD): the configuration is read there, like the engines do.
    ref_file = isolated_reports_dir / "raw" / "base_ref"
    try:
        cfg_ref = (safe_read_text(ref_file, encoding="utf-8").strip() or "HEAD") if ref_file.is_file() and not ref_file.is_symlink() else None
    except OSError:
        cfg_ref = None
    try:
        enable_low = low_confidence_enabled(ws_path, ref=cfg_ref)
    except ConfigError as e:
        enable_low, exit_code = False, max(exit_code, 2)
        stderr = f"{stderr}\nconfig: {e}"
    if not sarif_path.exists():
        findings_error = "no SARIF report was produced"
        if stderr.strip():
            findings_error += f". Execution error: {stderr.strip()[-500:]}"
    else:
        try:
            sarif_data = validate_sarif(read_json(safe_read_text(sarif_path, encoding="utf-8")))
            metadata = metadata_from_sarif(sarif_data)
            for run in sarif_data.get("runs", []):
                # Only the findings the gate reports: low-confidence rules stay hidden unless enabled.
                for res in visible(run.get("results", []), enable_low):
                    if any(s.get("status", "accepted") == "accepted" for s in res.get("suppressions", [])):
                        continue  # an honoured inline ignore: listed, never counted
                    sev = (res.get("properties") or {}).get("severity") or {"error": "P1", "warning": "P2"}.get(res.get("level"), "P3")
                    props = res.get("properties", {})
                    effective_blockers += props.get("blocking", sev in ("P0", "P1")) is True
                    location = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                    normalized.append({"rule": res.get("ruleId", "unknown-rule"), "severity": sev,
                                       "engine": props.get("engine", props.get("tool", "prufgate")),
                                       "file": location.get("artifactLocation", {}).get("uri", "workspace"),
                                       "line": location.get("region", {}).get("startLine", 1),
                                       "message": res.get("message", {}).get("text", ""),
                                       "confidence": props.get("confidence")})
                    if sev == "P0":
                        p0 += 1
                    elif sev == "P1":
                        p1 += 1
                    elif sev == "P2":
                        p2 += 1
                    else:
                        p3 += 1
            counted = True
        except (OSError, ValueError, AttributeError) as e:
            findings_error = f"SARIF report could not be read: {e.__class__.__name__}"

    if not counted and profile == "core":
        try:
            fallback = validate_result(read_json(safe_read_text(isolated_reports_dir / "prufgate-result.json")))
            metadata, normalized = fallback, fallback["findings"]
        except (OSError, ValueError):
            pass

    if counted and exit_code in (0, 1) and (exit_code == 0) != (effective_blockers == 0):
        findings_error = "scanner exit code disagrees with blocking findings"
        exit_code = 2
    if exit_code not in (0, 1) or not counted:
        verdict = "ERROR"
    else:
        verdict = "PASSED" if exit_code == 0 else "FAILED"

    incomplete = metadata.get("incomplete_reasons", []) if exit_code not in (0, 1) else []
    issues = [findings_error] if findings_error else []
    if exit_code not in (0, 1) and not incomplete:
        issues += metadata.get("errors") or ["Scan execution did not complete."]
    if metadata.get("scan_status") in ("error", "incomplete") and exit_code in (0, 1):
        issues.append("SARIF records an unsuccessful scan despite a successful exit code.")
    result = make_result(normalized, root=ws_path, coverage=metadata.get("coverage"), errors=issues,
                         incomplete=incomplete, profile=metadata.get("profile", profile),
                         # The scan already applied policy and dismissals: never twice.
                         enforcement=metadata.get("enforcement"), revision=metadata.get("revision"))
    if metadata.get("governance"):
        result["governance"] = metadata["governance"]
    exit_code = result["exit_code"]
    if result["scan_status"] in ("incomplete", "error"):
        verdict = "ERROR"

    with SCANS_LOCK:
        if scan_id in SCANS:
            # Cancellation cannot publish reports after removing the scan record.
            if counted and exit_code in (0, 1):
                for src in (sarif_path, markdown_path):
                    if src.is_file() and not src.is_symlink():
                        try:
                            safe_write_text(reports_root / src.name, safe_read_text(src, encoding="utf-8"))
                        except OSError:
                            pass
            SCANS[scan_id].update({
                **{key: value for key, value in result.items() if key != "exit_code"},
                "status": "completed",
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "elapsed_seconds": elapsed,
                "exit_code": exit_code,
                "verdict": verdict,
                "blockers": result["summary"]["blockers"] if counted else None,
                "advisories": result["summary"]["advisories"] if counted else None,
                "findings_summary": {"p0": p0, "p1": p1, "p2": p2, "p3": p3} if counted else None,
                "findings_error": findings_error,
                "sarif_path": str(sarif_path) if sarif_path.exists() else None,
                "markdown_path": str(markdown_path) if markdown_path.exists() else None,
                "log": redact((stdout + "\n" + stderr).strip()),
            })
            deleted = False
        else:
            deleted = True
    if deleted:
        _remove_scan_artifacts({"scan_id": scan_id, "workspace": workspace})
    prune_scan_history(ws_path)


OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "PrufGate REST API",
        "description": "Start PrufGate scans, read their SARIF and Markdown reports, and receive CI webhooks.",
        "version": __version__,
        "contact": {
            "name": "PrufGate",
        },
    },
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
            "webhookSignature": {"type": "apiKey", "in": "header", "name": "X-Hub-Signature-256"},
        }
    },
    "security": [{"bearer": []}],
    "paths": {
        "/api/v1/health": {
            "get": {
                "summary": "Engine Health Check",
                "security": [],
                "responses": {
                    "200": {"description": "Service is healthy and operational"}
                }
            }
        },
        "/api/v1/scan": {
            "post": {
                "summary": "Trigger a New Audit Scan",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "battery": {
                                        "type": "string",
                                        "enum": list(BATTERIES),
                                        "default": "review"
                                    },
                                    "profile": {"type": "string", "enum": ["core", "battery"], "default": "battery",
                                                "description": "core matches CLI check and editor scans; battery includes the shell gate when installed"},
                                    "workspace": {
                                        "type": "string",
                                        "default": ".",
                                        "description": "Path inside PRUFGATE_WORKSPACE_ROOT"
                                    },
                                    "target_url": {
                                        "type": "string",
                                        "description": "Optional http(s) URL for the live two-token BOLA probe (prufgate.sh only)"
                                    },
                                    "async": {
                                        "type": "boolean",
                                        "default": True
                                    },
                                    "dry_run": {
                                        "type": "boolean",
                                        "default": False
                                    }
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "202": {"description": "Scan queued or running"},
                    "200": {"description": "Scan completed (synchronous mode) or dry-run successful"}
                }
            }
        },
        "/api/v1/scans": {
            "get": {
                "summary": "List All Scans",
                "responses": {
                    "200": {"description": "A list of all known scans"}
                }
            }
        },
        "/api/v1/scans/{scan_id}": {
            "get": {
                "summary": "Get Scan Status and Summary",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Current status and metrics of the requested scan"},
                    "404": {"description": "Scan not found"}
                }
            },
            "delete": {
                "summary": "Cancel or Delete a Scan",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Scan deleted"},
                    "404": {"description": "Scan not found"}
                }
            }
        },
        "/api/v1/scans/{scan_id}/sarif": {
            "get": {
                "summary": "Retrieve SARIF 2.1.0 Report",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "SARIF 2.1.0 JSON payload"},
                    "404": {"description": "SARIF report not found"}
                }
            }
        },
        "/api/v1/scans/{scan_id}/report": {
            "get": {
                "summary": "Retrieve Markdown Audit Review",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Markdown formatted audit report"},
                    "404": {"description": "Report not found"}
                }
            }
        },
        "/api/v1/webhook": {
            "post": {
                "summary": "Handle GitHub or GitLab Incoming Webhook",
                "description": "Requires PRUFGATE_WEBHOOK_SECRET. GitHub requests must carry a valid X-Hub-Signature-256; GitLab requests an X-Gitlab-Token equal to the secret.",
                "security": [{"webhookSignature": []}],
                "responses": {
                    "202": {"description": "Webhook received and audit scan initiated"},
                    "401": {"description": "Missing or invalid signature"},
                    "503": {"description": "No webhook secret is configured"}
                }
            }
        }
    }
}

SWAGGER_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>PrufGate REST API Documentation</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css"
        integrity="sha384-+yyzNgM3K92sROwsXxYCxaiLWxWJ0G+v/9A+qIZ2rgefKgkdcmJI+L601cqPD/Ut" crossorigin="anonymous">
  <style>
    body { margin: 0; background: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .swagger-ui .topbar { display: none; }
    #swagger-ui { background: #ffffff; margin: 24px auto; max-width: 1200px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); padding: 16px; min-height: 80vh; }
    .header { padding: 24px 32px; background: #020617; border-bottom: 1px solid #1e293b; color: white; display: flex; align-items: center; justify-content: space-between; }
    .header h1 { margin: 0; font-size: 20px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 10px; }
    .badge { background: #1e293b; padding: 4px 10px; border-radius: 9999px; font-size: 12px; color: #94a3b8; font-weight: 600; }
  </style>
</head>
<body>
  <div class="header">
    <h1>PrufGate REST API</h1>
    <span class="badge">v{VERSION}</span>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"
          integrity="sha384-qn5tagrAjZi8cSmvZ+k3zk4+eDEEUcP9myuR2J6V+/H6rne++v6ChO7EeHAEzqxQ" crossorigin="anonymous"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>
"""
# The page loads only the pinned, integrity-checked Swagger UI files and its own
# inline start-up script (allowed by hash); the UI applies inline styles.
_SWAGGER_SCRIPT = SWAGGER_HTML.split("<script>", 1)[1].split("</script>", 1)[0]
SWAGGER_CSP = (
    "default-src 'none'; "
    "script-src https://unpkg.com 'sha256-"
    + base64.b64encode(hashlib.sha256(_SWAGGER_SCRIPT.encode("utf-8")).digest()).decode("ascii") + "'; "
    "style-src https://unpkg.com 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class PrufGateHTTPServer(ThreadingHTTPServer):
    """Bound request threads and the lifetime of every accepted connection."""

    daemon_threads = True

    def __init__(self, address, handler):
        self._connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._last_prune = 0.0
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(HTTP_TIMEOUT)
        return connection, address

    def process_request(self, request, client_address):
        if not self._connections.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def service_actions(self):
        if time.monotonic() - self._last_prune >= 60:
            self._last_prune = time.monotonic()
            prune_scan_history()


class PrufGateAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for PrufGate REST API.

    No CORS headers: the API is for CI systems and local tools, not for other
    origins' pages, and a browser page must not be able to start a scan.
    """

    server_version = "PrufGate"
    sys_version = ""

    def handle(self) -> None:
        # A socket timeout alone resets on every byte and permits a slow drip forever.
        def expire():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = threading.Timer(HTTP_TIMEOUT, expire)
        deadline.daemon = True
        deadline.start()
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass  # The connection deadline or client closed the socket.
        finally:
            deadline.cancel()

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(redact_result(data), indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain", csp: str = "") -> None:
        # A page with its own CSP is this module's constant (integrity hashes would
        # read as secrets); everything else may carry scan output and is redacted.
        payload = (text if csp else redact(text)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        if bearer_ok(self.headers.get("Authorization")):
            return True
        self._send_json(401, {"error": "A valid Authorization: Bearer <PRUFGATE_API_TOKEN> header is required"})
        return False

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1:
            raise RequestError(400, "send one Content-Length without Transfer-Encoding")
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            raise RequestError(400, "invalid Content-Length") from None
        if length < 0:
            raise RequestError(400, "invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise RequestError(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
        try:
            body = self.rfile.read(length) if length else b""
        except TimeoutError:
            raise RequestError(408, "request body deadline exceeded") from None
        if len(body) != length:
            raise RequestError(400, "incomplete request body")
        return body

    def _get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with SCANS_LOCK:
            scan = SCANS.get(scan_id)
            return dict(scan) if scan else None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/health", "/api/v1/health"):
            self._send_json(200, {
                "status": "healthy",
                "service": "PrufGate Verification Engine",
                "version": __version__,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            return

        if path == "/openapi.json":
            self._send_json(200, OPENAPI_SPEC)
            return

        if path in ("/docs", "/api"):
            self._send_text(200, SWAGGER_HTML.replace("{VERSION}", __version__), content_type="text/html", csp=SWAGGER_CSP)
            return

        if path == "/api/v1/scans":
            if not self._authorized():
                return
            with SCANS_LOCK:
                # Return a summary of all scans
                scan_list = [
                    {
                        "scan_id": s_id,
                        "status": s.get("status"),
                        "battery": s.get("battery"),
                        "created_at": s.get("created_at"),
                    }
                    for s_id, s in SCANS.items()
                ]
            self._send_json(200, {"scans": scan_list})
            return

        m = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)(/sarif|/report)?$", path)
        if not m:
            self._send_json(404, {"error": "Endpoint not found"})
            return
        if not self._authorized():
            return

        scan_id, kind = m.group(1), m.group(2)
        scan = self._get_scan(scan_id)
        if not scan:
            self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})
            return
        if kind is None:
            self._send_json(200, scan)
            return
        if scan.get("status") in ("queued", "running"):
            self._send_json(202, {"status": scan.get("status"), "message": "Scan is still in progress. Please retry after completion.", "scan_id": scan_id})
            return

        if kind == "/sarif":
            sarif_file = scan.get("sarif_path")
            if sarif_file and Path(sarif_file).exists():
                try:
                    self._send_json(200, json.loads(safe_read_text(Path(sarif_file), encoding="utf-8")))
                except (OSError, ValueError):
                    self._send_json(500, {"error": "Failed to parse SARIF report", "scan_id": scan_id})
            else:
                self._send_json(404, {"error": "SARIF file not generated or missing", "scan_id": scan_id})
            return

        rep_file = scan.get("markdown_path")
        if rep_file and Path(rep_file).exists():
            self._send_text(200, safe_read_text(Path(rep_file), encoding="utf-8"), content_type="text/markdown")
        else:
            self._send_json(404, {"error": "Report not generated or missing", "scan_id": scan_id})

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        m = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)$", path)
        if not m:
            self._send_json(404, {"error": "Endpoint not found"})
            return
        if not self._authorized():
            return

        scan_id = m.group(1)
        found = False
        with SCANS_LOCK:
            if scan_id in SCANS:
                found = True
                record = SCANS.pop(scan_id)
        if found:
            _terminate_scan_process(scan_id)
            _remove_scan_artifacts({"scan_id": scan_id, "workspace": record.get("workspace")})
            self._send_json(200, {"message": "Scan deleted", "scan_id": scan_id})
        else:
            self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        try:
            if path == "/api/v1/scan":
                self._post_scan()
            elif path == "/api/v1/webhook":
                self._post_webhook()
            else:
                self._send_json(404, {"error": "Endpoint not found"})
        except RequestError as e:
            self._send_json(e.status, {"error": e.message})

    def _start(self, record: Dict[str, Any], battery: str, workspace: Path,
               target_url: Optional[str], is_async: bool = True) -> Optional[Dict[str, Any]]:
        """Register and start a scan, or refuse when too many are running."""
        prune_scan_history(workspace)
        with SCANS_LOCK:
            active = {sid for sid, s in SCANS.items() if s.get("status") in ("queued", "running")} | set(SCAN_PROCESSES)
            if len(active) >= MAX_RUNNING:
                raise RequestError(429, "too many scans are running; retry later")
            SCANS[record["scan_id"]] = record
        if is_async:
            try:
                threading.Thread(
                    target=execute_scan_worker,
                    args=(record["scan_id"], battery, str(workspace), target_url),
                    daemon=True,
                ).start()
            except RuntimeError:
                with SCANS_LOCK:
                    SCANS.pop(record["scan_id"], None)
                raise RequestError(503, "could not start scan worker") from None
            return None
        execute_scan_worker(record["scan_id"], battery, str(workspace), target_url)
        return self._get_scan(record["scan_id"])

    def _post_scan(self) -> None:
        if not self._authorized():
            return
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "Content-Type must be application/json")
        body = self._read_body()
        try:
            payload = json.loads(body) if body.strip() else {}
        except ValueError:
            raise RequestError(400, "body is not valid JSON") from None
        if not isinstance(payload, dict):
            raise RequestError(400, "body must be a JSON object")

        battery = validate_battery(payload.get("battery", "review"))
        workspace = resolve_workspace(payload.get("workspace", "."))
        target_url = validate_target_url(payload.get("target_url"))
        profile = payload.get("profile", "battery")
        if profile not in ("core", "battery"):
            raise RequestError(400, "profile must be core or battery")
        if profile == "core" and target_url:
            raise RequestError(400, "core profile is static; request battery for live probes")
        is_async = payload.get("async", payload.get("is_async", True)) is not False
        dry_run = payload.get("dry_run", False) is not False

        if dry_run:
            self._send_json(200, {
                "status": "completed",
                "message": "Dry run successful. Parameters are valid.",
                "battery": battery,
                "workspace": str(workspace),
                "target_url": target_url
            })
            return

        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "battery": battery,
            "profile": profile,
            "workspace": str(workspace),
            "target_url": target_url,
            "status": "queued",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        result = self._start(record, battery, workspace, target_url, is_async)
        if result is not None:
            self._send_json(200, result)
            return
        self._send_json(202, {
            "scan_id": scan_id,
            "status": "queued",
            "message": f"PrufGate audit '{battery}' enqueued",
            "status_url": f"/api/v1/scans/{scan_id}",
            "sarif_url": f"/api/v1/scans/{scan_id}/sarif",
            "report_url": f"/api/v1/scans/{scan_id}/report",
        })

    def _post_webhook(self) -> None:
        if not WEBHOOK_SECRET:
            raise RequestError(503, "webhooks are disabled: set PRUFGATE_WEBHOOK_SECRET to enable them")
        body = self._read_body()
        if not webhook_signature_ok(self.headers, body):
            raise RequestError(401, "missing or invalid webhook signature")

        event_type = self.headers.get("X-GitHub-Event") or self.headers.get("X-Gitlab-Event") or "push"
        if event_type == "ping":
            self._send_json(200, {"status": "pong"})
            return
        try:
            payload = json.loads(body) if body.strip() else {}
        except ValueError:
            raise RequestError(400, "body is not valid JSON") from None
        repo = payload.get("repository") if isinstance(payload, dict) else None
        repo_name = repo.get("name", "webhook-repo") if isinstance(repo, dict) else "webhook-repo"
        workspace = resolve_workspace(os.environ.get("PRUFGATE_DEFAULT_WORKSPACE", "."))

        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "event": event_type,
            "repository": str(repo_name)[:200],
            "battery": "review",
            "workspace": str(workspace),
            "status": "queued",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._start(record, "review", workspace, None)
        self._send_json(202, {
            "scan_id": scan_id,
            "event": event_type,
            "status": "enqueued",
            "status_url": f"/api/v1/scans/{scan_id}",
        })


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def configure(token: Optional[str] = None, webhook_secret: Optional[str] = None,
              max_running: Optional[int] = None) -> bool:
    """Set the server's credentials. Returns True when the token was generated."""
    global API_TOKEN, WEBHOOK_SECRET, MAX_RUNNING, HTTP_TIMEOUT, MAX_CONNECTIONS, MAX_SCAN_HISTORY, REPORT_RETENTION_SECONDS
    token = token if token is not None else os.environ.get("PRUFGATE_API_TOKEN", "")
    generated = not token
    API_TOKEN = token or secrets.token_urlsafe(32)
    WEBHOOK_SECRET = webhook_secret if webhook_secret is not None else os.environ.get("PRUFGATE_WEBHOOK_SECRET", "")
    if max_running is None:
        try:
            max_running = int(os.environ.get("PRUFGATE_API_MAX_SCANS", "2"))
        except ValueError:
            max_running = 2
    MAX_RUNNING = max(1, max_running)
    for name, default in (("HTTP_TIMEOUT", 30), ("MAX_CONNECTIONS", 16), ("MAX_SCAN_HISTORY", 200), ("REPORT_RETENTION_SECONDS", 86400)):
        setting = {"HTTP_TIMEOUT": "HTTP_TIMEOUT", "MAX_CONNECTIONS": "MAX_CONNECTIONS",
                   "MAX_SCAN_HISTORY": "MAX_HISTORY", "REPORT_RETENTION_SECONDS": "RETENTION_SECONDS"}[name]
        try:
            value = int(os.environ.get("PRUFGATE_API_" + setting, str(default)))
        except ValueError:
            value = default
        globals()[name] = max(1, value)
    return generated


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    generated = configure()
    if not is_loopback(host) and generated:
        print("Refusing to listen on a non-loopback address without PRUFGATE_API_TOKEN set.", file=sys.stderr)
        sys.exit(2)
    server = PrufGateHTTPServer((host, port), PrufGateAPIHandler)
    print("══════════════════════════════════════════════════════════════════════")
    print(f"  PrufGate REST API Server listening on http://{host}:{port}")
    print(f"  Workspace root:               {workspace_root()}")
    print(f"  Swagger OpenAPI Documentation: http://{host}:{port}/docs")
    print(f"  Health Check:                 http://{host}:{port}/api/v1/health")
    if generated:
        print(f"  API token (generated for this run): {API_TOKEN}")
    print(f"  Webhooks: {'enabled' if WEBHOOK_SECRET else 'disabled (set PRUFGATE_WEBHOOK_SECRET)'}")
    print("══════════════════════════════════════════════════════════════════════", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down PrufGate REST API Server.")
    finally:
        server.server_close()
        with SCANS_LOCK:
            cancelled = [SCANS.pop(sid) for sid in list(SCANS)
                         if SCANS[sid].get("status") in ("queued", "running")]
            active_ids = list(SCAN_PROCESSES)
        for scan_id in active_ids:
            _terminate_scan_process(scan_id)
        for record in cancelled:
            _remove_scan_artifacts(record)


def main() -> None:
    parser = argparse.ArgumentParser(description="PrufGate REST API & Webhook Service")
    parser.add_argument("--host", default=os.environ.get("PRUFGATE_API_HOST", "127.0.0.1"),
                        help="Host interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    from prufgate.console import utf8_output  # Windows: piped output is cp1252

    utf8_output()
    main()
