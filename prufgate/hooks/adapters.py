#!/usr/bin/env python3
"""Fail-closed hook adapters for coding agents (`prufgate hook <agent> <event>`).

Each adapter reads the agent's hook payload on stdin, applies one PrufGate
guard and answers in the agent's own protocol:

- `pre-tool`: before a tool runs. Shell tools go through the shell guard
  (`shell_guard.check_command`); file edits are refused on CI, PrufGate and
  agent-hook configuration, and file deletions also on tests.
- `shell`: Cursor's `beforeShellExecution` (the payload carries `command`).
- `stop`: when the agent finishes, run `prufgate check --changed` and send it
  back once to fix P0/P1 findings.

Unreadable input, a missing field or any internal error is a block, never a
pass. Protocols (from each agent's hook reference):

| agent   | block a tool                                         | send back at stop                     |
|---------|------------------------------------------------------|---------------------------------------|
| claude  | exit 2, reason on stderr                             | exit 2, reason on stderr              |
| codex   | exit 2, reason on stderr                             | exit 2, reason on stderr              |
| gemini  | exit 2, reason on stderr                             | exit 2, reason on stderr (AfterAgent) |
| copilot | exit 2 + {"permissionDecision": "deny", ...}         | {"decision": "block", "reason": ...}  |
| cursor  | {"permission": "deny", "agent_message": ...}         | {"followup_message": ...}             |
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from prufgate.hooks.shell_guard import RUN_IT_YOURSELF, check_command, protected, protected_config
from prufgate.process import cli_command

AGENTS = ("claude", "codex", "copilot", "cursor", "gemini")
EVENTS = ("pre-tool", "shell", "stop")

# Tool names across the supported agents. A tool in neither set is allowed:
# the matcher written by `prufgate init` decides which tools reach the adapter.
SHELL_TOOLS = {"Bash", "bash", "powershell", "Shell", "run_shell_command", "shell", "exec_command"}
EDIT_TOOLS = {
    "Edit", "Write", "MultiEdit", "NotebookEdit",  # Claude Code (Copilot's PascalCase payloads too)
    "apply_patch",  # Codex
    "edit", "create", "str_replace_editor",  # Copilot
    "StrReplace",  # Cursor
    "write_file", "replace",  # Gemini CLI
}
DELETE_TOOLS = {"Delete"}  # Cursor

_PATCH_FILE = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)
_PATH_KEY = re.compile(r"(^|_)(path|file|filename|target_file|notebook_path)$|Path$", re.I)
_STOP_TIMEOUT = 600


class BadPayload(ValueError):
    """The hook input cannot be read, so the action is refused."""


def _load(stdin_text: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdin_text)
    except ValueError as exc:
        raise BadPayload(f"the hook input is not JSON ({exc})") from exc
    if not isinstance(payload, dict):
        raise BadPayload("the hook input is not a JSON object")
    return payload


def _tool(payload: dict[str, Any]) -> tuple[str, Any]:
    """(tool name, tool input) from a snake_case or Copilot camelCase payload."""
    name = payload.get("tool_name", payload.get("toolName"))
    if not isinstance(name, str):
        raise BadPayload("the tool name is missing")
    args = payload.get("tool_input", payload.get("toolArgs"))
    if isinstance(args, str) and name != "apply_patch":
        try:  # Copilot sends toolArgs as a JSON string
            args = json.loads(args)
        except ValueError as exc:
            raise BadPayload(f"the tool arguments are not JSON ({exc})") from exc
    return name, args


def _paths(args: Any) -> list[str]:
    """Every string value under a path-like key, at any depth (MultiEdit, nested inputs)."""
    found: list[str] = []
    if isinstance(args, dict):
        for key, value in args.items():
            if isinstance(value, str) and _PATH_KEY.search(str(key)):
                found.append(value)
            elif isinstance(value, (dict, list)):
                found.extend(_paths(value))
    elif isinstance(args, list):
        for item in args:
            found.extend(_paths(item))
    return found


def _patch_paths(patch: str) -> list[tuple[str, bool]]:
    """(path, deleted) for each file a Codex apply_patch touches. A file moved away (`*** Move to:`) is deleted."""
    out: list[tuple[str, bool]] = []
    for m in _PATCH_FILE.finditer(patch):
        if m.group(3) is not None and out:
            out[-1] = (out[-1][0], True)
        out.append(((m.group(2) or m.group(3)).strip(), m.group(1) == "Delete"))
    return out


def _refuse_paths(tool: str, paths: list[tuple[str, bool]]) -> str | None:
    if not paths:
        raise BadPayload(f"no file path found in the {tool} tool input")
    for path, deleting in paths:
        why = protected(path) if deleting else protected_config(path)
        if why:
            verb = "deletes" if deleting else "changes"
            return f"`{tool}` {verb} {path!r}, which is {why}. Fix the code instead of the check. {RUN_IT_YOURSELF}"
    return None


def tool_reason(payload: dict[str, Any]) -> str | None:
    """Why this tool call must not run, or None."""
    name, args = _tool(payload)
    if name in SHELL_TOOLS:
        command = args.get("command") if isinstance(args, dict) else None
        if isinstance(command, list) and command and all(isinstance(c, str) for c in command):
            command = shlex.join(command)  # Codex shell: ["bash", "-lc", "..."]
        if not isinstance(command, str):
            raise BadPayload("the shell command is missing or not a string")
        return check_command(command)
    if name == "apply_patch":
        patch = args.get("command") if isinstance(args, dict) else args
        if isinstance(patch, list):  # older Codex payloads: ["apply_patch", "<patch>"]
            patch = "\n".join(p for p in patch if isinstance(p, str))
        if not isinstance(patch, str):
            raise BadPayload("the patch is missing or not a string")
        return _refuse_paths(name, _patch_paths(patch))
    if name in EDIT_TOOLS or name in DELETE_TOOLS:
        return _refuse_paths(name, [(p, name in DELETE_TOOLS) for p in _paths(args)])
    return None


def shell_reason(payload: dict[str, Any]) -> str | None:
    command = payload.get("command")
    if not isinstance(command, str):
        raise BadPayload("command is missing or not a string")
    return check_command(command)


def run_check(cwd: str) -> tuple[int, str]:
    """Run `prufgate check --changed` in `cwd`: (exit code, what to tell the agent)."""
    package_parent = str(Path(__file__).resolve().parent.parent.parent)
    env = dict(os.environ, PRUFGATE_NO_AI_ADJUDICATE="1")
    env["PYTHONPATH"] = os.pathsep.join(p for p in (package_parent, env.get("PYTHONPATH", "")) if p)
    try:
        r = subprocess.run(
            cli_command("check", "--changed", "--format", "agent-hook", "."),
            cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=_STOP_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 2, f"prufgate: the check could not run ({exc.__class__.__name__}); this work was not checked."
    text = (r.stderr.strip() or r.stdout.strip())
    if r.returncode not in (0, 1, 2) or (r.returncode and not text):
        text = f"prufgate: the check could not run (exit {r.returncode}); this work was not checked. {text}".strip()
    return r.returncode, text


def stop_reason(agent: str, payload: dict[str, Any]) -> tuple[str | None, str]:
    """(reason to send the agent back, note for stderr). The agent is sent back once only."""
    if agent == "cursor":
        if payload.get("status") != "completed":
            return None, ""
        again = payload.get("loop_count", 0) != 0
    else:
        again = payload.get("stop_hook_active") is True
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        roots = payload.get("workspace_roots")
        cwd = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else os.getcwd()
    rc, text = run_check(cwd)
    if rc == 0:
        return None, ""
    if again:
        return None, f"{text}\nprufgate: already sent back once; reporting without blocking again."
    return text or "prufgate: the check failed; this work was not checked.", ""


def respond(agent: str, event: str, reason: str | None) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) in the agent's protocol for a block (reason) or an allow (None)."""
    if agent == "cursor":
        if event == "stop":
            return 0, json.dumps({"followup_message": reason} if reason else {}), ""
        if reason:
            return 0, json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason}), ""
        return 0, json.dumps({"permission": "allow"}), ""
    if agent == "copilot":
        if not reason:
            return 0, "", ""
        if event == "stop":
            return 0, json.dumps({"decision": "block", "reason": reason}), ""
        # Exit 2 denies a preToolUse call even if the JSON were lost.
        return 2, json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}), reason
    # claude, codex, gemini: exit 2 with the reason on stderr blocks the tool or continues the turn.
    return (2, "", reason) if reason else (0, "", "")


def handle(agent: str, event: str, stdin_text: str) -> tuple[int, str, str]:
    """Run one adapter. Any error blocks."""
    note = ""
    try:
        if agent not in AGENTS or event not in EVENTS or (event == "shell" and agent != "cursor"):
            raise BadPayload(f"unsupported agent/event {agent} {event}")
        payload = _load(stdin_text)
        if event == "stop":
            reason, note = stop_reason(agent, payload)
        else:
            found = shell_reason(payload) if event == "shell" else tool_reason(payload)
            reason = f"prufgate blocked this: {found}" if found else None
    except BadPayload as exc:
        reason = f"prufgate hook {agent} {event}: {exc}; blocking."
    except Exception as exc:  # fail closed: a crash must never allow the action
        reason = f"prufgate hook {agent} {event}: could not check ({exc.__class__.__name__}); blocking."
    rc, out, err = respond(agent, event, reason)
    return rc, out, "\n".join(x for x in (err, note) if x)


def main(agent: str, event: str) -> int:
    try:
        rc, out, err = handle(agent, event, sys.stdin.read())
    except Exception as exc:  # stdin unreadable: block in the agent's own protocol
        reason = f"prufgate hook: could not check ({exc.__class__.__name__}); blocking."
        try:
            rc, out, err = respond(agent, event, reason)
        except Exception:
            rc, out, err = 2, "", reason
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return rc
