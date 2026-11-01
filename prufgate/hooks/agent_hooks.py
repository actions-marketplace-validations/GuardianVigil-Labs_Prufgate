#!/usr/bin/env python3
"""PrufGate Workspace Initializer & Coding Agent Stop Hook Generators (`prufgate/hooks/agent_hooks.py`).

Generates:
1. `.prufgate/config.yaml`: Clean YAML configuration for PrufGate.
2. `.claude/settings.json`: Claude Code `Stop` hook running `prufgate check --changed --format agent-hook`,
   and a `PreToolUse` (Bash) hook running `prufgate shell-guard`.
   plus a `PreToolUse` (Edit/Write) hook running `prufgate hook claude pre-tool`.
3. `.cursor/hooks.json` (fail-closed `beforeShellExecution`, `preToolUse` and `stop`) and
   `.cursor/rules/prufgate-guardrails.mdc`.
4. With `--agent`: `.github/hooks/prufgate.json` (Copilot), `.codex/hooks.json` (Codex),
   `.gemini/settings.json` (Gemini CLI). See docs/AGENT_HOOKS.md.
5. `.pre-commit-config.yaml`: Git pre-commit hook running `prufgate check --changed`.
6. With `--agents-md` / `--bugbot`: a marked PrufGate section in `AGENTS.md` / `.cursor/BUGBOT.md`
   telling coding agents and AI reviewers how to use PrufGate's output. Rerunning updates it in place.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from prufgate.hooks.adapters import respond

STARTER_CONFIG_YAML = """# PrufGate Configuration (.prufgate/config.yaml)
version: 1

# Rule packs to enforce:
#   core      - Universal anti-fabrication, hardcoded scores/verdicts, literal returns
#   ai-safety - Unseeded LLM judgment prompts, missing evidence citations
#   web-ui    - Stub click handlers, disconnected form submits, canned API fallbacks
#   cti       - Threat-intelligence data rules (opt-in, off by default)
packs:
  - core
  - ai-safety
  - web-ui

# Leave empty to auto-detect all languages (TypeScript, JavaScript, Python, Go, Rust, Java, Kotlin, Ruby, PHP, C#)
languages: []

# Paths and globs excluded from scanning
exclude:
  - "dist/**"
  - "build/**"
  - ".next/**"
  - "node_modules/**"
  - "vendor/**"
  - "coverage/**"

# Custom authentication guard function/decorator names for BOLA verification (Engine 5)
auth_guards:
  - requireAuth
  - verifySession
  - get_current_user

# Custom multi-tenant / ownership column or attribute keys for BOLA verification (Engine 5)
tenant_keys:
  - tenant_id
  - tenantId
  - organization_id
  - organizationId
  - workspace_id
  - user_id

# Per-file rule exemptions, each with a reason, e.g.
#   exempt:
#     src/legacy/adapter.ts:
#       canned-error-fallback: "#104: legacy fallback until the payments API migration"
exempt: {}

# Ratcheting debt ceilings (counts can only stay equal or decrease)
known_debt: {}
"""

CURSOR_RULE_MDC = """---
description: PrufGate Anti-Fabrication, Test Integrity & BOLA Guardrails
globs: "**/*"
alwaysApply: true
---

# PrufGate Agent Verification Rules

1. **Zero Fabrication**: Never hardcode return values, mock production business logic, or swallow exceptions in empty `catch` / `except` blocks.
2. **Genuine Tests**: Every test must invoke the real unit under test and assert concrete behavioral outcomes. Never write zero-assertion tests, tautological assertions, or tests that only assert a mock's configured return value.
3. **No Guardrail Tampering**: Never add `.skip`, `@pytest.mark.skip`, `@ts-ignore`, `# noqa`, or weaken linter/typechecker configs without an explicit `#issue: reason` reference.
4. **Multi-Tenant BOLA Scoping**: Every dynamic-ID route handler (`{id}`, `:id`, `[id]`) must enforce caller authentication and scope database queries by tenant/owner key (`tenant_id`, `organization_id`, `user_id`).
5. **Never Bypass the Gate**: Never run `git commit --no-verify`, force-push, or delete or move tests, test directories or CI configuration to get past a failing check.
6. **Pre-Completion Check**: Run `prufgate check --changed` before finishing any coding task and resolve all `P0` and `P1` findings.
"""

PRE_COMMIT_CONFIG_YAML = """repos:
  - repo: local
    hooks:
      - id: prufgate-check-changed
        name: PrufGate Anti-Fabrication & Test Integrity Gate
        entry: prufgate check --changed
        language: system
        pass_filenames: false
"""

# The section `init --agents-md` / `--bugbot` writes into AGENTS.md and .cursor/BUGBOT.md
# (read by coding agents and by AI reviewers such as Cursor Bugbot). Everything between
# the markers belongs to PrufGate and is replaced on every run; the rest of the file is kept.
AGENTS_MD_START = "<!-- prufgate:start -->"
AGENTS_MD_END = "<!-- prufgate:end -->"
AGENTS_MD_SECTION = f"""{AGENTS_MD_START}
## PrufGate

This repository is checked by [PrufGate](https://github.com/GuardianVigil-Labs/Prufgate), which catches code that fakes its result, tests that cannot fail and weakened checks. For coding agents and AI reviewers:

- Before saying a task is done, run `prufgate check --changed` and fix every P0 and P1 finding. Exit 0 is clean, 1 means blocking findings, 2 means the check could not run: treat 2 as not checked, never as a pass.
- In review, treat P0 and P1 PrufGate findings as blockers. P2 and P3 are advisory.
- Never add a `prufgate-ignore` comment without a real reason after `--` (`prufgate-ignore: rule-id -- why`). An ignore without a reason suppresses nothing and is reported itself.
- Never edit `.prufgate/` configuration (exemptions, `known_debt`, packs, excludes) to silence a finding. Fix the code; a configuration change needs a maintainer's approval.
- If `reports/prufgate-review.md` or `reports/prufgate.sarif` exists (written by `./prufgate.sh` or the PrufGate GitHub Action), read it before reviewing and check its findings against the code.
{AGENTS_MD_END}
"""

# The Stop hook, as one POSIX sh command. It uses `prufgate` when it is on PATH,
# else the installed module. Any failure to run PrufGate exits 2 (blocking) with a
# message, so a missing install never passes silently; when the agent is
# already continuing because of this hook (stop_hook_active), it reports and
# exits 0 so it can never loop.
_STOP_ACTIVE = "case \"$input\" in *'\"stop_hook_active\": true'*|*'\"stop_hook_active\":true'*) active=1;; *) active=0;; esac"
HOOK_COMMAND = "; ".join([
    "input=$(cat)",
    _STOP_ACTIVE,
    "if command -v prufgate >/dev/null 2>&1; then printf '%s' \"$input\" | prufgate check --changed --format agent-hook; rc=$?",
    "elif python3 -c 'import prufgate.cli' >/dev/null 2>&1; then printf '%s' \"$input\" | python3 -m prufgate.cli check --changed --format agent-hook; rc=$?",
    # Windows (Git Bash) has `python`, not `python3`.
    "elif python -c 'import prufgate.cli' >/dev/null 2>&1; then printf '%s' \"$input\" | python -m prufgate.cli check --changed --format agent-hook; rc=$?",
    "else echo 'prufgate: not installed (no prufgate on PATH, no engine module for python3 or python); this work was not checked' >&2; rc=3; fi",
    "[ \"$rc\" -eq 0 ] && exit 0",
    "[ \"$rc\" -eq 2 ] || echo \"prufgate: the check could not run (exit $rc)\" >&2",
    "[ \"$active\" -eq 1 ] && exit 0",
    "exit 2",
])


def guard_command(subcommand: str, blocked: str, deny: str = "", loop_guard: bool = False) -> str:
    """A POSIX sh hook command running `prufgate <subcommand>` on the hook payload.

    The adapter's own exit code and stdout pass through. Anything else, including
    a missing install, exits 2 with a message: most agents treat other exit
    codes as a non-blocking failure, so they must never reach the agent. `deny`
    is printed on stdout then too, for agents (Cursor, Copilot) that read a JSON
    block from stdout. `loop_guard` (Stop hooks) exits 0 when the payload says the agent is
    already continuing because of a stop hook, so a missing install reports once and never loops.
    """
    say_deny = [f"printf '%s\\n' {shlex.quote(deny)}"] if deny else []
    return "; ".join([
        "input=$(cat)",
        *([_STOP_ACTIVE] if loop_guard else []),
        f"if command -v prufgate >/dev/null 2>&1; then printf '%s' \"$input\" | prufgate {subcommand}; rc=$?",
        f"elif python3 -c 'import prufgate.cli' >/dev/null 2>&1; then printf '%s' \"$input\" | python3 -m prufgate.cli {subcommand}; rc=$?",
        f"elif python -c 'import prufgate.cli' >/dev/null 2>&1; then printf '%s' \"$input\" | python -m prufgate.cli {subcommand}; rc=$?",
        f"else echo {shlex.quote(f'prufgate: not installed (no prufgate on PATH, no engine module for python3 or python); {blocked} until it is')} >&2; rc=3; fi",
        "[ \"$rc\" -eq 0 ] && exit 0",
        f"[ \"$rc\" -eq 2 ] || echo \"prufgate: {subcommand} could not run (exit $rc)\" >&2",
        *(["[ \"$rc\" -eq 2 ] || " + say_deny[0]] if say_deny else []),
        *(["[ \"$active\" -eq 1 ] && exit 0"] if loop_guard else []),
        "exit 2",
    ])


# The PreToolUse(Bash) hook: `prufgate shell-guard` reads the hook payload on
# stdin and exits 2 (block, reason on stderr) or 0.
SHELL_GUARD_COMMAND = guard_command("shell-guard", "shell commands are blocked")

AGENT_CHOICES = ("claude", "cursor", "copilot", "codex", "gemini")
DEFAULT_AGENTS = ("claude", "cursor")

# Claude-shaped settings files: {"hooks": {Event: [{"matcher": ..., "hooks": [{"type": "command", ...}]}]}}.
# Each entry: (event, matcher, adapter subcommand).
_NESTED_HOOKS: dict[str, tuple[str, list[tuple[str, str, str]]]] = {
    "claude": (".claude/settings.json", [
        ("PreToolUse", "Edit|Write|MultiEdit|NotebookEdit", "hook claude pre-tool"),
    ]),
    "codex": (".codex/hooks.json", [
        ("PreToolUse", "Bash|shell|exec_command|apply_patch", "hook codex pre-tool"),
        ("Stop", "", "hook codex stop"),
    ]),
    "gemini": (".gemini/settings.json", [
        ("BeforeTool", "run_shell_command|write_file|replace", "hook gemini pre-tool"),
        ("AfterAgent", "", "hook gemini stop"),
    ]),
}

# Flat `{"version": 1, "hooks": {event: [{...}]}}` files (Cursor, Copilot). Each
# entry: (event, adapter subcommand, extra fields). The command key differs.
_FLAT_HOOKS: dict[str, tuple[str, str, list[tuple[str, str, dict[str, Any]]]]] = {
    "cursor": (".cursor/hooks.json", "command", [
        ("beforeShellExecution", "hook cursor shell", {"failClosed": True}),
        ("preToolUse", "hook cursor pre-tool", {"matcher": "Write|Edit|StrReplace|MultiEdit|Delete", "failClosed": True}),
        ("stop", "hook cursor stop", {"timeout": 600, "failClosed": True}),
    ]),
    "copilot": (".github/hooks/prufgate.json", "bash", [
        ("preToolUse", "hook copilot pre-tool", {"type": "command", "matcher": "bash|edit|create|str_replace_editor|powershell|Bash|Edit|Write|MultiEdit",
                                                 "timeoutSec": 30}),
        ("agentStop", "hook copilot stop", {"type": "command", "timeoutSec": 600}),
    ]),
}


class HookConfigError(ValueError):
    """An existing agent settings file cannot be merged safely."""


def generate_starter_config_yaml() -> str:
    return STARTER_CONFIG_YAML


def generate_cursor_rule_mdc() -> str:
    return CURSOR_RULE_MDC


def generate_pre_commit_config_yaml() -> str:
    return PRE_COMMIT_CONFIG_YAML


def _add_hook(hooks: dict[str, Any], event: str, matcher: str, marker: str, command: str,
              label: str = ".claude/settings.json") -> None:
    """Append a command hook to `hooks[event]` unless a hook whose command contains `marker` is there."""
    entries = hooks.setdefault(event, [])
    if not isinstance(entries, list):
        raise HookConfigError(f'"hooks.{event}" in {label} is not a list; fix it, then rerun')
    for entry in entries:
        inner = entry.get("hooks", []) if isinstance(entry, dict) else []
        if isinstance(inner, list) and any(isinstance(h, dict) and marker in str(h.get("command", "")) for h in inner):
            return
    entries.append({"matcher": matcher, "hooks": [{"type": "command", "command": command}]})


def generate_claude_settings_json(existing_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create or merge the Claude Code `Stop` hook and the `PreToolUse` (Bash) shell guard."""
    data: dict[str, Any] = dict(existing_data) if isinstance(existing_data, dict) else {}
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise HookConfigError('"hooks" in .claude/settings.json is not an object; fix it, then rerun')
    _add_hook(hooks, "Stop", "", "prufgate check", HOOK_COMMAND)
    _add_hook(hooks, "PreToolUse", "Bash", "prufgate shell-guard", SHELL_GUARD_COMMAND)
    return merge_agent_hooks("claude", data)


def merge_agent_hooks(agent: str, existing: dict[str, Any] | None) -> dict[str, Any]:
    """Merge PrufGate's hooks for `agent` into its parsed config, keeping every other entry."""
    data: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    if agent in _NESTED_HOOKS:
        label, entries = _NESTED_HOOKS[agent]
        hooks = data.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise HookConfigError(f'"hooks" in {label} is not an object; fix it, then rerun')
        for event, matcher, sub in entries:
            _add_hook(hooks, event, matcher, f"prufgate {sub}", guard_command(sub, "this agent's actions are blocked", loop_guard=sub.endswith("stop")), label)
        return data
    label, key, flat = _FLAT_HOOKS[agent]
    version = data.setdefault("version", 1)
    if version != 1:
        raise HookConfigError(f'{label} has "version": {version!r}; PrufGate writes version 1 only')
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise HookConfigError(f'"hooks" in {label} is not an object; fix it, then rerun')
    for event, sub, extra in flat:
        items = hooks.setdefault(event, [])
        if not isinstance(items, list):
            raise HookConfigError(f'"hooks.{event}" in {label} is not a list; fix it, then rerun')
        if not any(isinstance(h, dict) and f"prufgate {sub}" in str(h.get(key, "")) for h in items):
            event_name = sub.split()[-1]
            deny = respond(agent, event_name, "prufgate could not run; this action was not checked.")[1]
            items.append({**extra, key: guard_command(sub, "this agent's actions are blocked", deny)})
    return data


def claude_plugin_hooks() -> dict[str, Any]:
    """`plugins/prufgate/hooks/hooks.json` in the Claude Code plugin (a test keeps the file equal to this)."""
    def hook(sub: str, blocked: str, **extra: Any) -> list[dict[str, Any]]:
        return [{"type": "command", "command": guard_command(sub, blocked, loop_guard=sub.endswith("stop")), **extra}]
    return {"hooks": {
        "PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
                        "hooks": hook("hook claude pre-tool", "shell commands and file edits are blocked")}],
        "Stop": [{"hooks": hook("hook claude stop", "this work is not checked", timeout=600)}],
    }}


def merge_agents_section(existing: str | None, label: str = "AGENTS.md") -> str:
    """`existing` with the PrufGate section added at the end, or replaced in place between its markers."""
    text = existing or ""
    start, end = text.find(AGENTS_MD_START), text.find(AGENTS_MD_END)
    if start == -1 and end == -1:
        return (text.rstrip("\n") + "\n\n" if text.strip() else "") + AGENTS_MD_SECTION
    if start == -1 or end < start or text.count(AGENTS_MD_START) > 1 or text.count(AGENTS_MD_END) > 1:
        raise HookConfigError(f"{label} has unmatched or repeated PrufGate markers; fix them, then rerun")
    after = text[end + len(AGENTS_MD_END):]
    return text[:start] + AGENTS_MD_SECTION + (after[1:] if after.startswith("\n") else after)


def _read_json_object(path: Path) -> dict[str, Any] | None:
    """The JSON object in `path`, None when it does not exist. Never overwrite what cannot be read."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise HookConfigError(f"{path} is not valid JSON ({e}); fix it or remove it, then rerun") from e
    if not isinstance(data, dict):
        raise HookConfigError(f"{path} must contain a JSON object")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def init_workspace(
    workspace: Path,
    install_hooks: bool = False,
    overwrite: bool = False,
    agents: list[str] | tuple[str, ...] | None = None,
    agents_md: bool = False,
    bugbot: bool = False,
) -> list[str]:
    """Initialize `.prufgate/config.yaml` and optional coding agent / pre-commit hooks in `workspace`.

    `agents` (default: Claude Code and Cursor) picks which agents get hooks; it implies `install_hooks`.
    `agents_md` / `bugbot` merge the PrufGate section into `AGENTS.md` / `.cursor/BUGBOT.md`.
    """
    created_or_updated: list[str] = []
    ws = workspace.resolve()
    if agents:
        install_hooks = True
    selected = list(dict.fromkeys(agents or DEFAULT_AGENTS))
    unknown = [a for a in selected if a not in AGENT_CHOICES]
    if unknown:
        raise HookConfigError(f"unknown agent(s): {', '.join(unknown)} (choose from {', '.join(AGENT_CHOICES)})")

    # 1. .prufgate/config.yaml
    cfg_path = ws / ".prufgate" / "config.yaml"
    if overwrite or not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(generate_starter_config_yaml(), encoding="utf-8")
        created_or_updated.append(".prufgate/config.yaml")

    # Read every file first, so a malformed one stops the run before anything is written.
    sections: list[tuple[Path, str]] = []
    for wanted, rel in ((agents_md, "AGENTS.md"), (bugbot, ".cursor/BUGBOT.md")):
        if wanted:
            path = ws / rel
            try:
                old = path.read_text(encoding="utf-8") if path.exists() else None
            except (OSError, UnicodeDecodeError) as e:
                raise HookConfigError(f"{rel} cannot be read ({e}); fix it, then rerun") from e
            new = merge_agents_section(old, rel)
            if new != old:
                sections.append((path, new))

    if install_hooks:
        # Read every file first, so a malformed one stops the run before anything is written.
        merged: list[tuple[Path, dict[str, Any]]] = []
        for agent in selected:
            path = ws / (_NESTED_HOOKS[agent][0] if agent in _NESTED_HOOKS else _FLAT_HOOKS[agent][0])
            existing = _read_json_object(path)
            merged.append((path, generate_claude_settings_json(existing) if agent == "claude" else merge_agent_hooks(agent, existing)))
        for path, data in merged:
            _write_json(path, data)
            created_or_updated.append(path.relative_to(ws).as_posix())

        if "cursor" in selected:
            cursor_path = ws / ".cursor" / "rules" / "prufgate-guardrails.mdc"
            if overwrite or not cursor_path.exists():
                cursor_path.parent.mkdir(parents=True, exist_ok=True)
                cursor_path.write_text(generate_cursor_rule_mdc(), encoding="utf-8")
                created_or_updated.append(".cursor/rules/prufgate-guardrails.mdc")

        pre_commit_path = ws / ".pre-commit-config.yaml"
        if overwrite or not pre_commit_path.exists():
            pre_commit_path.write_text(generate_pre_commit_config_yaml(), encoding="utf-8")
            created_or_updated.append(".pre-commit-config.yaml")

    for path, text in sections:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        created_or_updated.append(path.relative_to(ws).as_posix())

    return created_or_updated
