#!/usr/bin/env python3
"""PrufGate Optional BYO-Agent / LLM Diff Review Adapter (`prufgate/review/ai_adapter.py`).

Supports delegating pull-request diff review to:
1. Local coding agent CLIs installed on PATH:
   - `claude -p` with every tool off (the only CLI picked by `auto`)
   - `codex exec` (read-only sandbox), `gemini -p` (plan mode), `opencode run`:
     these can still read files, so they run only when named with --ai-provider
2. Standard LLM HTTP APIs via environment variables (`urllib.request`, zero external SDKs):
   - `OPENAI_API_KEY` (`https://api.openai.com/v1/chat/completions`)
   - `ANTHROPIC_API_KEY` (`https://api.anthropic.com/v1/messages`)
   - `OLLAMA_HOST` (`http://127.0.0.1:11434/api/chat`)

Always fails closed/gracefully: if no provider is configured or the provider returns
malformed output, returns an empty list of comments with a diagnostic status string
so deterministic verification is never disrupted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from prufgate.privacy import redact, redact_data
from prufgate.result_validation import read_json

AI_REVIEW_SYSTEM_PROMPT = (
    "You are PrufGate, a high-precision security and software engineering diff reviewer.\n"
    "Review the provided unified git diff ONLY for:\n"
    "1. Broken Object Level Authorization (BOLA/IDOR) or missing tenant scoping.\n"
    "2. Fabricated/hardcoded return values, stubbed business logic, or swallowed errors.\n"
    "3. Tautological, assertion-free, or over-mocked tests.\n"
    "4. Concrete security vulnerabilities (SQLi, command injection, SSRF, XSS, auth bypass).\n"
    "Return ONLY a JSON array of objects with keys: "
    '{"file": str, "line": int, "severity": "P0"|"P1"|"P2", "title": str, "message": str, "suggestion": str|null}.\n'
    "If no high-confidence issues exist, return []."
)


@dataclass
class AIReviewResult:
    """Result from an optional AI diff review invocation."""

    provider: str
    status: str  # "executed", "skipped", "error"
    comments: list[dict[str, Any]]
    note: str = ""


def detect_ai_provider(preferred: str = "auto") -> str | None:
    """Detect the first available local CLI agent or API key provider."""
    pref = (preferred or "auto").strip().lower()
    if pref != "auto":
        return pref

    # 1. Check environment variables first for deterministic CI usage
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"

    # 2. Local agent CLI: only one that can run with every tool switched off.
    # codex, gemini and opencode can still read files, so they run only when named.
    if shutil.which("claude"):
        return "claude"

    return None


def _extract_json_array(raw_text: str) -> list[dict[str, Any]]:
    """Extract and validate a JSON array of review comment dicts from LLM text output."""
    text = raw_text.strip()
    if not text:
        raise ValueError("empty AI response")

    # Strip markdown code fences if present
    fence_match = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text)
    if fence_match:
        text = fence_match.group(1)

    try:
        parsed = read_json(text)
    except ValueError as exc:
        raise ValueError("AI response is not a JSON array") from exc

    if not isinstance(parsed, list):
        raise ValueError("AI response is not an array")

    valid_items: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            raise ValueError("AI response contains a non-object finding")
        if not all(isinstance(item.get(k), str) and item[k].strip() for k in ("file", "title", "message")):
            raise ValueError("AI finding is missing required string fields")
        file_path = item["file"].strip()
        title = str(item.get("title") or "").strip()
        message = str(item.get("message") or "").strip()
        if not file_path or not title or not message:
            raise ValueError("AI finding has empty fields")
        line = item.get("line")
        if type(line) is not int or line < 1:
            raise ValueError("AI finding has an invalid line")
        sev = item.get("severity")
        if sev not in ("P0", "P1", "P2", "P3"):
            raise ValueError("AI finding has an invalid severity")
        suggestion = item.get("suggestion")
        if suggestion is not None and not isinstance(suggestion, str):
            raise ValueError("AI finding has an invalid suggestion")
        if not isinstance(suggestion, str) or not suggestion.strip():
            suggestion = None
        valid_items.append(
            {
                "file": file_path,
                "line": line,
                "severity": sev,
                "title": f"[AI] {title}" if not title.startswith("[AI]") else title,
                "message": message,
                "suggestion": suggestion,
            }
        )
    return valid_items


def _private_tmp_parent() -> str | None:
    """A parent for the CLI working directory that other users cannot write to:
    the user's cache directory, so no shared ancestor (like /tmp) can hold a
    planted settings or instructions file. None falls back to the system temp."""
    cache = os.path.join(os.path.expanduser("~"), ".cache")
    try:
        os.makedirs(cache, mode=0o700, exist_ok=True)
        return cache
    except OSError:
        return None


@contextmanager
def _private_cli_directory():
    """Fall back when an existing cache directory cannot actually be written."""
    parent = _private_tmp_parent()
    temporary = None
    if parent is not None:
        try:
            temporary = tempfile.TemporaryDirectory(prefix="prufgate-ai-", dir=parent)
        except OSError:
            pass
    if temporary is not None:
        with temporary as cwd:
            yield cwd
        return
    # A private parent keeps the CLI away from files placed directly in the shared temp directory.
    with tempfile.TemporaryDirectory(prefix="prufgate-private-") as parent:
        with tempfile.TemporaryDirectory(prefix="prufgate-ai-", dir=parent) as cwd:
            yield cwd


def _invoke_cli_agent(cli_name: str, prompt: str, timeout: int = 45) -> tuple[bool, str]:
    binary = shutil.which(cli_name)
    if not binary:
        return False, f"CLI binary '{cli_name}' not found on PATH"

    # The prompt holds the untrusted diff: it goes on stdin, never argv, and each
    # CLI runs one-shot with the narrowest tool access its documentation offers.
    stdin: str | None = prompt
    if cli_name == "claude":
        cmd = [binary, "-p", "--tools", "", "--strict-mcp-config", "--setting-sources", "user",
               "--permission-mode", "dontAsk", "--no-session-persistence"]
    elif cli_name == "codex":
        cmd = [binary, "exec", "--sandbox", "read-only", "--ephemeral", "--skip-git-repo-check",
               "--ignore-user-config", "--ignore-rules", "-"]
    elif cli_name == "gemini":
        cmd = [binary, "-p", "Follow the request given on stdin and reply in the format it asks for; do not use tools.",
               "--approval-mode", "plan", "--output-format", "text"]
    elif cli_name == "opencode":
        # ponytail: `opencode run` documents the message only as an argument and no
        # tool switch; named explicitly only, see detect_ai_provider.
        cmd, stdin = [binary, "run", prompt], None
    else:
        return False, f"Unsupported AI CLI: {cli_name}"

    try:
        # Agent CLIs read project settings, hooks and instruction files from their
        # working directory and its parents. Run them in a fresh private directory,
        # never the scanned repository or a shared one such as /tmp itself.
        with _private_cli_directory() as cwd:
            proc = subprocess.run(
                cmd,
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        if proc.returncode != 0:
            return False, redact((proc.stderr or proc.stdout or f"{cli_name} exited with {proc.returncode}").strip())[:200]
        return True, proc.stdout
    except Exception as exc:
        return False, redact(str(exc))[:200]


def _invoke_http_llm(provider: str, prompt: str, timeout: int = 30, system: str = AI_REVIEW_SYSTEM_PROMPT) -> tuple[bool, str]:
    try:
        if provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            if not api_key:
                return False, "OPENAI_API_KEY not set"
            model = os.environ.get("PRUFGATE_AI_MODEL", "gpt-4o-mini")
            url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
            payload = {
                "model": model,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="ignore"))
                choice = body.get("choices", [{}])[0]
                if choice.get("finish_reason") not in (None, "stop"):
                    return False, "Provider returned an incomplete review"
                content = choice.get("message", {}).get("content", "")
                return True, str(content)

        if provider == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
            if not api_key:
                return False, "ANTHROPIC_API_KEY not set"
            model = os.environ.get("PRUFGATE_AI_MODEL", "claude-3-5-haiku-latest")
            url = "https://api.anthropic.com/v1/messages"
            payload = {
                "model": model,
                "max_tokens": 2048,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if body.get("stop_reason") not in (None, "end_turn", "stop_sequence"):
                    return False, "Provider returned an incomplete review"
                blocks = body.get("content", [])
                text = "\n".join(b.get("text", "") for b in blocks if isinstance(b, dict))
                return True, text

        if provider == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            parsed = urllib.parse.urlparse(host)
            if parsed.scheme not in ("http", "https"):
                return False, f"Invalid OLLAMA_HOST scheme: {host}"
            model = os.environ.get("PRUFGATE_AI_MODEL", "qwen2.5-coder:7b")
            url = f"{host}/api/chat"
            payload = {
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if body.get("done") is False or body.get("done_reason") == "length":
                    return False, "Provider returned an incomplete review"
                content = body.get("message", {}).get("content", "")
                return True, str(content)

        return False, f"Unsupported AI provider: {provider}"
    except urllib.error.URLError as exc:
        return False, redact(f"Network/HTTP error from {provider}: {exc}")[:300]
    except Exception as exc:
        return False, redact(str(exc))[:200]


def review_diff_with_ai(
    diff_text: str,
    provider: str = "auto",
    timeout: int = 45,
) -> AIReviewResult:
    """Run optional BYO-Agent / LLM review on `diff_text` and return structured comments."""
    if not diff_text.strip():
        return AIReviewResult(provider="none", status="skipped", comments=[], note="Empty git diff")

    resolved = detect_ai_provider(provider)
    if not resolved:
        return AIReviewResult(
            provider="none",
            status="skipped",
            comments=[],
            note="No claude CLI or API key (OPENAI_API_KEY, ANTHROPIC_API_KEY, OLLAMA_HOST) detected.",
        )

    if len(diff_text) > 24000:
        return AIReviewResult(resolved, "error", [], "Diff exceeds the 24000-character AI review limit; no AI review was run.")
    truncated_diff = redact(diff_text)
    full_prompt = f"{AI_REVIEW_SYSTEM_PROMPT}\n\n```diff\n{truncated_diff}\n```"

    if resolved in ("claude", "opencode", "codex", "gemini"):
        ok, raw_out = _invoke_cli_agent(resolved, full_prompt, timeout=timeout)
    else:
        ok, raw_out = _invoke_http_llm(resolved, full_prompt, timeout=timeout)

    if not ok:
        return AIReviewResult(provider=resolved, status="error", comments=[], note=raw_out)

    try:
        comments = redact_data(_extract_json_array(raw_out))
    except ValueError as exc:
        return AIReviewResult(resolved, "error", [], str(exc))
    return AIReviewResult(
        provider=resolved,
        status="executed",
        comments=comments,
        note=f"{len(comments)} AI finding(s) from {resolved}",
    )
