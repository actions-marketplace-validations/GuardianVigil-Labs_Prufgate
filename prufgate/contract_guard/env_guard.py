#!/usr/bin/env python3
"""PrufGate Environment Variable Drift Guard (`undocumented-env-var-drift`).

Detects when application code reads environment variables (`process.env.X`,
`import.meta.env.X`, `os.environ["X"]`, `os.getenv("X")`, `os.Getenv("X")`,
`std::env::var("X")`, `env!("X")`) that are missing from `.env.example`
(or `.env.template` / `.env.sample`) without a fallback default.

The rule runs when the repository has an example env file. Config schemas and deploy
manifests (zod, pydantic-settings, docker-compose, Kubernetes, Helm, GitHub Actions) also
count as documentation: see `env_sources.py`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import inline_ignore  # noqa: E402
from prufgate.config import PrufGateConfig  # noqa: E402
from prufgate.contract_guard.dependency_guard import Finding  # noqa: E402
from prufgate.contract_guard.env_sources import load_env_sources  # noqa: E402

ENV_EXAMPLE_FILES = (
    ".env.example",
    ".env.template",
    ".env.sample",
    ".env.defaults",
)

STANDARD_RUNTIME_ENV_VARS = {
    "NODE_ENV",
    "PORT",
    "HOST",
    "HOSTNAME",
    "CI",
    "HOME",
    "PATH",
    "PWD",
    "USER",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "TZ",
    "LANG",
    "LC_ALL",
    "DEBUG",
    "LOG_LEVEL",
    "TEST",
    "VITEST",
    "JEST_WORKER_ID",
    "PYTEST_CURRENT_TEST",
    "GITHUB_ACTIONS",
    "GITHUB_SHA",
    "GITHUB_REF",
    "VERCEL_URL",
    "NEXT_RUNTIME",
    "WORKSPACE",
}

# Environment variable extraction patterns
ENV_READ_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Node / TypeScript: process.env.VAR or process.env["VAR"] or import.meta.env.VAR
    ("js-dot", re.compile(r"\b(?:process|import\.meta)\.env\.([A-Z][A-Z0-9_]{2,})\b")),
    ("js-bracket", re.compile(r"""\bprocess\.env\[\s*["']([A-Z][A-Z0-9_]{2,})["']\s*\]""")),
    # Python: os.environ["VAR"] or os.environ.get("VAR") or os.getenv("VAR")
    ("py-subscript", re.compile(r"""\bos\.environ\[\s*["']([A-Z][A-Z0-9_]{2,})["']\s*\]""")),
    ("py-get-no-default", re.compile(r"""\bos\.(?:getenv|environ\.get)\(\s*["']([A-Z][A-Z0-9_]{2,})["']\s*\)""")),
    # Go: os.Getenv("VAR") or os.LookupEnv("VAR")
    ("go-getenv", re.compile(r"""\bos\.(?:Getenv|LookupEnv)\(\s*"([A-Z][A-Z0-9_]{2,})"\s*\)""")),
    # Rust: std::env::var("VAR") or env::var("VAR") or env!("VAR")
    ("rust-env", re.compile(r"""\b(?:(?:std::)?env::var|env!)\(\s*"([A-Z][A-Z0-9_]{2,})"\s*\)""")),
)


def load_documented_env_vars(workspace: Path, config: PrufGateConfig | None = None) -> set[str] | None:
    """Documented env var keys from `.env.example`, schemas and manifests (None if no example file exists)."""
    if not workspace.is_dir():
        return None
    found_files = [workspace / name for name in ENV_EXAMPLE_FILES if (workspace / name).is_file()]
    if not found_files:
        return None

    documented: set[str] = set(STANDARD_RUNTIME_ENV_VARS)
    key_re = re.compile(r"^\s*(?:#\s*)?(?:export\s+)?([A-Z][A-Z0-9_]{1,})\s*=")
    for ef in found_files:
        try:
            for line in ef.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = key_re.match(line)
                if m:
                    documented.add(m.group(1).strip())
        except OSError:
            pass
    return documented | load_env_sources(workspace, config)


def _line_has_inline_fallback(line: str, match_end: int) -> bool:
    """Return True if a JS/TS env read is followed by `|| 'default'` or `?? 'default'`, also
    outside the call that reads it (`Number(process.env.X) || 5000`), or by a ternary."""
    tail = line[match_end:].lstrip()
    while tail.startswith(")"):
        tail = tail[1:].lstrip()
    if tail.startswith("?") and not tail.startswith(("?.", "??")):
        m_colon = re.search(r":\s*([^;,\n]+)", tail[1:])
        if m_colon and not re.match(r"^(?:undefined|null)\b", m_colon.group(1).strip()):
            return True
        return False
    if tail.startswith(("||", "??")):
        after_op = tail[2:].lstrip()
        # Fallback must be a non-empty literal or expression
        if after_op and not re.match(r"^(?:undefined|null)\b", after_op) and not after_op.startswith(";"):
            return True
    return False


_ASSIGNED_RE = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=")


def _nearby_fallback(lines: list[str], ln: int) -> bool:
    """A JS/TS env read assigned to a variable that one of the next three lines falls back
    from: `const n = Number(process.env.X);` then `return n > 0 ? n : 5000;` (or `n ?? 5000`)."""
    m = _ASSIGNED_RE.match(lines[ln - 1])
    if not m:
        return False
    var = re.escape(m.group(1))
    fb_re = re.compile(
        rf"(?<![\w$.!]){var}\b(?:[^?:;\n]*?\?(?![.?])\s*[^?:;\s][^?:;]*:\s*(?!undefined\b|null\b)\S"
        rf"|\s*(?:\?\?|\|\|)\s*(?!undefined\b|null\b|;)\S)"
    )
    for nxt in lines[ln : ln + 3]:
        s = nxt.strip()
        if re.match(r"^(?:if|while)\s*\(", s) and "?" not in s:
            continue
        if fb_re.search(s) and "throw" not in s:
            return True
    return False


def scan_file_env_drift(
    path: Path | str,
    content: str,
    workspace: Path,
    documented_vars: set[str] | None = None,
    config: PrufGateConfig | None = None,
) -> list[Finding]:
    """Scan a source file for environment variables missing from `.env.example`."""
    doc_vars = documented_vars if documented_vars is not None else load_documented_env_vars(workspace, config)
    if doc_vars is None:
        return []

    p = Path(path)
    try:
        rel_path = str(p.resolve().relative_to(workspace.resolve())).replace("\\", "/")
    except ValueError:
        rel_path = str(p).replace("\\", "/")

    cfg = config or PrufGateConfig()
    if cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "undocumented-env-var-drift"):
        return []

    findings: list[Finding] = []
    lines = content.splitlines()

    for ln, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith(("#", "//", "/*", "*")):
            continue
        for kind, pat in ENV_READ_PATTERNS:
            for m in pat.finditer(s):
                var_name = m.group(1)
                if var_name in doc_vars:
                    continue
                if kind in ("js-dot", "js-bracket") and (_line_has_inline_fallback(s, m.end()) or _nearby_fallback(lines, ln)):
                    continue
                message = (
                    f"Environment variable '{var_name}' in '{rel_path}:{ln}' is not documented in "
                    f"`.env.example`, a config schema or a deploy manifest, and has no fallback default."
                )
                if inline_ignore.suppressed_at(
                    lines, ln, "undocumented-env-var-drift", engine="contract-guard", path=rel_path,
                    severity="P1", message=message,
                ):
                    continue
                findings.append(
                    Finding(
                        path=rel_path,
                        line=ln,
                        rule="undocumented-env-var-drift",
                        severity="P1",
                        text=s,
                        message=message,
                    )
                )
    return findings
