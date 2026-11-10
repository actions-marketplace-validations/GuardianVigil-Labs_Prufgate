"""Shared credential redaction for provider prompts, reports and diagnostics."""

from __future__ import annotations

import os
import re
from typing import Any, Iterable

_SECRET_ENV_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PWD", "CREDENTIAL", "COOKIE", "AUTH")


# (pattern, replacement prefix): the value after the kept groups is removed.
_SECRET_SHAPES = (
    (re.compile(r"(?i)(bearer\s+|x-api-key['\"]?\s*[:=]\s*['\"]?)[^\s'\",}]+"), r"\1"),
    # `PGPASSWORD=x cmd`, `DB_PASS=x`: an unquoted value of an upper-case secret-named variable.
    (re.compile(r"\b([A-Z0-9_]*(?:PASS|PWD|TOKEN|SECRET|KEY|AUTH|COOKIE|CREDENTIAL)[A-Z0-9_]*=)(?![\"'$\[])[^\s;&|()<>]+"), r"\1"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+(?=@)"), r"\1"),  # URL userinfo
    (re.compile(r"(?<!\S)(-u\s*|--user[=\s]\s*)([^\s:]+:)(?!\[redacted\])\S+"), r"\1\2"),  # curl -u user:pass
    (re.compile(r"(?i)(?<!\S)(--(?:passw(?:or)?d|token|api-key|secret)(?:=|\s+))(?!\[redacted\])\S+"), r"\1"),
    (re.compile(r"(\blogin\b[^\n;&|]*?\s-p\s+)\S+"), r"\1"),  # docker login -p x
    (re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n;&|]*?\s-p)(?=[^\s\[])\S+"), r"\1"),  # mysql -px
    (re.compile(r"(?i)\b((?:proxy-)?authorization|(?:set-)?cookie)(\s*:\s*)[^\n'\"]+"), r"\1\2"),
)


_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\b(?=[A-Za-z+/_-]*[0-9])[A-Za-z0-9+/_-]{40,}={0,2}"),  # a long identifier is not a key
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)((?:secret|token|passw(?:or)?d|pwd|api[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_]*"
    r"[\"']?\s*[:=]\s*[\"'])([^\"'\n]{4,})([\"'])"
)

def _redact_known(text: str) -> str:
    """Remove the values of credential-like environment variables from a diagnostic string."""
    for name, value in os.environ.items():
        if len(value) >= 8 and any(h in name.upper() for h in _SECRET_ENV_HINTS):
            text = text.replace(value, "[redacted]")
    for pat, keep in _SECRET_SHAPES:
        text = pat.sub(keep + "[redacted]", text)
    return text


def _redact_fragment(text: str, secrets: Iterable[str]) -> str:
    """Remove known environment secrets, token shapes and credential assignments."""
    for value in sorted({v for v in secrets if v}, key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    text = _redact_known(text)
    text = _SECRET_ASSIGN_RE.sub(r"\1[redacted]\3", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


_SAFE_REFERENCE = re.compile(
    r"((?i:Authorization:\s*Bearer)\s+\$PRUFGATE_(?:TOKEN_[AB]|ROLE_[A-Z0-9_]+)\b)"
)


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Redact credentials, preserving only named shell references used by PoCs."""
    values = tuple(secrets)
    parts = _SAFE_REFERENCE.split(text)
    return "".join(part if i % 2 else _redact_fragment(part, values) for i, part in enumerate(parts))


def redact_data(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Redact string values without changing a report's structure or field names."""
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, list):
        return [redact_data(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_data(item, secrets) for key, item in value.items()}
    return value
