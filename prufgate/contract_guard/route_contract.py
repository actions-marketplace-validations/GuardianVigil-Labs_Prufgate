#!/usr/bin/env python3
"""PrufGate Frontend-to-Backend API Route Contract Verifier (`frontend-backend-route-mismatch`).

Cross-checks frontend HTTP client invocations (`fetch("/api/...")`, `axios.<method>("/api/...")`,
`useSWR("/api/...")`) against backend route handlers and OpenAPI specifications discovered by
`prufgate.bola.bola_engine.discover_all_routes`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import inline_ignore  # noqa: E402
from prufgate.bola.bola_engine import DiscoveredRoute, discover_all_routes  # noqa: E402
from prufgate.contract_guard.dependency_guard import Finding  # noqa: E402
from prufgate.source_text import views  # noqa: E402

FRONTEND_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".vue", ".svelte"}

# Matches fetch('/api/...', { method: 'POST' }) or fetch(`/api/users/${id}`)
FETCH_CALL_RE = re.compile(
    r"""\bfetch\s*\(\s*(['"`])(/api/[a-zA-Z0-9_./${}:-]+(?:\?[^'"`]*)?)\1(?:\s*,\s*\{([^}]{0,240})\})?""",
    re.DOTALL,
)
FETCH_METHOD_RE = re.compile(r"""\bmethod\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]""", re.IGNORECASE)

# Matches axios.get('/api/...'), api.post('/api/...'), httpClient.delete('/api/...')
AXIOS_CALL_RE = re.compile(
    r"""\b(?:axios|apiClient|httpClient)\s*\.\s*(get|post|put|patch|delete)\s*(?:<[^>]+>)?\s*\(\s*(['"`])(/api/[a-zA-Z0-9_./${}:-]+(?:\?[^'"`]*)?)\2"""
)

# Matches useSWR('/api/...') or useSWR<Type>('/api/...')
SWR_CALL_RE = re.compile(
    r"""\buseSWR(?:Immutable|Mutation)?\s*(?:<[^>]+>)?\s*\(\s*(['"`])(/api/[a-zA-Z0-9_./${}:-]+(?:\?[^'"`]*)?)\1"""
)


def _normalize_frontend_api_path(raw_url: str) -> str:
    """Strip query string and normalize `${expr}` / `:param` segments to `{param}`."""
    path_only = raw_url.split("?", 1)[0].strip()
    if len(path_only) > 1 and path_only.endswith("/"):
        path_only = path_only.rstrip("/")
    normalized = re.sub(r"\$\{[^}]+\}", "{param}", path_only)
    normalized = re.sub(r":([a-zA-Z0-9_]+)", "{param}", normalized)
    normalized = re.sub(r"\{[^}]+\}", "{param}", normalized)
    return normalized


def _normalize_backend_route_pattern(route_path: str) -> str:
    """Normalize backend `{id}` parameters to `{param}` for structural matching."""
    cleaned = route_path.split("?", 1)[0].strip()
    if len(cleaned) > 1 and cleaned.endswith("/"):
        cleaned = cleaned.rstrip("/")
    return re.sub(r"\{[^}]+\}", "{param}", cleaned)


def _route_matches(frontend_norm: str, backend_norm: str) -> bool:
    """Return True if normalized frontend path matches normalized backend path."""
    if frontend_norm == backend_norm:
        return True
    fe_segs = [s for s in frontend_norm.strip("/").split("/") if s]
    be_segs = [s for s in backend_norm.strip("/").split("/") if s]
    if len(fe_segs) != len(be_segs):
        return False
    for f_seg, b_seg in zip(fe_segs, be_segs):  # noqa: B905 - lengths checked above; strict= needs Python 3.10
        if f_seg == b_seg or f_seg == "{param}" or b_seg == "{param}":
            continue
        return False
    return True


def build_backend_api_index(workspace: Path) -> dict[str, set[str]]:
    """Build a map of normalized `/api/...` route patterns -> allowed HTTP methods."""
    routes: list[DiscoveredRoute] = discover_all_routes(workspace)
    api_index: dict[str, set[str]] = {}
    for r in routes:
        if not r.path.startswith("/api/"):
            continue
        norm = _normalize_backend_route_pattern(r.path)
        methods = api_index.setdefault(norm, set())
        for m in r.methods:
            methods.add(m.upper())
    return api_index


def scan_file_route_contracts(
    file_path: Path,
    rel_path: str,
    content: str,
    api_index: dict[str, set[str]],
) -> list[Finding]:
    """Scan a frontend source file for `/api/...` calls that do not match any backend route."""
    findings: list[Finding] = []
    if not api_index:
        return findings

    norm_rel = rel_path.replace("\\", "/")
    # Skip backend route definition files themselves
    if "/app/api/" in f"/{norm_rel}" or "/pages/api/" in f"/{norm_rel}":
        return findings
    if file_path.suffix.lower() not in FRONTEND_EXTENSIONS:
        return findings

    lines = content.splitlines()
    searchable, executable, _ = views(content, norm_rel)
    calls: list[tuple[int, str, str, str]] = []  # (line_no, method, raw_path, line_snippet)

    for m in FETCH_CALL_RE.finditer(searchable):
        if not executable[m.start():m.start() + 1].strip():
            continue
        raw_url = m.group(2)
        opts = m.group(3) or ""
        m_method = FETCH_METHOD_RE.search(opts)
        method = m_method.group(1).upper() if m_method else "GET"
        line_no = content[: m.start()].count("\n") + 1
        snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else raw_url
        calls.append((line_no, method, raw_url, snippet))

    for m in AXIOS_CALL_RE.finditer(searchable):
        if not executable[m.start():m.start() + 1].strip():
            continue
        method = m.group(1).upper()
        raw_url = m.group(3)
        line_no = content[: m.start()].count("\n") + 1
        snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else raw_url
        calls.append((line_no, method, raw_url, snippet))

    for m in SWR_CALL_RE.finditer(searchable):
        if not executable[m.start():m.start() + 1].strip():
            continue
        raw_url = m.group(2)
        line_no = content[: m.start()].count("\n") + 1
        snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else raw_url
        calls.append((line_no, "GET", raw_url, snippet))

    seen_locs: set[tuple[int, str, str]] = set()
    for line_no, method, raw_url, snippet in calls:
        key = (line_no, method, raw_url)
        if key in seen_locs:
            continue
        seen_locs.add(key)

        fe_norm = _normalize_frontend_api_path(raw_url)
        matched_methods: set[str] = set()
        path_exists = False
        for be_norm, be_methods in api_index.items():
            if _route_matches(fe_norm, be_norm):
                path_exists = True
                matched_methods.update(be_methods)

        if not path_exists:
            findings.append(
                Finding(
                    path=norm_rel,
                    line=line_no,
                    rule="frontend-backend-route-mismatch",
                    severity="P1",
                    text=snippet,
                    message=(
                        f"Frontend calls '{method} {raw_url.split('?', 1)[0]}', "
                        f"but no matching backend `/api/...` route handler or OpenAPI path exists in workspace."
                    ),
                )
            )
        elif "ALL" not in matched_methods and method not in matched_methods:
            allowed_str = ", ".join(sorted(matched_methods))
            findings.append(
                Finding(
                    path=norm_rel,
                    line=line_no,
                    rule="frontend-backend-route-mismatch",
                    severity="P1",
                    text=snippet,
                    message=(
                        f"Frontend calls '{method} {raw_url.split('?', 1)[0]}', "
                        f"but backend route only supports [{allowed_str}]."
                    ),
                )
            )

    return [
        f for f in findings
        if not inline_ignore.suppressed_at(
            lines, f.line, f.rule, engine="contract-guard", path=norm_rel, severity=f.severity, message=f.message
        )
    ]
