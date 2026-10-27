#!/usr/bin/env python3
"""PrufGate Universal Multi-Tenant BOLA / IDOR Verification Engine (Engine 5).

Performs dual-mode Broken Object Level Authorization (BOLA/IDOR) verification across
Python (FastAPI, Django, Flask), TypeScript/Node.js (Next.js App/Pages Router, Express,
Fastify, NestJS), Go (net/http, Gin, Echo, Chi), Java/Kotlin (Spring Boot), Ruby (Rails),
and PHP (Laravel):

1. Universal Route & Dynamic Resource Parameter Discovery:
   - Discovers API endpoints and dynamic object ID parameters (`{id}`, `:id`, `[id]`, `<id>`)
     from OpenAPI/Swagger specs and framework route declarations.
2. Static Authorization & Tenant Isolation Verification (`static-bola-unscoped-access`):
   - Verifies that dynamic-ID route handlers enforce authentication guards (`auth_guards`)
     and scope database/ORM lookups by a tenant/owner key (`tenant_keys`) rather than
     querying solely by primary key.
   - Verifies Next.js Server Actions (`BOLA-UNGUARDED-SERVER-ACTION`) and SQL schema tables
     (`BOLA-TABLE-MISSING-TENANT-COLUMN`).
3. Live Two-Token Differential Matrix Probe (`BOLA-UNAUTHENTICATED-ACCESS`, `BOLA-CROSS-TENANT-ACCESS`):
   - Evaluates 4-request differential matrix (`Unauthenticated` vs `Tenant A -> Self` vs
     `Tenant A -> Tenant B` vs `Tenant B -> Tenant A`) with `curl` PoC generation.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from prufgate import __version__, diff_scope, inline_ignore  # noqa: E402
from prufgate.anti_reward_hacking.test_integrity import (  # noqa: E402
    _strip_comments_and_strings_Preserve_len as _mask,
)
from prufgate.config import ConfigError, PrufGateConfig, rules_match  # noqa: E402
from prufgate.netguard import target_url_error  # noqa: E402
from prufgate.rules import visible  # noqa: E402


class BolaFinding:
    """A static or dynamic BOLA / multi-tenant isolation finding."""

    def __init__(
        self,
        rule_id: str,
        severity: str,
        message: str,
        endpoint_or_file: str,
        line: int = 1,
        curl_poc: str = "",
        details: str = "",
        end_line: int | None = None,
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.endpoint_or_file = endpoint_or_file
        self.line = line
        self.curl_poc = curl_poc
        self.details = details
        # Last line of the handler or table: a changed-files scan keeps the finding
        # when the change touched any line of it.
        self.end_line = max(line, end_line or line)

    @property
    def rule(self) -> str:
        return self.rule_id

    @property
    def path(self) -> str:
        return self.endpoint_or_file

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "target": self.endpoint_or_file,
            "file": self.endpoint_or_file,
            "line": self.line,
            "end_line": self.end_line,
            "curl_poc": self.curl_poc,
            "details": self.details,
        }


@dataclass
class DiscoveredRoute:
    """A discovered API route across any supported web framework or OpenAPI spec."""

    path: str
    raw_path: str
    methods: list[str] = field(default_factory=lambda: ["GET"])
    framework: str = "generic"
    file_path: str = ""
    line: int = 1
    end_line: int = 0
    has_dynamic_param: bool = False
    param_names: list[str] = field(default_factory=list)
    handler_snippet: str = ""
    file_content: str = ""
    # Object access the framework does for the handler (Laravel route-model binding, a
    # Django generic view's get_object()): whether it is scoped was decided at discovery.
    prechecked_scope: bool | None = None


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "reports",
    "out",
}

# PrufGate's own engine sources carry rule patterns as string literals. They are
# skipped only when PrufGate scans its own repository, never in a user's project.
INTERNAL_SCANNER_PATHS = ("prufgate/", "tests/")
_PRUFGATE_ROOT = _THIS_DIR.parent.parent

TEST_DIR_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs", "test_samples", "testdata", "__mocks__"}
_TEST_FILE_RE = re.compile(
    r"(?:^test_.*\.py$|_test\.(?:py|go)$|^conftest\.py$|\.(?:test|spec)\.[cm]?[jt]sx?$"
    r"|(?:Test|Tests|Spec)\.(?:java|kt|cs|php|scala)$|_spec\.rb$)"
)


def is_test_path(rel_path: str) -> bool:
    """True for test files and files inside test directories, matched on whole path segments."""
    parts = rel_path.replace("\\", "/").split("/")
    return any(seg in TEST_DIR_SEGMENTS for seg in parts[:-1]) or bool(_TEST_FILE_RE.search(parts[-1]))


def is_self_scan(workspace: Path) -> bool:
    """True when `workspace` is the PrufGate checkout this engine runs from."""
    try:
        return workspace.resolve() == _PRUFGATE_ROOT
    except OSError:
        return False


def iter_workspace_files(workspace: Path, suffixes: set[str] | None = None) -> list[Path]:
    """Walk `workspace`, pruning SKIP_DIRS by name relative to the workspace (never its parents)."""
    skip_internal = is_self_scan(workspace)
    out: list[Path] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            p = Path(root) / name
            if suffixes is not None and p.suffix.lower() not in suffixes:
                continue
            if skip_internal and str(p.relative_to(workspace)).replace("\\", "/").startswith(INTERNAL_SCANNER_PATHS):
                continue
            out.append(p)
    return out


PUBLIC_ROUTE_KEYWORDS = (
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/metrics",
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/public",
    "/webhook",
    "/api-docs",
    "/openapi",
    "/swagger",
)

DEFAULT_AUTH_GUARD_PATTERNS = (
    r"\bassert[A-Z]\w*",
    r"\bverifySession\b",
    r"\bverify[A-Z]\w*",
    r"\brequireAuth\b",
    r"\brequire[A-Z]\w*",
    r"\bauth\s*\(",
    r"\bauthCheck\b",
    r"\bgetSession\b",
    r"\bgetCurrentUser\b",
    r"\bget_current_user\b",
    r"\bget_current_active_user\b",
    r"\bprotect[A-Z]\w*",
    r"\bcheckPermission\b",
    r"\bDepends\s*\(\s*(?:get_current\w*|require_\w*|verify_\w*|auth\w*)",
    r"@login_required\b",
    r"@permission_required\b",
    r"\bIsAuthenticated\b",
    r"\bLoginRequiredMixin\b",
    r"\bmethod_decorator\(\s*login_required\b",
    r"@UseGuards\b",
    r"@PreAuthorize\b",
    r"@Secured\b",
    r"@RolesAllowed\b",
    r"\bauthenticate_user!\b",
    r"\bauth\(\)->",
    r"\bmiddleware\s*\(\s*['\"]auth",
)

DEFAULT_TENANT_KEYS = (
    "tenant_id",
    "tenantId",
    "organization_id",
    "organizationId",
    "org_id",
    "orgId",
    "workspace_id",
    "workspaceId",
    "user_id",
    "userId",
    "owner_id",
    "ownerId",
    "account_id",
    "accountId",
    "customer_id",
    "customerId",
    "member_id",
    "author_id",
    "created_by",
)

DB_OBJECT_LOOKUP_RE = re.compile(
    # Prisma / Drizzle / TypeORM / Mongoose / Sequelize
    r"\b(?:prisma|db|repo|repository|model|\w+Repository|\w+Repo|\w+Model|\w+Dao)\b[\s\S]{0,80}?\."
    r"(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findById|findOne|findByPk|update|delete|findByIdAndUpdate|findByIdAndDelete|getById|deleteById|getReferenceById)\s*\("
    # Sequelize / Mongoose / Spring Data lookups on any model, e.g. `Invoice.findByPk(id)`
    r"|\.(?:findByPk|findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|getReferenceById)\s*\("
    # Python SQLAlchemy / Django ORM / Tortoise
    r"|\b(?:db|session|async_session)\.(?:get|query|execute|scalar|scalars)\s*\("
    r"|\b[A-Z]\w*\.objects\.(?:get|filter)\s*\("
    r"|\bget_object_or_404\s*\("
    r"|\bfilter_by\s*\(\s*id\s*="
    # Go GORM / sqlx / database/sql
    r"|\b(?:db|tx|conn|r\.db|s\.db|h\.db)\.(?:First|Take|Last|Find|Delete|QueryRow|QueryRowContext|Get|Exec|ExecContext)\s*\("
    # Ruby ActiveRecord / PHP Eloquent
    r"|\b[A-Z]\w*(?:\.find|\.find_by|::find|::findOrFail)(?:\s*\(|\s+params\b)"
    r"|(?:\.|->)(?:find|find_by|findOrFail)\s*\(\s*(?:params\[|\$\w*id\b)"
    # Raw SQL by ID
    r"|\b(?:SELECT|UPDATE|DELETE)\b[\s\S]{0,100}?\bWHERE\s+id\s*=",
    re.MULTILINE,
)


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only within the target's origin (scheme, host, port).

    The target URL is checked before probing; a redirect to another origin (a
    metadata address, say) must not receive the probe or its bearer tokens. A
    refused redirect becomes an HTTPError and is recorded in `refused`, so the
    caller can report the routes it could not test instead of passing them."""

    def __init__(self, target_url: str, refused: list[str] | None = None):
        super().__init__()
        self.origin = _origin(target_url)
        self.refused = refused if refused is not None else []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) == self.origin:
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        self.refused.append(req.full_url)
        print(f"  [BOLA] Not following HTTP {code} redirect to another origin from {req.full_url}", file=sys.stderr)
        return None


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlparse(url)
    try:
        port = p.port or {"http": 80, "https": 443}.get(p.scheme)
    except ValueError:
        port = None
    return (p.scheme.lower(), (p.hostname or "").lower(), port)


def _with_refused_redirects(findings: list, refused: list[str], target_url: str) -> list:
    if refused:
        findings.append(
            BolaFinding(
                rule_id="BOLA-PROBE-REDIRECT-REFUSED",
                severity="P1",
                message=f"{len(refused)} probe request(s) were redirected to another origin and not followed; those routes were not tested",
                endpoint_or_file=target_url,
                details="Point the probe at the final origin (for example the https:// URL) so every route can be tested.",
            )
        )
    return findings


def check_server_active(target_url: str) -> bool:
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or target_url_error(target_url):
        return False
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}"})
        with urllib.request.build_opener(SameOriginRedirectHandler(target_url)).open(req, timeout=2) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _is_meaningful_api_payload(content_type: str, body: str) -> bool:
    """Return True only if response body is non-empty structured API data (not an SPA HTML fallback or error payload)."""
    stripped = body.strip()
    if not stripped or len(stripped) <= 2 or stripped in ("[]", "{}"):
        return False
    ct_lower = (content_type or "").lower()
    if "text/html" in ct_lower or stripped.lower().startswith(("<!doctype", "<html", "<head", "<body")):
        return False
    try:
        parsed = json.loads(stripped)
    except Exception:
        return "application/json" in ct_lower or "application/vnd.api+json" in ct_lower

    if isinstance(parsed, list):
        return len(parsed) > 0
    if isinstance(parsed, dict):
        if not parsed:
            return False
        keys_lower = {k.lower() for k in parsed.keys()}
        if keys_lower <= {"error", "errors", "message", "status", "statuscode", "code", "detail", "ok", "success"}:
            if parsed.get("ok") is False or parsed.get("success") is False or parsed.get("error") or parsed.get("errors"):
                return False
            msg = str(parsed.get("message") or parsed.get("detail") or "").lower()
            if any(w in msg for w in ("unauthorized", "unauthenticated", "forbidden", "not found", "invalid token", "denied")):
                return False
        if "data" in parsed and parsed["data"] in (None, [], {}) and len(parsed) <= 2:
            return False
        return True
    return False


def _normalize_route_template(raw_route: str) -> tuple[str, list[str]]:
    """Normalize framework parameter syntax (`:id`, `[id]`, `<int:id>`, `{id}`) to `{param}` and return `(norm_path, params)`."""
    route = raw_route.strip()
    # Strip Go 1.22 method prefix like "GET /api/items/{id}"
    m_go_method = re.match(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/.*)$", route, re.IGNORECASE)
    if m_go_method:
        route = m_go_method.group(1).strip()

    if not route.startswith("/"):
        route = "/" + route

    params: list[str] = []

    def _record(name: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_]", "", name) or "id"
        params.append(clean)
        return f"{{{clean}}}"

    # Flask / Django: <int:item_id> or <uuid:pk> or <id>
    route = re.sub(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", lambda m: _record(m.group(1)), route)
    # Next.js: [...slug] or [id]
    route = re.sub(r"\[\.{0,3}([a-zA-Z0-9_]+)\]", lambda m: _record(m.group(1)), route)
    # Express / Gin / Rails: :id
    route = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", lambda m: _record(m.group(1)), route)
    # OpenAPI / FastAPI / Spring / Chi: {id}
    for m_brace in re.finditer(r"\{([a-zA-Z0-9_]+)\}", route):
        p_name = m_brace.group(1)
        if p_name not in params:
            params.append(p_name)

    route = re.sub(r"//+", "/", route)
    if len(route) > 1 and route.endswith("/"):
        route = route.rstrip("/")
    return route, params


def _join_route_prefix(prefix: str, sub: str) -> str:
    p = ("/" + prefix.strip("/")) if prefix.strip("/") else ""
    s = ("/" + sub.strip("/")) if sub.strip("/") else ""
    joined = (p + s) or "/"
    return re.sub(r"//+", "/", joined)


# A line that starts another route handler: the current handler's window ends there.
_NEXT_HANDLER_RE = re.compile(
    r"^(?:@\w+\.(?:get|post|put|patch|delete|route|api_route)\s*\("  # FastAPI / Flask
    r"|@(?:Get|Post|Put|Delete|Patch|RequestMapping)\w*\b"  # NestJS / Spring
    r"|export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|DELETE|PATCH)\b"  # Next.js
    r"|(?:app|router|server|fastify|api|hono)\.(?:get|post|put|patch|delete|all)\s*\("  # Express & co
    r"|\w+\.(?:GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*\""  # Go routers
    r"|func\s+(?:\([^)]*\)\s*)?\w+\s*\("  # Go functions
    r"|(?:def|public\s+function|private\s+function|protected\s+function)\s"  # Python / Ruby / PHP
    r"|Route::"  # Laravel
    r"|@[A-Za-z]"  # an annotation/decorator after the body has started opens the next method
    r")"
)


def _extract_handler_window(lines: list[str], start_line: int, max_lines: int = 60) -> str:
    """Lines of the handler starting at `start_line` (1-indexed), up to the next handler or `max_lines`.

    Decorators and the definition they decorate stay together; the window never
    bleeds into the next route definition.
    """
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), start_idx + max_lines)
    window: list[str] = []
    in_header = True  # decorators / the definition line the route starts with
    for idx in range(start_idx, end_idx):
        s = lines[idx].strip()
        if idx > start_idx:
            if in_header and (s.startswith("@") or s.startswith(("def ", "async def ", "func ", "public ", "fun "))):
                window.append(lines[idx])
                if not s.startswith("@"):
                    in_header = False
                continue
            in_header = False
            if _NEXT_HANDLER_RE.match(s):
                break
        window.append(lines[idx])
    return "\n".join(window)


def discover_all_routes(workspace: Path | None) -> list[DiscoveredRoute]:
    """Discover API routes across OpenAPI specs and 10+ web frameworks in `workspace`."""
    if not workspace or not workspace.is_dir():
        return []

    routes: list[DiscoveredRoute] = []

    # 1. OpenAPI / Swagger JSON & YAML files
    openapi_candidates = (
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
        "docs/openapi.json",
        "docs/openapi.yaml",
        "api/openapi.json",
        "api/openapi.yaml",
    )
    for spec_rel in openapi_candidates:
        spec_path = workspace / spec_rel
        if not spec_path.is_file():
            continue
        try:
            raw_text = spec_path.read_text(encoding="utf-8", errors="ignore")
            if spec_path.suffix.lower() in (".yaml", ".yml"):
                spec_data = yaml.safe_load(raw_text) if yaml is not None else {}
            else:
                spec_data = json.loads(raw_text)
            if isinstance(spec_data, dict) and isinstance(spec_data.get("paths"), dict):
                for r_path, methods_obj in spec_data["paths"].items():
                    if not isinstance(r_path, str) or not r_path.startswith("/"):
                        continue
                    norm_path, params = _normalize_route_template(r_path)
                    methods = (
                        [m.upper() for m in methods_obj.keys() if m.lower() in ("get", "post", "put", "patch", "delete")]
                        if isinstance(methods_obj, dict)
                        else ["GET"]
                    )
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=r_path,
                            methods=methods or ["GET"],
                            framework="openapi",
                            file_path=spec_rel,
                            line=1,
                            has_dynamic_param=bool(params),
                            param_names=params,
                        )
                    )
        except Exception:
            pass

    # Walk source files in workspace
    route_suffixes = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".py", ".go", ".java", ".kt", ".rb", ".php"}
    for src_file in iter_workspace_files(workspace, route_suffixes):
        rel_file = str(src_file.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel_file):
            continue
        sfx = src_file.suffix.lower()

        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = content.splitlines()

        # 2. Next.js App Router (**/app/api/**/route.{ts,js}) & Pages Router (**/pages/api/**/*.{ts,js})
        parts = Path(rel_file).parts
        if src_file.stem == "route" and "app" in parts and sfx in (".ts", ".tsx", ".js", ".jsx"):
            app_idx = parts.index("app")
            seg_parts = [s for s in parts[app_idx + 1 : -1] if not (s.startswith("(") and s.endswith(")"))]
            raw_route = "/" + "/".join(seg_parts)
            norm_path, params = _normalize_route_template(raw_route)
            # Find exported HTTP method functions (GET, POST, PUT, PATCH, DELETE)
            found_handler = False
            for idx, line in enumerate(lines, start=1):
                m_fn = re.search(
                    r"\bexport\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b",
                    line,
                )
                if m_fn:
                    found_handler = True
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_fn.group(1)],
                            framework="nextjs",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
            if not found_handler:
                routes.append(
                    DiscoveredRoute(
                        path=norm_path,
                        raw_path=raw_route,
                        methods=["GET"],
                        framework="nextjs",
                        file_path=rel_file,
                        line=1,
                        has_dynamic_param=bool(params),
                        param_names=params,
                        handler_snippet=content[:2000],
                        file_content=content,
                    )
                )
            continue

        if "pages" in parts and "api" in parts and sfx in (".ts", ".tsx", ".js", ".jsx"):
            pages_idx = parts.index("pages")
            seg_parts = list(parts[pages_idx + 1 : -1])
            if src_file.stem != "index":
                seg_parts.append(src_file.stem)
            raw_route = "/" + "/".join(seg_parts)
            norm_path, params = _normalize_route_template(raw_route)
            routes.append(
                DiscoveredRoute(
                    path=norm_path,
                    raw_path=raw_route,
                    methods=["ALL"],
                    framework="nextjs",
                    file_path=rel_file,
                    line=1,
                    has_dynamic_param=bool(params),
                    param_names=params,
                    handler_snippet=content[:2500],
                    file_content=content,
                )
            )
            continue

        # 3. Express / Fastify / NestJS (TypeScript / JavaScript)
        if sfx in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            # Check NestJS @Controller('prefix')
            ctrl_m = re.search(r"""@Controller\(\s*["'`]([^"'`]*)["'`]\s*\)""", content)
            if ctrl_m:
                ctrl_prefix = ctrl_m.group(1)
                nest_re = re.compile(
                    r"""@(Get|Post|Put|Patch|Delete)\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)"""
                )
                for idx, line in enumerate(lines, start=1):
                    m_nest = nest_re.search(line)
                    if m_nest:
                        method = m_nest.group(1).upper()
                        sub_path = m_nest.group(2) or ""
                        raw_route = _join_route_prefix(ctrl_prefix, sub_path)
                        norm_path, params = _normalize_route_template(raw_route)
                        routes.append(
                            DiscoveredRoute(
                                path=norm_path,
                                raw_path=raw_route,
                                methods=[method],
                                framework="nestjs",
                                file_path=rel_file,
                                line=idx,
                                has_dynamic_param=bool(params),
                                param_names=params,
                                handler_snippet=_extract_handler_window(lines, idx),
                                file_content=content,
                            )
                        )

            # Express / Fastify / Hono route registrations: app.get('/api/...', ...) or router.get('/items/:id', ...)
            exp_re = re.compile(
                r"""\b(?:app|router|server|fastify|api|hono)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]([^"'`]+)["'`]"""
            )
            for idx, line in enumerate(lines, start=1):
                m_exp = exp_re.search(line)
                if m_exp:
                    method = m_exp.group(1).upper()
                    raw_route = m_exp.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="express",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

        # 4. Python: FastAPI, Flask, Django
        elif sfx == ".py":
            prefix_m = re.search(
                r"""(?:APIRouter|Blueprint)\([^)]*(?:prefix|url_prefix)\s*=\s*["']([^"']+)["']""",
                content,
            )
            router_prefix = prefix_m.group(1) if prefix_m else ""

            py_route_re = re.compile(
                r"""^\s*@\w+\.(get|post|put|patch|delete|route|api_route)\s*\(\s*["']([^"']+)["']"""
            )
            for idx, line in enumerate(lines, start=1):
                m_py = py_route_re.search(line)
                if m_py:
                    method_raw = m_py.group(1).upper()
                    method = "GET" if method_raw in ("ROUTE", "API_ROUTE") else method_raw
                    raw_route = _join_route_prefix(router_prefix, m_py.group(2))
                    norm_path, params = _normalize_route_template(raw_route)
                    fw = "flask" if "<" in m_py.group(2) or "Blueprint" in content else "fastapi"
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework=fw,
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

            # Django urls.py: path("items/<uuid:id>/", views.detail)
            django_re = re.compile(r"""\b(?:path|re_path)\s*\(\s*["']([^"']+)["']""")
            if "urlpatterns" in content or src_file.name.endswith("urls.py"):
                for idx, line in enumerate(lines, start=1):
                    m_dj = django_re.search(line)
                    if m_dj:
                        raw_route = "/" + m_dj.group(1).lstrip("^/")
                        norm_path, params = _normalize_route_template(raw_route)
                        routes.append(
                            DiscoveredRoute(
                                path=norm_path,
                                raw_path=raw_route,
                                methods=["ALL"],
                                framework="django",
                                file_path=rel_file,
                                line=idx,
                                has_dynamic_param=bool(params),
                                param_names=params,
                                handler_snippet=_extract_handler_window(lines, idx),
                                file_content=content,
                            )
                        )

        # 5. Go: net/http, Gin, Echo, Chi, Gorilla Mux
        elif sfx == ".go":
            go_route_re = re.compile(
                r"""\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*"([^"]+)"(?:\s*,\s*([a-zA-Z0-9_.]+))?"""
            )
            for idx, line in enumerate(lines, start=1):
                m_go = go_route_re.search(line)
                if m_go:
                    verb = m_go.group(1).upper()
                    method = "ALL" if verb.startswith("HANDLE") else verb
                    raw_route = m_go.group(2)
                    handler_ref = m_go.group(3) or ""
                    norm_path, params = _normalize_route_template(raw_route)
                    snippet = _extract_handler_window(lines, idx)
                    end_ln = idx + max(0, len(snippet.splitlines()) - 1)
                    # If handler is a named function in the same file, append its body to snippet
                    if handler_ref:
                        fn_short = handler_ref.split(".")[-1]
                        m_fn_def = re.search(rf"\bfunc\s+(?:\([^)]+\)\s*)?{re.escape(fn_short)}\s*\(", content)
                        if m_fn_def:
                            fn_ln = content[: m_fn_def.start()].count("\n") + 1
                            fn_win = _extract_handler_window(lines, fn_ln)
                            snippet = snippet + "\n" + fn_win
                            end_ln = max(end_ln, fn_ln + max(0, len(fn_win.splitlines()) - 1))
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="go",
                            file_path=rel_file,
                            line=idx,
                            end_line=end_ln,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=snippet,
                            file_content=content,
                        )
                    )

        # 6. Java / Kotlin: Spring Boot (@RequestMapping, @GetMapping, @PostMapping, etc.)
        elif sfx in (".java", ".kt"):
            cls_map = re.search(
                r"""@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""",
                content,
            )
            base_prefix = cls_map.group(1) if cls_map else ""
            spring_re = re.compile(
                r"""@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']*)["'][^)]*\))?"""
            )
            for idx, line in enumerate(lines, start=1):
                if idx == (content[: cls_map.start()].count("\n") + 1 if cls_map else -1):
                    continue
                m_sp = spring_re.search(line)
                if m_sp:
                    ann = m_sp.group(1)
                    method = ann.replace("Mapping", "").upper()
                    if method == "REQUEST":
                        method = "ALL"
                    sub_path = m_sp.group(2) or ""
                    raw_route = _join_route_prefix(base_prefix, sub_path)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="spring",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

        # 7. Ruby on Rails & PHP Laravel
        elif sfx == ".rb":
            rails_re = re.compile(r"""^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']""")
            res_re = re.compile(r"""^\s*resources\s+:([a-zA-Z0-9_]+)""")
            for idx, line in enumerate(lines, start=1):
                m_rl = rails_re.search(line)
                if m_rl:
                    raw_route = m_rl.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_rl.group(1).upper()],
                            framework="rails",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
                m_res = res_re.search(line)
                if m_res:
                    res_name = m_res.group(1)
                    routes.append(
                        DiscoveredRoute(
                            path=f"/{res_name}/{{id}}",
                            raw_path=f"/{res_name}/:id",
                            methods=["GET", "PUT", "DELETE"],
                            framework="rails",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=True,
                            param_names=["id"],
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
        elif sfx == ".php":
            laravel_re = re.compile(
                r"""\bRoute::(get|post|put|patch|delete|any)\s*\(\s*["']([^"']+)["']""",
                re.IGNORECASE,
            )
            for idx, line in enumerate(lines, start=1):
                m_lv = laravel_re.search(line)
                if m_lv:
                    raw_route = m_lv.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_lv.group(1).upper()],
                            framework="laravel",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

    return routes


def discover_workspace_api_routes(workspace: Path | None) -> list[str]:
    """Discover API endpoint strings for dynamic probing (backward-compatible with `bola_matrix.py`)."""
    all_routes = discover_all_routes(workspace)
    discovered: list[str] = []
    for r in all_routes:
        low = r.path.lower()
        if any(pub in low for pub in PUBLIC_ROUTE_KEYWORDS):
            continue
        # Convert any `{param}` in dynamic routes to `{tenant_id}` for cross-tenant probe substitution
        probe_route = re.sub(r"\{[^}]+\}", "{tenant_id}", r.path)
        discovered.append(probe_route)

    seen: set[str] = set()
    unique: list[str] = []
    for route_str in discovered:
        if route_str not in seen:
            seen.add(route_str)
            unique.append(route_str)
    return unique[:25]


def _build_auth_guard_regex(config: PrufGateConfig) -> re.Pattern[str]:
    patterns = list(DEFAULT_AUTH_GUARD_PATTERNS)
    for custom in config.auth_guards:
        clean = custom.strip()
        if clean:
            patterns.append(rf"\b{re.escape(clean)}\b")
    return re.compile("|".join(patterns))


def _build_tenant_key_regex(config: PrufGateConfig) -> re.Pattern[str]:
    keys = list(DEFAULT_TENANT_KEYS) + [k.strip() for k in config.tenant_keys if k.strip()]
    escaped = [re.escape(k) for k in dict.fromkeys(keys)]
    return re.compile(r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE)


# The authenticated caller as a value (`req.user.id`, `current_user.projects`, `Auth::user()->`).
# It proves scoping only inside the lookup itself or in an ownership comparison.
_ID = (
    r"(?:\b(?:current_user|currentUser|current_account|current_tenant|current_organization|Current\.(?:user|account|tenant))\??\.\w[\w.]*"
    r"|\b(?:req|request|ctx|c|context|session|auth|g)\??\.(?:user|session|auth|principal|tenant|org)\??\.\w[\w.]*"
    r"|\bprincipal\.\w[\w.]*|\bc\.(?:MustGet|Get)\(\s*\"(?:user|tenant|claims|org)\w*\"\)"
    r"|\bAuth::user\(\)|\bauth\(\)->(?:user|id)\(\)|\$request->user\(\))"
)
CALLER_IDENTITY_RE = re.compile(_ID, re.IGNORECASE)
# `doc.ownerId !== req.user.id`, `if record.user_id != current_user.id` (but not `!req.user.id` or `== null`).
OWNERSHIP_COMPARE_RE = re.compile(
    rf"[\w\])]\s*(?:===?|!==?)\s*{_ID}|{_ID}\s*(?:===?|!==?)\s*(?!null\b|undefined\b|nil\b|None\b)[\w$@]",
    re.IGNORECASE,
)
# An explicit authorization/ownership check in the handler, given something to check:
# a throwing check (`authorize(user, doc)`, Pundit `authorize @doc`), or a boolean one
# that is tested (`if (!canAccess(user, id))`, `abort_unless(Gate::allows(...), 403)`).
# Use `_ownership_call`, which ignores comments and strings.
OWNERSHIP_CALL_RE = re.compile(
    r"\b(?:authorize|checkOwnership|verifyOwnership|assertTenant|assertMembership|assertOwner|checkAccess)\s*\(\s*[^\s)]"
    r"|\bauthorize\s+@\w"
    r"|(?:\bif\s*\(|\bunless\s|\bassert\s|\babort_(?:if|unless)\s*\(|!)[\s!(]*(?:await\s+)?"
    r"(?:[\w$.]+\.)?(?:canAccess|isMember|hasAccess|Gate::(?:allows|check))\s*\(\s*[^\s)]",
)


def _ownership_call(code: str) -> bool:
    return bool(_code_matches(OWNERSHIP_CALL_RE, code))

# A tenant key read from the request (URL params, query string or body) is attacker-controlled.
_REQUEST_VALUE_PREFIX_RE = re.compile(
    r"(?:\b(?:params|query|body|args|kwargs|path_params|query_params|route|GET|POST)\s*(?:\??\.|\[\s*[\"':]?|\.get\(\s*[\"'])"
    r"|\.(?:Param|Query|PostForm|FormValue|PathValue)\(\s*\"|\$request->(?:input|route|query|get)\(\s*[\"'])\s*$"
)


# The value assigned to a tenant key (`orgId: req.query.orgId`, `org_id=org_id`).
_KEY_VALUE_RE = re.compile(r"""\s*(?:['"]\s*(?:,|=>|:)|===?|=>|:|=)\s*([\w$.>\[\]'"-]+(?:\(\s*["']?\w*)?)""")
_REQUEST_SOURCE_RE = re.compile(
    r"""^(?:\w+\.)?(?:params|query|body|args|path_params|query_params|form)\b"""
    r"""|^\$request->(?:input|route|query|get)\b|^\$_(?:GET|POST|REQUEST)\b|^\w+\.(?:Param|Query|PostForm|FormValue|PathValue)\("""
)


def _norm_key(name: str) -> str:
    return name.replace("_", "").lower()


_REQUEST_INPUT_RE = re.compile(
    r"\b(?:req|request|ctx|c|context)\.(?:params|query|body|args|path_params|query_params|Param|Query|PostForm|FormValue|PathValue)\b"
    r"|\bparams\s*[\[.]|\$request->|\$_(?:GET|POST|REQUEST)\b"
)


# Where a traced local value came from. Request input (query, params, body, headers)
# is chosen by the caller; scoping has to come from the authenticated session.
_TRACE_REQUEST_RE = re.compile(
    r"\b(?:req|request|ctx|c|context|ctx\.request|self\.request)\.(?:query|params|body|headers|header|args|form|json|data"
    r"|GET|POST|COOKIES|cookies|query_params|path_params|kwargs|getParameter|getHeader|get_json)\b"
    r"|\bself\.kwargs\b|\.(?:Param|Query|DefaultQuery|PostForm|FormValue|PathValue|GetHeader|QueryParam)\s*\("
    r"|\.URL\.Query\(\)|\.Header\.Get\(|\bparams\s*\[|\bparams\.(?:require|permit|fetch)\b"
    r"|\$request->(?:input|route|query|get|header|all|post)\b|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"
    r"|@(?:RequestParam|PathVariable|RequestHeader|RequestBody)\b"
)
_TRACE_CALLER_RE = re.compile(
    _ID + r"|\b(?:req|request|ctx\.state|session|context)\.(?:user|session|auth|principal)\b"
    r"|\b(?:current_user|currentUser|current_tenant|current_account)\b|\bget_current_user\b|\bgetServerSession\s*\("
    r"|\bgetSession\s*\(|\bauth\(\s*\)|\bAuth::(?:user|id)\(\)|\bSecurityContextHolder\b|@AuthenticationPrincipal\b",
    re.IGNORECASE,
)


def _assignments(name: str, snippet: str) -> list[str]:
    """The right-hand sides of every simple assignment to local `name` in the handler:
    `const org = ...`, `org := ...`, `$org = ...`, `String org = ...`, a destructuring
    `const { org } = source` (returned as `source.org`) or `const [org] = source`."""
    n = re.escape(name)
    rhs: list[str] = []
    for m in re.finditer(
        rf"^[ \t]*(?:(?:const|let|var|val|final)\s+)?(?:[\w<>\[\]]+\s+)?(?<![\w$.]){n}(?:\s*,\s*[\w$]+)*"
        rf"\s*(?::\s*[\w<>\[\]|.]+)?\s*:?=(?![=>])\s*([^;\n]+)",
        snippet,
        re.MULTILINE,
    ):
        rhs.append(m.group(1).strip())
    for m in re.finditer(r"^[ \t]*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([^;\n]+)", snippet, re.MULTILINE):
        if re.search(rf"(?<![\w$]){n}\b", m.group(1)):
            rhs.append(f"{m.group(2).strip()}.{name}")
    for m in re.finditer(r"^[ \t]*(?:const|let|var)\s*\[([^\]]*)\]\s*=\s*([^;\n]+)", snippet, re.MULTILINE):
        if re.search(rf"(?<![\w$]){n}\b", m.group(1)):
            rhs.append(m.group(2).strip())
    return rhs


def _traced_source(value: str, snippet: str, hops: int = 6, seen: frozenset[str] = frozenset()) -> str | None:
    """'caller', 'request' or None (unknown): where `value` came from, following every
    local it names back through every assignment to it (at most `hops` deep). Request input
    anywhere wins: `org = req.user.orgId || req.query.orgId`, `String(raw)` with
    `raw = req.query.orgId`, or one reassignment from the request among several. The
    assignment is followed before any name heuristic, so `const currentUser = req.query`
    is request input."""
    if _TRACE_REQUEST_RE.search(value) or _REQUEST_SOURCE_RE.match(value):
        return "request"
    found = None
    if hops > 0:
        for name in dict.fromkeys(re.findall(r"(?<![\w$.])\$?[A-Za-z_]\w*", value)):
            if name in seen:
                continue
            for rhs in _assignments(name, snippet):
                src = _traced_source(rhs, snippet, hops - 1, seen | {name})
                if src == "request":
                    return "request"
                found = found or src
    if found:
        return found
    return "caller" if _TRACE_CALLER_RE.search(value) else None


def _lookup_regions(snippet: str) -> list[str]:
    """The statement around each DB lookup: from the start of its line until the
    brackets balance (following `.chain()` continuation lines), capped at 800 chars."""
    regions: list[str] = []
    for m in DB_OBJECT_LOOKUP_RE.finditer(snippet):
        start = snippet.rfind("\n", 0, m.start()) + 1
        depth, i, end = 0, start, min(len(snippet), start + 800)
        while i < end:
            ch = snippet[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth <= 0 and i > m.start():
                break
            elif ch == "\n" and depth <= 0 and i > m.start():
                if not snippet[i + 1 : i + 80].lstrip().startswith((".", "->")):
                    break
            i += 1
        regions.append(snippet[start:i])
    return regions


def _caller_identity(text: str, snippet: str) -> bool:
    """The caller's identity appears in `text`, and is not a local that holds request input
    under an identity-like name (`const currentUser = req.query`)."""
    return any(_traced_source(m.group(0), snippet) != "request" for m in CALLER_IDENTITY_RE.finditer(text))


def _region_scoped(region: str, params: set[str], tenant_re: re.Pattern[str], snippet: str = "") -> bool:
    if _caller_identity(region, snippet):
        return True
    for m in tenant_re.finditer(region):
        if _norm_key(m.group(0)) in params:
            continue
        if _REQUEST_VALUE_PREFIX_RE.search(region[max(0, m.start() - 40) : m.start()]):
            continue
        mv = _KEY_VALUE_RE.match(region, m.end())
        if mv:
            value = mv.group(1)
            if _REQUEST_SOURCE_RE.match(value) or _norm_key(value.split("(")[0]) in params:
                continue
        elif region[m.start() - 1 : m.start()] == ".":
            # A value read off a local (`orgId: currentUser.orgId`): trace that local.
            value = re.search(r"[\w$.]+$", region[: m.end()]).group(0)
        elif re.match(r"\s*[,}]", region[m.end() :]):
            value = m.group(0)  # shorthand `{ id, orgId }`: the local variable of that name
        else:
            return True
        # A local variable traced back to request input is not scoping (`const org = req.query.orgId`).
        if _traced_source(value, snippet) == "request":
            continue
        return True
    return False


def _has_tenant_scope(snippet: str, route_params: list[str], tenant_re: re.Pattern[str]) -> bool:
    """True when every lookup in the handler is scoped by something the caller cannot forge.

    Scoped means: the caller's identity or a tenant key not taken from the request
    appears in the lookup statement itself, or the handler compares the record's owner
    with the caller, or calls an explicit authorization check. A tenant key that is only a
    route parameter or request value (`orgId: req.params.orgId`) proves nothing, and the
    identity merely appearing elsewhere (`log(req.user.email)`) proves nothing either.
    """
    if _ownership_call(snippet) or any(_caller_identity(m.group(0), snippet) for m in OWNERSHIP_COMPARE_RE.finditer(snippet)):
        return True
    params = {_norm_key(p) for p in route_params}
    regions = _lookup_regions(snippet) or [snippet]
    # Lookups fed by request input must be scoped; one keyed by an already-loaded record
    # (`where: { id: order.customerId }`) is not the IDOR entry point.
    param_word = (
        re.compile(r"(?<![.\w])(?:" + "|".join(re.escape(p) for p in route_params) + r")\b(?!\s*:[^:])")
        if route_params
        else None
    )
    fed = [r for r in regions if _REQUEST_INPUT_RE.search(r) or (param_word and param_word.search(r))]
    return all(_region_scoped(r, params, tenant_re, snippet) for r in (fed or regions))


# Auth applied to every handler in a file: Express/Fastify `router.use(auth)`, Rails
# `before_action :authenticate...`, Laravel `$this->middleware('auth')`, a class-level
# Spring/NestJS guard, a Go router group `.Use(authMiddleware)`.
FILE_LEVEL_AUTH_RE = re.compile(
    r"^\s*(?:app|router|server|api|r|g|e|v1|group|\w+Router)\.use\s*\(\s*(?:[\"'][^\"']*[\"']\s*,\s*)?\w*(?:auth|Auth|jwt|Jwt|JWT|login|Login|protect|Protect)"
    r"|^\s*before_action\s+:(?:authenticate|require_login|require_user|authorize)\w*"
    r"|\$this->middleware\(\s*\[?\s*[\"']auth"
    r"|^\s*(?:@UseGuards|@PreAuthorize|@Secured|@RolesAllowed)\b[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:export\s+)?(?:public\s+)?class\b"
    r"|\.Use\(\s*\w*(?:auth|Auth|jwt|JWT|Jwt)"
    r"|\.addHook\(\s*[\"'](?:onRequest|preHandler|preValidation|preParsing)[\"']\s*,\s*[\w.]*(?:auth|Auth|jwt|Jwt|JWT|verify|Verify)",
    re.MULTILINE,
)
_SKIPPED_AUTH_RE = re.compile(r"^\s*skip_before_action\s+:authenticate", re.MULTILINE)

# Auth registered once for the whole application, in a file other than the handler's.
# Explicit auth words only: `session(...)`, `requestId` or `rateLimitGuard` authenticate no one.
_MIDDLEWARE_AUTH_WORD = r"[\w$.]*(?:auth|Auth|AUTH|jwt|Jwt|JWT|login|Login|passport|protect|Protect)[\w$.]*"
_EXPRESS_ROUTE_RE = re.compile(r"""\b\w+\.(?:get|post|put|patch|delete|all|route)\s*\(\s*["'`]/""")
_JS_IMPORT_RES = (
    re.compile(r"""\bimport\s+(\w+)\s+from\s+["'](\.[^"']+)["']"""),
    re.compile(r"""\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["'](\.[^"']+)["']\s*\)"""),
)
_JS_NAMED_IMPORT_RE = re.compile(r"""\bimport\s*\{([^}]*)\}\s*from\s*["'](\.[^"']+)["']""")
_NEST_GLOBAL_GUARD_RE = re.compile(r"provide\s*:\s*APP_GUARD\s*,\s*useClass\s*:\s*(\w+)|useGlobalGuards\s*\(\s*(?:new\s+)?(\w+)")
_NEST_AUTH_GUARD_NAME_RE = re.compile(r"auth|jwt|session|passport|clerk|keycloak|access", re.IGNORECASE)
_NEST_PUBLIC_RE = re.compile(r"@(?:Public|SkipAuth|AllowAnonymous|IsPublic|NoAuth)\s*\(")
_SPRING_METHOD_SECURITY_RE = re.compile(r"@Enable(?:Global)?MethodSecurity\b")
_SPRING_ANY_REQUEST_AUTH_RE = re.compile(
    r"\.anyRequest\(\)\s*\.(?:authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\(|anyRequest\s*,\s*authenticated\b"
)
_SPRING_PERMIT_ALL_RE = re.compile(r"(?:requestMatchers|antMatchers|mvcMatchers)\(([^)]*)\)\s*\.permitAll\(\)")
# Method security that ties the object to the caller: `@PreAuthorize("@acl.canRead(#id)")`,
# `hasPermission(#id, ...)`, `@PostAuthorize("returnObject.ownerId == authentication.name")`.
_SPRING_OBJECT_AUTH_RE = re.compile(r"""@(?:Pre|Post)Authorize\(\s*(?:value\s*=\s*)?"([^"]*)\"""")
# A bean or hasPermission call counts only when it is handed the object (`#id`, `returnObject`)
# or the caller: `@guard.check()` checks nothing about this record.
_SPRING_OBJECT_EXPR_RE = re.compile(
    r"(?:hasPermission|@\w+\.\w+)\s*\([^)]*(?:#\w+|returnObject|filterObject|authentication|principal)|(?:authentication|principal)[\s\S]*(?:#\w+|returnObject)"
    r"|(?:#\w+|returnObject)[\s\S]*(?:authentication|principal)"
)
_DRF_DEFAULT_AUTH_RE = re.compile(
    r"""["']DEFAULT_PERMISSION_CLASSES["']\s*:\s*[\[(][^\])]*\b(?:IsAuthenticated|IsAdminUser|DjangoModelPermissions)\b"""
)


def _code_matches(rx: re.Pattern[str], text: str) -> list[re.Match[str]]:
    """Matches of `rx` in code: comments are removed first, and a match lying wholly inside
    a string literal is dropped. String contents stay visible to the pattern (paths, keys)."""
    masked = _mask(text)
    return [m for m in rx.finditer(_mask(text, keep_strings=True)) if masked[m.start() : m.end()].strip()]


# Files where application-wide auth is configured. Text elsewhere (notes, docs, a helper
# nobody imports) configures nothing.
_NEST_ENTRY_RE = re.compile(r"(?:^|/)main\.[jt]s$|\.module\.[jt]s$")
_DJANGO_SETTINGS_RE = re.compile(r"(?:^|/)settings[^/]*\.py$|(?:^|/)settings/[^/]+\.py$")
_SPRING_CONFIG_RE = re.compile(r"@(?:Configuration|EnableWebSecurity|SpringBootApplication)\b|\bSecurityFilterChain\b")


def _resolve_js_import(src: Path, spec: str, workspace: Path) -> Path | None:
    if spec.startswith(("@/", "~/")):  # the usual tsconfig alias for the source root
        bases = [workspace / "src" / spec[2:], workspace / spec[2:]]
    else:
        bases = [src.parent / spec]
    cands: list[Path] = []
    for base in bases:
        cands += [base] + [Path(f"{base}{ext}") for ext in (".ts", ".js", ".mjs", ".cjs", ".tsx")]
        cands += [base / "index.ts", base / "index.js"]
        if base.suffix in (".js", ".mjs"):
            cands.append(base.with_suffix(".ts"))
    root = workspace.resolve()
    for c in cands:
        try:
            if c.is_file() and c.resolve().is_relative_to(root):
                return c
        except OSError:
            continue
    return None


_BODY_CALL_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(?:[\w$\[\]{},\s]+?(?::=|=)\s*)?(?:await\s+)?(?:this\.)?([A-Za-z_$][\w$]*)\s*\("
)
_NOT_A_GUARD_CALL = {"if", "for", "while", "switch", "return", "catch", "function", "print", "console"}
# The wrapper refuses the request: an error status, a throw, or an abort/redirect.
_REFUSES_RE = re.compile(
    r"\b(?:401|403)\b|Unauthori[sz]ed|Forbidden|\bthrow\b|\braise\b|\babort\w*\s*\(|\bhttp\.Error\b|\bredirect\s*\(|\bnotFound\s*\("
)
_JS_IMPORT_NAMES_RE = re.compile(r"""import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']""")
_PY_IMPORT_NAMES_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^)\n]+)", re.MULTILINE)


def _definition_body(text: str, name: str) -> str:
    """The body of function `name` defined in `text` (at most 40 lines), or ""."""
    n = re.escape(name)
    m = re.search(
        rf"^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*{n}\s*[(<]"
        rf"|(?:const|let|var)\s+{n}\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b|\(|[\w$]+\s*=>)"
        rf"|(?:async\s+)?def\s+{n}\s*\(|func\s+(?:\([^)]*\)\s*)?{n}\s*\()",
        text,
        re.MULTILINE,
    )
    if not m:
        return ""
    lines = text.splitlines()
    start = text.count("\n", 0, m.start())
    masked = tuple(_mask(text).splitlines())
    end_ln = min(start + 40, diff_scope.block_end(masked, start + 1))
    if end_ln <= start + 1 and "{" not in masked[start] and not masked[start].rstrip().endswith(":"):
        while (
            end_ln < min(len(lines), start + 6)
            and lines[end_ln - 1].strip()
            and not lines[end_ln - 1].rstrip().endswith(";")
        ):
            end_ln += 1
    return "\n".join(lines[start:end_ln])


def _wrapper_body(name: str, file_content: str, file_path: str, workspace: Path) -> str:
    """The definition of `name`: in the route's file, a file it imports `name` from, or (Go) its package."""
    body = _definition_body(file_content, name)
    if body:
        return body
    src = workspace / file_path
    for m in _JS_IMPORT_NAMES_RE.finditer(file_content):
        names = {part.split(" as ")[-1].strip() for part in m.group(1).split(",")}
        if name in names:
            original = next((part.split(" as ")[0].strip() for part in m.group(1).split(",")
                             if part.split(" as ")[-1].strip() == name), name)
            target = _resolve_js_import(src, m.group(2), workspace) if m.group(2).startswith((".", "@/", "~/")) else None
            if target is not None:
                with contextlib.suppress(OSError):
                    return _definition_body(target.read_text(encoding="utf-8", errors="ignore"), original)
            return ""
    for m in _PY_IMPORT_NAMES_RE.finditer(file_content):
        if name in {part.split(" as ")[-1].strip() for part in m.group(2).split(",")}:
            mod = m.group(1)
            rel = mod.lstrip(".").replace(".", "/")
            base = src.parent if mod.startswith(".") else workspace
            for cand in (base / f"{rel}.py", base / rel / "__init__.py"):
                if cand.is_file() and cand.resolve().is_relative_to(workspace.resolve()):
                    with contextlib.suppress(OSError):
                        return _definition_body(cand.read_text(encoding="utf-8", errors="ignore"), name)
            return ""
    if file_path.endswith(".go"):
        for sib in sorted(src.parent.glob("*.go")):
            if sib != src and not sib.name.endswith("_test.go"):
                with contextlib.suppress(OSError):
                    body = _definition_body(sib.read_text(encoding="utf-8", errors="ignore"), name)
                    if body:
                        return body
    return ""


_ASYNC_DEF_RE = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?async\b|=\s*async\b")


def _wrapper_guard(snippet: str, file_content: str, file_path: str, workspace: Path, auth_re: re.Pattern[str]) -> bool:
    """A project guard wrapper, followed one hop: the handler's first statements (before any
    object lookup, at most three) call a function whose definition calls a known guard and
    refuses the request (an error status, a throw, an abort or a redirect)."""
    lines = _mask(snippet, keep_strings=True).splitlines()
    body_at = next((i + 1 for i, ln in enumerate(lines) if ln.rstrip().endswith(("{", ":"))), None)
    if body_at is None:
        return False
    checked = 0
    for ln in lines[body_at:]:
        if not ln.strip():
            continue
        if checked == 3 or DB_OBJECT_LOOKUP_RE.search(ln):
            break
        checked += 1
        m = _BODY_CALL_RE.match(ln)
        if not m or m.group(1) in _NOT_A_GUARD_CALL:
            continue
        body = _wrapper_body(m.group(1), file_content, file_path, workspace)
        if not body:
            continue
        if _ASYNC_DEF_RE.search(body.splitlines()[0]) and not re.search(r"\b(?:await|return)\b", ln):
            continue
        # The guard must be called inside the wrapper, not be the wrapper's own name.
        inner = "\n".join(body.splitlines()[1:]) or re.sub(rf"\b{re.escape(m.group(1))}\b", "_", body, count=1)
        if _code_matches(auth_re, inner) and _code_matches(_REFUSES_RE, body):
            return True
    return False


def _under_prefix(path: str, prefix: str) -> bool:
    """`path` is `prefix` or below it on a `/` boundary: `/api` covers `/api/x`, not `/api-public`."""
    prefix = prefix.rstrip("/")
    return not prefix or path == prefix or path.startswith(prefix + "/")


def _middleware_auth_files(workspace: Path) -> set[str]:
    """Route files mounted after application-wide auth in another file.

    Resolved, one level deep: in an entry file, `app.use(auth)` (or `app.use('/api', auth)`,
    or a Fastify `addHook('onRequest', auth)`) on a line before `app.use('/api/x', router)`
    / `fastify.register(plugin)`, where the router is a relative import of a file that
    registers routes; or auth passed inline, `app.use('/x', auth, router)`. Not resolved:
    auth applied after the mount, sub-routers mounted by the mounted router, routers
    built by a function or a package import.
    """
    out: set[str] = set()
    for f in iter_workspace_files(workspace, {".ts", ".js", ".mjs", ".cjs"}):
        rel = str(f.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel):
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        text = _mask(raw, keep_strings=True)
        if ".use(" not in text and ".register(" not in text:
            continue
        masked = _mask(raw)
        imports: dict[str, str] = {}
        for rx in _JS_IMPORT_RES:
            imports.update({m.group(1): m.group(2) for m in rx.finditer(text)})
        for m in _JS_NAMED_IMPORT_RE.finditer(text):
            for part in m.group(1).split(","):
                name = part.split(" as ")[-1].strip()
                if name:
                    imports[name] = m.group(2)
        routers: dict[str, Path] = {}
        for name, spec in imports.items():
            target = _resolve_js_import(f, spec, workspace)
            if target is not None and _EXPRESS_ROUTE_RE.search(target.read_text(encoding="utf-8", errors="ignore")):
                routers[name] = target
        if not routers:
            continue
        global_auth: list[str] = []  # path prefixes protected from here on ("" = every path)
        for m in re.finditer(r"^\s*(\w+)\.(use|register|addHook)\s*\((.*)", text, re.MULTILINE):
            if not masked[m.start(1)].strip():  # inside a string literal
                continue
            kind, args = m.group(2), m.group(3)
            if kind == "addHook":
                if re.match(r"""\s*["'](?:onRequest|preHandler|preValidation|preParsing)["']\s*,\s*""" + _MIDDLEWARE_AUTH_WORD, args):
                    global_auth.append("")
                continue
            m_path = re.match(r"""\s*["'`]([^"'`]*)["'`]\s*,""", args) if kind == "use" else None
            path = m_path.group(1) if m_path else ""
            idents = re.findall(r"[A-Za-z_$][\w$.]*", re.sub(r"""(["'`]).*?\1""", "''", args))
            mounted = [routers[i] for i in idents if i in routers]
            authy = [i for i in idents if i not in routers and re.fullmatch(_MIDDLEWARE_AUTH_WORD, i)]
            if not mounted:
                if authy and kind == "use":
                    global_auth.append(path)
                continue
            if authy or any(_under_prefix(path, p) for p in global_auth):
                out.update(str(t.relative_to(workspace)).replace("\\", "/") for t in mounted)
    return out


def _global_auth_context(workspace: Path) -> dict[str, Any]:
    """Application-wide security settings that apply to handlers in other files."""
    ctx: dict[str, Any] = {
        "middleware_files": _middleware_auth_files(workspace),
        "nest_guard": False,
        "spring_auth": False,
        "spring_permit": [],
        "method_security": False,
        "drf_auth": False,
    }
    for f in iter_workspace_files(workspace, {".ts", ".js", ".java", ".kt", ".py"}):
        rel = str(f.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if f.suffix == ".py":
            if _DJANGO_SETTINGS_RE.search(rel) and _code_matches(_DRF_DEFAULT_AUTH_RE, text):
                ctx["drf_auth"] = True
            continue
        if f.suffix in (".ts", ".js"):
            if _NEST_ENTRY_RE.search(rel):
                for m in _code_matches(_NEST_GLOBAL_GUARD_RE, text):
                    if _NEST_AUTH_GUARD_NAME_RE.search(m.group(1) or m.group(2)):
                        ctx["nest_guard"] = True
            continue
        if not _code_matches(_SPRING_CONFIG_RE, text):
            continue
        if _code_matches(_SPRING_METHOD_SECURITY_RE, text):
            ctx["method_security"] = True
        if _code_matches(_SPRING_ANY_REQUEST_AUTH_RE, text):
            ctx["spring_auth"] = True
            for m in _code_matches(_SPRING_PERMIT_ALL_RE, text):
                ctx["spring_permit"] += [p.split("*")[0] for p in re.findall(r"""["']([^"']*)["']""", m.group(1))]
    return ctx


def _inherits_auth(route: DiscoveredRoute, ctx: dict[str, Any]) -> bool:
    if route.file_path in ctx["middleware_files"]:
        return True
    if route.framework == "nestjs":
        return ctx["nest_guard"] and not _NEST_PUBLIC_RE.search(route.file_content)
    if route.framework == "spring":
        return ctx["spring_auth"] and not any(route.path.startswith(p) for p in ctx["spring_permit"])
    if route.framework == "drf":
        return ctx["drf_auth"] and "permission_classes" not in route.handler_snippet
    return False


def _spring_object_authorized(snippet: str) -> bool:
    return any(_SPRING_OBJECT_EXPR_RE.search(m.group(1)) for m in _SPRING_OBJECT_AUTH_RE.finditer(snippet))


def _preceding_decorators(file_content: str, line: int) -> str:
    """Decorator/annotation lines directly above the route line (`@PreAuthorize` above `@GetMapping`)."""
    lines = file_content.splitlines()
    i = line - 2
    while i >= 0 and lines[i].strip().startswith("@"):
        i -= 1
    return "\n".join(lines[i + 1 : line - 1])


_DJANGO_OBJECT_VIEW_RE = re.compile(
    r"\b(?:(?:Detail|Update|Delete)View|SingleObjectMixin|Retrieve\w*APIView|(?:Update|Destroy)APIView"
    r"|(?:ReadOnly)?ModelViewSet|(?:Retrieve|Update|Destroy)ModelMixin)\b"
)
_DJANGO_CALLER_RE = re.compile(r"\brequest\.(?:user|auth|tenant)\b")


def _py_block(lines: list[str], idx: int) -> str:
    """The `class`/`def` block starting at 0-based `idx`: following lines indented deeper."""
    indent = len(lines[idx]) - len(lines[idx].lstrip())
    end = idx + 1
    while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > indent):
        end += 1
    return "\n".join(lines[idx:end])


def _real_object_permission(cls: str) -> bool:
    """The class defines `has_object_permission` that does more than `return True`."""
    lines = cls.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"\s+def\s+has_object_permission\b", ln):
            body = _mask(_py_block(lines, i)).split(":", 1)[-1]
            return re.sub(r"\s+", " ", body).strip() not in ("return True", "pass", "...", "")
    return False


def _django_filters_by_caller(code: str) -> bool:
    """The queryset is narrowed by the caller: `.filter(owner=self.request.user)` (also
    `.exclude`, `.get`, `get_object_or_404(...)`), or read through the caller's related
    manager (`self.request.user.invoices.all()`). Merely mentioning the caller
    (`if self.request.user.is_authenticated:`) narrows nothing."""
    if re.search(r"\brequest\.user\.\w+\.(?:all|filter|exclude|get)\s*\(", code):
        return True
    for m in re.finditer(r"\.(?:filter|exclude|get)\s*\(|\bget_object_or_404\s*\(", code):
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[i], 0)
            i += 1
        args = code[m.end() : i]
        if _DJANGO_CALLER_RE.search(args) or CALLER_IDENTITY_RE.search(args):
            return True
    return False


def _django_cbv_routes(workspace: Path, tenant_re: re.Pattern[str]) -> list[DiscoveredRoute]:
    """Django generic single-object views and DRF viewsets: `get_object()` loads the record
    from `queryset`/`get_queryset()` by the URL's pk. Scoped when `get_queryset` or
    `get_object` filters by the caller (`self.request.user`) or a tenant key not taken from
    the request, the class compares ownership, or it uses a permission class that defines
    `has_object_permission`. A class-level `queryset = Model.objects.all()` alone is unscoped.
    """
    files: list[tuple[str, str]] = []
    for f in iter_workspace_files(workspace, {".py"}):
        rel = str(f.relative_to(workspace)).replace("\\", "/")
        if not is_test_path(rel):
            files.append((rel, f.read_text(encoding="utf-8", errors="ignore")))
    object_perms: set[str] = set()
    for _, text in files:
        if "has_object_permission" in text:
            lines = text.splitlines()
            for i, ln in enumerate(lines):
                m = re.match(r"\s*class\s+(\w+)", ln)
                if m and _real_object_permission(_py_block(lines, i)):
                    object_perms.add(m.group(1))
    routes: list[DiscoveredRoute] = []
    for rel, text in files:
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            m = re.match(r"\s*class\s+(\w+)\s*\(([^)]*)\)\s*:", line)
            if not m or not _DJANGO_OBJECT_VIEW_RE.search(m.group(2)):
                continue
            body = _py_block(lines, idx)
            if not re.search(r"^\s+(?:queryset|model)\s*=|def\s+get_(?:queryset|object)\b", body, re.MULTILINE):
                continue
            body_lines = body.splitlines()
            scoping = "\n".join(
                _py_block(body_lines, i) for i, ln in enumerate(body_lines) if re.match(r"\s+def\s+get_(?:queryset|object)\b", ln)
            )
            live = _mask(body, keep_strings=True)
            perm_lists = " ".join(re.findall(r"^\s+permission_classes\s*=\s*[\[(]([^\])]*)", live, re.MULTILINE))
            scoped = bool(
                _django_filters_by_caller(_mask(scoping, keep_strings=True))
                or (bool(_lookup_regions(scoping)) and _has_tenant_scope(scoping, [], tenant_re))
                or OWNERSHIP_COMPARE_RE.search(live)
                or any(re.search(rf"\b{re.escape(name)}\b", perm_lists) for name in object_perms)
            )
            routes.append(
                DiscoveredRoute(
                    path=f"{m.group(1)}#get_object",
                    raw_path=f"{m.group(1)}#get_object",
                    methods=["ALL"],
                    framework="drf" if re.search(r"APIView|ViewSet|ModelMixin", m.group(2)) else "django",
                    file_path=rel,
                    line=idx + 1,
                    has_dynamic_param=True,
                    param_names=["pk"],
                    handler_snippet=body,
                    file_content=text,
                    prechecked_scope=scoped,
                )
            )
    return routes


_USE_SERVER_RE = re.compile(r"""^\s*(?:(?://[^\n]*|/\*[\s\S]*?\*/)\s*)*["']use server["']""")
_SERVER_ACTION_EXPORT_RE = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+function\s+(\w+)|const\s+(\w+)\s*=\s*async\b)"
)


def _server_action_findings(workspace: Path, cfg: PrufGateConfig, auth_re: re.Pattern[str]) -> list[BolaFinding]:
    """Exported functions of a `"use server"` module without an authorization guard."""
    findings: list[BolaFinding] = []
    for af in iter_workspace_files(workspace, {".ts", ".tsx", ".js", ".jsx", ".mjs"}):
        rel_path = str(af.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel_path) or cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "BOLA-UNGUARDED-SERVER-ACTION"):
            continue
        try:
            text = af.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _USE_SERVER_RE.match(text):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _SERVER_ACTION_EXPORT_RE.match(line)
            if not m:
                continue
            end_idx = len(lines)
            for j in range(i + 1, len(lines)):
                if lines[j].lstrip().startswith("export "):
                    end_idx = j
                    break
            if auth_re.search("\n".join(lines[i:end_idx])) or _wrapper_guard(
                "\n".join(lines[i:end_idx]), text, rel_path, workspace, auth_re
            ):
                continue
            name = m.group(1) or m.group(2)
            findings.append(
                BolaFinding(
                    rule_id="BOLA-UNGUARDED-SERVER-ACTION",
                    severity="P0",
                    message=f"Server Action '{name}' has no authorization guard (e.g. auth(), requireAuth(), verifySession())",
                    endpoint_or_file=rel_path,
                    line=i + 1,
                    end_line=end_idx,
                    curl_poc=f"# Invoke the Server Action directly without a valid session cookie\n# Path: {rel_path}:{i + 1}",
                    details="Next.js Server Actions are publicly reachable HTTP endpoints. Without a session guard they can be invoked unauthenticated.",
                )
            )
    return findings


_RAILS_MEMBER_ACTIONS = ("show", "edit", "update", "destroy")
_LARAVEL_MEMBER_ACTION_RE = re.compile(r"^\s*public\s+function\s+(show|edit|update|destroy)\s*\(([^)]*)\)")
# A type-hinted model parameter: `show(Invoice $invoice)` (not `Request $request`).
_LARAVEL_BOUND_MODEL_RE = re.compile(r"(?:^|,)\s*\??\\?([A-Z][\w\\]*)\s+\$(\w+)")
# A policy check on the bound model, in the action or the controller: one that throws
# (`$this->authorize(...)`, `Gate::authorize(...)`, `Gate::inspect(...)->authorize()`), or a
# boolean one that is tested (`if (! $user->can(...))`, `abort_unless(Gate::allows(...), 403)`).
_LARAVEL_POLICY_RE = re.compile(
    r"\$this->authorize\(|\bGate::authorize\(|->authorize\(\s*\)|\bauthorizeResource\s*\("
    r"|(?:\bif\s*\(|\babort_(?:if|unless)\s*\(|!|&&|\|\|)[^;{}\n]{0,120}?(?:\bGate::(?:allows|denies|check|any|none)\(|->can(?:not)?\()"
)


def _live_php(code: str) -> str:
    """PHP with comments and obviously dead code blanked: `if (false) { ... }` (also `0`,
    `null`) and the rest of a block after an unconditional `return` (one that starts its
    line and does not follow a brace-less `if (...)` / `else`). Lengths are preserved."""
    out = list(_mask(code, keep_strings=True))

    def blank_to_block_end(i: int, depth: int) -> None:
        while i < len(out) and depth > 0:
            depth += {"{": 1, "}": -1}.get(out[i], 0)
            if depth > 0 and out[i] != "\n":
                out[i] = " "
            i += 1

    for m in re.finditer(r"\bif\s*\(\s*(?:false|0|null)\s*\)\s*\{", "".join(out), re.IGNORECASE):
        blank_to_block_end(m.end(), 1)
    text = "".join(out)
    for m in re.finditer(r"^[ \t]*return\b[^;\n]*;", text, re.MULTILINE):
        before = text[: m.start()].rstrip()
        if before.endswith(")") or re.search(r"\belse$", before):
            continue
        blank_to_block_end(m.end(), 1)
    return "".join(out)


def _rails_member_actions(routes_rb: str) -> dict[str, set[str]]:
    """Custom member actions per resource in config/routes.rb: `member do get :preview end`,
    `member { post :approve }` and `get :preview, on: :member` inside `resources :x do`."""
    out: dict[str, set[str]] = {}
    stack: list[str | None] = []  # resource name, "" for a member block, None for any other block
    verb = r"\b(?:get|post|put|patch|delete|match)\s+:(\w+)"
    for raw in routes_rb.splitlines():
        line = raw.split("#", 1)[0].strip()
        resource = next((r for r in reversed(stack) if r), None)
        m_res = re.match(r"resources\s+:(\w+)", line)
        if resource and (re.search(r"\bmember\s*\{", line) or (stack and stack[-1] == "" and re.match(verb, line))
                         or re.search(r"\bon:\s*:member\b", line)):
            out.setdefault(resource, set()).update(re.findall(verb, line))
        if re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", line):
            stack.append(m_res.group(1) if m_res else ("" if re.match(r"member\b", line) else None))
        elif line == "end" and stack:
            stack.pop()
    return out


def _laravel_route_scoped(laravel_routes: str, stem: str, action: str) -> bool:
    """`->scopeBindings()`, `->scoped()`, `->can(...)` or `can:` middleware on a route line
    naming the controller and this action (or a `Route::resource` line for the controller),
    or the controller inside a `Route::scopeBindings()->group(...)` (matched by balanced
    parentheses). A check on another action's route scopes nothing here."""
    for ln in laravel_routes.splitlines():
        if (
            re.search(rf"\b{re.escape(stem)}\b", ln)
            and (re.search(rf"""["']{re.escape(action)}["']""", ln) or re.search(r"\bRoute::(?:api)?[rR]esources?\(", ln))
            and re.search(r"->(?:scopeBindings|scoped|can)\(|['\"]can:", ln)
        ):
            return True
    for m in re.finditer(r"\bscopeBindings\(\)\s*->\s*group\s*\(", laravel_routes):
        depth, i = 1, m.end()
        while i < len(laravel_routes) and depth:
            depth += {"(": 1, ")": -1}.get(laravel_routes[i], 0)
            i += 1
        if re.search(rf"\b{re.escape(stem)}\b", laravel_routes[m.end() : i]):
            return True
    return False


def _controller_routes(workspace: Path) -> list[DiscoveredRoute]:
    """Rails and Laravel controller member actions, whose routes live in a separate routes file.

    Rails: show/edit/update/destroy plus the custom member actions declared in
    config/routes.rb, each with an explicit `find(params[:id])`. Laravel: show/edit/
    update/destroy taking an `$id`, or a type-hinted model (implicit route-model binding),
    which is scoped only by a policy check or scoped bindings in routes/*.php.
    """
    routes: list[DiscoveredRoute] = []
    rails_app_auth = ""
    app_ctrl = workspace / "app" / "controllers" / "application_controller.rb"
    if app_ctrl.is_file():
        rails_app_auth = app_ctrl.read_text(encoding="utf-8", errors="ignore")
    routes_rb = workspace / "config" / "routes.rb"
    rails_members = _rails_member_actions(routes_rb.read_text(encoding="utf-8", errors="ignore")) if routes_rb.is_file() else {}
    laravel_routes = ""
    routes_dir = workspace / "routes"
    if routes_dir.is_dir():
        laravel_routes = "\n".join(
            _mask(p.read_text(encoding="utf-8", errors="ignore"), keep_strings=True) for p in sorted(routes_dir.glob("*.php"))
        )

    for f in iter_workspace_files(workspace, {".rb", ".php"}):
        rel = str(f.relative_to(workspace)).replace("\\", "/")
        is_rails = rel.endswith("_controller.rb") and "/controllers/" in f"/{rel}"
        is_laravel = rel.endswith("Controller.php") and "/Controllers/" in f"/{rel}"
        if not (is_rails or is_laravel) or is_test_path(rel):
            continue
        content = f.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        # Auth inherited from ApplicationController, or applied to the controller in routes/*.php.
        inherited = ""
        if is_rails and "< ApplicationController" in content and not _SKIPPED_AUTH_RE.search(content):
            inherited = rails_app_auth
        if is_laravel and re.search(re.escape(f.stem) + r"\b", laravel_routes):
            for ln in laravel_routes.splitlines():
                if f.stem in ln and re.search(r"middleware\(\s*\[?\s*['\"]auth", ln):
                    inherited = "$this->middleware('auth')"
        if is_rails:
            names = _RAILS_MEMBER_ACTIONS + tuple(sorted(rails_members.get(f.stem.removesuffix("_controller"), ())))
            action_re = re.compile(r"^\s*def\s+(" + "|".join(map(re.escape, names)) + r")\b")
        else:
            action_re = _LARAVEL_MEMBER_ACTION_RE
        for idx, line in enumerate(lines, start=1):
            m = action_re.match(line)
            if not m:
                continue
            snippet = _extract_handler_window(lines, idx)
            prechecked: bool | None = None
            if is_rails and not re.search(r"params\[:\w*id\]", snippet):
                continue
            # A type-hinted model is bound implicitly even beside an `$...Id` parameter
            # (`show(Invoice $invoice, string $traceId = '')`).
            bound = [b for b in _LARAVEL_BOUND_MODEL_RE.findall(m.group(2)) if not b[0].endswith("Request")] if is_laravel else []
            if is_laravel and not bound and not re.search(r"\$\w*[iI]d\b", m.group(2)):
                continue
            if bound:
                live = _live_php(snippet)
                prechecked = bool(
                    _LARAVEL_POLICY_RE.search(live)
                    or _ownership_call(live)
                    or OWNERSHIP_COMPARE_RE.search(live)
                    or re.search(r"\bauthorizeResource\s*\(", _live_php(content))
                    or _laravel_route_scoped(laravel_routes, f.stem, m.group(1))
                )
            routes.append(
                DiscoveredRoute(
                    path=f"{f.stem}#{m.group(1)}",
                    raw_path=f"{f.stem}#{m.group(1)}",
                    methods=["ALL"],
                    framework="rails" if is_rails else "laravel",
                    file_path=rel,
                    line=idx,
                    has_dynamic_param=True,
                    param_names=["id"],
                    handler_snippet=snippet,
                    file_content=content + "\n" + inherited,
                    prechecked_scope=prechecked,
                )
            )
    return routes


def run_static_matrix_audit(
    workspace: Path,
    config: PrufGateConfig | None = None,
    changed_files: set[str] | None = None,
) -> list[BolaFinding]:
    """Scan workspace for unguarded server actions, unscoped multi-tenant tables, and unscoped BOLA route handlers.

    With `changed_files` (workspace-relative paths of a changed-files scan), only findings in
    those files are returned: application-wide auth is still read from the whole workspace."""
    findings = _static_matrix_audit(workspace, config)
    if changed_files is None:
        return findings
    return [f for f in findings if f.endpoint_or_file in changed_files]


def _static_matrix_audit(workspace: Path, config: PrufGateConfig | None) -> list[BolaFinding]:
    if config is not None:
        cfg = config
    else:
        cfg = PrufGateConfig.load(workspace) if (workspace / ".prufgate").exists() else PrufGateConfig()
    auth_re = _build_auth_guard_regex(cfg)
    tenant_re = _build_tenant_key_regex(cfg)

    print("  [BOLA Static Matrix] Scanning server actions and database queries for missing tenant constraints...")

    # 1. Next.js Server Actions
    findings: list[BolaFinding] = _server_action_findings(workspace, cfg, auth_re)

    # 2. Scan SQL migrations and repositories for missing tenant scoping. Tables shared by
    # every tenant (countries, currencies) are skipped only when listed in bola.global_tables.
    global_tables = {t.lower() for t in cfg.bola_global_tables}
    for sf in iter_workspace_files(workspace, {".sql"}):
        rel_path = str(sf.relative_to(workspace)).replace("\\", "/")
        rel_dirs = rel_path.split("/")[:-1]
        if not ("migrations" in rel_dirs[-1:] or "database" in rel_dirs):
            continue
        if cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "BOLA-TABLE-MISSING-TENANT-COLUMN"):
            continue
        try:
            text = sf.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\);",
                text,
                re.DOTALL | re.IGNORECASE,
            ):
                table_name = match.group(1).lower()
                table_body = match.group(2)
                if table_name in ("migrations", "schema_migrations", "tenants", "organizations", "roles", "permissions"):
                    continue
                if table_name in global_tables:
                    continue
                if not tenant_re.search(table_body):
                    line_no = text[: match.start()].count("\n") + 1
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-TABLE-MISSING-TENANT-COLUMN",
                            severity="P1",
                            message=f"Multi-tenant table '{table_name}' declared without tenant_id or org_id foreign key",
                            endpoint_or_file=rel_path,
                            line=line_no,
                            end_line=text[: match.end()].count("\n") + 1,
                            details="Tables storing customer data without tenant_id require complex join constraints for RLS, increasing BOLA leakage risk.",
                        )
                    )
        except Exception:
            pass

    # 3. Universal Multi-Framework Route Handler BOLA Verification (`static-bola-unscoped-access`)
    discovered_routes = discover_all_routes(workspace) + _controller_routes(workspace) + _django_cbv_routes(workspace, tenant_re)
    auth_ctx = _global_auth_context(workspace)
    seen_handler_locs: set[tuple[str, int]] = set()

    for route in discovered_routes:
        if route.framework == "openapi" or not route.has_dynamic_param:
            continue
        if any(pub in route.path.lower() for pub in PUBLIC_ROUTE_KEYWORDS):
            continue
        if cfg.is_excluded(route.file_path) or cfg.is_exempt(route.file_path, "static-bola-unscoped-access"):
            continue
        loc_key = (route.file_path, route.line)
        if loc_key in seen_handler_locs:
            continue

        # Check if the handler performs a direct database/ORM object lookup or mutation
        # (or the framework does it for the handler: route-model binding, get_object()).
        if route.prechecked_scope is None and not DB_OBJECT_LOOKUP_RE.search(route.handler_snippet):
            continue

        # Auth counts per handler; a file-wide guard counts only when it is applied to every handler,
        # and application-wide auth in another file only where it is resolved (`_inherits_auth`).
        decorated = _preceding_decorators(route.file_content, route.line) + "\n" + route.handler_snippet
        has_auth = bool(
            auth_re.search(decorated) or FILE_LEVEL_AUTH_RE.search(route.file_content) or _inherits_auth(route, auth_ctx)
            or _wrapper_guard(route.handler_snippet, route.file_content, route.file_path, workspace, auth_re)
        )
        if route.prechecked_scope is not None:
            has_tenant_scope = route.prechecked_scope
        else:
            has_tenant_scope = _has_tenant_scope(route.handler_snippet, route.param_names, tenant_re) or (
                route.framework == "spring" and auth_ctx["method_security"] and _spring_object_authorized(decorated)
            )

        if not has_tenant_scope or not has_auth:
            seen_handler_locs.add(loc_key)
            missing_desc = (
                "missing both authentication guard and tenant/owner scoping"
                if (not has_auth and not has_tenant_scope)
                else ("missing authentication guard" if not has_auth else "missing tenant/owner key scoping on object lookup")
            )
            message = (
                f"Route '{','.join(route.methods)} {route.path}' ({route.framework}) performs direct object lookup "
                f"by '{route.param_names[-1] if route.param_names else 'id'}' {missing_desc}."
            )
            # On the route line or the comment just above it any ignore counts; elsewhere in the
            # handler it must name this rule, so an ignore meant for another line cannot hide the route.
            texts = inline_ignore.context(route.file_content.splitlines(), route.line) + [
                t for t in route.handler_snippet.splitlines()
                if (ig := inline_ignore.parse(t)) and any(rules_match("static-bola-unscoped-access", r) for r in ig[0])
            ]
            if inline_ignore.suppressed(
                texts, "static-bola-unscoped-access", engine="bola-matrix", path=route.file_path, line=route.line,
                severity="P0", message=message,
            ):
                continue
            findings.append(
                BolaFinding(
                    rule_id="static-bola-unscoped-access",
                    severity="P0",
                    message=message,
                    endpoint_or_file=route.file_path,
                    line=route.line,
                    end_line=max(route.end_line, route.line + max(0, len(route.handler_snippet.splitlines()) - 1)),
                    curl_poc=(
                        f"curl -X {'GET' if route.methods[0] == 'ALL' else route.methods[0]} "
                        f'-H "Authorization: Bearer $PRUFGATE_TOKEN_A" "$TARGET_URL{route.path}"'
                        if route.path.startswith("/")
                        else ""
                    ),
                    details=(
                        f"Scope database queries in '{route.file_path}:{route.line}' by a tenant/owner key "
                        f"(e.g. `tenant_id`, `organization_id`, `user_id`) and enforce caller authentication."
                    ),
                )
            )

    return findings


def _probe_url(target_url: str, path: str) -> str:
    """Join a probe path (`PRUFGATE_BOLA_PATHS`, discovered or `--routes-from`) onto the target URL."""
    return f"{target_url.rstrip('/')}{path}"


def run_dynamic_matrix(
    target_url: str,
    workspace: Path | None = None,
    config: PrufGateConfig | None = None,
    extra_paths: list[str] | None = None,
    max_extra_paths: int = 200,
) -> list[BolaFinding]:
    """Execute the 4-request two-token differential BOLA probe matrix against a live target.

    `extra_paths` (from `--routes-from`) are added after dedupe, capped at `max_extra_paths`;
    a path holding `{tenant_id}` joins the cross-tenant probes, like a discovered route."""
    # Every entry point (CLI, batteries, MCP, API, this module's main) reaches the probe
    # here, so the metadata/link-local guard is enforced here, not only by the callers.
    url_error = target_url_error(target_url)
    if url_error:
        raise ValueError(url_error)
    findings: list[BolaFinding] = []
    print(f"  [BOLA Dynamic Matrix] Probing cross-tenant authorization boundaries on {target_url}...")

    refused: list[str] = []
    opener = urllib.request.build_opener(SameOriginRedirectHandler(target_url, refused))
    discovered_routes = discover_workspace_api_routes(workspace)

    env_paths = os.environ.get("PRUFGATE_BOLA_PATHS")
    if env_paths:
        test_paths = [p.strip() for p in env_paths.split(",") if p.strip()]
    else:
        default_paths = [
            "/api/v1/tenant/profile",
            "/api/v1/workspaces/current",
            "/api/v1/users/me",
            "/api/v1/projects",
            "/api/v1/settings",
            "/api/v1/billing/subscription",
            "/api/v1/audit-logs",
        ]
        static_discovered = [r for r in discovered_routes if "{tenant_id}" not in r]
        test_paths = list(dict.fromkeys(static_discovered + default_paths))

    extra_cross: list[str] = []
    if extra_paths:
        known = set(test_paths)
        new_paths = [p for p in dict.fromkeys(extra_paths) if p not in known]
        added = new_paths[:max_extra_paths]
        print(
            f"  [BOLA Dynamic Matrix] Route files: {len(added)} new path(s) added, "
            f"{len(extra_paths) - len(new_paths)} already known, {len(new_paths) - len(added)} over the --max-routes cap."
        )
        test_paths += [p for p in added if "{tenant_id}" not in p]
        extra_cross = [p for p in added if "{tenant_id}" in p]

    # Real tokens for two tenants are required for the cross-tenant probes: a made-up
    # token only measures the 401 path. Tokens never appear in findings or reports.
    token_a = os.environ.get("PRUFGATE_TEST_PROBE_TOKEN_A") or os.environ.get("PRUFGATE_TENANT_A_TOKEN") or ""
    token_b = os.environ.get("PRUFGATE_TEST_PROBE_TOKEN_B") or os.environ.get("PRUFGATE_TENANT_B_TOKEN") or ""
    tenant_a_id = os.environ.get("PRUFGATE_TEST_PROBE_TENANT_A_ID", os.environ.get("PRUFGATE_TENANT_A_ID", "tenant-a-1111"))
    tenant_b_id = os.environ.get("PRUFGATE_TEST_PROBE_TENANT_B_ID", os.environ.get("PRUFGATE_TENANT_B_ID", "tenant-b-2222"))

    # 1. Unauthenticated request check across protected paths
    for path in test_paths:
        full_url = _probe_url(target_url, path)
        try:
            req = urllib.request.Request(
                full_url,
                headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}", "Accept": "application/json"},
            )
            with opener.open(req, timeout=3) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                content_type = resp.headers.get("Content-Type", "")
                if resp.status == 200 and _is_meaningful_api_payload(content_type, body):
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-UNAUTHENTICATED-ACCESS",
                            severity="P0",
                            message=f"Endpoint {path} accessible without authentication token",
                            endpoint_or_file=path,
                            curl_poc=f"curl -s -i '{full_url}'",
                            details="Expected 401 Unauthorized, received HTTP 200 with structured JSON payload.",
                        )
                    )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # 2. Cross-Tenant Two-Token Matrix Probes
    if not (token_a and token_b):
        print(
            "  [BOLA Dynamic Matrix] Cross-tenant probes skipped: set PRUFGATE_TEST_PROBE_TOKEN_A and "
            "PRUFGATE_TEST_PROBE_TOKEN_B (or --token-a/--token-b) to two real tenant tokens."
        )
        return _with_refused_redirects(findings, refused, target_url)
    env_cross = os.environ.get("PRUFGATE_CROSS_TENANT_PATHS")
    if env_cross:
        cross_tenant_paths = [p.strip().replace("{tenant_id}", tenant_b_id) for p in env_cross.split(",") if p.strip()]
    else:
        param_discovered = [r.replace("{tenant_id}", tenant_b_id) for r in discovered_routes if "{tenant_id}" in r]
        default_cross = [
            f"/api/v1/workspaces/{tenant_b_id}",
            f"/api/v1/tenants/{tenant_b_id}",
            f"/api/v1/users?tenant_id={tenant_b_id}",
            f"/api/v1/projects?organization_id={tenant_b_id}",
            f"/api/v1/billing/subscription?tenant_id={tenant_b_id}",
        ]
        cross_tenant_paths = list(dict.fromkeys(param_discovered + default_cross))
    cross_tenant_paths = list(dict.fromkeys(cross_tenant_paths + [p.replace("{tenant_id}", tenant_b_id) for p in extra_cross]))

    for path in cross_tenant_paths:
        full_url = _probe_url(target_url, path)
        url_for_a = full_url.replace(tenant_b_id, tenant_a_id)

        unauth_baseline = None
        try:
            req_unauth = urllib.request.Request(
                full_url,
                headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}", "Accept": "application/json"},
            )
            with opener.open(req_unauth, timeout=3) as resp_u:
                if resp_u.status == 200:
                    unauth_baseline = resp_u.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        self_a_body = None
        try:
            req_self_a = urllib.request.Request(
                url_for_a,
                headers={
                    "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token_a}",
                    "X-Tenant-ID": tenant_a_id,
                    "Cookie": f"session={token_a}; auth_token={token_a}",
                },
            )
            with opener.open(req_self_a, timeout=3) as resp_self_a:
                if resp_self_a.status == 200:
                    self_a_body = resp_self_a.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        headers_a = {
            "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
            "Accept": "application/json",
            "Authorization": f"Bearer {token_a}",
            "X-Tenant-ID": tenant_b_id,
            "Cookie": f"session={token_a}; auth_token={token_a}",
        }
        try:
            req_a = urllib.request.Request(full_url, headers=headers_a)
            with opener.open(req_a, timeout=3) as resp_a:
                body = resp_a.read().decode("utf-8", errors="ignore")
                ct_a = resp_a.headers.get("Content-Type", "")
                if resp_a.status == 200 and _is_meaningful_api_payload(ct_a, body):
                    stripped_body = body.strip()
                    is_actually_tenant_a_only = (
                        self_a_body is not None
                        and stripped_body == self_a_body
                        and tenant_a_id in stripped_body
                        and tenant_b_id not in stripped_body
                    )
                    if stripped_body != unauth_baseline and not is_actually_tenant_a_only:
                        findings.append(
                            BolaFinding(
                                rule_id="BOLA-CROSS-TENANT-ACCESS",
                                severity="P0",
                                message=f"BOLA / IDOR: Tenant A token accessed Tenant B private resource at {path}",
                                endpoint_or_file=path,
                                curl_poc=f"curl -s -i -H \"Authorization: Bearer $PRUFGATE_TOKEN_A\" -H 'X-Tenant-ID: {tenant_b_id}' '{full_url}'",
                                details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {stripped_body[:120]}...",
                            )
                        )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

        headers_b = {
            "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
            "Accept": "application/json",
            "Authorization": f"Bearer {token_b}",
            "X-Tenant-ID": tenant_a_id,
            "Cookie": f"session={token_b}; auth_token={token_b}",
        }
        try:
            req_b = urllib.request.Request(url_for_a, headers=headers_b)
            with opener.open(req_b, timeout=3) as resp_b:
                body_b = resp_b.read().decode("utf-8", errors="ignore")
                ct_b = resp_b.headers.get("Content-Type", "")
                if resp_b.status == 200 and _is_meaningful_api_payload(ct_b, body_b):
                    stripped_b = body_b.strip()
                    if stripped_b != unauth_baseline:
                        findings.append(
                            BolaFinding(
                                rule_id="BOLA-CROSS-TENANT-ACCESS",
                                severity="P0",
                                message=f"BOLA / IDOR: Tenant B token accessed Tenant A private resource at {path.replace(tenant_b_id, tenant_a_id)}",
                                endpoint_or_file=path.replace(tenant_b_id, tenant_a_id),
                                curl_poc=f"curl -s -i -H \"Authorization: Bearer $PRUFGATE_TOKEN_B\" -H 'X-Tenant-ID: {tenant_a_id}' '{url_for_a}'",
                                details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {stripped_b[:120]}...",
                            )
                        )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return _with_refused_redirects(findings, refused, target_url)


_U = "static-bola-unscoped-access"
_T = "BOLA-TABLE-MISSING-TENANT-COLUMN"
_NEST_CONTROLLER = (
    "@Controller('invoices')\n"
    "export class InvoicesController {\n"
    "  @Get(':id')\n"
    "  findOne(@Param('id') id: string, @Req() req) {\n"
    "    return this.repo.findOne({ where: { id, ownerId: req.user.id } });\n"
    "  }\n"
    "}\n"
)
_EXPRESS_ROUTER = (
    "const router = express.Router();\n"
    "router.get('/:id', async (req, res) => {\n"
    "  res.json(await prisma.item.findFirst({ where: { id: req.params.id, ownerId: req.user.id } }));\n"
    "});\n"
    "export default router;\n"
)
_RAILS_APP_CONTROLLER = "class ApplicationController < ActionController::Base\n  before_action :authenticate_user!\nend\n"

# Issue #22 gaps: (name, files, config keyword arguments, expected (rule, file, line) findings).
# Every case holds a sample that must be flagged and a near miss that must not.
GAP_CASES: list[tuple[str, dict[str, str], dict[str, Any], set[tuple[str, str, int]]]] = [
    (
        "laravel implicit route-model binding",
        {
            "routes/web.php": "<?php\n"
            "Route::get('/invoices/{invoice}', [InvoiceController::class, 'show'])->middleware('auth');\n"
            "Route::get('/notes/{note}', [NoteController::class, 'show'])->middleware('auth');\n"
            "Route::scopeBindings()->group(function () {\n"
            "    Route::get('/users/{user}/posts/{post}', [PostController::class, 'show'])->middleware('auth');\n"
            "});\n",
            "app/Http/Controllers/InvoiceController.php": "<?php\nclass InvoiceController extends Controller\n{\n"
            "    public function show(Invoice $invoice)\n    {\n        return $invoice;\n    }\n}\n",
            "app/Http/Controllers/NoteController.php": "<?php\nclass NoteController extends Controller\n{\n"
            "    public function show(Request $request, Note $note)\n    {\n"
            "        $this->authorize('view', $note);\n        return $note;\n    }\n}\n",
            "app/Http/Controllers/PostController.php": "<?php\nclass PostController extends Controller\n{\n"
            "    public function show(User $user, Post $post)\n    {\n        return $post;\n    }\n}\n",
        },
        {},
        {(_U, "app/Http/Controllers/InvoiceController.php", 4)},
    ),
    (
        "tenant value traced through a local variable",
        {
            "routes.ts": "app.get('/api/invoices/:id', requireAuth, async (req, res) => {\n"
            "  const org = req.query.orgId;\n"
            "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: org } }));\n"
            "});\n",
            "safe_routes.ts": "app.get('/api/bills/:id', requireAuth, async (req, res) => {\n"
            "  const org = req.user.orgId;\n"
            "  res.json(await prisma.bill.findFirst({ where: { id: req.params.id, orgId: org } }));\n"
            "});\n",
        },
        {},
        {(_U, "routes.ts", 1)},
    ),
    (
        "DRF viewset queryset without a caller filter",
        {
            "views.py": "class InvoiceViewSet(viewsets.ModelViewSet):\n"
            "    permission_classes = [IsAuthenticated]\n"
            "    queryset = Invoice.objects.all()\n",
            "safe_views.py": "class NoteViewSet(viewsets.ModelViewSet):\n"
            "    permission_classes = [IsAuthenticated]\n"
            "    def get_queryset(self):\n"
            "        return Note.objects.filter(owner=self.request.user)\n",
        },
        {},
        {(_U, "views.py", 1)},
    ),
    (
        "NestJS APP_GUARD that authenticates",
        {
            "src/app.module.ts": "@Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })\nexport class AppModule {}\n",
            "src/invoices.controller.ts": _NEST_CONTROLLER,
        },
        {},
        set(),
    ),
    (
        "NestJS APP_GUARD that only rate-limits",
        {
            "src/app.module.ts": "@Module({ providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }] })\nexport class AppModule {}\n",
            "src/invoices.controller.ts": _NEST_CONTROLLER,
        },
        {},
        {(_U, "src/invoices.controller.ts", 3)},
    ),
    (
        "Spring global method security",
        {
            "SecurityConfig.java": "@EnableMethodSecurity\npublic class SecurityConfig {\n"
            "    SecurityFilterChain chain(HttpSecurity http) {\n"
            "        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n    }\n}\n",
            "DocController.java": '@RestController\n@RequestMapping("/api/docs")\npublic class DocController {\n'
            '    @PreAuthorize("@docAccess.canRead(#id, authentication)")\n'
            '    @GetMapping("/{id}")\n'
            "    public Doc get(@PathVariable String id) {\n        return docRepository.findById(id);\n    }\n}\n",
            "NoteController.java": '@RestController\n@RequestMapping("/api/notes")\npublic class NoteController {\n'
            "    @PreAuthorize(\"hasRole('USER')\")\n"
            '    @GetMapping("/{id}")\n'
            "    public Note get(@PathVariable String id) {\n        return noteRepository.findById(id);\n    }\n}\n",
        },
        {},
        {(_U, "NoteController.java", 5)},
    ),
    (
        "Express auth middleware registered in the entry file",
        {
            "src/app.ts": "import notes from './routes/notes';\n"
            "import invoices from './routes/invoices';\n"
            "const app = express();\n"
            "app.use('/api/notes', notes);\n"
            "app.use(requireAuth);\n"
            "app.use('/api/invoices', invoices);\n",
            "src/routes/notes.ts": _EXPRESS_ROUTER,
            "src/routes/invoices.ts": _EXPRESS_ROUTER,
        },
        {},
        {(_U, "src/routes/notes.ts", 2)},
    ),
    (
        "Rails custom member action",
        {
            "config/routes.rb": "Rails.application.routes.draw do\n"
            "  resources :invoices do\n    member do\n      get :preview\n    end\n  end\n"
            "  resources :notes do\n    get :preview, on: :member\n  end\nend\n",
            "app/controllers/application_controller.rb": _RAILS_APP_CONTROLLER,
            "app/controllers/invoices_controller.rb": "class InvoicesController < ApplicationController\n"
            "  def preview\n    @invoice = Invoice.find(params[:id])\n  end\nend\n",
            "app/controllers/notes_controller.rb": "class NotesController < ApplicationController\n"
            "  def preview\n    @note = current_user.notes.find(params[:id])\n  end\nend\n",
        },
        {},
        {(_U, "app/controllers/invoices_controller.rb", 2)},
    ),
    (
        "listed global table",
        {
            "migrations/001_init.sql": "CREATE TABLE countries (id serial primary key, code text);\n"
            "CREATE TABLE invoices (id serial primary key, total int);\n",
        },
        {"bola_global_tables": ["countries"]},
        {(_T, "migrations/001_init.sql", 2)},
    ),
    (
        "Laravel policy check in a comment or dead code",
        {
            "routes/web.php": "<?php\n"
            "Route::get('/a/{invoice}', [InvoiceController::class, 'show'])->middleware('auth');\n"
            "Route::get('/b/{bill}', [BillController::class, 'show'])->middleware('auth');\n"
            "Route::get('/c/{note}', [NoteController::class, 'show'])->middleware('auth');\n"
            "Route::get('/d/{post}', [PostController::class, 'show'])->middleware('auth');\n",
            "app/Http/Controllers/InvoiceController.php": "<?php\nclass InvoiceController extends Controller\n{\n"
            "    public function show(Invoice $invoice)\n    {\n"
            "        // $this->authorize('view', $invoice);\n        return $invoice;\n    }\n}\n",
            "app/Http/Controllers/BillController.php": "<?php\nclass BillController extends Controller\n{\n"
            "    public function show(Bill $bill)\n    {\n"
            "        if (false) { $this->authorize('view', $bill); }\n        return $bill;\n    }\n}\n",
            "app/Http/Controllers/PostController.php": "<?php\nclass PostController extends Controller\n{\n"
            "    public function show(Post $post)\n    {\n"
            "        return $post;\n        $this->authorize('view', $post);\n        return $post;\n    }\n}\n",
            "app/Http/Controllers/NoteController.php": "<?php\nclass NoteController extends Controller\n{\n"
            "    public function show(Note $note)\n    {\n"
            "        if ($note->draft)\n            return abort(404);\n        $this->authorize('view', $note);\n        return $note;\n    }\n}\n",
        },
        {},
        {
            (_U, "app/Http/Controllers/InvoiceController.php", 4),
            (_U, "app/Http/Controllers/BillController.php", 4),
            (_U, "app/Http/Controllers/PostController.php", 4),
        },
    ),
    (
        "identity-named local holding request input",
        {
            "routes.ts": "app.get('/api/invoices/:id', requireAuth, async (req, res) => {\n"
            "  const currentUser = req.query;\n"
            "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: currentUser.orgId } }));\n"
            "});\n",
            "safe_routes.ts": "app.get('/api/bills/:id', requireAuth, async (req, res) => {\n"
            "  const currentUser = req.user;\n"
            "  res.json(await prisma.bill.findFirst({ where: { id: req.params.id, orgId: currentUser.orgId } }));\n"
            "});\n",
        },
        {},
        {(_U, "routes.ts", 1)},
    ),
]


def run_gap_case(files: dict[str, str], config: dict[str, Any]) -> set[tuple[str, str, int]]:
    """Static findings of one GAP_CASES workspace, as (rule, file, line)."""
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        for rel, text in files.items():
            (ws / rel).parent.mkdir(parents=True, exist_ok=True)
            (ws / rel).write_text(text, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            findings = run_static_matrix_audit(ws, config=PrufGateConfig(**config))
    return {(f.rule_id, f.endpoint_or_file, f.line) for f in findings}


def run_self_check() -> int:
    """Validate universal route discovery and static BOLA scoping across Next.js, FastAPI, Express, Go, and Spring Boot."""
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        # 1. Vulnerable FastAPI route (unscoped DB lookup by id)
        (ws / "api_vulnerable.py").write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(prefix='/api/v1')\n"
            "@router.get('/invoices/{invoice_id}')\n"
            "def get_invoice(invoice_id: str, user=Depends(get_current_user)):\n"
            "    return db.query(Invoice).filter_by(id=invoice_id).first()\n",
            encoding="utf-8",
        )
        # 2. Safe FastAPI route (scoped by tenant_id + auth guard)
        (ws / "api_safe.py").write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(prefix='/api/v1')\n"
            "@router.get('/orders/{order_id}')\n"
            "def get_order(order_id: str, user=Depends(get_current_user)):\n"
            "    return db.query(Order).filter_by(id=order_id, tenant_id=user.tenant_id).first()\n",
            encoding="utf-8",
        )
        # 3. Vulnerable Express route
        (ws / "routes.ts").write_text(
            "app.get('/api/projects/:id', async (req, res) => {\n"
            "  const proj = await prisma.project.findUnique({ where: { id: req.params.id } });\n"
            "  return res.json(proj);\n"
            "});\n",
            encoding="utf-8",
        )
        # 4. Vulnerable Go Gin route
        (ws / "handler.go").write_text(
            "package api\n"
            "func Register(r *gin.Engine) {\n"
            '    r.GET("/api/documents/:id", func(c *gin.Context) {\n'
            "        var doc Document\n"
            '        db.First(&doc, c.Param("id"))\n'
            "    })\n"
            "}\n",
            encoding="utf-8",
        )
        # 5. Vulnerable Spring Boot route
        (ws / "DocumentController.java").write_text(
            '@RestController\n@RequestMapping("/api/v1/docs")\n'
            "public class DocumentController {\n"
            '    @GetMapping("/{id}")\n'
            "    public Doc getDoc(@PathVariable String id) {\n"
            "        return docRepository.findById(id);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        routes = discover_all_routes(ws)
        if len(routes) < 5:
            print(f"bola_engine self-check FAILED: expected >= 5 routes, found {len(routes)}", file=sys.stderr)
            return 1

        findings = run_static_matrix_audit(ws)
        flagged_files = {f.endpoint_or_file for f in findings if f.rule_id == "static-bola-unscoped-access"}
        expected_files = {"api_vulnerable.py", "routes.ts", "handler.go", "DocumentController.java"}
        if flagged_files != expected_files:
            print(
                f"bola_engine self-check FAILED: expected {sorted(expected_files)}, got {sorted(flagged_files)}",
                file=sys.stderr,
            )
            return 1

    for name, files, config, expected in GAP_CASES:
        got = run_gap_case(files, config)
        if got != expected:
            print(f"bola_engine self-check FAILED: {name}: expected {sorted(expected)}, got {sorted(got)}", file=sys.stderr)
            return 1

    print(f"bola_engine self-check: 5 framework case(s) and {len(GAP_CASES)} gap case(s) ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Exit 0: no P0/P1 finding. 1: a P0/P1 finding. 2: the engine could not run."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in raw_args:
        return run_self_check()

    ws_env = os.environ.get(
        "WORKSPACE",
        "/workspace" if Path("/workspace").exists() and os.access("/workspace", os.W_OK) else str(Path.cwd()),
    )
    parser = argparse.ArgumentParser(description="PrufGate Universal BOLA / Cross-Tenant Matrix Engine")
    parser.add_argument(
        "--target",
        "--target-url",
        "--url",
        dest="target",
        default=os.environ.get("TARGET_URL") or None,
        help="Live target for the two-token probe (default: $TARGET_URL; no live probe without one)",
    )
    parser.add_argument("--workspace", default=ws_env)
    parser.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    parser.add_argument("--base", default=None, help="Read the PrufGate configuration as it is at this base ref (changed-files runs)")
    parser.add_argument("--output", "--json-out", dest="output", default=None)
    parser.add_argument("--static-only", action="store_true", help="Run only static route & query scoping checks")
    parser.add_argument("--token-a", default=None, help="Bearer token for tenant A (or PRUFGATE_TEST_PROBE_TOKEN_A)")
    parser.add_argument("--token-b", default=None, help="Bearer token for tenant B (or PRUFGATE_TEST_PROBE_TOKEN_B)")
    parser.add_argument("--tenant-a", "--id-a", dest="tenant_a", default=None, help="Resource/tenant ID owned by tenant A")
    parser.add_argument("--tenant-b", "--id-b", dest="tenant_b", default=None, help="Resource/tenant ID owned by tenant B")
    args = parser.parse_args(raw_args)

    for env_key, val in (
        ("PRUFGATE_TEST_PROBE_TOKEN_A", args.token_a),
        ("PRUFGATE_TEST_PROBE_TOKEN_B", args.token_b),
        ("PRUFGATE_TEST_PROBE_TENANT_A_ID", args.tenant_a),
        ("PRUFGATE_TEST_PROBE_TENANT_B_ID", args.tenant_b),
    ):
        if val:
            os.environ[env_key] = val

    workspace = Path(args.workspace)
    if not workspace.is_dir():
        print(f"bola_engine: workspace not found: {workspace}", file=sys.stderr)
        return 2
    output_path = Path(args.output or f"{workspace}/reports/raw/bola_matrix.json")
    if args.target and not args.static_only:
        url_error = target_url_error(args.target)
        if url_error:
            print(f"bola_engine: {url_error}", file=sys.stderr)
            return 2

    try:
        cfg = PrufGateConfig.load(workspace, args.config, ref=args.base)
        findings: list[BolaFinding] = []
        if args.target and not args.static_only:
            if check_server_active(args.target):
                findings.extend(run_dynamic_matrix(args.target, workspace=workspace, config=cfg))
            else:
                print(f"  [BOLA Dynamic Matrix] Target {args.target} not reachable. Skipping dynamic network probes.")
        findings.extend(run_static_matrix_audit(workspace, config=cfg))
        findings = visible(findings, cfg.enable_low_confidence)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    except ConfigError as e:
        print(f"bola_engine: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # fail closed: a crash is never a pass
        print(f"bola_engine: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    print(f"✔ BOLA / Cross-Tenant Matrix complete: {len(findings)} finding(s) written to {output_path}")
    return 1 if any(f.severity in ("P0", "P1") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
