#!/usr/bin/env python3
"""PrufGate Ghost Dependency, API Contract & Environment Drift Guard (Engine 4).

Detects:
- `undeclared-or-hallucinated-import` (`P0`): Third-party imports across JS/TS (`package.json`),
  Python (`pyproject.toml` / `requirements*.txt`), Go (`go.mod`), and Rust (`Cargo.toml`)
  missing from workspace dependency manifests.
- `undocumented-env-var-drift` (`P1`): Environment variables referenced in code (`process.env.X`,
  `import.meta.env.X`, `os.environ["X"]`, `os.getenv("X")`, `os.Getenv("X")`, `std::env::var("X")`,
  `env!("X")`) that are missing from `.env.example` / `.env.template` / `.env.sample` and from
  config schemas and deploy manifests (zod, pydantic-settings, compose, Kubernetes, Helm, Actions).
- `ghost-symbol` (`P1`): A name imported from, or called on, a module in the repository (and,
  opt-in, an installed package) that the module does not define: a hallucinated API. Checked on
  added lines only in `--changed` mode.
- `frontend-backend-route-mismatch` (`P1`): Frontend HTTP client calls (`fetch("/api/...")`,
  `axios.<method>("/api/...")`, `useSWR("/api/...")`) targeting `/api/...` routes or HTTP methods
  that do not exist in backend route handlers or OpenAPI specifications.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import inline_ignore  # noqa: E402
from prufgate.bola.bola_engine import (  # noqa: E402
    INTERNAL_SCANNER_PATHS,
    is_self_scan,
    is_test_path,
    iter_workspace_files,
)
from prufgate.config import ConfigError, PrufGateConfig, _diff_base, _git  # noqa: E402
from prufgate.contract_guard.dependency_guard import (  # noqa: E402
    Finding,
    WorkspaceManifests,
    load_declared_dependencies,
    scan_file_dependencies,
)
from prufgate.contract_guard.env_guard import (  # noqa: E402
    load_documented_env_vars,
    scan_file_env_drift,
)
from prufgate.contract_guard.ghost_symbols import scan_file_ghost_symbols  # noqa: E402
from prufgate.contract_guard.registry_check import check_new_dependencies  # noqa: E402
from prufgate.contract_guard.route_contract import (  # noqa: E402
    build_backend_api_index,
    scan_file_route_contracts,
)

SUPPORTED_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".go", ".rs"}


def _git_paths(workspace: Path, args: list[str]) -> list[str]:
    res = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {res.stderr.strip()[:200]}")
    return [p for p in res.stdout.split("\0") if p]


def _changed_files(workspace: Path, base: str | None = None) -> list[Path] | None:
    """Changed, staged and untracked files (plus `base...HEAD` when a base ref is given).

    Returns None outside a git repository (callers then scan everything). An invalid
    base ref raises ValueError/RuntimeError: a diff that cannot be computed must not pass.
    """
    if base is not None and (not base or base.startswith("-")):
        raise ValueError(f"invalid base ref: {base!r}")
    probe = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "rev-parse", "--is-inside-work-tree"],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        if base is not None:
            raise RuntimeError("--changed with a base ref needs a git repository")
        return None
    rels: list[str] = []
    rename_source = False
    # -uall lists files inside new directories, not just the directory.
    for entry in _git_paths(workspace, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]):
        if rename_source:  # -z prints a rename's old path as the next entry
            rename_source = False
            continue
        rename_source = entry[:1] in ("R", "C")
        rels.append(entry[3:])
    if base is not None:
        rels += _git_paths(workspace, ["diff", "--name-only", "-z", "--end-of-options", f"{base}...HEAD"])
    elif not rels:
        try:
            rels += _git_paths(workspace, ["diff", "--name-only", "-z", "HEAD~1", "HEAD"])
        except RuntimeError:
            pass  # a single-commit repository has no HEAD~1
    paths = [workspace / r for r in dict.fromkeys(rels)]
    return [p for p in paths if p.is_file()]


def _added_lines(workspace: Path, base: str | None) -> dict[str, set[int]]:
    """{repository-relative path: added line numbers} against the merge base with `base`
    (else HEAD). A changed file missing here (untracked, or committed in HEAD with a clean
    tree) is treated as wholly added by the caller; a file whose diff adds no lines (a mode
    change) maps to an empty set. Outside a repository there is no diff ({}); inside one,
    a diff that cannot be computed raises GitDiffError: it must not pass."""
    from prufgate.diff_scope import _HUNK_RE, _unquote_git_path

    probe = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "rev-parse", "--is-inside-work-tree"],
        cwd=workspace,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0 and base is None:
        return {}
    commit = _diff_base(base, workspace)
    diff = _git(
        ["-c", "core.quotePath=false", "diff", "-U0", "-M", "--text", "--no-color", "--no-ext-diff", "--relative", commit],
        workspace,
    )
    added: dict[str, set[int]] = {}
    current = None
    old_left = 0
    new_left = 0
    for line in diff.splitlines():
        if old_left > 0 or new_left > 0:
            if line.startswith("-") and old_left > 0:
                old_left -= 1
                continue
            if line.startswith("+") and new_left > 0:
                new_left -= 1
                continue
            if line.startswith(" ") and old_left > 0 and new_left > 0:
                old_left -= 1
                new_left -= 1
                continue
            if line.startswith("\\"):
                continue
        if line.startswith("diff --git "):
            header = re.match(r"diff --git a/.* b/(.*)$", line)
            current = added.setdefault(header.group(1), set()) if header else None
            old_left = new_left = 0
        elif line.startswith("rename to ") and old_left == 0 and new_left == 0:
            rel = _unquote_git_path(line[len("rename to "):])
            if rel:
                current = added.setdefault(rel, set())
        elif line.startswith("--- ") and old_left == 0:
            new_left = 0
        elif line.startswith("+++ ") and new_left == 0:
            rel = _unquote_git_path(line[4:], prefix="b/")
            current = added.setdefault(rel, set()) if rel else None
            old_left = 0
        elif current is not None and (m := _HUNK_RE.match(line)):
            old_left = int(m.group(2) or "1")
            start, count = int(m.group(3)), int(m.group(4) or "1")
            new_left = count
            current.update(range(start, start + count))
    return added


def _iter_source_files(workspace: Path, changed_only: bool = False, base: str | None = None) -> list[Path]:
    if changed_only:
        changed = _changed_files(workspace, base)
        if changed is not None:
            return [p for p in changed if p.suffix.lower() in SUPPORTED_EXTENSIONS]
    return iter_workspace_files(workspace, SUPPORTED_EXTENSIONS)


def scan_contract_guard(
    workspace: Path,
    changed_only: bool = False,
    config: PrufGateConfig | None = None,
    base: str | None = None,
    ghost_third_party: bool = False,
) -> list[Finding]:
    """Run Ghost Dependency, Env Drift, and API Route Contract checks across `workspace`."""
    cfg = config or (PrufGateConfig.load(workspace, ref=base) if base or (workspace / ".prufgate").exists() else PrufGateConfig())
    manifests: WorkspaceManifests = load_declared_dependencies(workspace)
    documented_env: set[str] | None = load_documented_env_vars(workspace, cfg)
    api_index = build_backend_api_index(workspace)

    findings: list[Finding] = []
    candidate_files = _iter_source_files(workspace, changed_only=changed_only, base=base)
    self_scan = is_self_scan(workspace)
    added_lines = _added_lines(workspace, base) if changed_only else {}
    ghost_third_party = cfg.ghost_third_party or ghost_third_party

    for file_path in candidate_files:
        try:
            rel_path = str(file_path.relative_to(workspace)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path).replace("\\", "/")

        if self_scan and rel_path.startswith(INTERNAL_SCANNER_PATHS):
            continue
        if is_test_path(rel_path) or cfg.is_excluded(rel_path):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            raise RuntimeError(f"cannot read {rel_path}: {e}") from e

        # 1. Ghost / Hallucinated Dependency Check (`undeclared-or-hallucinated-import`)
        if not cfg.is_exempt(rel_path, "undeclared-or-hallucinated-import"):
            findings.extend(scan_file_dependencies(file_path, content, workspace, manifests, cfg))

        # 2. Undocumented Environment Variable Drift (`undocumented-env-var-drift`)
        if documented_env is not None and not cfg.is_exempt(rel_path, "undocumented-env-var-drift"):
            findings.extend(scan_file_env_drift(file_path, content, workspace, documented_env, cfg))

        # 2b. Ghost symbols: names the imported module does not define (`ghost-symbol`)
        if not cfg.is_exempt(rel_path, "ghost-symbol"):
            lines = content.splitlines()
            findings.extend(
                f
                for f in scan_file_ghost_symbols(
                    file_path, rel_path, content, workspace, added_lines.get(rel_path) if changed_only else None, ghost_third_party
                )
                if not inline_ignore.suppressed_at(
                    lines, f.line, f.rule, engine="contract-guard", path=rel_path, severity=f.severity, message=f.message
                )
            )

        # 3. Frontend-to-Backend Route Mismatch (`frontend-backend-route-mismatch`)
        if api_index and not cfg.is_exempt(rel_path, "frontend-backend-route-mismatch"):
            findings.extend(scan_file_route_contracts(file_path, rel_path, content, api_index))

    # 4. Registry check for newly added dependencies (opt-in: it needs the network)
    if cfg.registry_check or os.environ.get("PRUFGATE_REGISTRY_CHECK") == "1":
        findings.extend(
            f
            for f in check_new_dependencies(
                workspace,
                base,
                max_age_days=cfg.registry_max_age_days,
                max_lookups=cfg.registry_max_lookups,
                offline_ok=cfg.registry_offline_ok,
            )
            if not cfg.is_excluded(f.path) and not cfg.is_exempt(f.path, f.rule)
        )

    return findings


def run_self_check() -> int:
    """Self-check all 3 Contract Guard rules across synthetic multi-language fixtures."""
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)

        # 1. Manifests
        (ws / "package.json").write_text(
            json.dumps({"name": "demo-app", "dependencies": {"react": "^19.0.0", "zod": "^3.23.0"}}),
            encoding="utf-8",
        )
        (ws / "pyproject.toml").write_text(
            '[project]\nname = "demo-py"\ndependencies = ["fastapi>=0.115.0", "pydantic>=2.0"]\n',
            encoding="utf-8",
        )
        (ws / "go.mod").write_text(
            "module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n)\n",
            encoding="utf-8",
        )
        (ws / "Cargo.toml").write_text(
            '[package]\nname = "demo-rs"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n',
            encoding="utf-8",
        )
        (ws / ".env.example").write_text(
            "DATABASE_URL=postgres://localhost:5432/db\nNEXT_PUBLIC_APP_URL=http://localhost:3000\n",
            encoding="utf-8",
        )

        # 2. Backend route (`GET /api/v1/invoices/{invoice_id}`)
        (ws / "backend_routes.py").write_text(
            "import os\nfrom fastapi import APIRouter\nimport stripe_magic_sdk\n"
            "router = APIRouter(prefix='/api/v1')\n"
            "DB_URL = os.getenv('DATABASE_URL')\n"
            "SECRET_KEY = os.environ['UNDECLARED_STRIPE_WEBHOOK_SECRET']\n"
            "@router.get('/invoices/{invoice_id}')\n"
            "def get_invoice(invoice_id: str):\n"
            "    return {'id': invoice_id}\n",
            encoding="utf-8",
        )

        # 3. Frontend component calling hallucinated npm pkg, undeclared env var, and mismatched route
        (ws / "Dashboard.tsx").write_text(
            "import React from 'react';\n"
            "import { SuperChart } from '@hallucinated/super-chart';\n"
            "export async function loadData(id: string) {\n"
            "  const apiKey = process.env.SECRET_UNTRACKED_KEY;\n"
            "  await fetch(`/api/v1/invoices/${id}`);\n"
            "  await fetch('/api/v1/nonexistent-endpoint');\n"
            "  await fetch(`/api/v1/invoices/${id}`, { method: 'DELETE' });\n"
            "  return apiKey;\n"
            "}\n",
            encoding="utf-8",
        )

        # 4. Go & Rust files with undeclared imports
        (ws / "service.go").write_text(
            'package main\nimport (\n\t"os"\n\t"github.com/gin-gonic/gin"\n\t"github.com/ghost/hallucinated-go"\n)\n'
            'func run() { _ = os.Getenv("DATABASE_URL") }\n',
            encoding="utf-8",
        )
        (ws / "lib.rs").write_text(
            "use serde::Serialize;\nuse ghost_crate::Client;\n",
            encoding="utf-8",
        )

        findings = scan_contract_guard(ws)
        by_rule: dict[str, list[Finding]] = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)

        dep_findings = by_rule.get("undeclared-or-hallucinated-import", [])
        env_findings = by_rule.get("undocumented-env-var-drift", [])
        route_findings = by_rule.get("frontend-backend-route-mismatch", [])

        if len(dep_findings) != 4:
            print(
                f"contract_guard self-check FAILED: expected 4 undeclared-or-hallucinated-import findings, got {len(dep_findings)}: {[f.message for f in dep_findings]}",
                file=sys.stderr,
            )
            return 1
        if len(env_findings) != 2:
            print(
                f"contract_guard self-check FAILED: expected 2 undocumented-env-var-drift findings, got {len(env_findings)}: {[f.message for f in env_findings]}",
                file=sys.stderr,
            )
            return 1
        if len(route_findings) != 2:
            print(
                f"contract_guard self-check FAILED: expected 2 frontend-backend-route-mismatch findings, got {len(route_findings)}: {[f.message for f in route_findings]}",
                file=sys.stderr,
            )
            return 1

    print("contract_guard self-check: 8 contract & dependency case(s) ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Exit 0: no P0/P1 finding. 1: a P0/P1 finding. 2: the guard could not run."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in raw_args:
        return run_self_check()

    parser = argparse.ArgumentParser(prog="contract_guard", description="PrufGate Engine 4: contract & dependency guard")
    parser.add_argument(
        "--changed",
        nargs="?",
        const=True,
        default=False,
        metavar="BASE",
        help="Scan changed and untracked files only; --changed=REF also includes REF...HEAD",
    )
    parser.add_argument("--base", default=None, help="Base ref for --changed (e.g. origin/main)")
    parser.add_argument("--json-out", default=None)
    parser.add_argument(
        "--ghost-third-party",
        action="store_true",
        help="Also check names imported from installed packages (reads their source, never imports them)",
    )
    parser.add_argument("--config", default=None)
    parser.add_argument("--workspace", default=os.environ.get("WORKSPACE", str(Path.cwd())))
    args = parser.parse_args(raw_args)

    workspace = Path(args.workspace)
    if not workspace.is_dir():
        print(f"contract_guard: workspace not found: {workspace}", file=sys.stderr)
        return 2
    base = args.base or (args.changed if isinstance(args.changed, str) else None)
    try:
        cfg = PrufGateConfig.load(workspace, args.config, ref=base)
        findings = scan_contract_guard(
            workspace, changed_only=bool(args.changed), config=cfg, base=base, ghost_third_party=args.ghost_third_party
        )
    except ConfigError as e:
        print(f"contract_guard: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # fail closed: a crash is never a pass
        print(f"contract_guard: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    serialized = [f.to_dict() for f in findings]
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(serialized, indent=2) + "\n", encoding="utf-8")
    elif findings:
        for f in findings:
            print(f)

    return 1 if any(f.severity in ("P0", "P1") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
