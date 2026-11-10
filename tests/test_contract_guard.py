import json
import tempfile
import unittest
from pathlib import Path

from prufgate.config import PrufGateConfig
from prufgate.contract_guard import main, run_self_check, scan_contract_guard


class TestContractGuard(unittest.TestCase):
    def test_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_js_ts_dependency_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "package.json").write_text(
                json.dumps(
                    {
                        "name": "web-client",
                        "dependencies": {"next": "15.0.0", "react": "19.0.0", "@tanstack/react-query": "5.0.0"},
                        "devDependencies": {"typescript": "5.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            (ws / "src").mkdir()
            (ws / "src" / "page.tsx").write_text(
                "import fs from 'node:fs';\n"
                "import React from 'react';\n"
                "import { useQuery } from '@tanstack/react-query/build/modern';\n"
                "import { helper } from '@/lib/helper';\n"
                "import { ghost } from 'hallucinated-ai-sdk';\n"
                "import { chart } from '@slopsquat/chart-pro/dist';\n",
                encoding="utf-8",
            )

            findings = scan_contract_guard(ws)
            dep_findings = [f for f in findings if f.rule == "undeclared-or-hallucinated-import"]
            self.assertEqual(len(dep_findings), 2)
            messages = " ".join(f.message for f in dep_findings)
            self.assertIn("hallucinated-ai-sdk", messages)
            self.assertIn("@slopsquat/chart-pro", messages)

    def test_python_go_rust_dependency_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "requirements.txt").write_text(
                "scikit-learn>=1.5.0\nPillow==10.4.0\nrequests>=2.32.0\n",
                encoding="utf-8",
            )
            (ws / "go.mod").write_text(
                "module github.com/acme/service\n\ngo 1.22\n\nrequire github.com/gorilla/mux v1.8.1\n",
                encoding="utf-8",
            )
            (ws / "Cargo.toml").write_text(
                '[package]\nname = "worker"\nversion = "0.1.0"\n\n[dependencies]\ntokio-util = "0.7"\n',
                encoding="utf-8",
            )

            # Local python module
            (ws / "local_helper.py").write_text("X = 1\n", encoding="utf-8")
            (ws / "app.py").write_text(
                "import os\n"
                "import sklearn.metrics\n"
                "from PIL import Image\n"
                "import local_helper\n"
                "try:\n"
                "    import optional_pkg\n"
                "except ImportError:\n"
                "    optional_pkg = None\n"
                "import hallucinated_py_lib\n",
                encoding="utf-8",
            )
            (ws / "main.go").write_text(
                "package main\n"
                "import (\n"
                '\t"net/http"\n'
                '\t"github.com/acme/service/internal/auth"\n'
                '\t"github.com/gorilla/mux"\n'
                '\t"github.com/untracked/ghostpkg"\n'
                ")\n",
                encoding="utf-8",
            )
            (ws / "main.rs").write_text(
                "use std::collections::HashMap;\n"
                "use tokio_util::codec::LinesCodec;\n"
                "use slopsquatted_crate::Runner;\n",
                encoding="utf-8",
            )

            findings = scan_contract_guard(ws)
            dep_findings = [f for f in findings if f.rule == "undeclared-or-hallucinated-import"]
            self.assertEqual(len(dep_findings), 3)
            files = {f.path for f in dep_findings}
            self.assertEqual(files, {"app.py", "main.go", "main.rs"})

    def test_env_var_drift_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".env.example").write_text(
                "DATABASE_URL=postgres://localhost/app\nREDIS_URL=redis://localhost:6379\n",
                encoding="utf-8",
            )
            (ws / "config.ts").write_text(
                "export const db = process.env.DATABASE_URL;\n"
                "export const port = process.env.PORT;\n"
                "export const fallbackVar = process.env.OPTIONAL_FEATURE_FLAG || 'false';\n"
                "export const secret = process.env.UNTRACKED_JWT_SIGNING_SECRET;\n",
                encoding="utf-8",
            )
            (ws / "settings.py").write_text(
                "import os\n"
                "REDIS = os.getenv('REDIS_URL')\n"
                "SAFE_DEFAULT = os.getenv('MISSING_WITH_DEFAULT', '123')\n"
                "DRIFTED = os.environ['UNTRACKED_BILLING_API_KEY']\n",
                encoding="utf-8",
            )

            findings = scan_contract_guard(ws)
            env_findings = [f for f in findings if f.rule == "undocumented-env-var-drift"]
            self.assertEqual(len(env_findings), 2)
            messages = " ".join(f.message for f in env_findings)
            self.assertIn("UNTRACKED_JWT_SIGNING_SECRET", messages)
            self.assertIn("UNTRACKED_BILLING_API_KEY", messages)

    def test_frontend_backend_route_contract_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Next.js App Router backend route supporting GET and POST on /api/projects/[id]
            route_dir = ws / "app" / "api" / "projects" / "[id]"
            route_dir.mkdir(parents=True)
            (route_dir / "route.ts").write_text(
                "export async function GET(req: Request) { return Response.json({}); }\n"
                "export async function POST(req: Request) { return Response.json({}); }\n",
                encoding="utf-8",
            )

            # Frontend component
            (ws / "ProjectView.tsx").write_text(
                "export async function syncProject(projectId: string) {\n"
                "  await fetch(`/api/projects/${projectId}`);\n"
                "  await fetch(`/api/projects/${projectId}?include=members`, { method: 'POST' });\n"
                "  await fetch(`/api/projects/${projectId}`, { method: 'DELETE' });\n"
                "  await fetch('/api/nonexistent/route');\n"
                "}\n",
                encoding="utf-8",
            )

            findings = scan_contract_guard(ws)
            route_findings = [f for f in findings if f.rule == "frontend-backend-route-mismatch"]
            self.assertEqual(len(route_findings), 2)
            msgs = " | ".join(f.message for f in route_findings)
            self.assertIn("DELETE /api/projects/${projectId}", msgs)
            self.assertIn("/api/nonexistent/route", msgs)

    def test_jsx_apostrophe_does_not_hide_route_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            route_dir = ws / "app" / "api" / "projects"
            route_dir.mkdir(parents=True)
            (route_dir / "route.ts").write_text(
                "export async function GET() { return Response.json({}); }\n", encoding="utf-8"
            )
            (ws / "Page.tsx").write_text(
                "export function Page() {\n"
                "  return <p>Don't worry</p>;\n"
                "}\n"
                "export async function load() {\n"
                "  await fetch('/api/nonexistent/route');\n"
                "}\n",
                encoding="utf-8",
            )
            findings = [f for f in scan_contract_guard(ws) if f.rule == "frontend-backend-route-mismatch"]
            self.assertEqual(len(findings), 1)
            self.assertIn("/api/nonexistent/route", findings[0].message)

    def test_config_exemption_and_cli_json_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            (ws / "legacy.ts").write_text("import 'legacy-untracked-pkg';\n", encoding="utf-8")
            cfg = PrufGateConfig(exempt={("legacy.ts", "ghost-dependency"): "legacy module"})
            findings = scan_contract_guard(ws, config=cfg)
            self.assertEqual(len(findings), 0)

            # Without exemption, CLI writes JSON and returns 1 on P0 finding
            out_json = ws / "out.json"
            rc = main([f"--workspace={ws}", f"--json-out={out_json}"])
            self.assertEqual(rc, 1)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["rule"], "undeclared-or-hallucinated-import")


if __name__ == "__main__":
    unittest.main()
