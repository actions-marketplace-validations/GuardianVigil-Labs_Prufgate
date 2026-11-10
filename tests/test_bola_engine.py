import http.server
import json
import os
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

from prufgate.bola import (
    discover_all_routes,
    run_dynamic_matrix,
    run_self_check,
    run_static_matrix_audit,
)
from prufgate.config import PrufGateConfig


class _BolaTestHttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output clean

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        # 1. Vulnerable unauthenticated endpoint
        if self.path == "/api/v1/projects":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"projects": [{"id": "proj-1", "secret": "internal"}]}')
            return

        # 2. Vulnerable cross-tenant endpoint: returns tenant B data to tenant A token
        if self.path.startswith("/api/v1/invoices/"):
            if not auth:
                self.send_response(401)
                self.end_headers()
                return
            inv_id = self.path.rsplit("/", 1)[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"invoice_id": inv_id, "owner": "leaked-record"}).encode("utf-8"))
            return

        # 3. Safe tenant-isolated endpoint
        if self.path.startswith("/api/v1/safe-orders/"):
            if not auth:
                self.send_response(401)
                self.end_headers()
                return
            target_tenant = self.path.rsplit("/", 1)[-1]
            if ("token_alpha" in auth and target_tenant == "tenant-a-1111") or ("token_bravo" in auth and target_tenant == "tenant-b-2222"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"order": target_tenant}).encode())
                return
            self.send_response(403)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


class TestUniversalBolaEngine(unittest.TestCase):
    def test_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_discover_all_routes_across_frameworks_and_openapi(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            # 1. OpenAPI 3.0 JSON
            (ws / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {
                            "/api/v1/customers/{customer_id}": {
                                "get": {"summary": "Get customer"},
                                "delete": {"summary": "Delete customer"},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            # 2. Next.js App Router
            next_dir = ws / "app" / "api" / "Billing" / "[invoiceId]"
            next_dir.mkdir(parents=True)
            (next_dir / "route.ts").write_text(
                "export async function GET(req: Request) { return Response.json({}); }\n",
                encoding="utf-8",
            )

            # 3. NestJS Controller
            (ws / "users.controller.ts").write_text(
                "@Controller('api/users')\n"
                "export class UsersController {\n"
                "  @Get(':userId')\n"
                "  findOne() {}\n"
                "}\n",
                encoding="utf-8",
            )

            # 4. Django urls.py
            (ws / "urls.py").write_text(
                "from django.urls import path\n"
                "urlpatterns = [\n"
                "    path('api/records/<uuid:record_id>/', views.detail),\n"
                "]\n",
                encoding="utf-8",
            )

            # 5. Ruby on Rails & PHP Laravel
            (ws / "routes.rb").write_text("resources :subscriptions\n", encoding="utf-8")
            (ws / "api.php").write_text("Route::get('/api/accounts/{accountId}', [AccountController::class, 'show']);\n", encoding="utf-8")

            routes = discover_all_routes(ws)
            frameworks = {r.framework for r in routes}
            self.assertTrue({"openapi", "nextjs", "nestjs", "django", "rails", "laravel"}.issubset(frameworks))
            dynamic_paths = {r.path for r in routes if r.has_dynamic_param}
            self.assertIn("/api/v1/customers/{customer_id}", dynamic_paths)
            self.assertIn("/api/Billing/{invoiceId}", dynamic_paths)
            self.assertIn("/api/users/{userId}", dynamic_paths)
            self.assertIn("/api/records/{record_id}", dynamic_paths)
            self.assertIn("/subscriptions/{id}", dynamic_paths)
            self.assertIn("/api/accounts/{accountId}", dynamic_paths)

    def test_custom_auth_guards_and_tenant_keys_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "routes.ts").write_text(
                "app.get('/api/vaults/:vaultId', async (req, res) => {\n"
                "  enforceCustomZeroTrustGuard(req);\n"
                "  const item = await prisma.vault.findFirst({ where: { id: req.params.vaultId, customRealmKey: req.realm } });\n"
                "  return res.json(item);\n"
                "});\n",
                encoding="utf-8",
            )

            # Without custom config, both auth guard and tenant key are unknown -> flagged
            default_findings = run_static_matrix_audit(ws)
            self.assertEqual(len(default_findings), 1)
            self.assertEqual(default_findings[0].rule_id, "static-bola-unscoped-access")

            # With custom auth_guards and tenant_keys in PrufGateConfig -> passes cleanly
            custom_cfg = PrufGateConfig(
                auth_guards=["enforceCustomZeroTrustGuard"],
                tenant_keys=["customRealmKey"],
            )
            scoped_findings = run_static_matrix_audit(ws, config=custom_cfg)
            self.assertEqual(len(scoped_findings), 0)

    def test_live_dynamic_two_token_differential_matrix(self) -> None:
        class _ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        with _ReusableTCPServer(("127.0.0.1", 0), _BolaTestHttpHandler) as httpd:
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                old_paths = os.environ.get("PRUFGATE_BOLA_PATHS")
                old_cross = os.environ.get("PRUFGATE_CROSS_TENANT_PATHS")
                os.environ["PRUFGATE_BOLA_PATHS"] = "/api/v1/projects,/api/v1/safe-orders/tenant-a-1111"
                os.environ["PRUFGATE_CROSS_TENANT_PATHS"] = (
                    "/api/v1/invoices/{tenant_id},/api/v1/safe-orders/{tenant_id}"
                )
                os.environ["PRUFGATE_TEST_PROBE_TOKEN_A"] = "probe_token_alpha"
                os.environ["PRUFGATE_TEST_PROBE_TOKEN_B"] = "probe_token_bravo"
                try:
                    findings = run_dynamic_matrix(f"http://127.0.0.1:{port}")
                finally:
                    os.environ.pop("PRUFGATE_TEST_PROBE_TOKEN_A", None)
                    os.environ.pop("PRUFGATE_TEST_PROBE_TOKEN_B", None)
                    if old_paths is None:
                        os.environ.pop("PRUFGATE_BOLA_PATHS", None)
                    else:
                        os.environ["PRUFGATE_BOLA_PATHS"] = old_paths
                    if old_cross is None:
                        os.environ.pop("PRUFGATE_CROSS_TENANT_PATHS", None)
                    else:
                        os.environ["PRUFGATE_CROSS_TENANT_PATHS"] = old_cross

                rules = {f.rule_id for f in findings}
                self.assertIn("BOLA-UNAUTHENTICATED-ACCESS", rules)
                self.assertIn("BOLA-CROSS-TENANT-ACCESS", rules)
                targets = {f.endpoint_or_file for f in findings}
                self.assertIn("/api/v1/projects", targets)
                self.assertTrue(any("/api/v1/invoices/" in t for t in targets))
                # Safe endpoint must never be flagged
                self.assertFalse(any("/api/v1/safe-orders/" in t for t in targets))
            finally:
                httpd.shutdown()


class TestTenantSubstitution(unittest.TestCase):
    def test_numeric_tenant_ids_fill_only_the_placeholder(self) -> None:
        from unittest import mock

        from prufgate.bola import bola_engine

        seen: list[str] = []

        class Recorder(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen.append(self.path)
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args) -> None:
                pass

        env = {"PRUFGATE_TEST_PROBE_TOKEN_A": "probe_token_alpha", "PRUFGATE_TEST_PROBE_TOKEN_B": "probe_token_bravo",
               "PRUFGATE_TEST_PROBE_TENANT_A_ID": "2", "PRUFGATE_TEST_PROBE_TENANT_B_ID": "1",
               "PRUFGATE_BOLA_PATHS": "/api/v1/projects", "PRUFGATE_CROSS_TENANT_PATHS": "/api/v1/tenants/{tenant_id}"}
        with socketserver.TCPServer(("127.0.0.1", 0), Recorder) as httpd, mock.patch.dict(os.environ, env):
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                with self.assertRaises(bola_engine.ProbeIncomplete):
                    bola_engine.run_dynamic_matrix(f"http://127.0.0.1:{httpd.server_address[1]}")
            finally:
                httpd.shutdown()
        self.assertIn("/api/v1/tenants/2", seen)
        self.assertIn("/api/v1/tenants/1", seen)
        self.assertFalse(any(p.startswith("/api/v2/") for p in seen), seen)


class TestUnsafeTargetRefused(unittest.TestCase):
    """The link-local / metadata guard holds when the engine is run directly, not only via the CLI."""

    def test_direct_run_and_probe_refuse_metadata_target(self) -> None:
        import subprocess
        import sys
        from unittest import mock

        from prufgate.bola import bola_engine

        env = {k: v for k, v in os.environ.items() if k != "PRUFGATE_ALLOW_LINK_LOCAL"}
        engine = Path(bola_engine.__file__)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env, clear=True):
            for target in ("http://169.254.169.254/", "http://metadata.google.internal/"):
                with self.subTest(target):
                    run = subprocess.run(
                        [sys.executable, str(engine), "--target", target, "--workspace", tmp],
                        capture_output=True, text=True, env=env, timeout=60,
                    )
                    self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
                    self.assertIn("Blocked SSRF target", run.stderr)
                    self.assertFalse(bola_engine.check_server_active(target))
                    with self.assertRaises(ValueError):
                        bola_engine.run_dynamic_matrix(target)


if __name__ == "__main__":
    unittest.main()
