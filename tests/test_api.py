"""REST API: authentication, input validation, workspace confinement and
webhook signatures. Standard library only; the scan worker is stubbed."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "prufgate" / "api"))
import server  # noqa: E402

TOKEN = "test-token-123"
SECRET = "webhook-secret-456"


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "root"
        (cls.root / "repo").mkdir(parents=True)
        cls.outside = Path(cls.tmp.name) / "outside"
        cls.outside.mkdir()
        (cls.root / "escape").symlink_to(cls.outside)
        os.environ["PRUFGATE_WORKSPACE_ROOT"] = str(cls.root)

        cls.started = []
        cls.block = threading.Event()

        def fake_worker(scan_id, battery, workspace, target_url):
            cls.started.append((battery, workspace, target_url))
            cls.block.wait(5)
            with server.SCANS_LOCK:
                if scan_id in server.SCANS:
                    server.SCANS[scan_id]["status"] = "completed"

        server._real_worker = server.execute_scan_worker
        server.execute_scan_worker = fake_worker
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.PrufGateAPIHandler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.block.set()
        cls.httpd.shutdown()
        cls.tmp.cleanup()
        os.environ.pop("PRUFGATE_WORKSPACE_ROOT", None)

    def setUp(self):
        server.configure(token=TOKEN, webhook_secret=SECRET, max_running=2)
        self.block.set()
        with server.SCANS_LOCK:
            server.SCANS.clear()
        self.started.clear()

    def request(self, method, path, body=None, headers=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def scan(self, body, token=TOKEN, content_type="application/json"):
        headers = {"Content-Type": content_type}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.request("POST", "/api/v1/scan", body, headers)

    # --- authentication -----------------------------------------------------

    def test_health_is_open(self):
        status, _, _ = self.request("GET", "/api/v1/health")
        self.assertEqual(status, 200)

    def test_docs_page_loads_only_pinned_integrity_checked_assets(self):
        import base64
        import re

        status, headers, body = self.request("GET", "/docs")
        self.assertEqual(status, 200)
        page = body.decode()
        assets = re.findall(r'<(?:script|link)[^>]*(?:src|href)="(https://[^"]+)"[^>]*>', page)
        self.assertEqual(len(assets), 2)
        for tag in re.findall(r'<(?:script|link)[^>]*(?:src|href)="https://[^>]*>', page):
            self.assertRegex(tag, r"swagger-ui-dist@\d+\.\d+\.\d+/")
            self.assertRegex(tag, r'integrity="sha384-[A-Za-z0-9+/=]{64}"')
            self.assertIn('crossorigin="anonymous"', tag)
        csp = headers["Content-Security-Policy"]
        inline = page.split("<script>", 1)[1].split("</script>", 1)[0]
        digest = base64.b64encode(hashlib.sha256(inline.encode()).digest()).decode()
        self.assertIn(f"'sha256-{digest}'", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("'unsafe-inline'", csp.split("script-src", 1)[1].split(";", 1)[0])

    def test_scan_requires_token(self):
        self.assertEqual(self.scan({"battery": "fast"}, token=None)[0], 401)
        self.assertEqual(self.scan({"battery": "fast"}, token="wrong")[0], 401)
        self.assertEqual(self.started, [])

    def test_scan_results_require_token(self):
        status, _, body = self.scan({"battery": "fast", "workspace": "repo"})
        self.assertEqual(status, 202)
        scan_id = json.loads(body)["scan_id"]
        for suffix in ("", "/sarif", "/report"):
            self.assertEqual(self.request("GET", f"/api/v1/scans/{scan_id}{suffix}")[0], 401)
        status, _, _ = self.request("GET", f"/api/v1/scans/{scan_id}",
                                    headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(status, 200)

    def test_no_cors_headers(self):
        _, headers, _ = self.request("GET", "/api/v1/health")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_simple_form_post_is_refused(self):
        # A browser can send text/plain cross-origin without a preflight.
        self.assertEqual(self.scan({"battery": "fast"}, content_type="text/plain")[0], 415)
        self.assertEqual(self.started, [])

    # --- input validation ---------------------------------------------------

    def test_unknown_battery(self):
        self.assertEqual(self.scan({"battery": "fast; rm -rf /"})[0], 400)

    def test_workspace_traversal(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "../outside"})[0], 403)

    def test_workspace_absolute_outside_root(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": str(self.outside)})[0], 403)

    def test_workspace_symlink_escape(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "escape"})[0], 403)

    def test_workspace_missing_is_not_created(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "nope"})[0], 400)
        self.assertFalse((self.root / "nope").exists())

    def test_target_url_scheme(self):
        self.assertEqual(self.scan({"battery": "full", "workspace": "repo", "target_url": "file:///etc/passwd"})[0], 400)

    def test_target_url_cloud_metadata_ssrf_blocked(self):
        self.assertEqual(
            self.scan({"battery": "full", "workspace": "repo", "target_url": "http://169.254.169.254/latest/meta-data/"})[0],
            400,
        )
        self.assertEqual(
            self.scan({"battery": "full", "workspace": "repo", "target_url": "http://metadata.google.internal"})[0],
            400,
        )

    def test_body_too_large(self):
        # Declared length only: the server must refuse before reading a byte.
        conn = http.client.HTTPConnection(self.base.split("//")[1], timeout=5)
        conn.putrequest("POST", "/api/v1/scan")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Authorization", f"Bearer {TOKEN}")
        conn.putheader("Content-Length", str(server.MAX_BODY_BYTES + 1))
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

    def test_valid_scan_runs_inside_root(self):
        status, _, _ = self.scan({"battery": "fast", "workspace": "repo"})
        self.assertEqual(status, 202)
        self.assertEqual(self.started[0][1], str((self.root / "repo").resolve()))

    def test_concurrency_limit(self):
        self.block.clear()
        try:
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 202)
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 202)
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 429)
        finally:
            self.block.set()

    # --- webhooks -----------------------------------------------------------

    def webhook(self, body: bytes, headers):
        return self.request("POST", "/api/v1/webhook", raw=body, headers=headers)

    def test_webhook_disabled_without_secret(self):
        server.configure(token=TOKEN, webhook_secret="")
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push"})[0], 503)

    def test_webhook_unsigned(self):
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push"})[0], 401)
        self.assertEqual(self.started, [])

    def test_webhook_bad_signature(self):
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=" + "0" * 64})[0], 401)

    def test_webhook_signature_over_other_body(self):
        sig = "sha256=" + hmac.new(SECRET.encode(), b"{}", hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(b'{"x":1}', {"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})[0], 401)

    def test_webhook_github_signed(self):
        body = json.dumps({"repository": {"name": "demo"}}).encode()
        sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(body, {"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})[0], 202)
        self.assertEqual(len(self.started), 1)

    def test_webhook_github_ping(self):
        sig = "sha256=" + hmac.new(SECRET.encode(), b"{}", hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig})[0], 200)
        self.assertEqual(self.started, [])

    def test_webhook_gitlab_token(self):
        self.assertEqual(self.webhook(b"{}", {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "nope"})[0], 401)
        self.assertEqual(self.webhook(b"{}", {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": SECRET})[0], 202)


class WorkerTest(unittest.TestCase):
    """Only the scan's own SARIF counts. An unreadable or missing report is
    "not counted", never zero findings, and never an older report."""

    def run_worker(self, sarif_text, exit_code=0, stale=None):
        real = server.__dict__.get("_real_worker") or server.execute_scan_worker
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "reports").mkdir()
            if stale is not None:
                (ws / "reports" / "prufgate.sarif").write_text(stale)

            def fake_run(scan_id, cmd, cwd, env):
                if sarif_text is not None:
                    Path(env["PRUFGATE_REPORTS_DIR"], "prufgate.sarif").write_text(sarif_text)
                return exit_code, "", "boom" if exit_code else ""

            with server.SCANS_LOCK:
                server.SCANS["w"] = {"scan_id": "w", "status": "queued"}
            with patch.object(server, "run_scan_process", fake_run):
                real("w", "fast", str(ws), None)
            with server.SCANS_LOCK:
                return dict(server.SCANS.pop("w"))

    def test_missing_report_is_not_zero(self):
        scan = self.run_worker(None)
        self.assertIsNone(scan["blockers"])
        self.assertIn("no SARIF", scan["findings_error"])
        self.assertEqual(scan["verdict"], "ERROR")

    def test_corrupt_report_is_not_zero(self):
        scan = self.run_worker("{not json")
        self.assertIsNone(scan["findings_summary"])
        self.assertIn("could not be read", scan["findings_error"])
        self.assertEqual(scan["verdict"], "ERROR")

    def test_report_is_counted(self):
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": [{"message": {"text": "blocker"}, "properties": {"severity": "P0"}}, {"message": {"text": "advisory"}, "properties": {"severity": "P2"}}]}]}
        scan = self.run_worker(json.dumps(sarif), exit_code=1)
        self.assertEqual(scan["blockers"], 1)
        self.assertEqual(scan["advisories"], 1)
        self.assertIsNone(scan["findings_error"])
        self.assertEqual(scan["verdict"], "FAILED")

    def test_engine_error_exit_is_an_error_verdict(self):
        scan = self.run_worker(json.dumps({"runs": [{"results": []}]}), exit_code=2)
        self.assertEqual(scan["verdict"], "ERROR")

    def test_stale_shared_sarif_is_never_read(self):
        # A clean old report in reports/ must not stand in for a scan that wrote none.
        scan = self.run_worker(None, exit_code=0, stale=json.dumps({"runs": [{"results": []}]}))
        self.assertIsNone(scan["blockers"])
        self.assertEqual(scan["verdict"], "ERROR")

    def test_symlinked_reports_dir_is_refused(self):
        real = server.__dict__.get("_real_worker") or server.execute_scan_worker
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            ws = Path(tmp)
            (ws / "reports").symlink_to(outside)
            with server.SCANS_LOCK:
                server.SCANS["s"] = {"scan_id": "s", "status": "queued"}
            with patch.object(server, "run_scan_process", side_effect=AssertionError("must not run")):
                real("s", "fast", str(ws), None)
            with server.SCANS_LOCK:
                scan = dict(server.SCANS.pop("s"))
            self.assertEqual(scan["verdict"], "ERROR")
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_target_url_resolving_to_metadata_is_refused(self):
        with self.assertRaises(server.RequestError):
            server.validate_target_url("http://2852039166/latest/meta-data/")

    def test_batteries_are_the_gate_modes(self):
        self.assertEqual(set(server.BATTERIES), {"fast", "check", "review", "full"})

    def test_pip_install_without_prufgate_sh_falls_back_to_prufgate_check(self):
        with patch.object(server, "PRUFGATE_ROOT", Path("/nonexistent")):
            cmd, on_stdout = server.scan_command("fast", Path("/ws"))
        self.assertTrue(on_stdout)
        # The workspace as the OS spells it (`\\ws` on Windows).
        self.assertEqual(cmd[1], "-I")
        self.assertTrue(cmd[2].endswith("cli.py"))
        self.assertEqual(cmd[3:5], ["check", str(Path("/ws"))])
        self.assertIn("--changed", cmd)
        self.assertEqual(cmd[-2:], ["--format", "sarif"])


class StartupTest(unittest.TestCase):
    def test_loopback_detection(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            self.assertTrue(server.is_loopback(host), host)
        for host in ("0.0.0.0", "192.0.2.5", "example.com"):
            self.assertFalse(server.is_loopback(host), host)

    def test_token_generated_when_unset(self):
        os.environ.pop("PRUFGATE_API_TOKEN", None)
        self.assertTrue(server.configure(webhook_secret=""))
        self.assertGreaterEqual(len(server.API_TOKEN), 32)

    def test_public_bind_without_token_refused(self):
        os.environ.pop("PRUFGATE_API_TOKEN", None)
        with self.assertRaises(SystemExit) as cm:
            server.run_server(host="0.0.0.0", port=0)
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
