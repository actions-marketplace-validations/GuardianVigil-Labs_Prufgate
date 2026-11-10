"""Issue #29: live BOLA probes follow redirects only within the target's
origin. The target URL is checked before probing; a 302 to another host (for
example a metadata address) must not receive the probe or its bearer tokens,
and the untested routes are reported, never passed silently."""

import contextlib
import http.server
import io
import os
import threading
import unittest
from unittest.mock import patch

from prufgate.bola import bola_engine


def _serve(handler: type) -> http.server.ThreadingHTTPServer:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class BolaRedirects(unittest.TestCase):
    def setUp(self) -> None:
        self.sink_hits: list[str] = []
        hits = self.sink_hits

        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_GET(self) -> None:
                hits.append(self.headers.get("Authorization", ""))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"leaked": "metadata"}')

        self.sink = _serve(Sink)
        sink_url = f"http://127.0.0.1:{self.sink.server_address[1]}"

        class Redirector(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", sink_url + self.path)
                self.end_headers()

        self.target = _serve(Redirector)
        self.target_url = f"http://127.0.0.1:{self.target.server_address[1]}"

    def tearDown(self) -> None:
        for s in (self.sink, self.target):
            s.shutdown()
            s.server_close()

    def test_probe_does_not_follow_redirects(self) -> None:
        env = {
            "PRUFGATE_BOLA_PATHS": "/api/v1/projects",
            "PRUFGATE_CROSS_TENANT_PATHS": "/api/v1/invoices/{tenant_id}",
            "PRUFGATE_TEST_PROBE_TOKEN_A": "probe_token_alpha",
            "PRUFGATE_TEST_PROBE_TOKEN_B": "probe_token_bravo",
        }
        err = io.StringIO()
        with patch.dict(os.environ, env), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(bola_engine.ProbeIncomplete) as caught:
                bola_engine.run_dynamic_matrix(self.target_url)
            findings = caught.exception.findings
        self.assertEqual(self.sink_hits, [], "a redirected probe reached another host")
        self.assertEqual([f.rule_id for f in findings], ["BOLA-PROBE-REDIRECT-REFUSED"])
        self.assertEqual(findings[0].severity, "P1")
        self.assertIn("redirect", err.getvalue().lower())

    def test_liveness_check_does_not_follow_redirects(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            bola_engine.check_server_active(self.target_url)
        self.assertEqual(self.sink_hits, [])


class BolaSameOriginRedirect(unittest.TestCase):
    def test_same_origin_redirect_is_followed(self) -> None:
        class Slash(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_GET(self) -> None:
                if self.path == "/api/v1/projects":
                    self.send_response(307)
                    self.send_header("Location", "/api/v1/projects/")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"projects": [{"id": "proj-1"}]}')

        srv = _serve(Slash)
        try:
            with patch.dict(os.environ, {"PRUFGATE_BOLA_PATHS": "/api/v1/projects", "PRUFGATE_TEST_PROBE_TOKEN_A": "fixture-alpha", "PRUFGATE_TEST_PROBE_TOKEN_B": "fixture-bravo"}), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(bola_engine.ProbeIncomplete) as caught:
                    bola_engine.run_dynamic_matrix(f"http://127.0.0.1:{srv.server_address[1]}")
                findings = caught.exception.findings
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("BOLA-UNAUTHENTICATED-ACCESS", {f.rule_id for f in findings})


if __name__ == "__main__":
    unittest.main()
