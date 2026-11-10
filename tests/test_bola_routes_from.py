"""Issue #53: `prufgate bola --routes-from FILE` adds GET/HEAD route paths from an
OpenAPI/Swagger, Postman v2.1 or HAR file. Only method and path are read; every
path is probed on --url, never on the file's host."""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

from prufgate.bola import bola_engine, route_sources
from prufgate.bola.route_sources import RouteSourceError, load_route_paths
from prufgate.cli import main as cli_main

OPENAPI_YAML = """
openapi: 3.0.3
servers:
  - url: https://api.example.com/v2
paths:
  /invoices/{invoiceId}:
    parameters:
      - name: invoiceId
        in: path
        example: inv-42
    get: {}
    delete: {}
  /projects/{projectId}/notes:
    get:
      parameters:
        - name: projectId
          in: path
          schema: {type: string}
  /reports:
    head: {}
    post: {}
"""

SWAGGER = {
    "swagger": "2.0",
    "host": "api.example.com",
    "basePath": "/v1",
    "parameters": {"Org": {"name": "orgId", "in": "path", "type": "string", "default": "org-7"}},
    "paths": {"/orgs/{orgId}": {"get": {"parameters": [{"$ref": "#/parameters/Org"}]}, "put": {}}},
}

POSTMAN = {
    "info": {"name": "Sample", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "not-a-real-secret"}]},
    "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
    "item": [
        {"name": "Folder", "item": [
            {"name": "List", "request": {"method": "GET", "url": {
                "raw": "{{baseUrl}}/api/items?page=2", "host": ["{{baseUrl}}"], "path": ["api", "items"]}}},
            {"name": "One", "request": {"method": "GET", "url": "{{baseUrl}}/api/items/:itemId?x=1"}},
        ]},
        {"name": "Make", "request": {"method": "POST", "url": "https://api.example.com/api/items",
                                     "body": {"mode": "raw", "raw": "{}"}}},
    ],
}

HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {"request": {"method": "GET", "url": "https://app.example.com/api/me?session=abc",
                         "headers": [{"name": "Cookie", "value": "sid=not-real"}]}},
            {"request": {"method": "PATCH", "url": "https://app.example.com/api/me"}},
            {"request": {"method": "HEAD", "url": "https://app.example.com/api/health"}},
        ]
    }
}


class RouteSourceFormats(unittest.TestCase):
    def _write(self, name: str, content: object) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(path)

    def test_openapi_yaml(self) -> None:
        paths, skipped = load_route_paths(self._write("api.yaml", OPENAPI_YAML))
        self.assertEqual(paths, ["/v2/invoices/inv-42", "/v2/projects/{tenant_id}/notes", "/v2/reports"])
        self.assertEqual(skipped, 2)

    def test_swagger_json(self) -> None:
        paths, skipped = load_route_paths(self._write("api.json", SWAGGER))
        self.assertEqual((paths, skipped), (["/v1/orgs/org-7"], 1))

    def test_postman(self) -> None:
        paths, skipped = load_route_paths(self._write("c.json", POSTMAN))
        self.assertEqual((paths, skipped), (["/api/items", "/api/items/{tenant_id}"], 1))

    def test_har(self) -> None:
        paths, skipped = load_route_paths(self._write("s.har", HAR))
        self.assertEqual((paths, skipped), (["/api/me", "/api/health"], 1))

    def test_yaml_aliases_are_refused(self) -> None:
        # Nested aliases expand without bound (a "billion laughs" file); a short one here.
        bomb = "l0: &l0 {request: {method: GET, url: /x}}\n"
        for i in range(1, 4):
            bomb += f"l{i}: &l{i} {{item: [{', '.join([f'*l{i - 1}'] * 10)}]}}\n"
        bomb += "item: [*l3]\n"
        openapi = "openapi: 3.0.3\nx-shared: &p {get: {}}\npaths:\n  /a: *p\n"
        for name, text in (("bomb.yaml", bomb), ("api.yaml", openapi)):
            with self.subTest(name=name), self.assertRaisesRegex(RouteSourceError, "aliases"):
                load_route_paths(self._write(name, text))

    def test_postman_walk_is_capped(self) -> None:
        with patch.object(route_sources, "MAX_NODES", 2), self.assertRaises(RouteSourceError):
            load_route_paths(self._write("c.json", POSTMAN))


def _serve(handler: type) -> http.server.ThreadingHTTPServer:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class RoutesFromCli(unittest.TestCase):
    def setUp(self) -> None:
        self.hits: list[str] = []
        hits = self.hits

        class App(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_GET(self) -> None:
                hits.append(self.path)
                self.send_response(404)
                self.end_headers()

        self.srv = _serve(App)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "ws"
        self.ws.mkdir()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def _file(self, name: str, content: object) -> str:
        p = Path(self.tmp.name) / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(p)

    def _run(self, *extra: str, env: dict | None = None) -> tuple[int, str, list[str]]:
        opened: list[str] = []
        real_open = urllib.request.OpenerDirector.open

        def spy(director: urllib.request.OpenerDirector, req: object, *a: object, **kw: object) -> object:
            opened.append(req.full_url if isinstance(req, urllib.request.Request) else str(req))
            return real_open(director, req, *a, **kw)

        err = io.StringIO()
        probe_env = {"PRUFGATE_BOLA_PATHS": "/api/known", "PRUFGATE_TEST_PROBE_TOKEN_A": "fixture-alpha", "PRUFGATE_TEST_PROBE_TOKEN_B": "fixture-bravo", **(env or {})}
        with patch.object(urllib.request.OpenerDirector, "open", spy), \
                patch.dict(os.environ, probe_env), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli_main(["bola", str(self.ws), "--url", self.url, *extra])
        return rc, err.getvalue(), opened

    def test_paths_join_onto_url_and_file_host_is_never_contacted(self) -> None:
        rc, err, opened = self._run("--routes-from", self._file("s.har", HAR), "--routes-from", self._file("c.json", POSTMAN))
        self.assertEqual(rc, 2, err)
        self.assertIn("/api/me", self.hits)
        self.assertIn("/api/health", self.hits)
        self.assertIn("/api/items", self.hits)
        self.assertNotIn("/api/me?session=abc", self.hits)
        self.assertTrue(opened)
        self.assertEqual({urllib.parse.urlsplit(u).hostname for u in opened}, {"127.0.0.1"})
        self.assertIn("skipped 2 other-method", err)

    def test_placeholder_paths_join_cross_tenant_probes(self) -> None:
        env = {"PRUFGATE_BOLA_PATHS": "/api/known", "PRUFGATE_CROSS_TENANT_PATHS": "/api/x/{tenant_id}",
               "PRUFGATE_TEST_PROBE_TOKEN_A": "probe_a", "PRUFGATE_TEST_PROBE_TOKEN_B": "probe_b",
               "PRUFGATE_TEST_PROBE_TENANT_B_ID": "tenant-b-2222"}
        rc, err, _ = self._run("--routes-from", self._file("c.json", POSTMAN), env=env)
        self.assertEqual(rc, 2, err)
        self.assertIn("/api/items/tenant-b-2222", self.hits)

    def test_dedupe_against_known_paths(self) -> None:
        har = {"log": {"entries": [{"request": {"method": "GET", "url": "https://app.example.com/api/known"}},
                                   {"request": {"method": "GET", "url": "https://app.example.com/api/known"}}]}}
        rc, err, _ = self._run("--routes-from", self._file("d.har", har))
        self.assertEqual(rc, 2, err)
        self.assertEqual(self.hits.count("/api/known"), 1)

    def test_cap(self) -> None:
        har = {"log": {"entries": [{"request": {"method": "GET", "url": f"https://app.example.com/api/r{i}"}}
                                   for i in range(5)]}}
        err_buf = io.StringIO()
        with patch.dict(os.environ, {"PRUFGATE_BOLA_PATHS": "/api/known", "PRUFGATE_TEST_PROBE_TOKEN_A": "fixture-alpha", "PRUFGATE_TEST_PROBE_TOKEN_B": "fixture-bravo"}), \
                contextlib.redirect_stdout(err_buf), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(bola_engine.ProbeIncomplete) as caught:
                bola_engine.run_dynamic_matrix(self.url, extra_paths=load_route_paths(self._file("c.har", har))[0],
                                           max_extra_paths=2)
        self.assertEqual(sorted(h for h in self.hits if h.startswith("/api/r")), ["/api/r0", "/api/r1"])
        self.assertIn("--max-routes", str(caught.exception))
        self.hits.clear()
        rc, err, _ = self._run("--routes-from", self._file("c.har", har), "--max-routes", "3")
        self.assertEqual(rc, 2, err)
        self.assertEqual(len([h for h in self.hits if h.startswith("/api/r")]), 3)

    def test_malformed_file_exits_2(self) -> None:
        for name, content in (("bad.json", "{not json: [}"), ("other.json", {"hello": "world"}), ("list.yaml", "- a\n- b\n")):
            rc, err, _ = self._run("--routes-from", self._file(name, content))
            self.assertEqual(rc, 2, name)
            self.assertIn(name, err)
        rc, err, _ = self._run("--routes-from", str(Path(self.tmp.name) / "missing.json"))
        self.assertEqual(rc, 2)
        self.assertEqual(self.hits, [])

    def test_directory_or_device_exits_2(self) -> None:
        for path in (self.tmp.name, "/dev/zero"):
            with self.subTest(path=path):
                rc, err, _ = self._run("--routes-from", path)
                self.assertEqual(rc, 2)
                self.assertIn("not a regular file", err)
        self.assertEqual(self.hits, [])

    def test_oversized_file_exits_2(self) -> None:
        big = self._file("big.json", b"{" + b" " * (5 * 1024 * 1024) + b"}")
        rc, err, _ = self._run("--routes-from", big)
        self.assertEqual(rc, 2)
        self.assertIn("5 MB", err)
        self.assertEqual(self.hits, [])


if __name__ == "__main__":
    unittest.main()
