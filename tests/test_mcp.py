"""Tests for the PrufGate MCP server: catalog, fail-closed tool results, and the
JSON-RPC 2.0 stdio loop (driven through a real subprocess)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PRUFGATE_ROOT = Path(__file__).resolve().parent.parent
if str(PRUFGATE_ROOT) not in sys.path:
    sys.path.insert(0, str(PRUFGATE_ROOT))

from prufgate import __version__  # noqa: E402
from prufgate.mcp import prufgate_mcp_server as mcp  # noqa: E402

# Hermetic: CI exports these on pull requests; a test that needs a base ref sets it.
for _ci_var in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF"):
    os.environ.pop(_ci_var, None)

TOOLS = {
    "prufgate_fast_scan", "prufgate_full_scan", "prufgate_anti_fabrication", "prufgate_test_audit",
    "prufgate_diff_guard", "prufgate_contract_check", "prufgate_bola_check", "prufgate_review", "prufgate_summary",
    "prufgate_explain",
}


def git(ws: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(ws), *args], check=True, capture_output=True)


class Catalog(unittest.TestCase):
    def test_catalog_lists_exactly_the_engine_tools(self):
        self.assertEqual({t["name"] for t in mcp.MCP_TOOLS}, TOOLS)

    def test_every_tool_declares_four_boolean_hints(self):
        for tool in mcp.MCP_TOOLS:
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                self.assertIsInstance(tool["annotations"][hint], bool, tool["name"])
                self.assertEqual(tool[hint], tool["annotations"][hint])
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertEqual(tool["inputSchema"]["type"], "object")
        open_world = {t["name"] for t in mcp.MCP_TOOLS if t["openWorldHint"]}
        self.assertEqual(open_world, {"prufgate_full_scan", "prufgate_bola_check"})


class Explain(unittest.TestCase):
    def test_explains_a_rule_without_a_workspace(self):
        tool = next(t for t in mcp.MCP_TOOLS if t["name"] == "prufgate_explain")
        self.assertEqual(set(tool["inputSchema"]["properties"]), {"rule"})
        self.assertEqual(tool["inputSchema"]["required"], ["rule"])
        res = mcp.handle_tool_call("prufgate_explain", {"rule": "anti-fabrication-canned-error-fallback"})
        self.assertEqual((res["status"], res["rule"]), ("ok", "canned-error-fallback"))
        self.assertIn("fix", res)

    def test_unknown_or_missing_rules(self):
        res = mcp.handle_tool_call("prufgate_explain", {"rule": "tautological-asertion"})
        self.assertEqual(res["status"], "error")
        self.assertIn("tautological-assertion", res["did_you_mean"])
        with self.assertRaises(mcp.ToolInputError):
            mcp.handle_tool_call("prufgate_explain", {})
        with self.assertRaises(mcp.ToolInputError):
            mcp.handle_tool_call("prufgate_explain", {"rule": "x", "workspace_path": "."})


class Tools(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        git(self.ws, "init", "-q")
        git(self.ws, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init")
        (self.ws / "src").mkdir()
        (self.ws / "src" / "main.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_workspace_is_an_input_error(self):
        with self.assertRaises(mcp.ToolInputError):
            mcp.prufgate_fast_scan(workspace_path=str(self.ws / "nope"))

    def test_clean_workspace_passes_every_engine_tool(self):
        for name in TOOLS - {"prufgate_summary", "prufgate_explain"}:
            res = mcp.handle_tool_call(name, {"workspace_path": str(self.ws)})
            self.assertEqual(res["status"], "ok", f"{name}: {res.get('error')}")
            self.assertTrue(res["passed"], name)

    def test_fabrication_is_reported_and_fails(self):
        (self.ws / "src" / "fake.ts").write_text('export function listUsers() {\n  throw new Error("TODO");\n}\n', encoding="utf-8")
        res = mcp.prufgate_anti_fabrication(workspace_path=str(self.ws))
        self.assertEqual(res["status"], "ok")
        self.assertFalse(res["passed"])
        self.assertGreaterEqual(res["blockers"], 1)

    def test_scans_do_not_write_into_the_workspace(self):
        mcp.prufgate_full_scan(workspace_path=str(self.ws))
        self.assertFalse((self.ws / "reports").exists())

    def test_engine_crash_is_an_error_not_a_pass(self):
        # Even with a parseable empty list on stdout, exit 2 is an error.
        crash = subprocess.CompletedProcess([], 2, stdout="[]", stderr="Traceback: boom")
        with patch.object(mcp.subprocess, "run", return_value=crash):
            res = mcp.prufgate_fast_scan(workspace_path=str(self.ws))
        self.assertEqual(res["status"], "error")
        self.assertFalse(res["passed"])
        self.assertIn("exited 2", res["error"])

    def test_missing_or_garbled_output_is_an_error(self):
        ok_no_output = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
        with patch.object(mcp.subprocess, "run", return_value=ok_no_output):
            self.assertEqual(mcp.prufgate_anti_fabrication(workspace_path=str(self.ws))["status"], "error")
            self.assertEqual(mcp.prufgate_fast_scan(workspace_path=str(self.ws))["status"], "error")

    def test_full_scan_runs_no_live_probe_without_target_url(self):
        calls = []
        real = subprocess.run

        def spy(cmd, *a, **kw):
            calls.append(cmd)
            return real(cmd, *a, **kw)

        with patch.object(mcp.subprocess, "run", side_effect=spy):
            res = mcp.prufgate_full_scan(workspace_path=str(self.ws))
        self.assertEqual(res["status"], "ok", res.get("error"))
        self.assertNotIn("bola_live", res["steps"])
        self.assertFalse(any("--url" in c for c in calls))

    def test_target_url_is_validated(self):
        for url in ("ftp://host/x", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"):
            with self.assertRaises(mcp.ToolInputError):
                mcp.prufgate_bola_check(workspace_path=str(self.ws), target_url=url)

    def test_unreachable_target_is_an_error(self):
        res = mcp.prufgate_bola_check(workspace_path=str(self.ws), target_url="http://127.0.0.1:9")
        self.assertEqual(res["status"], "error")
        self.assertFalse(res["passed"])

    def test_base_ref_cannot_smuggle_options(self):
        with self.assertRaises(mcp.ToolInputError):
            mcp.prufgate_diff_guard(workspace_path=str(self.ws), base_ref="--output=/tmp/x")

    def test_base_ref_that_does_not_exist_is_an_error(self):
        # Review item: base_ref "nope" returned ok/passed.
        for fn in (mcp.prufgate_diff_guard, mcp.prufgate_review):
            res = fn(workspace_path=str(self.ws), base_ref="nope")
            self.assertEqual(res["status"], "error", fn.__name__)
            self.assertFalse(res["passed"])
        res = mcp.prufgate_test_audit(workspace_path=str(self.ws), changed_only=True, base_ref="nope")
        self.assertEqual(res["status"], "error")

    def test_clean_tree_with_nothing_to_compare_is_an_error(self):
        (self.ws / "src" / "main.py").unlink()
        res = mcp.prufgate_diff_guard(workspace_path=str(self.ws))
        self.assertEqual(res["status"], "error")

    def test_ssrf_guard_resolves_numeric_and_mapped_forms(self):
        for url in ("http://2852039166/", "http://0xA9FEA9FE/", "http://[::ffff:169.254.169.254]/",
                    "http://metadata.google.internal./", "http://169.254.169.254./"):
            self.assertIsNotNone(mcp.validate_target_url(url), url)
        self.assertIsNone(mcp.validate_target_url("http://127.0.0.1:8080/"))

    def test_unknown_tool_and_argument(self):
        with self.assertRaises(ValueError):
            mcp.handle_tool_call("unknown_tool_xyz", {})
        with self.assertRaises(mcp.ToolInputError):
            mcp.handle_tool_call("prufgate_fast_scan", {"workspace_path": str(self.ws), "fix_mode": True})


class StdioProtocol(unittest.TestCase):
    def converse(self, *messages: str) -> list[dict]:
        proc = subprocess.run(
            [sys.executable, str(PRUFGATE_ROOT / "prufgate" / "mcp" / "prufgate_mcp_server.py")],
            input="\n".join(messages) + "\n", capture_output=True, text=True, timeout=120,
        )
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

    def test_initialize_list_ping_and_errors(self):
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "prufgate_summary", "arguments": {"workspace_path": "/does/not/exist"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "bogus"},
        ]
        out = self.converse(*(json.dumps(m) for m in msgs), "{not json")
        by_id = {r.get("id"): r for r in out}
        self.assertEqual(len(out), 7, out)  # no answer to the notification
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(by_id[1]["result"]["serverInfo"]["version"], __version__)
        self.assertEqual({t["name"] for t in by_id[2]["result"]["tools"]}, TOOLS)
        self.assertEqual(by_id[3]["result"], {})
        self.assertEqual(by_id[4]["error"]["code"], -32602)
        self.assertTrue(by_id[5]["result"]["isError"])
        self.assertEqual(by_id[6]["error"]["code"], -32601)
        self.assertEqual(by_id[None]["error"]["code"], -32700)

    def test_unknown_protocol_version_gets_the_newest(self):
        out = self.converse(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}))
        self.assertEqual(out[0]["result"]["protocolVersion"], mcp.SUPPORTED_PROTOCOL_VERSIONS[0])


if __name__ == "__main__":
    unittest.main()
