"""The same result contract for CLI, Action, MCP and REST scans."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate import cli
from prufgate.api import server
from prufgate.bola import bola_engine
from prufgate.coverage import Coverage, recording
from prufgate.mcp import prufgate_mcp_server as mcp
from prufgate.process import git_command
from prufgate.result_validation import read_json
from prufgate.safe_fs import safe_read_text
from prufgate.scan_result import ai_privacy, attach_sarif, make_result, validate_result
from prufgate.synthesizer import parse_results as synth

ROOT = Path(__file__).resolve().parent.parent


def finding(**overrides):
    return {"rule": "unimplemented-production-stub", "engine": "anti-fabrication", "severity": "P0",
            "file": "app.py", "line": 2, "message": "Production stub", **overrides}


def git(root, *args):
    subprocess.run(git_command(*args), cwd=root, capture_output=True, check=True)


class ResultContract(unittest.TestCase):
    def test_status_and_exit_policy_include_advisories_and_partial_findings(self):
        for items, errors, incomplete, state, code in (
            ([], [], [], "clean", 0), ([finding()], [], [], "findings", 1),
            ([finding(severity="P2")], [], [], "findings", 0),
            ([finding()], [], ["owner controls unavailable"], "incomplete", 2),
            ([finding()], ["engine crashed"], [], "error", 2),
            ([], ["engine crashed"], ["probe incomplete"], "error", 2),
        ):
            with self.subTest(state=state, code=code):
                result = make_result(items, errors=errors, incomplete=incomplete)
                self.assertEqual(result["scan_status"], state)
                self.assertEqual(result["exit_code"], code)
                self.assertEqual(validate_result(result), result)
                self.assertEqual(result["passed"], code == 0)
                self.assertEqual(len(result["findings"]), len(items))

    def test_status_cannot_disagree_with_findings(self):
        result = make_result([finding()])
        for key, value in (("scan_status", "clean"), ("passed", True), ("exit_code", 0), ("summary", {})):
            changed = {**result, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_result(changed)
        for key, value in (("exit_code", True), ("coverage", {"files_checked": "one"}), ("errors", "failure")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_result({**result, key: value})

    def test_evidence_is_redacted_and_has_explanation_fix_and_caveats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = 'def handler():\n    password = "' + "fixture-private-value" + '"\n    raise NotImplementedError\n'
            (root / "app.py").write_text(source)
            item = make_result([finding(line=3)], root=root)["findings"][0]
            self.assertIn("[redacted]", item["evidence"]["code"])
            self.assertNotIn("fixture-private-value", json.dumps(item))
            self.assertIn("Implement", item["explanation"]["suggested_fix"])
            self.assertTrue(item["explanation"]["reasoning"])
            self.assertTrue(item["explanation"]["could_be_incorrect_when"])
            hidden = make_result([finding(snippet=source)], root=root, include_code=False)["findings"][0]
            self.assertIsNone(hidden["evidence"]["code"])
            self.assertNotIn("snippet", hidden)
            secret = make_result([finding(engine="gitleaks")], root=root)["findings"][0]
            self.assertIsNone(secret["evidence"]["code"])

    def test_coverage_records_reads_without_retaining_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("a = 1\nb = 2\n")
            trace = Coverage(root)
            with recording(trace):
                trace.step("fixture")
                safe_read_text(root / "app.py")
                safe_read_text(root / "app.py")
            result = trace.to_dict()
            self.assertEqual((result["files_checked"], result["lines_checked"]), (1, 2))
            self.assertNotIn("a = 1", json.dumps(result))
            self.assertEqual(result["engines"][0]["status"], "completed")

    def test_default_privacy_manifest_and_custom_ai_endpoint(self):
        self.assertFalse(ai_privacy()["external_ai"]["enabled"])
        with patch.dict(os.environ, {"OPENAI_BASE_URL": "https://service.example/v1?credential=fixture"}):
            info = ai_privacy(True, "openai", "review")["external_ai"]
        self.assertEqual(info["provider"], "openai")
        self.assertNotIn("credential", info["destination"])
        self.assertIn("diff", info["content"])
        self.assertIn("Best effort", info["redaction"])

    def test_cli_error_is_structured_and_does_not_look_like_zero_findings_passed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["check", "/nonexistent-prufgate-fixture", "--format", "result"])
        result = validate_result(read_json(output.getvalue()))
        self.assertEqual(code, 2)
        self.assertEqual(result["scan_status"], "error")
        self.assertFalse(result["passed"])

    def test_cli_and_mcp_preserve_confirmed_findings_on_incomplete_probe(self):
        partial = bola_engine.BolaFinding("BOLA-CROSS-TENANT-ACCESS", "P0", "Confirmed other resource", "/api/resource")
        with tempfile.TemporaryDirectory() as tmp, patch.object(bola_engine, "check_server_active", return_value=True), \
                patch.object(bola_engine, "run_static_matrix_audit", return_value=[]), \
                patch.object(bola_engine, "run_dynamic_matrix", side_effect=bola_engine.ProbeIncomplete("One control failed", [partial], {"failed": 1})), \
                patch("prufgate.netguard.target_url_error", return_value=None):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(["bola", tmp, "--url", "https://example.com", "--format", "result"])
            result = validate_result(read_json(output.getvalue()))
            self.assertEqual(code, 2)
            proc = subprocess.CompletedProcess([], 2, stdout=json.dumps(result), stderr="incomplete")
            with patch.object(mcp.subprocess, "run", return_value=proc):
                items, error = mcp._run_json([str(mcp.CLI), "bola"], Path(tmp), stdout_json=True)
            shared = mcp._result("prufgate_bola_check", Path(tmp), items, error)
            self.assertEqual(shared["scan_status"], "incomplete")
            self.assertEqual(len(shared["findings"]), 1)
            self.assertFalse(shared["passed"])

    def test_api_preserves_incomplete_state_from_sarif_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = make_result([finding()], root=root, incomplete=["A requested control failed."])
            sarif = attach_sarif(cli._sarif_findings_doc(result["findings"], root), result)
            def run(scan_id, cmd, cwd, env):
                (Path(env["PRUFGATE_REPORTS_DIR"]) / "prufgate.sarif").write_text(json.dumps(sarif))
                return 2, "", "incomplete"
            with patch.dict(server.SCANS, {"fixture": {"status": "queued"}}, clear=True), \
                    patch.object(server, "run_scan_process", side_effect=run):
                server.execute_scan_worker("fixture", "full", tmp, None)
                record = server.SCANS["fixture"]
                self.assertEqual(record["scan_status"], "incomplete")
                self.assertEqual(record["exit_code"], 2)
                self.assertFalse(record["passed"])
                self.assertEqual(len(record["findings"]), 1)

    def test_failed_gate_replaces_the_previous_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com", "commit", "--allow-empty", "-qm", "fixture")
            reports = root / "reports"
            raw = reports / "raw"
            raw.mkdir(parents=True)
            (raw / "base_ref").write_text("missing-fixture-base")
            path = reports / "prufgate-result.json"
            path.write_text(json.dumps(make_result([])))
            with patch.dict(os.environ, {"WORKSPACE": tmp, "PRUFGATE_REPORTS_DIR": str(reports)}), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                synth.main()
            self.assertEqual(stopped.exception.code, 2)
            result = validate_result(read_json(path.read_text()))
            self.assertEqual(result["scan_status"], "error")
            self.assertFalse(result["passed"])

    def test_single_engine_cli_commands_emit_the_common_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            for command in ("test-audit", "bola", "review"):
                output = io.StringIO()
                args = [command, "--workspace", tmp] if command == "review" else [command, tmp]
                with self.subTest(command=command), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    code = cli.main([*args, "--format", "result"])
                result = validate_result(read_json(output.getvalue()))
                self.assertEqual(code, result["exit_code"])
                self.assertIn(result["scan_status"], ("clean", "error"))


class IntegrationConsistency(unittest.TestCase):
    def scan(self, root, *args):
        env = {**os.environ, "PRUFGATE_BASE_REF": "HEAD", "PRUFGATE_NO_AI_ADJUDICATE": "1"}
        return subprocess.run([sys.executable, "-I", str(ROOT / "prufgate/cli.py"), "check", str(root), *args],
                              cwd=root, env=env, capture_output=True, text=True, timeout=30)

    def identity(self, result):
        return sorted((f["file"], f["line"], f["rule"], f["severity"]) for f in result["findings"])

    def test_equivalent_core_cli_mcp_and_api_scans_match(self):
        for source in ("def add(a, b):\n    return a + b\n", "def add(a, b):\n    raise NotImplementedError\n"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                git(root, "init", "-q")
                git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com", "commit", "--allow-empty", "-qm", "fixture")
                (root / "app.py").write_text(source)
                proc = self.scan(root, "--changed", "--base", "HEAD", "--format", "result")
                expected = validate_result(read_json(proc.stdout))
                with patch.dict(os.environ, {"PRUFGATE_BASE_REF": "HEAD"}):
                    tools = mcp.prufgate_fast_scan(str(root), "HEAD")
                    with patch.dict(server.SCANS, {"fixture": {"scan_id": "fixture", "status": "queued", "profile": "core"}}, clear=True):
                        server.execute_scan_worker("fixture", "fast", tmp, None)
                        api = dict(server.SCANS["fixture"])
                for name, actual in (("MCP", tools), ("API", api)):
                    self.assertEqual(actual["scan_status"], expected["scan_status"], name)
                    self.assertEqual(actual["exit_code"], expected["exit_code"], name)
                    self.assertEqual(actual["summary"], expected["summary"], name)
                    self.assertEqual(self.identity(actual), self.identity(expected), name)
                    self.assertEqual(actual["coverage"]["files"], expected["coverage"]["files"], name)

    @unittest.skipIf(sys.platform == "win32", "the Action runner requires a POSIX shell")
    def test_action_core_profile_matches_the_real_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com", "commit", "--allow-empty", "-qm", "fixture")
            (root / "app.py").write_text("def add(a, b):\n    raise NotImplementedError\n")
            expected = read_json(self.scan(root, "--changed", "--format", "result").stdout)
            output = root / "action-output"
            env = {**os.environ, "ACTION_PATH": str(ROOT), "GITHUB_WORKSPACE": tmp, "GITHUB_OUTPUT": str(output),
                   "PRUFGATE_PROFILE": "core", "PRUFGATE_EXECUTION": "native", "PRUFGATE_BATTERY": "fast",
                   "PRUFGATE_BASE_REF": "HEAD", "FAIL_ON_BLOCKER": "true", "ALLOW_EXTERNAL_AI": "false"}
            proc = subprocess.run(["bash", str(ROOT / "scripts/run_action.sh")], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            actual = validate_result(read_json((root / "reports/prufgate-result.json").read_text()))
            self.assertEqual(self.identity(actual), self.identity(expected))
            self.assertEqual(actual["scan_status"], expected["scan_status"])
            self.assertIn("scan_status=findings", output.read_text())


if __name__ == "__main__":
    unittest.main()
