"""Invented regressions for complete, correctly scoped scan results."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate import inline_ignore
from prufgate.anti_fabrication import detector
from prufgate.api import server
from prufgate.bola import bola_engine as bola
from prufgate.cli import main as cli_main
from prufgate.contract_guard.route_contract import scan_file_route_contracts
from prufgate.diff_guard.tamper_detector import scan_diff_for_tampering
from prufgate.gitleaks_policy import materialize
from prufgate.process import git_command
from prufgate.result_validation import InvalidResult, validate_findings, validate_sarif
from prufgate.review import ai_adapter, reviewer
from prufgate.synthesizer import parse_results as synth

ROOT = Path(__file__).resolve().parent.parent
IGNORE = "prufgate-" "ignore"


def git(root: Path, *args: str) -> str:
    return subprocess.run(git_command(*args), cwd=root, text=True, capture_output=True, check=True).stdout


def commit(root: Path) -> str:
    git(root, "add", "-A")
    git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com", "commit", "-qm", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def sarif(results=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": results or []}]}


class Scope(unittest.TestCase):
    def test_committed_staged_unstaged_and_untracked_are_all_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            for name in ("branch.py", "staged.py", "unstaged.py"):
                (root / name).write_text("value = 1\n")
            base = commit(root)
            (root / "branch.py").write_text("value = 2\n")
            commit(root)
            (root / "staged.py").write_text("value = 3\n")
            git(root, "add", "staged.py")
            (root / "unstaged.py").write_text("value = 4\n")
            (root / "new.py").write_text("value = 5\n")
            wanted = {"branch.py", "staged.py", "unstaged.py", "new.py"}
            self.assertEqual(set(detector.changed_files(base, root)), wanted)
            diff = reviewer.get_git_diff(base, root, strict=True)
            self.assertEqual({h["file"] for h in reviewer.parse_diff_hunks(diff)}, wanted)


class OutputValidation(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "requires the POSIX shell runner")
    def test_bad_trusted_policy_stops_gitleaks_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / ".gitleaks.toml").write_text("[invalid toml")
            commit(root)
            binaries = root / "fixture-bin"
            binaries.mkdir()
            executable = binaries / "gitleaks"
            executable.write_text("#!/bin/sh\nexit 99\n")
            executable.chmod(0o700)
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""))
            for key in ("PRUFGATE_BASE_REF", "GITHUB_BASE_REF", "TARGET_URL", "PRUFGATE_REPORTS_DIR"):
                env.pop(key, None)
            proc = subprocess.run(["bash", str(ROOT / "prufgate.sh"), "full", str(root)],
                                  capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            manifest = synth.load_execution_manifest(root / "reports" / "raw")
            self.assertEqual(manifest["gitleaks"]["status"], "error")
            self.assertEqual(manifest["gitleaks"]["exit_code"], 2)

    def test_invalid_json_shapes_cannot_pass_as_engine_output(self):
        for data in (None, {}, {"findings": None}, [None], [{}], [{"rule": "r", "line": "1"}], [{"rule": "r", "severity": "unknown"}]):
            with self.subTest(data=data), self.assertRaises(InvalidResult):
                validate_findings(data, "anti-fabrication")
        self.assertEqual(validate_findings([], "anti-fabrication"), [])

    def test_invalid_sarif_is_not_a_clean_scan(self):
        samples = [{}, None, {"version": "2.1.0", "runs": []},
                   {"version": "2.1.0", "runs": [{"results": []}]},
                   sarif([{}]), sarif([{"message": {"text": "finding"}, "properties": []}])]
        failed = sarif()
        failed["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        samples.append(failed)
        for value in samples:
            with self.subTest(value=value), self.assertRaises(InvalidResult):
                validate_sarif(value)
        self.assertEqual(validate_sarif(sarif()), sarif())

    def test_synthesizer_checks_schema_and_external_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp)
            manifest = {tool: {"status": "skipped", "exit_code": 0} for tool in synth.CORE_ENGINES}
            manifest["anti-fabrication"] = {"status": "executed", "exit_code": 0}
            (raw / "anti_fabrication.json").write_text("null")
            self.assertIn("anti-fabrication", synth.engine_errors(raw, manifest))
            (raw / "anti_fabrication.json").write_text("[]")
            for tool, code in (("gitleaks", 2), ("ast-grep", 6), ("zizmor", 1), ("anti-fabrication", -9)):
                with self.subTest(tool=tool):
                    manifest[tool] = {"status": "executed", "exit_code": code}
                    (raw / synth.ENGINE_OUTPUTS[tool]).write_text("[]")
                    self.assertIn(tool, synth.engine_errors(raw, manifest))
                    manifest[tool] = {"status": "skipped", "exit_code": 0}

    def test_api_refuses_structurally_invalid_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            def run(scan_id, cmd, cwd, env):
                (Path(env["PRUFGATE_REPORTS_DIR"]) / "prufgate.sarif").write_text("{}")
                return 0, "", ""
            with patch.dict(server.SCANS, {"fixture": {"status": "queued"}}, clear=True), \
                    patch.object(server, "run_scan_process", side_effect=run):
                server.execute_scan_worker("fixture", "full", tmp, None)
                result = server.SCANS["fixture"]
                self.assertEqual(result["verdict"], "ERROR")
                self.assertIsNone(result["blockers"])

    def test_api_never_calls_a_blocking_report_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = sarif([{"message": {"text": "fixture finding"}, "properties": {"severity": "P0"}}])
            def run(scan_id, cmd, cwd, env):
                (Path(env["PRUFGATE_REPORTS_DIR"]) / "prufgate.sarif").write_text(json.dumps(report))
                return 0, "", ""
            with patch.dict(server.SCANS, {"fixture": {"status": "queued"}}, clear=True), \
                    patch.object(server, "run_scan_process", side_effect=run):
                server.execute_scan_worker("fixture", "full", tmp, None)
                result = server.SCANS["fixture"]
                self.assertEqual(result["verdict"], "ERROR")
                self.assertEqual(result["blockers"], 1)

    def test_partial_live_findings_survive_an_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp)
            item = {"rule_id": "BOLA-CROSS-TENANT-ACCESS", "severity": "P0", "target": "/api/resource", "line": 1}
            (raw / "bola_matrix.json").write_text(json.dumps({"status": "incomplete", "findings": [item]}))
            findings = synth.parse_raw_results(raw)
            self.assertEqual(len(findings), 1)
            self.assertEqual(synth.scope_to_change(findings, {"src/app.py": [(1, 1)]}, raw), findings)
            manifest = {tool: {"status": "skipped", "exit_code": 0} for tool in synth.CORE_ENGINES}
            manifest["bola-matrix"] = {"status": "executed", "exit_code": 2}
            self.assertIn("bola-matrix", synth.engine_errors(raw, manifest))


class CommentAwareness(unittest.TestCase):
    def test_literals_cannot_suppress_findings(self):
        snippets = [("a.ts", f'const note = "{IGNORE}: all -- documented";'),
                    ("a.tsx", f'<button title="{IGNORE}: all -- documented" onClick={{() => {{}}}}>Save</button>'),
                    ("a.py", f'note = """\n# {IGNORE}: all -- documented\n"""'),
                    ("a.ts", f'const r = /[//] {IGNORE}: all -- documented/;')]
        for path, text in snippets:
            for n in range(1, len(text.splitlines()) + 1):
                with self.subTest(path=path, line=n):
                    self.assertFalse(inline_ignore.suppressed_at(text.splitlines(), n, "r", engine="e", path=path))
        self.assertTrue(inline_ignore.suppressed_at([f'code(); // {IGNORE}: r -- intentional'], 1, "r", engine="e", path="a.ts"))

    def test_multiline_comments_preserve_locations_and_real_calls(self):
        text = "/* fetch('/api/missing')\n axios.get('/api/missing') */\n" + \
               'const example = "fetch(\'/api/missing\')";\n' + "fetch('/api/existing');\nfetch('/api/missing');\n"
        findings = scan_file_route_contracts(Path("ui.ts"), "ui.ts", text, {"/api/existing": {"GET"}})
        self.assertEqual([f.line for f in findings], [5])


class AICompleteness(unittest.TestCase):
    def test_malformed_responses_are_errors_and_valid_empty_arrays_are_clean(self):
        for reply in ("", "not JSON", "{}", '{"findings":[]}', "[null]", "[{}]", '[{"file":"a.py","title":"t","message":"m","line":true}]'):
            with self.subTest(reply=reply), patch.object(ai_adapter, "detect_ai_provider", return_value="openai"), \
                    patch.object(ai_adapter, "_invoke_http_llm", return_value=(True, reply)):
                self.assertEqual(ai_adapter.review_diff_with_ai("+code").status, "error")
        with patch.object(ai_adapter, "detect_ai_provider", return_value="openai"), \
                patch.object(ai_adapter, "_invoke_http_llm", return_value=(True, "[]")):
            self.assertEqual(ai_adapter.review_diff_with_ai("+code").status, "executed")

    def test_oversized_diff_is_not_silently_truncated(self):
        with patch.object(ai_adapter, "detect_ai_provider", return_value="openai"), \
                patch.object(ai_adapter, "_invoke_http_llm") as invoke:
            result = ai_adapter.review_diff_with_ai("+" + "x" * 24000)
            self.assertEqual(result.status, "error")
            self.assertIn("limit", result.note)
            invoke.assert_not_called()

    def test_explicit_ai_failure_does_not_pass_review(self):
        diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+value = 1\n"
        with patch.object(reviewer, "review_diff_with_ai", return_value=ai_adapter.AIReviewResult("fixture", "error", [], "invalid response")), \
                self.assertRaises(reviewer.DiffUnavailableError):
            reviewer.run_hybrid_review(diff, enable_ai=True)


class TrustedSecretPolicy(unittest.TestCase):
    def test_working_policy_and_extended_policy_cannot_weaken_this_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / ".gitleaks.toml").write_text('[extend]\npath = "extra.toml"\n')
            (root / "extra.toml").write_text('[extend]\nuseDefault = true\n# trusted fixture\n')
            base = commit(root)
            (root / "extra.toml").write_text('[extend]\nuseDefault = false\n# changed fixture\n')
            (root / ".gitleaks.toml").write_text('[extend]\nuseDefault = false\n')
            path = materialize(root, root / "raw", ROOT / "configs/gitleaks.toml", base)
            self.assertEqual(path.name, "gitleaks.base-0.toml")
            self.assertIn("gitleaks.base-1.toml", path.read_text())
            self.assertIn('"useDefault" = true', (root / "raw/gitleaks.base-1.toml").read_text())
            self.assertNotIn('"useDefault" = false', (root / "raw/gitleaks.base-1.toml").read_text())
            diff = git(root, "diff", "HEAD")
            self.assertTrue(any(f.rule == "prufgate-config-self-exemption" for f in scan_diff_for_tampering(diff)))

    def test_toml_include_spellings_are_materialized_safely(self):
        for spelling in ('extend.path = "shared.toml"\n', '["extend"]\n"path" = "shared.toml"\n',
                         '[extend] # documented include\npath = "shared.toml"\n'):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                git(root, "init", "-q")
                (root / ".gitleaks.toml").write_text(spelling)
                (root / "shared.toml").write_text('[extend]\nuseDefault = true\n')
                commit(root)
                (root / "shared.toml").write_text('[extend]\nuseDefault = false\n')
                materialize(root, root / "reports/raw", ROOT / "configs/gitleaks.toml")
                self.assertIn('"useDefault" = true', (root / "reports/raw/gitleaks.base-1.toml").read_text())

    @unittest.skipUnless(shutil.which("gitleaks"), "requires the optional Gitleaks binary")
    def test_real_gitleaks_does_not_lose_inherited_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "policy").mkdir()
            (root / ".gitleaks.toml").write_text('[extend]\npath = "policy/extra.toml"\n')
            (root / "policy/extra.toml").write_text('[extend]\npath = "shared.toml"\n')
            (root / "shared.toml").write_text('[[rules]]\nid="fixture-rule"\nregex="PROJ-[0-9]{12}"\n')
            (root / "input.txt").write_text("PROJ-123456789012")
            config = materialize(root, root / "reports/raw", ROOT / "configs/gitleaks.toml")
            output = root / "reports/result.json"
            result = subprocess.run(["gitleaks", "dir", "--no-banner", "--redact=100", "--config", str(config),
                                     "--report-format", "json", "--report-path", str(output), str(root)],
                                    cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            findings = json.loads(output.read_text())
            self.assertEqual({item["RuleID"] for item in findings}, {"fixture-rule"})
            self.assertEqual({str(Path(item["File"]).relative_to(root)) if Path(item["File"]).is_absolute() else item["File"] for item in findings}, {"input.txt"})


class LiveMatrix(unittest.TestCase):
    def run_matrix(self, mode="deny", failure=False):
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}
            def __init__(self, data):
                self.data = data
            def read(self):
                return json.dumps(self.data).encode()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        class Opener:
            def open(self, req, timeout):
                if failure:
                    raise TimeoutError("invented timeout")
                token = req.get_header("Authorization", "")
                if not token:
                    raise bola.urllib.error.HTTPError(req.full_url, 401, "unauthenticated", {}, None)
                owner = "tenant-a-1111" if token.endswith("fixture-alpha") else "tenant-b-2222"
                target = req.full_url.rsplit("/", 1)[-1]
                if owner != target and mode == "deny":
                    raise bola.urllib.error.HTTPError(req.full_url, 403, "denied", {}, None)
                return Response({"resource": owner if mode == "self" else target})
        env = {"PRUFGATE_TEST_PROBE_TOKEN_A": "fixture-alpha", "PRUFGATE_TEST_PROBE_TOKEN_B": "fixture-bravo",
               "PRUFGATE_BOLA_PATHS": "/api/private", "PRUFGATE_CROSS_TENANT_PATHS": "/api/{tenant_id}",
               "PRUFGATE_TEST_PROBE_TENANT_A_ID": "tenant-a-1111", "PRUFGATE_TEST_PROBE_TENANT_B_ID": "tenant-b-2222"}
        with patch.dict(os.environ, env), patch.object(bola, "target_url_error", return_value=None), \
                patch.object(bola, "discover_workspace_api_routes", return_value=[]), \
                patch.object(bola.urllib.request, "build_opener", return_value=Opener()), \
                contextlib.redirect_stdout(io.StringIO()):
            return bola.run_dynamic_matrix("https://example.com")

    def test_denied_and_self_scoped_resources_are_not_bola(self):
        self.assertEqual(self.run_matrix(), [])
        self.assertEqual(self.run_matrix("self"), [])

    def test_real_cross_tenant_data_is_confirmed_in_both_directions(self):
        findings = self.run_matrix("leak")
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule_id == "BOLA-CROSS-TENANT-ACCESS" for f in findings))

    def test_transport_failure_is_structured_incomplete(self):
        with self.assertRaises(bola.ProbeIncomplete) as caught:
            self.run_matrix(failure=True)
        result = caught.exception.to_dict()
        self.assertEqual(result["status"], "incomplete")
        self.assertGreater(result["coverage"]["failed"], 0)

    def test_missing_tokens_cannot_report_clean(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(bola, "target_url_error", return_value=None), self.assertRaises(bola.ProbeIncomplete) as caught:
            bola.run_dynamic_matrix("https://example.com")
        self.assertEqual(caught.exception.coverage["attempted"], 0)

    def test_cli_unreachable_target_returns_incomplete_json(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bola, "check_server_active", return_value=False), \
                patch.object(bola, "run_static_matrix_audit", return_value=[]), \
                patch("prufgate.netguard.target_url_error", return_value=None):
            output, diagnostic = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostic):
                code = cli_main(["bola", tmp, "--url", "https://example.com", "--format", "json"])
            self.assertEqual(code, 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["coverage"]["failed"], 1)

    def test_standalone_incomplete_output_write_failure_still_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bola, "check_server_active", return_value=False), \
                patch.object(bola, "target_url_error", return_value=None), \
                patch.object(bola, "run_static_matrix_audit", return_value=[]), \
                patch.object(bola, "safe_write_text", side_effect=OSError("fixture write failure")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bola.main(["--workspace", tmp, "--target", "https://example.com"]), 2)


if __name__ == "__main__":
    unittest.main()
