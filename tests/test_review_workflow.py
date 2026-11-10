"""Local review workflow: policies, exact dismissals, expiration and audit history."""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate import cli, dismissals, inline_ignore
from prufgate.api import server
from prufgate.config import ConfigError, PrufGateConfig
from prufgate.hooks.shell_guard import check_command
from prufgate.mcp import prufgate_mcp_server as mcp
from prufgate.pr_summary import Finding, Report, compare_reports, workflow_summary
from prufgate.process import git_command
from prufgate.report_formats import junit_xml
from prufgate.scan_result import attach_sarif, make_result, validate_result


def git(root, *args):
    return subprocess.run(git_command(*args), cwd=root, check=True, capture_output=True, text=True).stdout


def commit(root):
    git(root, "add", "-A")
    git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com", "commit", "-qm", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def finding():
    return {"rule": "unimplemented-production-stub", "file": "app.py", "line": 2, "severity": "P0", "confidence": "high", "message": "Production stub"}


class Ledger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q")
        (self.root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
        self.base = commit(self.root)

    def request(self):
        item = make_result([finding()], root=self.root)["findings"][0]
        return dismissals.append(self.root, "requested", "requester-role", "Intentional fixture behavior", finding=item, owner="owner-team", expires="2100-01-01")

    def approve(self, request):
        return dismissals.append(self.root, "approved", "reviewer-role", "Reviewed fixture exception", dismissal_id=request["id"])

    def test_review_is_inactive_until_committed_and_then_tracks_owner_and_audit(self):
        request = self.request()
        self.approve(request)
        pending = make_result([finding()], root=self.root)
        self.assertEqual(pending["governance"]["pending_changes"], 2)
        self.assertTrue(any(f["rule"] == finding()["rule"] for f in pending["findings"]))
        commit(self.root)
        result = validate_result(make_result([finding()], root=self.root))
        self.assertEqual(result["scan_status"], "clean")
        self.assertEqual(result["governance"]["dismissed"][0]["owner"], "owner-team")
        self.assertEqual(len(result["governance"]["audit"]), 2)

    def test_self_approval_and_invalid_state_transitions_are_refused(self):
        request = self.request()
        with self.assertRaises(dismissals.DismissalError):
            dismissals.append(self.root, "approved", "REQUESTER-ROLE", "Cannot self approve", dismissal_id=request["id"])
        with self.assertRaises(dismissals.DismissalError):
            dismissals.append(self.root, "revoked", "reviewer-role", "Not yet approved", dismissal_id=request["id"])

    def test_expiration_and_revocation_restore_the_finding(self):
        request = self.request()
        self.approve(request)
        commit(self.root)
        with patch.object(dismissals, "now", return_value=dt.datetime(2100, 1, 2, tzinfo=dt.timezone.utc)):
            result = make_result([finding()], root=self.root)
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["governance"]["states"][0]["state"], "expired")
        dismissals.append(self.root, "revoked", "reviewer-role", "The exception is no longer needed", dismissal_id=request["id"])
        commit(self.root)
        self.assertEqual(make_result([finding()], root=self.root)["exit_code"], 1)

    def test_changed_code_and_an_untrusted_branch_approval_cannot_hide_findings(self):
        request = self.request()
        self.approve(request)
        commit(self.root)
        result = make_result([finding()], root=self.root, coverage={"base_ref": self.base})
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["governance"]["dismissed"], [])
        (self.root / "app.py").write_text("def run():\n    raise NotImplementedError('changed')\n")
        self.assertEqual(make_result([finding()], root=self.root)["exit_code"], 1)

    def test_audit_tampering_is_a_fatal_error(self):
        self.request()
        path = self.root / dismissals.LEDGER
        data = json.loads(path.read_text())
        data["events"][0]["reason"] = "Rewritten history"
        path.write_text(json.dumps(data))
        result = make_result([finding()], root=self.root)
        self.assertEqual(result["scan_status"], "error")
        self.assertEqual(result["exit_code"], 2)

    def test_cli_request_and_review_are_explicit_local_operations(self):
        reports = self.root / "reports"
        reports.mkdir()
        path = reports / "result.json"
        path.write_text(json.dumps(make_result([finding()], root=self.root)))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["dismiss", "request", "--workspace", str(self.root), "--result", str(path),
                             "--owner", "owner-team", "--actor", "requester-role", "--reason", "Deliberate fixture behavior"])
        self.assertEqual(code, 0)
        uid = json.loads(output.getvalue())["id"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["dismiss", "approve", uid, "--workspace", str(self.root), "--actor", "reviewer-role", "--reason", "Reviewed by the owning team"]), 0)
        self.assertIsNotNone(check_command("prufgate dismiss approve fixture --actor reviewer --reason reviewed"))
        self.assertIsNone(check_command("prufgate dismiss list"))


class InlineOwnership(unittest.TestCase):
    def test_owner_and_expiration_are_audited_and_expired_ignores_do_not_suppress(self):
        for expires, expected in (("2100-01-01", True), ("2000-01-01", False), ("invalid", False)):
            with self.subTest(expires=expires), inline_ignore.recording() as audit:
                text = "# prufgate-" + f"ignore: fixture-rule -- Deliberate fixture [owner=owner-team; expires={expires}]"
                self.assertEqual(inline_ignore.suppressed([text], "fixture-rule", engine="fixture", path="app.py", line=1), expected)
                self.assertEqual(audit[0]["owner"], "owner-team")
                self.assertEqual(audit[0]["kind"], "honoured" if expected else "refused")

    def test_metadata_does_not_substitute_for_a_reason(self):
        text = "# prufgate-" + "ignore: fixture-rule -- [owner=owner-team]"
        self.assertFalse(inline_ignore.suppressed([text], "fixture-rule", engine="fixture", path="app.py", line=1))


class Policies(unittest.TestCase):
    def test_advisory_and_selected_policies_preserve_severity_and_errors_remain_fatal(self):
        for mode, rules, code in (("strict", [], 1), ("advisory", [], 0), ("selected", [finding()["rule"]], 1), ("selected", ["other-rule"], 0)):
            policy = {"mode": mode, "blocking_rules": rules, "minimum_confidence": "high"}
            result = validate_result(make_result([finding()], enforcement=policy))
            self.assertEqual(result["exit_code"], code)
            self.assertEqual(result["findings"][0]["severity"], "P0")
            self.assertEqual(make_result([finding()], enforcement=policy, errors=["Engine failed"])["exit_code"], 2)
        guard = {**finding(), "rule": "prufgate-config-self-exemption"}
        self.assertEqual(make_result([guard], enforcement={"mode": "advisory", "blocking_rules": [], "minimum_confidence": "low"})["exit_code"], 1)

    def test_bad_policy_configuration_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".prufgate").mkdir()
            for value in ("mode: unknown", "mode: selected\n  blocking_rules: ['*']", "minimum_confidence: guessed"):
                (root / ".prufgate/config.yaml").write_text("enforcement:\n  " + value + "\n")
                with self.subTest(value=value), self.assertRaises(ConfigError):
                    PrufGateConfig.load(root)

    def test_swapped_blocking_flags_cannot_pass_result_validation(self):
        result = make_result([finding(), {**finding(), "rule": "advisory-rule", "severity": "P2"}])
        result["findings"][0]["blocking"] = False
        result["findings"][1]["blocking"] = True
        with self.assertRaises(ValueError):
            validate_result(result)

    def test_advisory_policy_is_consistent_in_cli_mcp_api_and_junit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / ".prufgate").mkdir()
            (root / ".prufgate/config.yaml").write_text("enforcement:\n  mode: advisory\n")
            commit(root)
            (root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(["check", tmp, "--changed", "--base", "HEAD", "--format", "result"])
            self.assertEqual(code, 0)
            result = validate_result(json.loads(out.getvalue()))
            self.assertEqual(result["summary"]["blockers"], 0)
            self.assertEqual(result["findings"][0]["severity"], "P0")
            doc = attach_sarif(cli._sarif_findings_doc(result["findings"], root), result)
            self.assertIn('failures="0"', junit_xml(doc))
            with patch.dict(os.environ, {"PRUFGATE_BASE_REF": "HEAD"}):
                tool = mcp.prufgate_fast_scan(tmp, "HEAD")
                self.assertTrue(tool["passed"])
                with patch.dict(server.SCANS, {"fixture": {"status": "queued", "profile": "core"}}, clear=True):
                    server.execute_scan_worker("fixture", "fast", tmp, None)
                    self.assertEqual(server.SCANS["fixture"]["exit_code"], 0)
                    self.assertEqual(server.SCANS["fixture"]["summary"], result["summary"])

    def test_pending_approval_is_reported_once_in_cli_mcp_and_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / "README.md").write_text("fixture\n")
            commit(root)
            (root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
            item = make_result([finding()], root=root)["findings"][0]
            request = dismissals.append(root, "requested", "requester-role", "Intentional fixture behavior", finding=item, owner="owner-team")
            dismissals.append(root, "approved", "reviewer-role", "Reviewed fixture exception", dismissal_id=request["id"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["check", tmp, "--changed", "--base", "HEAD", "--format", "result"])
            result = validate_result(json.loads(out.getvalue()))
            rules = [f["rule"] for f in result["findings"]]
            self.assertEqual(rules.count("prufgate-config-self-exemption"), 1)
            with patch.dict(os.environ, {"PRUFGATE_BASE_REF": "HEAD"}):
                tool = mcp.prufgate_fast_scan(tmp, "HEAD")
                self.assertEqual(tool["summary"], result["summary"])
                self.assertEqual(tool["total_findings"], result["summary"]["total_findings"])
                with patch.dict(server.SCANS, {"fixture": {"status": "queued", "profile": "core"}}, clear=True):
                    server.execute_scan_worker("fixture", "fast", tmp, None)
                    scan = server.SCANS["fixture"]
                    self.assertEqual(scan["summary"], result["summary"])
                    self.assertEqual(sum(scan["findings_summary"].values()), result["summary"]["total_findings"])

    def test_mcp_full_scan_and_engine_tool_report_the_pending_approval_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / "README.md").write_text("fixture\n")
            commit(root)
            (root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
            item = make_result([finding()], root=root)["findings"][0]
            request = dismissals.append(root, "requested", "requester-role", "Intentional fixture behavior", finding=item, owner="owner-team")
            dismissals.append(root, "approved", "reviewer-role", "Reviewed fixture exception", dismissal_id=request["id"])
            with patch.dict(os.environ, {"PRUFGATE_BASE_REF": "HEAD"}):
                for tool in (mcp.prufgate_full_scan(tmp, "HEAD"), mcp.prufgate_anti_fabrication(tmp)):
                    with self.subTest(tool=tool["tool"]):
                        rules = [f["rule"] for f in tool["findings"]]
                        self.assertEqual(rules.count("prufgate-config-self-exemption"), 1, rules)
                        self.assertIn("unimplemented-production-stub", rules)
                        self.assertEqual(tool["total_findings"], tool["summary"]["total_findings"])
                        self.assertEqual(tool["summary"]["total_findings"], len(tool["findings"]))

    def test_result_formats_of_bola_and_test_audit_honour_config(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            custom = Path(other) / "custom.yaml"
            custom.write_text("enforcement:\n  mode: advisory\n")
            for argv in (["bola", tmp, "--static-only"], ["test-audit", tmp]):
                with self.subTest(command=argv[0]), contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()):
                    cli.main([*argv, "--format", "result", "--config", str(custom)])
                self.assertEqual(json.loads(out.getvalue())["enforcement"]["mode"], "advisory")

    def test_check_config_file_sets_the_enforcement_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / "README.md").write_text("fixture\n")
            commit(root)
            (root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
            with tempfile.TemporaryDirectory() as other:
                custom = Path(other) / "custom.yaml"
                custom.write_text("enforcement:\n  mode: advisory\n")
                for args, code in (([], 1), (["--config", str(custom)], 0)):
                    with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as out:
                        self.assertEqual(cli.main(["check", tmp, "--changed", "--base", "HEAD", "--format", "result", *args]), code)
                    self.assertEqual(json.loads(out.getvalue())["enforcement"]["mode"], "advisory" if args else "strict")

    def test_summary_distinguishes_new_existing_and_unknown_debt(self):
        old = Report([Finding("rule", "P1", "app.py", 2, "old", "stable")])
        new = Report([Finding("rule", "P1", "app.py", 8, "moved", "stable"), Finding("new-rule", "P1", "other.py", 1, "new", "new")])
        comparison = compare_reports(new, old)
        self.assertEqual(comparison, {"available": True, "new": 1, "existing": 1, "resolved": 0})
        result = make_result([finding()], errors=["A check failed"])
        body = workflow_summary(result, comparison)
        self.assertIn("New findings: **1**", body)
        self.assertIn("Existing debt: **unknown**", body)
        self.assertIn("Repair the failed inputs", body)

    def test_review_formats_apply_the_trusted_advisory_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            (root / ".prufgate").mkdir()
            (root / ".prufgate/config.yaml").write_text("enforcement:\n  mode: advisory\n")
            (root / "app.py").write_text("import requests\n")
            base = commit(root)
            (root / "app.py").write_text("import requests\nrequests.get('https://example.com', verify=False)\n")
            for fmt in ("result", "json", "sarif", "markdown", "junit"):
                with self.subTest(format=fmt), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = cli.main(["review", "--workspace", tmp, "--base", base, "--format", fmt])
                self.assertEqual(code, 0)
                text = out.getvalue()
                if fmt == "result":
                    result = validate_result(json.loads(text))
                    self.assertTrue(result["findings"])
                    self.assertEqual(result["summary"]["blockers"], 0)
                    self.assertTrue(all(not f["blocking"] for f in result["findings"]))
                elif fmt == "json":
                    self.assertTrue(all(not f["blocking"] for f in json.loads(text)))
                elif fmt == "sarif":
                    self.assertTrue(all(not f["properties"]["blocking"] for f in json.loads(text)["runs"][0]["results"]))
                elif fmt == "junit":
                    self.assertIn('failures="0"', text)
                else:
                    self.assertIn("TLS", text)


if __name__ == "__main__":
    unittest.main()
