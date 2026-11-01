"""Unit tests for PrufGate Review Synthesizer (prufgate/synthesizer/parse_results.py).
Tests all 6 core engine parsers, cross-engine deduplication, baseline filtering,
execution manifest integration, and GitHub SARIF 2.1.0 URI normalization.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PRUFGATE_ROOT = Path(__file__).resolve().parent.parent
if str(PRUFGATE_ROOT) not in sys.path:
    sys.path.insert(0, str(PRUFGATE_ROOT))

from prufgate.config import GitDiffError
from prufgate.synthesizer.parse_results import (
    Finding,
    deduplicate_findings,
    filter_baseline_findings,
    generate_markdown,
    generate_sarif,
    load_execution_manifest,
    parse_raw_results,
)


class SynthesizerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        self.raw_dir = self.ws / "reports" / "raw"
        self.raw_dir.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parses_all_six_core_engines_and_accelerators(self):
        # Engine 1: anti-fabrication
        (self.raw_dir / "anti_fabrication.json").write_text(
            json.dumps([{"file": "src/api.ts", "line": 12, "rule": "canned-error-fallback", "snippet": "return { ok: true }"}]),
            encoding="utf-8",
        )
        # Engine 2: test-integrity
        (self.raw_dir / "test_integrity.json").write_text(
            json.dumps([{"file": "tests/api.test.ts", "line": 4, "rule": "zero-assertion-test", "severity": "P0", "message": "Zero assertions"}]),
            encoding="utf-8",
        )
        # Engine 3: diff-guard
        (self.raw_dir / "diff_guard.json").write_text(
            json.dumps([{"file": "tests/api.test.ts", "line": 10, "rule": "test-skip-smuggling", "severity": "P0", "message": "Unjustified skip"}]),
            encoding="utf-8",
        )
        # Engine 4: contract-guard
        (self.raw_dir / "contract_guard.json").write_text(
            json.dumps([{"file": "src/index.ts", "line": 1, "rule": "undeclared-or-hallucinated-import", "severity": "P1", "message": "Ghost package"}]),
            encoding="utf-8",
        )
        # Engine 5: bola-matrix
        (self.raw_dir / "bola_matrix.json").write_text(
            json.dumps([{"target": "src/routes.py", "line": 22, "rule_id": "BOLA-ID-QUERY-WITHOUT-TENANT-CONSTRAINT", "severity": "P0", "message": "Missing tenant filter"}]),
            encoding="utf-8",
        )
        # Engine 6: pr-reviewer
        (self.raw_dir / "pr_review.json").write_text(
            json.dumps([{"file": "src/db.ts", "line": 30, "title": "SQL Injection Vector", "severity": "P0", "message": "Interpolated query"}]),
            encoding="utf-8",
        )
        # Optional Gitleaks
        (self.raw_dir / "gitleaks.json").write_text(
            json.dumps([{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "src/config.ts", "StartLine": 5, "Match": "KEY=***"}]),
            encoding="utf-8",
        )
        # Optional Zizmor
        (self.raw_dir / "zizmor.json").write_text(
            json.dumps([{"ident": "unpinned-uses", "desc": "unpinned action reference", "determinations": {"severity": "High"}}]),
            encoding="utf-8",
        )

        findings = parse_raw_results(self.raw_dir)
        tools = {f.tool for f in findings}
        self.assertEqual(
            tools,
            {"anti-fabrication", "test-integrity", "diff-guard", "contract-guard", "bola-matrix", "pr-reviewer", "gitleaks", "zizmor"},
        )
        zizmor_finding = next(f for f in findings if f.tool == "zizmor")
        self.assertEqual(zizmor_finding.severity, "P2")

    def test_deduplication_merges_overlapping_findings(self):
        f1 = Finding(
            tool="ast-grep",
            rule_id="server-action-auth-guard",
            severity="P2",
            message="Missing guard",
            file_path="/workspace/src/actions.ts",
            line=25,
        )
        f2 = Finding(
            tool="pr-reviewer",
            rule_id="pr-server-action-missing-authorization-guard",
            severity="P1",
            message="Missing guard",
            file_path="src/actions.ts",
            line=25,
        )
        deduped = deduplicate_findings([f1, f2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, "P1")
        self.assertIn("Also detected by: pr-reviewer", deduped[0].details)

    def test_sarif_paths_are_relative_through_a_symlinked_workspace(self):
        """macOS temporary folders are /var/... -> /private/var/...: a finding's absolute path and the
        workspace can name the same folder in either spelling, and still give a relative URI."""
        from prufgate.synthesizer.parse_results import _normalize_sarif_uri

        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real"
            real.mkdir()
            link = Path(d) / "link"
            link.symlink_to(real, target_is_directory=True)
            for ws in (real, link):
                for f in (real / "src" / "app.py", link / "src" / "app.py"):
                    self.assertEqual(_normalize_sarif_uri(str(f), ws), "src/app.py", (ws, f))
            self.assertEqual(_normalize_sarif_uri("src\\app.py", real), "src/app.py")

    def test_baseline_suppression_supports_yaml_and_json_schemas(self):
        (self.ws / ".prufgate").mkdir(exist_ok=True)
        (self.ws / ".prufgate" / "baseline.yaml").write_text(
            "ignore:\n"
            "  - file_path: src/legacy.ts\n"
            "    rule: undocumented-env-var-drift\n"
            "  - file: src/only_this_file.ts\n",
            encoding="utf-8",
        )
        findings = [
            Finding(tool="contract-guard", rule_id="undocumented-env-var-drift", severity="P2", message="Env", file_path="src/legacy.ts", line=10),
            Finding(tool="contract-guard", rule_id="undocumented-env-var-drift", severity="P2", message="Env", file_path="src/active.ts", line=10),
        ]
        filtered = filter_baseline_findings(findings, self.ws)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].file_path, "src/active.ts")

    def _git(self, *args: str) -> None:
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=self.ws, check=True, capture_output=True)

    def test_baseline_is_read_at_the_base_ref(self):
        """A change that baselines its own finding: with a base ref the branch's baseline is ignored."""
        self._git("init", "-q", "-b", "main")
        (self.ws / "README.md").write_text("notes\n")
        self._git("add", "README.md")
        self._git("commit", "-qm", "base")
        self._git("checkout", "-qb", "feature")
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "baseline.yaml").write_text("- {file: src/app.py, rule: unimplemented-production-stub}\n")
        self._git("add", ".prufgate")
        self._git("commit", "-qm", "feature")
        found = [Finding(tool="anti-fabrication", rule_id="unimplemented-production-stub", severity="P0", message="x", file_path="src/app.py")]
        self.assertEqual(filter_baseline_findings(found, self.ws), [])
        self.assertEqual(len(filter_baseline_findings(found, self.ws, "main")), 1)
        with self.assertRaises(GitDiffError):
            filter_baseline_findings(found, self.ws, "no-such-ref")
        # The gate: the finding stays, a P2 notice says the baseline was ignored, and a bad base exits 2.
        env = {**os.environ, "WORKSPACE": str(self.ws), "PRUFGATE_REPORTS_DIR": str(self.ws / "reports"), "NO_COLOR": "1"}
        (self.raw_dir / "anti_fabrication.json").write_text(json.dumps([{"rule": "unimplemented-production-stub", "file": "src/app.py", "line": 1, "text": "x"}]))
        (self.raw_dir / "execution_manifest.jsonl").write_text(
            json.dumps({"tool": "anti-fabrication", "status": "executed", "exit_code": 1, "duration_seconds": 1.0, "note": ""}) + "\n"
            + "".join(
                json.dumps({"tool": t, "status": "skipped", "exit_code": 0, "duration_seconds": 0.0, "note": "test"}) + "\n"
                for t in ("test-integrity", "diff-guard", "contract-guard", "bola-matrix", "pr-reviewer")
            )
        )
        script = str(PRUFGATE_ROOT / "prufgate" / "synthesizer" / "parse_results.py")
        (self.raw_dir / "base_ref").write_text("main\n")
        res = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        sarif = (self.ws / "reports" / "prufgate.sarif").read_text()
        self.assertIn("prufgate-config-not-applied", sarif)
        self.assertIn("unimplemented-production-stub", sarif)
        # The entry the branch adds is itself a blocking self-exemption.
        added = [r for run in json.loads(sarif)["runs"] for r in run["results"] if r["ruleId"] == "prufgate-config-self-exemption"]
        self.assertEqual([r["properties"]["severity"] for r in added], ["P1"])
        (self.raw_dir / "base_ref").write_text("no-such-ref\n")
        res = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        # A changed scan of the working-tree diff (empty base): the baseline is the one committed at HEAD.
        self._git("checkout", "-q", "main")
        self.assertFalse((self.ws / ".prufgate" / "baseline.yaml").exists())
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "baseline.yaml").write_text("- {file: src/app.py, rule: unimplemented-production-stub}\n")
        (self.raw_dir / "base_ref").write_text("\n")
        res = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("unimplemented-production-stub", (self.ws / "reports" / "prufgate.sarif").read_text())

    def test_sarif_normalization_and_manifest_markdown(self):
        manifest_path = self.raw_dir / "execution_manifest.jsonl"
        manifest_path.write_text(
            json.dumps({"tool": "anti-fabrication", "status": "executed", "exit_code": 0, "duration_seconds": 1.0, "note": "changed files"}) + "\n"
            + json.dumps({"tool": "gitleaks", "status": "skipped", "exit_code": 0, "duration_seconds": 0.0, "note": "gitleaks binary not found"}) + "\n"
            + json.dumps({"tool": "bola-matrix", "status": "executed", "exit_code": 2, "duration_seconds": 1.0, "note": "config error"}) + "\n",
            encoding="utf-8",
        )
        manifest = load_execution_manifest(self.raw_dir)
        self.assertEqual(manifest["anti-fabrication"]["status"], "executed")
        self.assertEqual(manifest["gitleaks"]["detail"], "gitleaks binary not found")
        self.assertEqual(manifest["bola-matrix"]["exit_code"], 2)

        findings = [
            Finding(
                tool="bola-matrix",
                rule_id="BOLA-CROSS-TENANT-READ",
                severity="P0",
                message="Dynamic endpoint flaw",
                file_path="http://127.0.0.1:3000/api/v1/projects/2",
                line=0,
            ),
            Finding(
                tool="anti-fabrication",
                rule_id="demo-named-data",
                severity="P0",
                message="Fake constant",
                file_path="/workspace/./src/app.py",
                line=14,
            ),
        ]

        sarif_out = self.ws / "reports" / "prufgate.sarif"
        generate_sarif(findings, sarif_out, workspace_dir=self.ws)
        sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
        results = sarif_data["runs"][0]["results"]
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "PRUFGATE_DYNAMIC_TARGET")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertEqual(results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.py")

        md_out = self.ws / "reports" / "prufgate-review.md"
        generate_markdown(findings, Path("/nonexistent/template.md"), md_out, manifest=manifest)
        md_text = md_out.read_text(encoding="utf-8")
        self.assertIn("`anti-fabrication`", md_text)
        self.assertIn("⚪ SKIPPED (gitleaks binary not found)", md_text)


if __name__ == "__main__":
    unittest.main()
