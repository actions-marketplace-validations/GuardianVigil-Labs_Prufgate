"""runners/run_ast_lint.sh: repository hooks are opt-in, ast-grep failures are errors."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "runners" / "run_ast_lint.sh"


def run(ws: Path, extra_env: dict[str, str] | None = None, path_prefix: str = "") -> list[dict]:
    env = {k: v for k, v in os.environ.items() if k not in ("PRUFGATE_ALLOW_REPO_HOOKS", "PRUFGATE_REPORTS_DIR")}
    env.update({"TOOL_ROOT": str(ROOT), "WORKSPACE": str(ws), **(extra_env or {})})
    if path_prefix:
        env["PATH"] = path_prefix + os.pathsep + env["PATH"]
    subprocess.run(["bash", str(RUNNER)], cwd=ws, env=env, capture_output=True, text=True, timeout=60, check=False)
    manifest = ws / "reports" / "raw" / "execution_manifest.jsonl"
    return [json.loads(line) for line in manifest.read_text().splitlines()] if manifest.exists() else []


@unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
class AstRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / ".prufgate" / "hooks").mkdir(parents=True)
        (self.ws / ".prufgate" / "hooks" / "evil.sh").write_text("touch \"$WORKSPACE/hook-ran\"\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_repository_hooks_do_not_run_by_default(self):
        entries = run(self.ws)
        self.assertFalse((self.ws / "hook-ran").exists(), "a scanned repository's hook ran without opt-in")
        self.assertIn(("repo-hooks", "skipped"), [(e["tool"], e["status"]) for e in entries])

    def test_repository_hooks_run_when_the_operator_opts_in(self):
        run(self.ws, {"PRUFGATE_ALLOW_REPO_HOOKS": "1"})
        self.assertTrue((self.ws / "hook-ran").exists())

    def test_a_failing_hook_is_recorded_as_an_error(self):
        (self.ws / ".prufgate" / "hooks" / "evil.sh").write_text("exit 3\n")
        entries = run(self.ws, {"PRUFGATE_ALLOW_REPO_HOOKS": "1"})
        hook = [e for e in entries if e["tool"] == "hook:evil.sh"]
        self.assertEqual((hook[0]["status"], hook[0]["exit_code"]), ("error", 3))

    def test_broken_ast_grep_output_is_an_error_not_a_pass(self):
        bin_dir = self.ws / "fakebin"
        bin_dir.mkdir()
        fake = bin_dir / "ast-grep"
        fake.write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "ast-grep 0.0.0" && exit 0\necho "not json"; exit 1\n')
        fake.chmod(0o755)
        (self.ws / "package.json").write_text("{}")
        entries = run(self.ws, path_prefix=str(bin_dir))
        sg = [e for e in entries if e["tool"] == "ast-grep"]
        self.assertEqual(sg[0]["status"], "error")
        self.assertGreaterEqual(sg[0]["exit_code"], 2)

    def test_an_ast_grep_rule_that_fails_to_run_is_an_error(self):
        # Real ast-grep prints nothing on stdout and exits 8 for an invalid rule.
        bin_dir = self.ws / "fakebin"
        bin_dir.mkdir()
        fake = bin_dir / "ast-grep"
        fake.write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "ast-grep 0.0.0" && exit 0\necho "bad rule" >&2; exit 8\n')
        fake.chmod(0o755)
        (self.ws / "package.json").write_text("{}")
        entries = run(self.ws, path_prefix=str(bin_dir))
        sg = [e for e in entries if e["tool"] == "ast-grep"]
        self.assertEqual(sg[0]["status"], "error")

    def test_ast_grep_matches_are_not_an_error(self):
        bin_dir = self.ws / "fakebin"
        bin_dir.mkdir()
        fake = bin_dir / "ast-grep"
        fake.write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "ast-grep 0.0.0" && exit 0\necho "[{\\"ruleId\\": \\"x\\"}]"; exit 1\n')
        fake.chmod(0o755)
        (self.ws / "package.json").write_text("{}")
        entries = run(self.ws, path_prefix=str(bin_dir))
        sg = [e for e in entries if e["tool"] == "ast-grep"]
        self.assertEqual(sg[0]["status"], "executed")
        self.assertEqual(len(json.loads((self.ws / "reports" / "raw" / "ast_grep.json").read_text())), 1)

    def test_opinionated_rules_are_opt_in_examples(self):
        built_in = {p.name for p in (ROOT / "configs" / "ast-grep" / "rules").glob("*.yml")}
        self.assertEqual(built_in, {"action-authorization-guard.yml"})
        examples = {p.name for p in (ROOT / "configs" / "ast-grep" / "examples").glob("*.yml")}
        self.assertTrue({"db-pool-isolation.yml", "go-egress.yml"} <= examples)


if __name__ == "__main__":
    unittest.main()
