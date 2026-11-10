"""Regression tests for the gate runner, synthesizer, CLI, config loader and
agent hooks: a crashed engine is never a pass, CI scans what the pull request
changed, and the CLI works from any directory."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


from prufgate import cli  # noqa: E402
from prufgate.config import ConfigError, PrufGateConfig, path_matches_pattern  # noqa: E402
from prufgate.hooks.agent_hooks import HOOK_COMMAND, HookConfigError, init_workspace  # noqa: E402
from tests.support import installed_python

# Hermetic: CI exports these on pull requests; a test that needs a base ref sets it.
for _ci_var in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF"):
    os.environ.pop(_ci_var, None)


def synth_core() -> set[str]:
    from prufgate.synthesizer.parse_results import CORE_ENGINES
    return set(CORE_ENGINES)


FABRICATED_TS = 'export function listUsers() {\n  throw new Error("TODO: list users");\n}\n'


def git(ws: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(ws), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   check=True, capture_output=True)


def repo_with_committed_change() -> tempfile.TemporaryDirectory:
    """A clean checkout of a branch whose last commit adds fabricated data,
    as a CI runner sees a pull request."""
    tmp = tempfile.TemporaryDirectory()
    ws = Path(tmp.name)
    git(ws, "init", "-q", "-b", "main")
    (ws / "src").mkdir()
    (ws / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "init")
    git(ws, "checkout", "-qb", "feature")
    (ws / "src" / "users.ts").write_text(FABRICATED_TS, encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "feature")
    return tmp


def run_gate(ws: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ, **(env or {}))
    for k in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF", "TARGET_URL", "WORKSPACE", "PRUFGATE_REPORTS_DIR"):
        if not env or k not in env:
            full_env.pop(k, None)
    full_env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + full_env.get("PATH", "")
    return subprocess.run(["bash", str(ROOT / "prufgate.sh"), *args], cwd=tempfile.gettempdir(),
                          capture_output=True, text=True, env=full_env, timeout=300)


class Synthesizer(unittest.TestCase):
    """BUG-01: an engine that crashed or wrote no readable output is an ERROR (exit 2)."""

    def synth(self, manifest: list[dict], files: dict[str, str]) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "reports" / "raw"
            raw.mkdir(parents=True)
            (raw / "execution_manifest.jsonl").write_text("".join(json.dumps(m) + "\n" for m in manifest))
            for name, text in files.items():
                (raw / name).write_text(text)
            env = dict(os.environ, WORKSPACE=tmp, PRUFGATE_REPORTS_DIR=str(Path(tmp) / "reports"))
            proc = subprocess.run([sys.executable, str(ROOT / "prufgate" / "synthesizer" / "parse_results.py")],
                                  capture_output=True, text=True, env=env, cwd=tmp)
            md = (Path(tmp) / "reports" / "prufgate-review.md").read_text(encoding="utf-8")
            if proc.returncode == 2:
                self.assertIn("ERROR", md)
            return proc.returncode

    def entry(self, tool: str, code: int, status: str = "executed") -> dict:
        return {"tool": tool, "status": status, "exit_code": code}

    def full(self, *entries: dict) -> list[dict]:
        """A manifest where every core engine reported; `entries` override."""
        given = {e["tool"] for e in entries}
        rest = [{"tool": t, "status": "skipped", "exit_code": 0, "note": "n/a"} for t in sorted(synth_core() - given)]
        return [*entries, *rest]

    def test_core_engine_missing_from_manifest_is_an_error(self):
        # Review item: a gate killed after engine 1 left a partial manifest that passed.
        self.assertEqual(self.synth([self.entry("anti-fabrication", 0)], {"anti_fabrication.json": "[]"}), 2)

    def test_engine_exit_2_is_an_error(self):
        self.assertEqual(self.synth([self.entry("anti-fabrication", 2)], {"anti_fabrication.json": "[]"}), 2)

    def test_missing_output_is_an_error(self):
        self.assertEqual(self.synth([self.entry("test-integrity", 0)], {}), 2)

    def test_malformed_output_is_an_error(self):
        self.assertEqual(self.synth([self.entry("diff-guard", 0)], {"diff_guard.json": "{not json"}), 2)

    def test_no_manifest_is_an_error(self):
        self.assertEqual(self.synth([], {}), 2)

    def test_runner_recorded_error_is_an_error(self):
        self.assertEqual(self.synth([self.entry("base-ref", 2, status="error")], {}), 2)

    def test_clean_and_findings(self):
        self.assertEqual(self.synth(self.full(self.entry("anti-fabrication", 0)), {"anti_fabrication.json": "[]"}), 0)
        finding = json.dumps([{"rule": "unimplemented-production-stub", "file": "a.ts", "line": 1}])
        self.assertEqual(self.synth(self.full(self.entry("anti-fabrication", 1)), {"anti_fabrication.json": finding}), 1)

    def test_skipped_optional_tool_is_not_an_error(self):
        manifest = self.full(self.entry("anti-fabrication", 0), {"tool": "gitleaks", "status": "skipped", "exit_code": 0})
        self.assertEqual(self.synth(manifest, {"anti_fabrication.json": "[]"}), 0)

    def test_reports_are_not_written_through_symlinks(self):
        # Review item: a repo committing reports/prufgate-review.md -> elsewhere had it overwritten.
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            victim = Path(outside) / "victim.txt"
            victim.write_text("keep me")
            raw = Path(tmp) / "reports" / "raw"
            raw.mkdir(parents=True)
            (raw / "execution_manifest.jsonl").write_text("".join(json.dumps(m) + "\n" for m in self.full()))
            (Path(tmp) / "reports" / "prufgate-review.md").symlink_to(victim)
            env = dict(os.environ, WORKSPACE=tmp, PRUFGATE_REPORTS_DIR=str(Path(tmp) / "reports"))
            subprocess.run([sys.executable, str(ROOT / "prufgate" / "synthesizer" / "parse_results.py")],
                           capture_output=True, env=env, cwd=tmp)
            self.assertEqual(victim.read_text(), "keep me")
            self.assertFalse((Path(tmp) / "reports" / "prufgate-review.md").is_symlink())


@unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
class Gate(unittest.TestCase):
    def setUp(self):
        self._tmp = repo_with_committed_change()
        self.ws = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_fast_scans_committed_changes_on_a_clean_checkout(self):
        # BUG-02: `--changed` with no base ref used to scan nothing in CI.
        proc = run_gate(self.ws, "fast", str(self.ws))  # BUG-04: positional workspace, other cwd
        self.assertEqual(proc.returncode, 1, proc.stdout[-2000:] + proc.stderr[-2000:])
        findings = json.loads((self.ws / "reports" / "raw" / "anti_fabrication.json").read_text())
        self.assertTrue(any(f["file"].endswith("users.ts") for f in findings))

    def test_workspace_under_a_symlinked_parent_is_scanned(self):
        # macOS /tmp and /home -> /var/home put a link above the workspace; it is not the repository's.
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link"
            link.symlink_to(self.ws.parent)
            proc = run_gate(self.ws, "fast", str(link / self.ws.name))
            self.assertEqual(proc.returncode, 1, proc.stdout[-2000:] + proc.stderr[-2000:])
            self.assertTrue((self.ws / "reports" / "prufgate.sarif").stat().st_size > 0)

    def test_github_base_ref_is_used(self):
        git(self.ws, "update-ref", "refs/remotes/origin/main", "main")
        proc = run_gate(self.ws, "fast", str(self.ws), env={"GITHUB_BASE_REF": "main"})
        self.assertEqual(proc.returncode, 1, proc.stdout[-2000:])
        self.assertIn("base: origin/main", proc.stdout)

    def test_missing_base_ref_is_an_error_not_a_pass(self):
        proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_BASE_REF": "origin/does-not-exist"})
        self.assertEqual(proc.returncode, 2, proc.stdout[-2000:])

    def test_option_shaped_base_ref_is_refused(self):
        proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_BASE_REF": "--output=/tmp/x"})
        self.assertEqual(proc.returncode, 2)

    def test_full_scan_hands_the_synthesizer_the_base_ref(self):
        # The synthesizer reads ai_adjudicate (and the baseline) at the base in a full scan too.
        run_gate(self.ws, "full", str(self.ws))
        self.assertEqual((self.ws / "reports" / "raw" / "base_ref").read_text().strip(), "HEAD~1")

    def test_crashing_engine_fails_the_gate(self):
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("packs: [no-such-pack]\n")
        proc = run_gate(self.ws, "full", str(self.ws))
        self.assertEqual(proc.returncode, 2, proc.stdout[-2000:])
        self.assertIn("VERDICT: ERROR", proc.stdout)

    def test_unreachable_target_url_is_an_error(self):
        # BUG-05: the runner passed a flag the BOLA engine rejects, hidden by >/dev/null.
        proc = run_gate(self.ws, "full", str(self.ws), env={"TARGET_URL": "http://127.0.0.1:9"})
        self.assertEqual(proc.returncode, 2, proc.stdout[-2000:])
        self.assertIn("bola-matrix", proc.stdout)

    def test_clean_default_branch_does_not_compare_with_itself(self):
        # Review item: origin/HEAD == HEAD gave an empty diff that passed.
        git(self.ws, "update-ref", "refs/remotes/origin/feature", "HEAD")
        git(self.ws, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/feature")
        proc = run_gate(self.ws, "fast", str(self.ws))
        self.assertEqual(proc.returncode, 1, proc.stdout[-2000:])
        self.assertIn("base: HEAD~1", proc.stdout)

    def test_shallow_clone_without_a_base_is_an_error(self):
        # Review item: a depth-1 clone with no usable base scanned an empty diff and passed.
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "clone"
            subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.ws}", str(clone)], check=True, capture_output=True)
            git(clone, "remote", "set-head", "origin", "-d")
            proc = run_gate(clone, "fast", str(clone))
            self.assertEqual(proc.returncode, 2, proc.stdout[-2000:])
            self.assertIn("base-ref", proc.stdout)

    def test_full_scope_without_git_skips_only_the_diff_engines(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "users.ts").write_text(FABRICATED_TS)
            proc = run_gate(Path(tmp), "full", tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout[-2000:])
            manifest = [json.loads(x) for x in (Path(tmp) / "reports" / "raw" / "execution_manifest.jsonl").read_text().splitlines()]
            status = {m["tool"]: m["status"] for m in manifest}
            self.assertEqual(status["diff-guard"], "skipped")
            self.assertEqual(status["pr-reviewer"], "skipped")
            self.assertEqual(status["anti-fabrication"], "executed")

    def test_changed_scope_without_git_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(run_gate(Path(tmp), "fast", tmp).returncode, 2)

    def test_symlinked_reports_dir_is_refused(self):
        # Review item: `rm -rf reports/raw/*` through a committed symlink deletes files elsewhere.
        with tempfile.TemporaryDirectory() as outside:
            keep = Path(outside) / "raw" / "keep.txt"
            keep.parent.mkdir()
            keep.write_text("keep")
            (self.ws / "reports").symlink_to(outside)
            proc = run_gate(self.ws, "fast", str(self.ws))
            self.assertEqual(proc.returncode, 2)
            self.assertTrue(keep.exists())

    def test_reports_dir_with_a_trailing_slash_or_dot_dot_is_refused(self):
        # `[ -L dir/ ]` follows the link, so a trailing slash bypassed the symlink refusal.
        with tempfile.TemporaryDirectory() as outside:
            keep = Path(outside) / "raw" / "keep.txt"
            keep.parent.mkdir()
            keep.write_text("keep")
            (self.ws / "reports").symlink_to(outside)
            for value in (f"{self.ws}/reports/", f"{self.ws}/x/../reports"):
                with self.subTest(value=value):
                    proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_REPORTS_DIR": value})
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn("PRUFGATE_REPORTS_DIR", proc.stderr)
                    self.assertTrue(keep.exists())

    def test_reports_dir_through_a_workspace_symlink_is_refused(self):
        # `[ -L reports/. ]` does not see the link, and a link in a parent directory
        # was never checked: both wrote reports outside the workspace.
        (self.ws / "nested").mkdir()
        for link, value in (("reports", f"{self.ws}/reports/."), ("nested/out", f"{self.ws}/nested/out/reports"),
                            # A doubled leading slash once skipped the symlink walk.
                            ("nested/out", f"/{self.ws}/nested/out/reports"), ("reports", "reports/.")):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as outside:
                keep = Path(outside) / "raw" / "keep.txt"
                keep.parent.mkdir()
                keep.write_text("keep")
                (Path(outside) / "reports" / "raw").mkdir(parents=True)
                before = sorted(p.relative_to(outside) for p in Path(outside).rglob("*"))
                (self.ws / link).symlink_to(outside)
                try:
                    proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_REPORTS_DIR": value})
                finally:
                    (self.ws / link).unlink()
                self.assertEqual(proc.returncode, 2)
                self.assertTrue(keep.exists())
                self.assertEqual(sorted(p.relative_to(outside) for p in Path(outside).rglob("*")), before)

    def test_reports_dir_inside_the_workspace_must_be_the_default(self):
        for value in (f"{self.ws}/out", f"{self.ws}/reports/sub", "out", str(self.ws)):
            with self.subTest(value=value):
                proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_REPORTS_DIR": value})
                self.assertEqual(proc.returncode, 2)
                self.assertIn("must be", proc.stderr)
                self.assertFalse((self.ws / "out").exists())

    def test_default_reports_dir_spelled_otherwise_is_used(self):
        for value in (f"{self.ws}/reports", f"/{self.ws}/reports/", "reports"):
            with self.subTest(value=value):
                proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_REPORTS_DIR": value})
                self.assertEqual(proc.returncode, 1, proc.stdout[-2000:] + proc.stderr[-2000:])
                self.assertTrue((self.ws / "reports" / "prufgate.sarif").stat().st_size > 0)

    def test_reports_dir_outside_the_workspace_is_used(self):
        with tempfile.TemporaryDirectory() as outside:
            reports = Path(outside) / "a" / "reports"
            proc = run_gate(self.ws, "fast", str(self.ws), env={"PRUFGATE_REPORTS_DIR": str(reports)})
            self.assertEqual(proc.returncode, 1, proc.stdout[-2000:] + proc.stderr[-2000:])
            self.assertTrue((reports / "prufgate.sarif").stat().st_size > 0)
            self.assertFalse((self.ws / "reports").exists())

    def test_symlinked_raw_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as outside:
            keep = Path(outside) / "keep.txt"
            keep.write_text("keep")
            (self.ws / "reports").mkdir()
            (self.ws / "reports" / "raw").symlink_to(outside)
            proc = run_gate(self.ws, "fast", str(self.ws))
            self.assertEqual(proc.returncode, 2)
            self.assertTrue(keep.exists())

    def test_workspace_must_exist(self):
        self.assertEqual(run_gate(self.ws, "fast", str(self.ws / "nope")).returncode, 2)


class Cli(unittest.TestCase):
    def setUp(self):
        self._tmp = repo_with_committed_change()
        self.ws = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *args: str, cwd: Path | None = None) -> tuple[int, str]:
        out = io.StringIO()
        prev = Path.cwd()
        os.chdir(cwd or tempfile.gettempdir())
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = cli.main(list(args))
        finally:
            os.chdir(prev)
        return rc, out.getvalue()

    def test_check_changed_from_another_directory(self):
        # BUG-04: git ran in the shell's directory, not the workspace.
        (self.ws / "src" / "new.ts").write_text('export function listItems() {\n  throw new Error("TODO: list items");\n}\n')
        rc, out = self.run_cli("check", str(self.ws), "--changed", "--format", "json")
        self.assertEqual(rc, 1)
        files = {f["file"] for f in json.loads(out)}
        self.assertIn("src/new.ts", files)  # workspace-relative, not absolute

    def test_check_base_ref_and_fast_alias(self):
        rc, out = self.run_cli("fast", str(self.ws), "--base", "main", "--format", "json")
        self.assertEqual(rc, 1)
        self.assertIn("src/users.ts", {f["file"] for f in json.loads(out)})

    def test_aliased_rules_are_one_finding(self):
        rc, out = self.run_cli("full", str(self.ws), "--format", "json")
        keys = [(f["file"], f["line"]) for f in json.loads(out) if f["engine"] == "anti-fabrication"]
        self.assertEqual(len(keys), len(set(keys)))

    def test_a_projects_own_tests_test_cli_is_scanned(self):
        # BUG-07 (cli part): PrufGate skipped any tests/test_cli.py as if it were its own.
        (self.ws / "tests").mkdir()
        (self.ws / "tests" / "test_cli.py").write_text("from src.app import add\n\ndef test_add():\n    add(1, 2)\n")
        rc, out = self.run_cli("check", str(self.ws), "--format", "json")
        self.assertIn("tests/test_cli.py", {f["file"] for f in json.loads(out)})

    def test_engine_crash_exits_2(self):
        with patch.object(cli.bola_engine, "run_static_matrix_audit", side_effect=RuntimeError("boom")):
            rc, _ = self.run_cli("check", str(self.ws))
        self.assertEqual(rc, 2)

    def test_known_debt_ceiling_is_applied(self):
        # MED-01: `prufgate check` ignored known_debt ceilings.
        (self.ws / ".prufgate").mkdir()
        cfg = self.ws / ".prufgate" / "config.yaml"
        cfg.write_text("known_debt:\n  unimplemented-production-stub: 5\n")
        rc, out = self.run_cli("check", str(self.ws), "--format", "json")
        self.assertNotIn("unimplemented-production-stub", {f["rule"] for f in json.loads(out)})
        cfg.write_text("known_debt:\n  unimplemented-production-stub: 0\n")
        rc, out = self.run_cli("check", str(self.ws), "--format", "json")
        self.assertEqual(rc, 1)
        self.assertIn("debt-ceiling-breached", {f["rule"] for f in json.loads(out)})

    def test_stop_hook_active_does_not_block_twice(self):
        # MED-03: the Stop hook must honour stop_hook_active or the agent loops forever.
        (self.ws / "src" / "new.ts").write_text('export function listItems() {\n  throw new Error("TODO: list items");\n}\n')
        base = [sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", str(self.ws), "--changed", "--format", "agent-hook"]
        first = subprocess.run(base, input="{}", capture_output=True, text=True)
        again = subprocess.run(base, input=json.dumps({"stop_hook_active": True}), capture_output=True, text=True)
        self.assertEqual(first.returncode, 2)
        self.assertEqual(again.returncode, 0)
        self.assertIn("TODO: list items", again.stderr)

    def test_agent_hook_errors_block_unless_stop_hook_active(self):
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("packs: [no-such-pack]\n")
        base = [sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", str(self.ws), "--changed", "--format", "agent-hook"]
        self.assertEqual(subprocess.run(base, input="{}", capture_output=True, text=True).returncode, 2)
        again = subprocess.run(base, input='{"stop_hook_active": true}', capture_output=True, text=True)
        self.assertEqual(again.returncode, 0)
        self.assertIn("no-such-pack", again.stderr)

    def test_no_subcommand_is_a_usage_error(self):
        self.assertEqual(self.run_cli()[0], 2)

    def test_sarif_has_no_third_party_information_uri(self):
        rc, out = self.run_cli("check", str(self.ws), "--format", "sarif")
        driver = json.loads(out)["runs"][0]["tool"]["driver"]
        self.assertNotIn("github.com/prufgate", driver["informationUri"])
        self.assertEqual(json.loads(out)["runs"][0]["results"][0]["properties"]["severity"], "P0")


class Config(unittest.TestCase):
    def load(self, text: str | bytes) -> PrufGateConfig:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ".prufgate" / "config.yaml"
            p.parent.mkdir()
            p.write_bytes(text if isinstance(text, bytes) else text.encode())
            return PrufGateConfig.load(tmp)

    def test_all_three_exempt_forms(self):
        a = self.load("exempt:\n  src/a.ts:\n    canned-error-fallback: '#1: legacy'\n")
        b = self.load("exempt:\n  canned-error-fallback:\n    - src/a.ts\n")
        c = self.load("exempt:\n  - {path: src/a.ts, rule: canned-error-fallback, reason: '#1: legacy'}\n")
        for cfg in (a, b, c):
            self.assertTrue(cfg.is_exempt("src/a.ts", "canned-error-fallback"))
        self.assertEqual(a.exempt[("src/a.ts", "canned-error-fallback")], "#1: legacy")

    def test_file_form_needs_a_reason(self):
        with self.assertRaises(ConfigError):
            self.load("exempt:\n  src/a.ts:\n    canned-error-fallback: ''\n")

    def test_invalid_utf8_is_a_config_error(self):
        with self.assertRaises(ConfigError):
            self.load(b"\xff\xfe packs: [core]\n")

    def test_paths_never_match_as_substrings(self):
        self.assertFalse(path_matches_pattern("src/data.py", "a.py"))
        self.assertFalse(path_matches_pattern("src/latest.py", "test"))
        self.assertTrue(path_matches_pattern("src/legacy/x.ts", "src/legacy"))
        self.assertTrue(path_matches_pattern("src/legacy/x.ts", "src/legacy/"))
        self.assertTrue(path_matches_pattern("./src/a.ts", "src/a.ts"))
        self.assertTrue(path_matches_pattern("dist/x/y.js", "dist/**"))
        self.assertTrue(path_matches_pattern("pkg/gen/x.go", "**/gen/*.go"))
        self.assertTrue(path_matches_pattern("x.min.js", "*.min.js"))


class Hooks(unittest.TestCase):
    def test_malformed_settings_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / ".claude" / "settings.json"
            settings.parent.mkdir()
            settings.write_text("{ broken")
            with self.assertRaises(HookConfigError):
                init_workspace(Path(tmp), install_hooks=True)
            self.assertEqual(settings.read_text(), "{ broken")

    def test_wrong_shaped_hooks_are_refused(self):
        for bad in ({"hooks": []}, {"hooks": {"Stop": {}}}):
            with tempfile.TemporaryDirectory() as tmp:
                settings = Path(tmp) / ".claude" / "settings.json"
                settings.parent.mkdir()
                settings.write_text(json.dumps(bad))
                with self.assertRaises(HookConfigError):
                    init_workspace(Path(tmp), install_hooks=True)
                self.assertEqual(json.loads(settings.read_text()), bad)

    def test_hook_blocks_when_prufgate_is_not_installed(self):
        # Review item: a failed `python3 -m prufgate.cli` exited 1, which agents treat as non-blocking.
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
            no_prufgate = subprocess.run(["sh", "-c", HOOK_COMMAND], cwd=tmp, env=env, capture_output=True, text=True, input="{}")
            self.assertEqual(no_prufgate.returncode, 2)
            self.assertIn("not installed", no_prufgate.stderr)
            active = subprocess.run(["sh", "-c", HOOK_COMMAND], cwd=tmp, env=env, capture_output=True, text=True,
                                    input='{"stop_hook_active": true}')
            self.assertEqual(active.returncode, 0)
            self.assertIn("not installed", active.stderr)

    def test_existing_hooks_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / ".claude" / "settings.json"
            settings.parent.mkdir()
            settings.write_text(json.dumps({"hooks": {"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}]}}))
            init_workspace(Path(tmp), install_hooks=True)
            init_workspace(Path(tmp), install_hooks=True)
            stops = json.loads(settings.read_text())["hooks"]["Stop"]
            self.assertEqual(len(stops), 2)

    def test_starter_config_keeps_every_default_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            init_workspace(Path(tmp))
            cfg = PrufGateConfig.load(tmp)
            self.assertEqual(set(cfg.packs), {"core", "web-ui", "ai-safety"})

    @unittest.skipUnless(shutil.which("sh"), "needs sh")
    @unittest.skipIf(sys.platform == "win32", "links a POSIX python3; test_shell_guard covers Windows' python")
    def test_hook_falls_back_to_the_module_without_prufgate_on_path(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install:
            git(Path(tmp), "init", "-q")
            git(Path(tmp), "commit", "-q", "--allow-empty", "-m", "init")
            env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT), "HOME": tmp}
            fake = Path(tmp) / "bin"
            fake.mkdir()
            python = installed_python(Path(install) / "venv")
            launcher = fake / "python3"
            launcher.write_text("#!/bin/sh\nexec " + shlex.quote(str(python)) + ' "$@"\n')
            launcher.chmod(0o755)
            env["PATH"] = f"{fake}:/usr/bin:/bin"
            proc = subprocess.run(["sh", "-c", HOOK_COMMAND], cwd=tmp, env=env, capture_output=True, text=True, input="{}")
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
