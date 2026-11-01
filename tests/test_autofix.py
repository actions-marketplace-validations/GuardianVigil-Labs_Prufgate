"""`prufgate fix`: deterministic fixes for safe cases, checked against their rule."""

from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate.cli import main as cli_main
from prufgate.review import autofix

# The cheats are assembled at run time so this file's own diff never carries them.
ONLY = "." + "only"
SKIP = "." + "skip"
NOQA = "# " + "noqa"
PIGNORE = "// prufgate-" + "ignore"
OR_TRUE = "|| " + "true"
COE = "continue-on-" + "error: true"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout


class AutofixTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name).resolve()
        git(self.repo, "init", "-q", "-b", "main")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def commit(self, msg: str) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", msg)

    def branch(self, files_base: dict[str, str], files_head: dict[str, str]) -> autofix.Plan:
        for k, v in files_base.items():
            self.write(k, v)
        self.commit("base")
        git(self.repo, "checkout", "-q", "-b", "feature")
        for k, v in files_head.items():
            self.write(k, v)
        self.commit("head")
        return autofix.plan_fixes(self.repo, "main")

    def fixed(self, plan: autofix.Plan, path: str) -> str:
        return "".join(autofix.fixed_files(plan)[path])

    def assert_rule_passes(self, plan: autofix.Plan, path: str, rule: str) -> None:
        st = plan.files[path]
        self.assertEqual(autofix._count(rule, path, st.base, autofix.fixed_files(plan)[path]), 0)

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(["fix", str(self.repo), "--base", "main", *args])
        return rc, out.getvalue(), err.getvalue()

    # --- each fix type --------------------------------------------------------

    def test_focus_removed(self) -> None:
        base = "it('adds', () => {\n  expect(add(1, 2)).toBe(3);\n});\n"
        head = base.replace("it(", "it" + ONLY + "(")
        plan = self.branch({"src/a.test.ts": base}, {"src/a.test.ts": head})
        self.assertEqual(self.fixed(plan, "src/a.test.ts"), base)
        self.assert_rule_passes(plan, "src/a.test.ts", autofix.SKIP_RULE)
        patch = autofix.format_patch(plan)
        self.assertIn("-it" + ONLY + "('adds'", patch)
        self.assertIn("+it('adds'", patch)

    def test_fdescribe_prefix_removed(self) -> None:
        base = "describe('x', () => {\n  it('y', () => { expect(f()).toBe(1); });\n});\n"
        plan = self.branch({"a.spec.js": base}, {"a.spec.js": "f" + base})
        self.assertEqual(self.fixed(plan, "a.spec.js"), base)

    def test_js_skip_restores_base_line(self) -> None:
        base = "test('pays', () => {\n  expect(pay()).toBe(true);\n});\n"
        head = base.replace("test(", "test" + SKIP + "(")
        plan = self.branch({"pay.test.js": base}, {"pay.test.js": head})
        self.assertEqual(self.fixed(plan, "pay.test.js"), base)
        self.assert_rule_passes(plan, "pay.test.js", autofix.SKIP_RULE)

    def test_pytest_skip_decorator_removed(self) -> None:
        base = "def test_total():\n    assert total() == 3\n"
        head = "import pytest\n\n\n@pytest.mark" + SKIP + "\n" + base
        plan = self.branch({"tests/test_t.py": base}, {"tests/test_t.py": head})
        fixed = self.fixed(plan, "tests/test_t.py")
        self.assertNotIn("mark" + SKIP, fixed)
        self.assertIn(base, fixed)
        self.assert_rule_passes(plan, "tests/test_t.py", autofix.SKIP_RULE)

    def test_go_t_skip_removed(self) -> None:
        base = "func TestSum(t *testing.T) {\n\tif Sum(1, 2) != 3 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n"
        head = base.replace("{\n\tif", "{\n\tt.Skip()\n\tif", 1)
        plan = self.branch({"sum_test.go": base}, {"sum_test.go": head})
        self.assertEqual(self.fixed(plan, "sum_test.go"), base)

    def test_deleted_assertions_restored(self) -> None:
        base = (
            "it('creates invoice', async () => {\n"
            "  const res = await api.post('/invoices', payload);\n"
            "  expect(res.status).toBe(201);\n"
            "  expect(res.body.total).toBe(450);\n"
            "});\n"
        )
        head = base.replace("  expect(res.status).toBe(201);\n  expect(res.body.total).toBe(450);\n", "")
        plan = self.branch({"src/api.test.ts": base}, {"src/api.test.ts": head})
        self.assertEqual(self.fixed(plan, "src/api.test.ts"), base)
        self.assert_rule_passes(plan, "src/api.test.ts", autofix.ASSERTION_RULE)

    def test_weakened_assertion_restored(self) -> None:
        base = "it('ok', async () => {\n  const res = await api.get('/');\n  expect(res.status).toBe(201);\n});\n"
        head = base.replace("toBe(201)", "toBeDefined()")
        plan = self.branch({"src/api.test.ts": base}, {"src/api.test.ts": head})
        self.assertEqual(self.fixed(plan, "src/api.test.ts"), base)
        self.assert_rule_passes(plan, "src/api.test.ts", autofix.ASSERTION_RULE)

    def test_bare_noqa_removed(self) -> None:
        base = "import os\n"
        head = "import os\nimport sys  " + NOQA + "\n"
        plan = self.branch({"app.py": base}, {"app.py": head})
        self.assertEqual(self.fixed(plan, "app.py"), "import os\nimport sys\n")
        self.assert_rule_passes(plan, "app.py", autofix.SUPPRESSION_RULE)

    def test_reasonless_prufgate_ignore_removed(self) -> None:
        base = "export const a = 1;\n"
        head = base + "export const b = load();  " + PIGNORE + ": some-rule\n"
        plan = self.branch({"src/b.ts": base}, {"src/b.ts": head})
        self.assertEqual(self.fixed(plan, "src/b.ts"), base + "export const b = load();\n")
        self.assert_rule_passes(plan, "src/b.ts", autofix.IGNORE_RULE)

    def test_ci_weakening_removed(self) -> None:
        wf = ".github/workflows/ci.yml"
        base = "jobs:\n  test:\n    steps:\n      - name: test\n        run: npm test\n"
        head = base.replace("run: npm test", f"run: npm test {OR_TRUE}\n        {COE}")
        plan = self.branch({wf: base}, {wf: head})
        self.assertEqual(self.fixed(plan, wf), base)
        self.assert_rule_passes(plan, wf, autofix.CI_RULE)

    # --- what gets no fix -----------------------------------------------------

    def test_ambiguous_cases_get_no_fix(self) -> None:
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        # Two focus filters on one line, and a noqa inside a string: both ambiguous.
        head = base + "it" + ONLY + "('b', () => {}); it" + ONLY + "('c', () => {});\n"
        py = "x = 1\n"
        py_head = py + 'y = "a # b"  ' + NOQA + "\n"
        plan = self.branch({"a.test.js": base, "m.py": py}, {"a.test.js": head, "m.py": py_head})
        self.assertEqual(plan.fixes, [])
        self.assertEqual({s.path for s in plan.skipped}, {"a.test.js", "m.py"})

    def test_mixed_assertion_hunk_gets_no_fix(self) -> None:
        base = "it('x', () => {\n  const r = run();\n  expect(r).toBe(2);\n});\n"
        head = base.replace("  const r = run();\n  expect(r).toBe(2);\n", "  const r = run(1);\n")
        plan = self.branch({"x.test.js": base}, {"x.test.js": head})
        self.assertEqual(plan.fixes, [])
        self.assertTrue(any(s.rule == autofix.ASSERTION_RULE for s in plan.skipped))

    def test_other_rules_report_no_safe_fix(self) -> None:
        plan = self.branch({"src/c.ts": "export const a = 1;\n"}, {"src/c.ts": "export const a = 1 as any;\n"})
        self.assertEqual(plan.fixes, [])
        rc, out, err = self.run_cli()
        self.assertEqual((rc, out), (0, ""))
        self.assertIn("no safe fix: src/c.ts:1 [unsafe-type-cast-cascade]", err)

    def test_line_unchanged_in_branch_is_untouched(self) -> None:
        # The focus filter is already on the base: not added by this branch, so not ours to fix.
        base = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        plan = self.branch({"a.test.js": base}, {"a.test.js": base + "// more\n"})
        self.assertEqual(plan.fixes, [])

    # --- the CLI ----------------------------------------------------------------

    def test_default_prints_patch_without_writing(self) -> None:
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        self.branch({"a.test.js": base}, {"a.test.js": head})
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("diff --git a/a.test.js b/a.test.js\n"))
        self.assertEqual((self.repo / "a.test.js").read_text(), head)
        res = subprocess.run(["git", "apply", "--check", "-"], cwd=self.repo, input=out, text=True, capture_output=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_apply_is_idempotent(self) -> None:
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        self.branch({"a.test.js": base}, {"a.test.js": head})
        rc, out, _ = self.run_cli("--apply")
        self.assertEqual((rc, out), (0, "fixed a.test.js\n"))
        self.assertEqual((self.repo / "a.test.js").read_text(), base)
        rc, out, _ = self.run_cli("--apply")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to write", out)
        self.assertEqual((self.repo / "a.test.js").read_text(), base)

    def test_apply_refuses_unrelated_uncommitted_changes(self) -> None:
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        self.branch({"a.test.js": base}, {"a.test.js": head})
        (self.repo / "a.test.js").write_text(head + "// local edit\n")
        rc, _, err = self.run_cli("--apply")
        self.assertEqual(rc, 2)
        self.assertIn("uncommitted changes", err)
        self.assertEqual((self.repo / "a.test.js").read_text(), head + "// local edit\n")
        rc, _, _ = self.run_cli("--apply", "--force")
        self.assertEqual(rc, 0)
        self.assertEqual((self.repo / "a.test.js").read_text(), base + "// local edit\n")

    def test_apply_refuses_symlinks(self) -> None:
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        self.branch({"t/a.test.js": base}, {"t/a.test.js": head})
        # Swap the directory for a symlink to a copy outside the repository.
        target = Path(outside.name) / "a.test.js"
        target.write_text(head)
        (self.repo / "t" / "a.test.js").unlink()
        (self.repo / "t").rmdir()
        (self.repo / "t").symlink_to(outside.name, target_is_directory=True)
        rc, _, err = self.run_cli("--apply", "--force")
        self.assertEqual(rc, 2)
        self.assertIn("symlink", err)
        self.assertEqual(target.read_text(), head)

    def _swap_dir_after_check(self) -> tuple[int, str, str, str]:
        """Apply a fix while `t/` is swapped for a symlink to an outside folder right after
        the path check. Returns (exit code, stderr, the outside file's text, its original text)."""
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        self.branch({"t/a.test.js": base}, {"t/a.test.js": head})
        target = Path(outside.name) / "a.test.js"
        target.write_text(head)
        real_check = autofix._safe_target

        def check_then_swap(root, rel):
            out = real_check(root, rel)
            (self.repo / "t" / "a.test.js").unlink()
            (self.repo / "t").rmdir()
            (self.repo / "t").symlink_to(outside.name, target_is_directory=True)
            return out

        with patch.object(autofix, "_safe_target", check_then_swap):
            rc, _, err = self.run_cli("--apply")
        return rc, err, target.read_text(), head

    def test_directory_swapped_for_symlink_after_the_check_is_refused(self) -> None:
        rc, err, outside_text, head = self._swap_dir_after_check()
        self.assertEqual(rc, 2)
        self.assertIn("symlink", err)
        self.assertEqual(outside_text, head)

    def test_directory_swapped_for_symlink_is_refused_without_dir_fd(self) -> None:
        # Windows has no dir_fd: the same swap is caught by checking the opened file's identity.
        with patch.object(autofix, "_DIR_FD", False):
            rc, err, outside_text, head = self._swap_dir_after_check()
        self.assertEqual(rc, 2)
        self.assertIn("symlink", err)
        self.assertEqual(outside_text, head)

    def test_force_moves_edits_onto_shifted_working_tree_lines(self) -> None:
        skip = "@pytest.mark" + SKIP + "\n"
        base = "def test_a():\n    assert f() == 1\n"
        head = skip + base
        self.branch({"test_a.py": base}, {"test_a.py": head})
        local = skip + "def test_z():\n    assert g() == 2\n" + head
        (self.repo / "test_a.py").write_text(local)
        rc, _, err = self.run_cli("--apply", "--force")
        self.assertEqual(rc, 0, err)
        # The branch's skip goes; the local one above it, now on the same line number, stays.
        self.assertEqual((self.repo / "test_a.py").read_text(), skip + "def test_z():\n    assert g() == 2\n" + base)

    def test_fixes_that_do_not_check_out_together_are_dropped(self) -> None:
        base = "it('a', () => { expect(f()).toBe(1); });\n"
        head = "it" + ONLY + "('a', () => { expect(f()).toBe(1); });\n"
        with patch.object(autofix, "_combined_ok", return_value=False):
            plan = self.branch({"a.test.js": base}, {"a.test.js": head})
        self.assertEqual(plan.fixes, [])
        self.assertIn("together", plan.skipped[0].why)

    def test_committed_symlink_is_never_a_target(self) -> None:
        self.write("real.test.js", "it('a', () => { expect(f()).toBe(1); });\n")
        self.commit("base")
        git(self.repo, "checkout", "-q", "-b", "feature")
        (self.repo / "link.test.js").symlink_to("real.test.js")
        self.commit("head")
        plan = autofix.plan_fixes(self.repo, "main")
        self.assertNotIn("link.test.js", plan.files)

    def test_github_suggestions_format(self) -> None:
        base = "def test_total():\n    assert total() == 3\n"
        head = "import pytest\n\n\n@pytest.mark" + SKIP + "\n" + base
        test = "it('a', () => { expect(f()).toBe(1); });\n"
        self.branch(
            {"tests/test_t.py": base, "a.test.js": test},
            {"tests/test_t.py": head, "a.test.js": test.replace("it(", "it" + ONLY + "(")},
        )
        rc, out, _ = self.run_cli("--format", "github-suggestions")
        self.assertEqual(rc, 0)
        self.assertIn("::warning file=a.test.js,line=1,title=[P2] Auto-fix (test-skip-smuggling)::", out)
        self.assertIn("**Location:** `a.test.js:1`", out)
        self.assertIn("```suggestion\n" + test + "```", out)
        # Removing a line is an empty suggestion block.
        self.assertIn("**Location:** `tests/test_t.py:4`", out)
        self.assertIn("```suggestion\n```", out)
        self.assertIn("::stop-commands::", out)

    def test_bad_base_exits_2(self) -> None:
        self.write("a.txt", "x\n")
        self.commit("base")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(["fix", str(self.repo), "--base", "no-such-ref"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
