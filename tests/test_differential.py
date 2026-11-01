"""`prufgate verify --differential`: base tests run on the head code, opt-in only."""

import contextlib
import io
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate import differential
from prufgate.cli import main as cli_main

# A tiny test runner committed into the fixture repository: unittest discovery,
# with a JUnit report written to $PRUFGATE_JUNIT_XML.
RUNNER = '''import os, sys, unittest
from xml.sax.saxutils import quoteattr
result = unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.discover("tests", top_level_dir="."))
bad = {t.id() for t, _ in result.failures + result.errors}
with open(os.environ["PRUFGATE_JUNIT_XML"], "w") as fh:
    fh.write("<testsuite>")
    for tid in sorted(bad):
        cls, _, name = tid.rpartition(".")
        fh.write("<testcase classname=%s name=%s><failure/></testcase>" % (quoteattr(cls), quoteattr(name)))
    fh.write("</testsuite>")
sys.exit(1 if bad else 0)
'''
CALC = "def add(a, b):\n    return a + b\n"
TEST = (
    "import unittest\nfrom calc import add\n\n"
    "class TestAdd(unittest.TestCase):\n"
    "    def test_add(self):\n        self.assertEqual(add(2, 2), 4)\n{extra}"
)
CMD = f"{shlex.quote(sys.executable)} runner.py"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout


@unittest.skipIf(sys.platform == "win32", "prufgate verify needs process groups; Windows refuses it (NeverOnWindows)")
class DifferentialTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.write("runner.py", RUNNER)
        self.write("calc.py", CALC)
        self.write("tests/__init__.py", "")
        self.write("tests/test_calc.py", TEST.format(extra="        self.assertEqual(add(1, 2), 3)\n"))
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")
        git(self.repo, "checkout", "-qb", "feature")
        env = patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in (differential.OPT_IN_ENV, "PRUFGATE_BASE_REF", "GITHUB_BASE_REF"):
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def commit(self) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "head")

    def verify(self, *extra: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(["verify", "--differential", str(self.repo), "--base", "main", *extra])
        return rc, out.getvalue(), err.getvalue()

    def assert_cleaned_up(self) -> None:
        listing = git(self.repo, "worktree", "list", "--porcelain")
        self.assertEqual(listing.count("worktree "), 1, listing)

    def test_deleted_assertion_is_caught_by_the_base_test(self) -> None:
        self.write("calc.py", "def add(a, b):\n    return 4\n")
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.commit()
        rc, out, err = self.verify("--allow-run-tests", "--test-cmd", CMD, "--format", "json")
        self.assertEqual(rc, 1, err)
        findings = json.loads(out)
        self.assertEqual([f["rule"] for f in findings], [differential.RULE])
        self.assertEqual(findings[0]["severity"], "P0")
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertEqual(findings[0]["file"], "tests/test_calc.py")
        self.assertIn("tests.test_calc.TestAdd::test_add", findings[0]["message"])
        self.assert_cleaned_up()
        # The user's checkout keeps the head version.
        self.assertNotIn("add(1, 2)", (self.repo / "tests/test_calc.py").read_text())

    def test_deleted_test_file_is_restored(self) -> None:
        self.write("calc.py", "def add(a, b):\n    return 4\n")
        (self.repo / "tests/test_calc.py").unlink()
        self.write("tests/test_other.py", "import unittest\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertTrue(1)\n")
        self.commit()
        rc, out, err = self.verify("--allow-run-tests", "--test-cmd", CMD, "--format", "sarif")
        self.assertEqual(rc, 1, err)
        self.assertEqual(json.loads(out)["runs"][0]["results"][0]["ruleId"], differential.RULE)

    def test_clean_change_passes(self) -> None:
        self.write("calc.py", "def add(a, b):\n    return sum((a, b))\n")
        self.write("tests/test_calc.py", TEST.format(extra="        self.assertEqual(add(1, 2), 3)\n        self.assertEqual(add(0, 0), 0)\n"))
        self.commit()
        with patch.dict(os.environ, {differential.OPT_IN_ENV: "1"}):
            rc, out, err = self.verify("--test-cmd", CMD)
        self.assertEqual(rc, 0, err)
        self.assertIn("1 file(s) restored", out)
        self.assert_cleaned_up()

    def test_refused_without_opt_in(self) -> None:
        with patch.object(differential, "run") as run:
            rc, _, err = self.verify("--test-cmd", CMD)
            with patch.dict(os.environ, {differential.OPT_IN_ENV: "true"}):
                rc2, _, _ = self.verify("--test-cmd", CMD)
        self.assertEqual((rc, rc2), (2, 2))
        self.assertIn("--allow-run-tests", err)
        run.assert_not_called()

    def test_no_test_command_exits_2(self) -> None:
        (self.repo / "runner.py").unlink()
        self.commit()
        rc, _, err = self.verify("--allow-run-tests")
        self.assertEqual(rc, 2)
        self.assertIn("--test-cmd", err)
        self.assert_cleaned_up()

    def test_timeout_exits_2_and_cleans_up(self) -> None:
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.commit()
        sleeper = f"{shlex.quote(sys.executable)} -c 'import time; time.sleep(30)'"
        rc, _, err = self.verify("--allow-run-tests", "--test-cmd", sleeper, "--timeout", "1")
        self.assertEqual(rc, 2)
        self.assertIn("within 1s", err)
        self.assert_cleaned_up()

    def test_failing_head_tests_are_inconclusive(self) -> None:
        self.write("calc.py", "def add(a, b):\n    return 5\n")
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.commit()
        rc, _, err = self.verify("--allow-run-tests", "--test-cmd", CMD)
        self.assertEqual(rc, 2)
        self.assertIn("inconclusive", err)

    def test_secrets_are_not_passed_to_the_tests(self) -> None:
        with patch.dict(os.environ, {"GITHUB_TOKEN": "x", "EXTRA": "y"}):
            env = differential._env(["EXTRA"], Path("j.xml"))
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertEqual(env["EXTRA"], "y")

    def test_detection_is_conservative(self) -> None:
        root, junit = self.repo, Path("j.xml")
        self.assertIsNone(differential.detect_test_command(root, junit))
        self.write("package.json", json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}))
        self.assertIsNone(differential.detect_test_command(root, junit))
        self.write("package.json", json.dumps({"scripts": {"test": "vitest run"}}))
        self.assertEqual(differential.detect_test_command(root, junit), ["npm", "test"])
        self.write("conftest.py", "")
        self.assertIn("pytest", differential.detect_test_command(root, junit))


    def leftovers(self, tmpdir: Path) -> list[str]:
        return [p.name for p in tmpdir.iterdir() if p.name.startswith(differential.TMP_PREFIX)]

    def test_head_only_file_in_the_test_run_is_removed(self) -> None:
        # A file head adds to the test run (here a module that patches the code at import, like a conftest
        # with collect_ignore) is not part of the base test run.
        self.write("calc.py", "def add(a, b):\n    return 4\n")
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.write("tests/test_aaa.py", "import calc\ncalc.add = lambda a, b: a + b\n")
        self.commit()
        rc, out, err = self.verify("--allow-run-tests", "--test-cmd", CMD, "--format", "json")
        self.assertEqual(rc, 1, err)
        self.assertIn("tests.test_calc.TestAdd::test_add", out)
        self.assert_cleaned_up()

    def test_helpers_config_and_conftest_are_part_of_the_base_test_run(self) -> None:
        self.write("tests/helpers.py", "def check(x):\n    assert x\n")
        self.write("pyproject.toml", "[tool.pytest.ini_options]\ntestpaths = ['tests']\n")
        self.write("package.json", json.dumps({"scripts": {"test": "jest", "build": "tsc"}, "jest": {"bail": True}}))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "more")
        git(self.repo, "branch", "-f", "main")
        self.write("tests/helpers.py", "def check(x):\n    pass\n")
        self.write("pyproject.toml", "[tool.pytest.ini_options]\ntestpaths = ['docs']\n")
        self.write("tests/conftest.py", "collect_ignore = ['test_calc.py']\n")
        self.write("package.json", json.dumps({"type": "module", "scripts": {"test": "jest || true", "build": "tsc"},
                                               "jest": {"testPathIgnorePatterns": ["calc"]}}))
        self.commit()
        writes, removes = differential._base_test_run(self.repo, "main")
        by_path = {p: c for p, c, _ in writes}
        self.assertEqual(sorted(by_path), ["package.json", "pyproject.toml", "tests/helpers.py"])
        self.assertEqual(removes, ["tests/conftest.py"])
        pkg = json.loads(by_path["package.json"])
        self.assertEqual(pkg, {"type": "module", "scripts": {"build": "tsc", "test": "jest"}, "jest": {"bail": True}})

    def test_tests_added_to_the_base_after_the_fork_are_not_run(self) -> None:
        git(self.repo, "checkout", "-q", "main")
        self.write("calc.py", CALC + "def sub(a, b):\n    return a - b\n")
        self.write("tests/test_sub.py", "import unittest\nfrom calc import sub\n\nclass T(unittest.TestCase):\n"
                   "    def test_sub(self):\n        self.assertEqual(sub(3, 1), 2)\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "main moves on")
        git(self.repo, "checkout", "-q", "feature")
        self.write("README.md", "docs\n")
        self.commit()
        rc, out, err = self.verify("--allow-run-tests", "--test-cmd", CMD)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("no test file was deleted or changed", out)

    def _detached(self, pidfile: Path, then: str) -> str:
        # Starts a grandchild in its own session that holds stdout, records its pid, then runs `then`.
        code = (f"import subprocess, sys, time; p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
                f"start_new_session=True); open({str(pidfile)!r}, 'w').write(str(p.pid)); {then}")
        return f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"

    def assert_dead(self, pidfile: Path) -> None:
        pid = int(pidfile.read_text())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        os.kill(pid, 9)
        self.fail(f"process {pid} outlived the run")

    def test_detached_child_neither_stalls_the_timeout_nor_survives(self) -> None:
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.commit()
        with tempfile.TemporaryDirectory() as side:
            pidfile = Path(side) / "pid"
            started = time.monotonic()
            rc, _, err = self.verify("--allow-run-tests", "--test-cmd", self._detached(pidfile, "time.sleep(30)"),
                                     "--timeout", "2")
            self.assertLess(time.monotonic() - started, 20)
            self.assertEqual(rc, 2, err)
            self.assertIn("within 2s", err)
            self.assert_dead(pidfile)
            rc, _, err = self.verify("--allow-run-tests", "--test-cmd", self._detached(pidfile, "sys.exit(0)"),
                                     "--timeout", "20")
            self.assertEqual(rc, 0, err)
            self.assert_dead(pidfile)
        self.assert_cleaned_up()

    def _cli(self, tmpdir: Path, test_cmd: str) -> subprocess.Popen:
        root = Path(__file__).resolve().parent.parent
        env = {**os.environ, "TMPDIR": str(tmpdir), "PYTHONPATH": str(root)}
        return subprocess.Popen(
            [sys.executable, "-m", "prufgate.cli", "verify", "--differential", str(self.repo), "--base", "main",
             "--allow-run-tests", "--test-cmd", test_cmd],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _wait_for_worktree(self, proc: subprocess.Popen, pidfile: Path) -> None:
        deadline = time.monotonic() + 30
        while not (pidfile.is_file() and pidfile.read_text()):
            self.assertIsNone(proc.poll(), "the run ended before its test command started")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)

    def test_sigterm_and_sigkill_leave_no_worktree_behind(self) -> None:
        self.write("tests/test_calc.py", TEST.format(extra=""))
        self.commit()
        with tempfile.TemporaryDirectory() as side, tempfile.TemporaryDirectory() as tmpdir:
            pidfile, tmpdir = Path(side) / "pid", Path(tmpdir)
            proc = self._cli(tmpdir, self._detached(pidfile, "time.sleep(60)"))
            self._wait_for_worktree(proc, pidfile)
            self.assertEqual(len(self.leftovers(tmpdir)), 1)
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=30), 128 + signal.SIGTERM)
            self.assert_cleaned_up()
            self.assertEqual(self.leftovers(tmpdir), [])
            self.assert_dead(pidfile)
            # SIGKILL cannot be handled: the next run removes what the killed one left.
            pidfile.unlink()
            proc = self._cli(tmpdir, self._detached(pidfile, "time.sleep(60)"))
            self._wait_for_worktree(proc, pidfile)
            proc.kill()
            proc.wait(timeout=30)
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            self.assertEqual(len(self.leftovers(tmpdir)), 1)
            proc = self._cli(tmpdir, CMD)
            self.assertEqual(proc.wait(timeout=60), 0)
            self.assert_cleaned_up()
            self.assertEqual(self.leftovers(tmpdir), [])

    def test_overlay_never_writes_through_links_or_into_the_way(self) -> None:
        with tempfile.TemporaryDirectory() as wt_dir, tempfile.TemporaryDirectory() as outside:
            wt, victim = Path(wt_dir), Path(outside) / "victim"
            victim.write_text("keep")
            (wt / "vendor").mkdir()
            (wt / "tests").symlink_to("vendor")  # a directory symlink that stays inside the worktree
            (wt / "spec").mkdir()
            os.link(victim, wt / "spec" / "a_test.py")  # a hardlink to a file outside
            os.mkfifo(wt / "spec" / "b_test.py")
            (wt / "spec" / "c_test.py").mkdir()
            writes = [(p, b"base\n", 0o644) for p in ("tests/test_x.py", "spec/a_test.py", "spec/b_test.py", "spec/c_test.py")]
            differential._overlay(wt, writes, ["vendor/gone.py"])
            self.assertEqual(victim.read_text(), "keep")
            self.assertFalse((wt / "tests").is_symlink())
            self.assertEqual(list((wt / "vendor").iterdir()), [])
            for p, _, _ in writes:
                self.assertTrue((wt / p).is_file() and not (wt / p).is_symlink(), p)
                self.assertEqual((wt / p).read_bytes(), b"base\n")

    def test_git_runs_no_repository_commands_and_no_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as side:
            leak, monitor = Path(side) / "leak", Path(side) / "monitor"
            self.write("tests/test_calc.py", TEST.format(extra=""))
            self.write("untracked.txt", "a dirty tree still compares the committed HEAD with HEAD~1\n")
            self.commit()
            (self.repo / "untracked.txt").write_text("dirty")
            git(self.repo, "rm", "-q", "--cached", "untracked.txt")
            git(self.repo, "config", "filter.leak.smudge", f"sh -c 'env >> {leak}; cat'")
            (self.repo / ".git" / "info").mkdir(exist_ok=True)
            (self.repo / ".git" / "info" / "attributes").write_text("*.py filter=leak\n")
            git(self.repo, "config", "core.fsmonitor", f"touch {monitor}; false")
            with patch.dict(os.environ, {"GITHUB_TOKEN": "s3cret-token"}):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc = cli_main(["verify", "--differential", str(self.repo), "--allow-run-tests", "--test-cmd", CMD])
            self.assertEqual(rc, 0, err.getvalue())
            self.assertTrue(leak.exists(), "the smudge filter fixture did not run")
            self.assertFalse(monitor.exists(), "core.fsmonitor ran")
            self.assertNotIn("s3cret-token", leak.read_text() if leak.exists() else "")


class NeverAutomatic(unittest.TestCase):
    def test_no_automatic_surface_reaches_the_differential_or_mutation_run(self) -> None:
        # verify --differential and verify --mutation run repository code: only the explicit CLI command may.
        root = Path(__file__).resolve().parent.parent
        paths = [root / "prufgate.sh", *(root / "runners").glob("*"), *(root / "prufgate").glob("*/**/*.py"),
                 root / "action.yml", *(root / "plugins").glob("**/*.json"), *(root / "plugins").glob("**/*.sh")]
        pattern = (r"prufgate[./](?:differential|mutation|repo_runner)|import (?:differential|mutation|repo_runner)"
                   r"|verify --(?:differential|mutation)|--allow-run-tests|PRUFGATE_ALLOW_RUN_TESTS")
        hits = [str(p.relative_to(root)) for p in paths
                if p.is_file() and re.search(pattern, p.read_text(encoding="utf-8", errors="ignore"))]
        self.assertEqual(hits, [], "a surface other than the explicit `prufgate verify` command reaches repository code")
        # Only the CLI and the two run modules themselves import them at the top level of the package.
        top = [p.name for p in (root / "prufgate").glob("*.py") if re.search(
            r"from prufgate(?:\.repo_runner| import [^\n]*\b(?:differential|mutation|repo_runner)\b)|"
            r"from prufgate\.(?:differential|mutation) import", p.read_text(encoding="utf-8"))]
        self.assertEqual(sorted(top), ["cli.py", "differential.py", "mutation.py"])


class NeverOnWindows(unittest.TestCase):
    """Without process groups (Windows) the repository's tests cannot be contained: verify refuses, exit 2."""

    def test_verify_refuses_without_process_groups(self) -> None:
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        from prufgate import repo_runner
        from prufgate.cli import main as cli_main

        for mode in ("--differential", "--mutation"):
            err = io.StringIO()
            with mock.patch.object(repo_runner, "supported", return_value=False), redirect_stderr(err):
                rc = cli_main(["verify", mode, ".", "--allow-run-tests"])
            self.assertEqual(rc, 2, mode)
            self.assertIn("not available on Windows", err.getvalue())
        with mock.patch.object(repo_runner, "supported", return_value=False):
            with self.assertRaises(repo_runner.RunError):
                repo_runner.run_command(["true"], Path("."), {}, 5, Path("unused.log"))


class RunMarkTest(unittest.TestCase):
    """Outside Linux, leftover processes are found by the run marker in their environment."""

    def test_only_processes_with_this_exact_mark(self) -> None:
        from unittest import mock

        from prufgate import repo_runner

        ps = (
            "  101 python -m pytest PATH=/usr/bin PRUFGATE_RUN_MARK=abc123\n"
            "  102 sleep 60 TERM=xterm PRUFGATE_RUN_MARK=abc123 LANG=C\n"
            "  103 sleep 60 PRUFGATE_RUN_MARK=abc1234\n"
            "  104 editor notes.txt X=PRUFGATE_RUN_MARK=abc123extra\n"
            "  105 bash\n"
            f"  {os.getpid()} prufgate verify PRUFGATE_RUN_MARK=abc123\n"
        )
        with mock.patch.object(repo_runner.subprocess, "run", return_value=mock.Mock(stdout=ps)):
            self.assertEqual(repo_runner._marked("abc123"), {101, 102})
        with mock.patch.object(repo_runner.subprocess, "run", side_effect=OSError("no ps")):
            self.assertEqual(repo_runner._marked("abc123"), set())


if __name__ == "__main__":
    unittest.main()
