"""`prufgate verify --mutation`: an installed mutation tool on the changed lines, opt-in only.

Every tool is a fake executable on PATH that prints canned machine-readable output, so no real
mutation tool is needed. One real mutmut run happens when mutmut is installed.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate import mutation, repo_runner
from prufgate.cli import main as cli_main

CALC_BASE = "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n"
CALC_HEAD = "def add(a, b):\n    return b + a\n\n\ndef sub(a, b):\n    return a - b\n"
TEST = "from calc import add\n\n\ndef test_add():\n    assert add(1, 2) is not None\n"

# A fake tool: logs its argv to LOG, then writes the canned report for the tool it is named after.
FAKE = r'''#!{python}
import json, os, sys, time
LOG, REPORTS = {log!r}, {reports!r}
tool = os.path.basename(sys.argv[0])
with open(LOG, "a") as fh:
    fh.write(json.dumps([tool] + sys.argv[1:]) + "\n")
if os.environ.get("FAKE_SLEEP"):
    time.sleep(60)
def arg(name):
    return sys.argv[sys.argv.index(name) + 1]
def put(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w").write(text)
if tool == "mutmut" and sys.argv[1] == "show":
    print(REPORTS["show"][sys.argv[-1]])
elif tool == "mutmut":
    put("mutants/calc.py.meta", REPORTS["mutmut"])
elif tool == "stryker":
    put("reports/mutation/mutation.json", REPORTS["stryker"])
elif tool == "mvn":
    put("target/pit-reports/mutations.xml", REPORTS["pit"])
elif tool == "gremlins":
    put(arg("--output"), REPORTS["gremlins"])
elif tool == "go-mutesting":
    put("report.json", REPORTS["go-mutesting"])
elif tool == "cargo":
    put(os.path.join(arg("--output"), "mutants.out", "outcomes.json"), REPORTS["cargo-mutants"])
sys.exit(int(os.environ.get("FAKE_RC") or 0))
'''

MUTMUT_SHOW = {
    "calc.x_add__mutmut_1": "# calc.x_add__mutmut_1: survived\n--- calc.py\n+++ calc.py\n@@ -1,2 +1,2 @@\n"
                            " def add(a, b):\n-    return b + a\n+    return b - a\n",
    "calc.x_sub__mutmut_1": "# calc.x_sub__mutmut_1: survived\n--- calc.py\n+++ calc.py\n@@ -1,2 +1,2 @@\n"
                            " def sub(a, b):\n-    return a - b\n+    return a + b\n",
}


def _mutmut_meta(codes: dict) -> str:
    return json.dumps({"exit_code_by_key": codes, "durations_by_key": {}})


REPORTS = {
    "show": MUTMUT_SHOW,
    "mutmut": _mutmut_meta({"calc.x_add__mutmut_1": 0, "calc.x_add__mutmut_2": 1, "calc.x_add__mutmut_3": 36,
                            "calc.x_sub__mutmut_1": 0, "calc.x_sub__mutmut_2": None}),
    # Each other tool: a survivor on line 2 (changed), a survivor on line 3 (unchanged), a kill on line 2.
    "stryker": json.dumps({"schemaVersion": "2", "files": {"src/a.ts": {"mutants": [
        {"id": "1", "mutatorName": "EqualityOperator", "replacement": "a <= b", "status": "Survived",
         "location": {"start": {"line": 2, "column": 3}, "end": {"line": 2, "column": 9}}},
        {"id": "2", "mutatorName": "BlockStatement", "replacement": "{}", "status": "Survived",
         "location": {"start": {"line": 3, "column": 1}, "end": {"line": 3, "column": 4}}},
        {"id": "3", "mutatorName": "BooleanLiteral", "replacement": "false", "status": "Killed",
         "location": {"start": {"line": 2, "column": 1}, "end": {"line": 2, "column": 4}}},
        {"id": "4", "mutatorName": "StringLiteral", "replacement": "\"\"", "status": "NoCoverage",
         "location": {"start": {"line": 2, "column": 1}, "end": {"line": 2, "column": 4}}}]}}}),
    "pit": """<?xml version="1.0" encoding="UTF-8"?><mutations>
<mutation detected='false' status='SURVIVED'><sourceFile>A.java</sourceFile><mutatedClass>demo.A$1</mutatedClass>
<lineNumber>2</lineNumber><mutator>ConditionalsBoundaryMutator</mutator><description>changed conditional boundary</description></mutation>
<mutation detected='false' status='SURVIVED'><sourceFile>A.java</sourceFile><mutatedClass>demo.A</mutatedClass>
<lineNumber>3</lineNumber><mutator>VoidMethodCallMutator</mutator><description>removed call</description></mutation>
<mutation detected='true' status='KILLED'><sourceFile>A.java</sourceFile><mutatedClass>demo.A</mutatedClass>
<lineNumber>2</lineNumber><mutator>NegateConditionalsMutator</mutator><description>negated conditional</description></mutation>
<mutation detected='false' status='TIMED_OUT'><sourceFile>A.java</sourceFile><mutatedClass>demo.A</mutatedClass>
<lineNumber>2</lineNumber><mutator>X</mutator><description>loop</description></mutation>
</mutations>""",
    "gremlins": json.dumps({"go_module": "example.com/demo", "files": [{"file_name": "a.go", "mutations": [
        {"line": 2, "column": 5, "type": "CONDITIONALS_BOUNDARY", "status": "LIVED"},
        {"line": 3, "column": 5, "type": "ARITHMETIC_BASE", "status": "LIVED"},
        {"line": 2, "column": 7, "type": "INCREMENT_DECREMENT", "status": "KILLED"},
        {"line": 2, "column": 9, "type": "INVERT_NEGATIVES", "status": "NOT COVERED"}]}]}),
    "go-mutesting": json.dumps({"stats": {}, "escaped": [
        {"mutator": {"mutatorName": "branch/if", "originalSourceCode": "x", "mutatedSourceCode": "package a\n",
                     "originalFilePath": "pkg/a.go", "originalStartLine": 2},
         "diff": "--- Original\n+++ New\n@@ -1,3 +1,3 @@\n x\n-if Y {\n+if true {\n"},
        {"mutator": {"mutatorName": "expression/remove", "originalFilePath": "pkg/a.go", "originalStartLine": 3}}],
        "killed": [{"mutator": {"mutatorName": "statement/remove", "originalFilePath": "pkg/a.go",
                                "originalStartLine": 2}}], "timeouted": [], "errored": []}),
    "cargo-mutants": json.dumps({"outcomes": [
        {"scenario": "Baseline", "summary": "Success"},
        {"scenario": {"Mutant": {"name": "src/a.rs:2:5: replace > with >= in check", "file": "src/a.rs",
                                 "span": {"start": {"line": 2, "column": 5}, "end": {"line": 2, "column": 6}},
                                 "replacement": ">=", "genre": "BinaryOperator"}}, "summary": "MissedMutant"},
        {"scenario": {"Mutant": {"name": "src/a.rs:3:1: replace check -> bool with true", "file": "src/a.rs",
                                 "span": {"start": {"line": 3, "column": 1}}, "replacement": "true"}},
         "summary": "MissedMutant"},
        {"scenario": {"Mutant": {"name": "src/a.rs:2:5: replace > with <", "file": "src/a.rs",
                                 "span": {"start": {"line": 2, "column": 5}}}}, "summary": "CaughtMutant"}],
        "total_mutants": 3}),
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout


@unittest.skipIf(sys.platform == "win32", "prufgate verify needs process groups; Windows refuses it (NeverOnWindows)")
class MutationTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name) / "repo"
        self.bin = Path(tmp.name) / "bin"
        self.log = Path(tmp.name) / "argv.log"
        self.repo.mkdir()
        self.bin.mkdir()
        self.write("calc.py", CALC_BASE)
        self.write("tests/test_calc.py", TEST)
        git(self.repo, "init", "-q", "-b", "main")
        self.commit("base")
        git(self.repo, "checkout", "-qb", "feature")
        env = patch.dict(os.environ, {"PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"})
        env.start()
        self.addCleanup(env.stop)
        for k in (repo_runner.OPT_IN_ENV, "PRUFGATE_BASE_REF", "GITHUB_BASE_REF", "FAKE_SLEEP", "FAKE_RC"):
            os.environ.pop(k, None)

    def write(self, rel: str, text: str) -> None:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def commit(self, msg: str = "head") -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", msg)

    def fake(self, *names: str, reports: dict | None = None) -> None:
        text = FAKE.format(python=sys.executable, log=str(self.log), reports=reports or REPORTS)
        for name in names:
            path = self.bin / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o755)

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def verify(self, *extra: str, opt_in: bool = True) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        args = ["verify", "--mutation", str(self.repo), "--base", "main", *extra]
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(args + (["--allow-run-tests"] if opt_in else []))
        return rc, out.getvalue(), err.getvalue()

    def assert_cleaned_up(self) -> None:
        listing = git(self.repo, "worktree", "list", "--porcelain")
        self.assertEqual(listing.count("worktree "), 1, listing)

    # --- mutmut (Python) ---------------------------------------------------------------------------

    def test_survivor_on_a_changed_line_is_reported(self) -> None:
        self.fake("mutmut")
        self.write("calc.py", CALC_HEAD)
        self.commit()
        rc, out, err = self.verify("--format", "json")
        self.assertEqual(rc, 1, err)
        findings = json.loads(out)
        self.assertEqual([(f["rule"], f["file"], f["line"]) for f in findings], [(mutation.RULE, "calc.py", 2)])
        self.assertEqual((findings[0]["severity"], findings[0]["confidence"]), ("P1", "medium"))
        self.assertIn("`return b + a` -> `return b - a`", findings[0]["message"])
        run, shows = self.calls()[0], [c for c in self.calls() if c[1] == "show"]
        self.assertEqual(run, ["mutmut", "run", "--", "calc.*"])
        self.assertEqual([c[3] for c in shows], ["calc.x_add__mutmut_1", "calc.x_sub__mutmut_1"])
        self.assert_cleaned_up()
        rc, out, _ = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("1 killed, 1 survived, 1 timeout on changed lines (1 outside them, ignored)", out)

    def test_all_killed_passes(self) -> None:
        self.fake("mutmut", reports={**REPORTS, "mutmut": _mutmut_meta({"calc.x_add__mutmut_1": 1})})
        self.write("calc.py", CALC_HEAD)
        self.commit()
        with patch.dict(os.environ, {repo_runner.OPT_IN_ENV: "1"}):
            rc, out, err = self.verify(opt_in=False)
        self.assertEqual(rc, 0, err)
        self.assertIn("passed: 1 changed file(s), mutmut: 1 killed", out)

    def test_survivor_outside_the_change_is_ignored(self) -> None:
        self.fake("mutmut", reports={**REPORTS, "mutmut": _mutmut_meta({"calc.x_sub__mutmut_1": 0,
                                                                         "calc.x_add__mutmut_2": 1})})
        self.write("calc.py", CALC_HEAD)
        self.commit()
        rc, out, err = self.verify("--format", "sarif")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["runs"][0]["results"], [])

    def test_only_test_changes_run_nothing(self) -> None:
        self.fake("mutmut")
        self.write("tests/test_calc.py", TEST + "\n\ndef test_more():\n    assert True\n")
        self.commit()
        rc, out, err = self.verify()
        self.assertEqual(rc, 0, err)
        self.assertIn("no changed production lines", out)
        self.assertEqual(self.calls(), [])

    def test_refused_without_opt_in(self) -> None:
        self.fake("mutmut")
        self.write("calc.py", CALC_HEAD)
        self.commit()
        with patch.object(mutation, "run") as run:
            rc, _, err = self.verify(opt_in=False)
            with patch.dict(os.environ, {repo_runner.OPT_IN_ENV: "yes"}):
                rc2, _, _ = self.verify(opt_in=False)
        self.assertEqual((rc, rc2), (2, 2))
        self.assertIn("--allow-run-tests", err)
        run.assert_not_called()
        self.assertEqual(self.calls(), [])

    def test_no_tool_installed_exits_2_and_names_one(self) -> None:
        git_dir = str(Path(shutil.which("git") or "/usr/bin/git").parent)
        with patch.dict(os.environ, {"PATH": f"{self.bin}{os.pathsep}{git_dir}"}):
            if shutil.which("mutmut"):
                self.skipTest("mutmut is installed next to git (#60)")
            self.write("calc.py", CALC_HEAD)
            self.commit()
            rc, _, err = self.verify()
            self.assertEqual(rc, 2)
            self.assertIn("pip install mutmut", err)
            self.assertIn("never installs", err)
            rc, _, err = self.verify("--tool", "stryker")
            self.assertEqual(rc, 2)
            self.assertIn("stryker is not on PATH", err)
        self.assert_cleaned_up()

    def test_tool_without_a_report_exits_2(self) -> None:
        (self.bin / "mutmut").write_text(f"#!{sys.executable}\nimport sys\nsys.exit(3)\n")
        (self.bin / "mutmut").chmod(0o755)
        self.write("calc.py", CALC_HEAD)
        self.commit()
        rc, _, err = self.verify()
        self.assertEqual(rc, 2)
        self.assertIn("mutmut failed (exit 3)", err)
        self.assert_cleaned_up()

    def test_timeout_exits_2_and_cleans_up(self) -> None:
        self.fake("mutmut")
        self.write("calc.py", CALC_HEAD)
        self.commit()
        with patch.dict(os.environ, {"FAKE_SLEEP": "1"}):
            rc, _, err = self.verify("--timeout", "1", "--pass-env", "FAKE_SLEEP")
        self.assertEqual(rc, 2)
        self.assertIn("within 1s", err)
        self.assert_cleaned_up()

    def test_secrets_are_not_passed_to_the_tool(self) -> None:
        dump = self.log.with_name("env.json")
        (self.bin / "mutmut").write_text(
            f"#!{sys.executable}\nimport json, os\njson.dump(dict(os.environ), open({str(dump)!r}, 'w'))\n")
        (self.bin / "mutmut").chmod(0o755)
        self.write("calc.py", CALC_HEAD)
        self.commit()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "s3cret-token"}):
            rc, _, _ = self.verify()
        self.assertEqual(rc, 2)  # exits 0 but reports no mutants on the changed lines: nothing was tested
        self.assertNotIn("GITHUB_TOKEN", json.loads(dump.read_text()))

    # --- the other tools ---------------------------------------------------------------------------

    def _other_tool(self, tool: str, fakes: tuple[str, ...], path: str, base: str, head: str) -> list[dict]:
        self.fake(*fakes)
        self.write(path, base)
        self.commit("add")
        git(self.repo, "branch", "-f", "main")
        self.write(path, head)
        self.commit()
        rc, out, err = self.verify("--tool", tool, "--format", "json")
        self.assertEqual(rc, 1, err)
        self.assert_cleaned_up()
        return json.loads(out)

    def test_each_tool_reports_only_changed_line_survivors(self) -> None:
        cases = {
            "stryker": (("stryker",), "src/a.ts", "x\ny\nz\n", "x\nY\nz\n", "EqualityOperator: `a <= b`"),
            "pit": (("mvn",), "src/main/java/demo/A.java", "package demo;\ny\nz\n", "package demo;\nY\nz\n",
                    "changed conditional boundary"),
            "gremlins": (("gremlins",), "a.go", "x\ny\nz\n", "x\nY\nz\n", "CONDITIONALS_BOUNDARY"),
            "go-mutesting": (("go-mutesting",), "pkg/a.go", "x\ny\nz\n", "x\nY\nz\n", "branch/if: `if Y {` -> `if true {`"),
            "cargo-mutants": (("cargo", "cargo-mutants"), "src/a.rs", "x\ny\nz\n", "x\nY\nz\n",
                              "replace > with >= in check"),
        }
        for tool, (fakes, path, base, head, desc) in cases.items():
            with self.subTest(tool=tool):
                self.setUp()
                findings = self._other_tool(tool, fakes, path, base, head)
                survivors = [f for f in findings if f["rule"] == mutation.RULE]
                self.assertEqual([(f["file"], f["line"]) for f in survivors], [(path, 2)])
                self.assertIn(desc, survivors[0]["message"])
                uncovered = [(f["rule"], f["line"]) for f in findings if f["rule"] != mutation.RULE]
                self.assertEqual(uncovered, [(mutation.RULE_NO_COVERAGE, 2)] if tool in ("stryker", "gremlins") else [])
                argv = self.calls()[0]
                if tool == "stryker":
                    self.assertEqual(argv[argv.index("--mutate") + 1], "src/a.ts:2-2")
                elif tool == "pit":
                    self.assertIn("-DtargetClasses=demo.A*", argv)
                    self.assertIn("-o", argv)  # offline: never downloads the plugin
                    self.assertIn("-Dfeatures=+CLASSLIMIT(limit[200])", argv)
                elif tool == "gremlins":
                    self.assertEqual(argv[argv.index("--diff") + 1], git(self.repo, "rev-parse", "main").strip())
                elif tool == "go-mutesting":
                    self.assertEqual(argv[-2:], ["--", path])  # a path never reads as a flag
                else:
                    self.assertEqual(argv[1], "mutants")
                    self.assertIn("--in-diff", argv)

    def test_committed_reports_are_never_read(self) -> None:
        # A repository commits an all-killed report; the tool then crashes, or exits 0 without writing one.
        killed = {
            "mutmut": ("mutmut", "calc.py", "mutants/calc.py.meta", _mutmut_meta({"calc.x_add__mutmut_1": 1})),
            "stryker": ("stryker", "src/a.ts", "reports/mutation/mutation.json", json.dumps({"files": {"src/a.ts": {
                "mutants": [{"status": "Killed", "location": {"start": {"line": 2}}}]}}})),
            "pit": ("mvn", "src/main/java/demo/A.java", "target/pit-reports/mutations.xml",
                    "<mutations><mutation status='KILLED'><mutatedClass>demo.A</mutatedClass>"
                    "<lineNumber>2</lineNumber></mutation></mutations>"),
            "go-mutesting": ("go-mutesting", "pkg/a.go", "report.json", json.dumps({"killed": [{"mutator": {
                "originalFilePath": "pkg/a.go", "originalStartLine": 2}}]})),
        }
        for tool, (exe, path, report, text) in killed.items():
            for code in (0, 1):
                with self.subTest(tool=tool, exit=code):
                    self.setUp()
                    (self.bin / exe).write_text(f"#!{sys.executable}\nimport sys\nsys.exit({code})\n")
                    (self.bin / exe).chmod(0o755)
                    self.write(path, "package demo;\ny\nz\n")
                    self.write(report, text)
                    self.commit("add")
                    git(self.repo, "branch", "-f", "main")
                    self.write(path, "package demo;\nY\nz\n")
                    self.commit()
                    rc, out, err = self.verify("--tool", tool)
                    self.assertEqual(rc, 2, out + err)
                    self.assert_cleaned_up()

    def test_report_path_through_a_committed_symlink_is_refused(self) -> None:
        outside = self.repo.parent / "outside"
        (outside / "mutation").mkdir(parents=True)
        (outside / "mutation" / "mutation.json").write_text("{}")
        self.fake("stryker")
        self.write("src/a.ts", "x\ny\nz\n")
        (self.repo / "reports").symlink_to(outside)
        self.commit("add")
        git(self.repo, "branch", "-f", "main")
        self.write("src/a.ts", "x\nY\nz\n")
        self.commit()
        rc, _, err = self.verify("--tool", "stryker")
        self.assertEqual(rc, 2)
        self.assertIn("outside the worktree", err)
        self.assertTrue((outside / "mutation" / "mutation.json").is_file())  # nothing outside is deleted
        self.assertEqual(self.calls(), [])

    def test_tool_exit_code_is_checked(self) -> None:
        for tool, fakes, path, rc_want in (("stryker", ("stryker",), "src/a.ts", 2),
                                           ("cargo-mutants", ("cargo", "cargo-mutants"), "src/a.rs", 1)):
            with self.subTest(tool=tool):
                self.setUp()
                self.fake(*fakes)
                self.write(path, "x\ny\nz\n")
                self.commit("add")
                git(self.repo, "branch", "-f", "main")
                self.write(path, "x\nY\nz\n")
                self.commit()
                with patch.dict(os.environ, {"FAKE_RC": "2"}):
                    rc, out, err = self.verify("--tool", tool, "--pass-env", "FAKE_RC")
                self.assertEqual(rc, rc_want, out + err)  # cargo-mutants exits 2 for missed mutants

    def test_no_mutants_on_changed_lines_exits_2(self) -> None:
        self.fake("mutmut", reports={**REPORTS, "mutmut": _mutmut_meta({})})
        self.write("calc.py", CALC_HEAD)
        self.commit()
        rc, out, err = self.verify()
        self.assertEqual(rc, 2, out)
        self.assertIn("no mutants on the changed lines of calc.py", err)

    def test_uncovered_changed_line_is_a_finding(self) -> None:
        self.fake("mutmut", reports={**REPORTS, "mutmut": _mutmut_meta({"calc.x_add__mutmut_1": 33,
                                                                         "calc.x_add__mutmut_2": 1})})
        self.write("calc.py", CALC_HEAD)
        self.commit()
        rc, out, err = self.verify("--format", "json")
        self.assertEqual(rc, 1, err)
        self.assertEqual([(f["rule"], f["line"], f["severity"]) for f in json.loads(out)],
                         [(mutation.RULE_NO_COVERAGE, 2, "P1")])

    def test_detection_order_and_tool_language(self) -> None:
        self.fake("gremlins", "go-mutesting")
        self.assertEqual(mutation.detect_tool("go"), "gremlins")
        (self.bin / "gremlins").unlink()
        self.assertEqual(mutation.detect_tool("go"), "go-mutesting")
        self.fake("cargo-mutants")
        with patch.dict(os.environ, {"PATH": str(self.bin)}):
            self.assertIsNone(mutation.detect_tool("rust"))  # cargo-mutants runs through cargo
        self.assertEqual(sorted(mutation.RUNNERS), sorted(mutation.TOOL_LANGUAGE))

    def test_cli_tool_choices_match_the_runners(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit):
            cli_main(["verify", "--mutation", "--tool", "nope"])
        for tool in mutation.RUNNERS:
            self.assertIn(tool, err.getvalue())

    def test_one_mode_at_a_time(self) -> None:
        rc, _, err = self.verify("--differential")
        self.assertEqual(rc, 2)
        self.assertIn("one mode", err)

    def test_helpers(self) -> None:
        self.assertEqual(mutation._ranges({1, 2, 3, 7, 9, 10}), [(1, 3), (7, 7), (9, 10)])
        self.assertEqual(mutation._py_module("src/pkg/__init__.py"), "pkg")
        self.assertEqual(mutation._py_module("pkg/mod.py"), "pkg.mod")
        src = "class C:\n    def m(self):\n        return 1\n\n\ndef f():\n    pass\n"
        self.assertEqual(mutation._py_function_span(src, "xǁCǁm"), (2, 3))
        self.assertEqual(mutation._py_function_span(src, "x_f"), (6, 7))
        self.assertIsNone(mutation._py_function_span(src, "x_missing"))
        self.assertEqual(mutation._py_function_span("@a\n@b(1)\ndef g():\n    pass\n", "x_g"), (1, 4))
        with self.assertRaises(repo_runner.RunError):  # never dropped as outside the change
            mutation._match_file("handler.go", {"pkg1/handler.go": {1}, "pkg2/handler.go": {1}})
        self.assertEqual(mutation._match_file("handler.go", {"pkg1/handler.go": {1}}), "pkg1/handler.go")
        self.write("A.java", "/*\npackage fake;\n*/\n// package fake2;\npackage demo.real;\nclass A {}\n")
        self.assertEqual(mutation._java_class(self.repo, "A.java"), "demo.real.A")

    def test_symlinked_changed_file_is_not_mutated(self) -> None:
        self.write("calc.py", CALC_HEAD)
        (self.repo / "link.py").symlink_to(self.repo.parent / "outside.py")
        self.commit()
        base = git(self.repo, "rev-parse", "main").strip()
        self.assertEqual(sorted(mutation.changed_lines(self.repo, base)), ["calc.py"])

    def test_zero_timeout_is_refused(self) -> None:
        with patch.object(mutation, "run") as run:
            rc, _, err = self.verify("--timeout", "0")
        self.assertEqual(rc, 2)
        self.assertIn("must be positive", err)
        run.assert_not_called()

    def test_status_check_runs_git_without_operator_tokens(self) -> None:
        dump = self.log.with_name("filter-env.txt")
        git(self.repo, "config", "filter.dump.clean", f"env > {dump}; cat")
        self.write(".gitattributes", "calc.py filter=dump\n")
        self.commit("attrs")
        self.write("calc.py", CALC_HEAD)  # dirty: git status runs the clean filter
        with patch.dict(os.environ, {"GITHUB_TOKEN": "s3cret-token"}), patch.object(mutation, "run") as run:
            run.return_value = mutation.Result()
            self.verify()
        self.assertTrue(dump.is_file())
        self.assertNotIn("s3cret-token", dump.read_text())
        self.assertEqual(mutation._diff_change("@@ -3,2 +3,2 @@\n a\n-b\n+c\n"), (4, "`b` -> `c`"))


@unittest.skipUnless(shutil.which("mutmut"), "mutmut is not installed (#60)")
class RealMutmut(unittest.TestCase):
    def test_hollow_test_lets_a_mutant_survive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "calc.py").write_text(CALC_BASE)
            (repo / "tests").mkdir()
            (repo / "tests" / "test_calc.py").write_text(TEST)
            (repo / "pyproject.toml").write_text('[tool.mutmut]\npaths_to_mutate = ["calc.py"]\n')
            git(repo, "init", "-q", "-b", "main")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "base")
            git(repo, "checkout", "-qb", "feature")
            (repo / "calc.py").write_text(CALC_HEAD)
            git(repo, "commit", "-qam", "head")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                rc = cli_main(["verify", "--mutation", str(repo), "--base", "main", "--allow-run-tests",
                               "--format", "json", "--timeout", "600"])
            self.assertEqual(rc, 1, out.getvalue())
            self.assertTrue(all(f["file"] == "calc.py" and f["line"] == 2 for f in json.loads(out.getvalue())))


if __name__ == "__main__":
    unittest.main()
