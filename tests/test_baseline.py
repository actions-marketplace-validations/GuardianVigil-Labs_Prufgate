"""The baseline (prufgate/baseline.py): `prufgate baseline` records the findings a
project already has, and `prufgate check` and the gate leave exactly those out.
A new finding, even of the same rule in the same file, is still reported."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from prufgate import baseline
from prufgate.baseline import BaselineError, Entry, Matcher
from prufgate.synthesizer.parse_results import Finding, filter_baseline_findings

ROOT = Path(__file__).resolve().parent.parent
CLI = [sys.executable, str(ROOT / "prufgate" / "cli.py")]

for _ci_var in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF"):
    os.environ.pop(_ci_var, None)

PAY = (
    "export async function pay(x: number) {\n"
    "  try {\n"
    "    return await charge(x);\n"
    "  } catch (e) {\n"
    "    return { ok: true };\n"
    "  }\n"
    "}\n"
)
REFUND = PAY.replace("pay(", "refund(").replace("charge(", "credit(")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *args], cwd=cwd, capture_output=True, text=True, timeout=120)


class ParseEntries(unittest.TestCase):
    def test_schemas(self):
        text = (
            "baseline:\n"
            "  - {file: ./src/a.ts, rule: Anti-Fabrication-Canned-Error-Fallback, fingerprint: 'ab:1'}\n"
            "  - {file_path: /workspace/src/b.py, rule_id: tautological-assertion}\n"
            "  - {file: '*', rule: zero-assertion-test}\n"
            "  - {file: src/legacy.ts}\n"
            "  - {file: '*', rule: '*'}\n"
            "  - just a string\n"
        )
        entries = baseline.parse_entries((".prufgate/baseline.yaml", text))
        self.assertEqual(entries, [
            Entry("src/a.ts", "canned-error-fallback", "ab:1"),
            Entry("src/b.py", "tautological-assertion"),
            Entry("*", baseline.canonical_rule("zero-assertion-test")),
            Entry("src/legacy.ts", "*"),
        ])
        self.assertEqual(
            baseline.parse_entries((".prufgate/baseline.json", json.dumps({"ignore": [{"file": "a", "rule": "b"}]}))),
            [Entry("a", "b")],
        )
        self.assertEqual(baseline.parse_entries((".prufgate/baseline.yaml", "")), [])
        self.assertEqual(baseline.parse_entries(None), [])

    def test_a_broken_file_is_an_error(self):
        for rel, text in ((".prufgate/baseline.yaml", "baseline: [unclosed"), (".prufgate/baseline.json", "{"),
                          (".prufgate/baseline.yaml", "baseline: {file: a}")):
            with self.assertRaises(BaselineError):
                baseline.parse_entries((rel, text))

    def test_rule_spellings(self):
        for spelling in ("canned-error-fallback", "CANNED-ERROR-FALLBACK", "anti-fabrication-canned-error-fallback",
                         "route-canned-fallback", "unhandled-empty-catch"):
            self.assertEqual(baseline.canonical_rule(spelling), baseline.canonical_rule("canned-error-fallback"))


class Fingerprints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "src").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fp(self, items):
        return [f for _, _, f in baseline.fingerprints(items, self.root)]

    def test_stable_when_lines_move_or_code_changes_elsewhere(self):
        (self.root / "src/pay.ts").write_text(PAY)
        before = self.fp([("src/pay.ts", "canned-error-fallback", 4)])
        (self.root / "src/pay.ts").write_text("// a header\n\n" + PAY + REFUND.replace("{ ok: true }", "null"))
        self.assertEqual(self.fp([("src/pay.ts", "canned-error-fallback", 6)]), before)

    def test_identical_findings_are_counted(self):
        (self.root / "src/pay.ts").write_text(PAY + REFUND)
        a, b = self.fp([("src/pay.ts", "canned-error-fallback", 11), ("src/pay.ts", "canned-error-fallback", 4)])
        self.assertEqual(a.split(":")[0], b.split(":")[0])
        self.assertEqual((b.split(":")[1], a.split(":")[1]), ("1", "2"))

    def test_an_edited_line_or_another_rule_changes_it(self):
        (self.root / "src/pay.ts").write_text(PAY)
        first = self.fp([("src/pay.ts", "canned-error-fallback", 4)])
        self.assertNotEqual(self.fp([("src/pay.ts", "stub-click-handler", 4)]), first)
        (self.root / "src/pay.ts").write_text(PAY.replace("catch (e)", "catch (err)"))
        self.assertNotEqual(self.fp([("src/pay.ts", "canned-error-fallback", 4)]), first)

    def test_unreadable_files_still_get_a_fingerprint(self):
        self.assertEqual(self.fp([("../outside.ts", "r", 1), ("GET /api/x", "r", 1)])[0].split(":")[1], "1")


class Matching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "pay.ts").write_text(PAY + REFUND)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_fingerprint_hides_one_finding(self):
        entries = [Entry(f, r, fp) for f, r, fp in baseline.fingerprints([("pay.ts", "canned-error-fallback", 4)], self.root)]
        found = [("pay.ts", "canned-error-fallback", 4), ("pay.ts", "canned-error-fallback", 11)]
        self.assertEqual(Matcher(entries, self.root).match_all(found), [True, False])

    def test_loose_entries_and_stale_entries(self):
        m = Matcher([Entry("pay.ts", "canned-error-fallback"), Entry("gone.ts", "x", "ab:1")], self.root)
        self.assertEqual(m.match_all([("pay.ts", "canned-error-fallback", 4), ("pay.ts", "canned-error-fallback", 11)]),
                         [True, True])
        self.assertEqual(m.stale(), [Entry("gone.ts", "x", "ab:1")])

    def test_gate_integrity_rules_are_never_hidden(self):
        m = Matcher([Entry("*", rule) for rule in baseline.PROTECTED_RULES] + [Entry(".prufgate/config.yaml", "*")], self.root)
        found = [(".prufgate/config.yaml", rule, 1) for rule in baseline.PROTECTED_RULES]
        self.assertEqual(m.match_all(found), [False] * len(found))

    def test_entries_name_the_rule_as_reported(self):
        written = baseline.entries_for([("pay.ts", "anti-fabrication-unhandled-empty-catch", 4)], self.root)
        self.assertEqual(written[0]["rule"], "unhandled-empty-catch")
        entries = baseline.parse_entries((".prufgate/baseline.yaml", baseline.render(written, as_json=False)))
        self.assertEqual(Matcher(entries, self.root).match_all([("pay.ts", "canned-error-fallback", 4)]), [True])

    def test_the_gate_filters_its_own_findings(self):
        # The gate prefixes anti-fabrication rules; an entry `prufgate baseline` wrote still matches.
        entries = baseline.entries_for([("pay.ts", "canned-error-fallback", 4)], self.root)
        (self.root / ".prufgate").mkdir()
        (self.root / ".prufgate" / "baseline.yaml").write_text(baseline.render(entries, as_json=False))
        found = [
            Finding(tool="anti-fabrication", rule_id="anti-fabrication-canned-error-fallback", severity="P0", message="m",
                    file_path="pay.ts", line=line)
            for line in (4, 11)
        ]
        self.assertEqual([f.line for f in filter_baseline_findings(found, self.root)], [11])


class RenderAndWrite(unittest.TestCase):
    def test_yaml_and_json_round_trip(self):
        entries = [{"rule": "r", "file": "src/a \"quoted\": b.ts", "fingerprint": "ab:1", "line": 3}]
        text = baseline.render(entries, as_json=False)
        self.assertTrue(text.startswith("# PrufGate baseline"))
        self.assertEqual(yaml.safe_load(text)["baseline"], entries)
        self.assertEqual(baseline.parse_entries((".prufgate/baseline.yaml", text)), [Entry('src/a "quoted": b.ts', "r", "ab:1")])
        self.assertEqual(json.loads(baseline.render(entries, as_json=True))["baseline"], entries)
        self.assertEqual(yaml.safe_load(baseline.render([], as_json=False))["baseline"], [])

    def test_never_writes_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "elsewhere.txt"
            target.write_text("keep")
            (Path(d) / ".prufgate").mkdir()
            link = Path(d) / ".prufgate" / "baseline.yaml"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                baseline.write(link, "x")
            self.assertEqual(target.read_text(), "keep")


class Commands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        git(self.ws, "init", "-q", "-b", "main")
        (self.ws / "src").mkdir()
        (self.ws / "tests").mkdir()
        (self.ws / "src" / "pay.ts").write_text(PAY)
        (self.ws / "tests" / "test_a.py").write_text("def test_a():\n    assert True\n")
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "legacy")

    def tearDown(self):
        self.tmp.cleanup()

    def test_baseline_then_check(self):
        self.assertEqual(run("check", ".", cwd=self.ws).returncode, 1)
        res = run("baseline", ".", cwd=self.ws)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("wrote 2 entries", res.stdout)
        res = run("check", ".", cwd=self.ws)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("2 finding(s) left out because the baseline lists them", res.stdout)
        # A new finding of the same rule in the same file is still reported, on its own line.
        (self.ws / "src" / "pay.ts").write_text(PAY + REFUND)
        res = run("check", ".", "--format", "json", cwd=self.ws)
        self.assertEqual(res.returncode, 1)
        self.assertEqual([(f["file"], f["line"]) for f in json.loads(res.stdout)], [("src/pay.ts", 11)])
        # SARIF carries the baselined findings as suppressed results.
        sarif = json.loads(run("check", ".", "--format", "sarif", cwd=self.ws).stdout)
        reasons = [r["suppressions"][0]["justification"] for r in sarif["runs"][0]["results"] if r.get("suppressions")]
        self.assertEqual(reasons, ["In the PrufGate baseline"] * 2)
        # Rewriting drops what was fixed and adds what is new.
        (self.ws / "tests" / "test_a.py").write_text("def test_a():\n    assert 1 + 1 == 2\n")
        res = run("check", ".", cwd=self.ws)
        self.assertIn("1 entry in .prufgate/baseline.yaml match no finding", res.stderr)
        res = run("baseline", ".", cwd=self.ws)
        self.assertIn("wrote 2 entries to .prufgate/baseline.yaml (1 new, 1 removed)", res.stdout)

    def test_stdout_and_an_existing_json_file(self):
        res = run("baseline", ".", "--stdout", cwd=self.ws)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(yaml.safe_load(res.stdout)["baseline"]), 2)
        self.assertFalse((self.ws / ".prufgate").exists())
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "baseline.json").write_text("[]")
        self.assertEqual(run("baseline", ".", cwd=self.ws).returncode, 0)
        self.assertEqual(len(json.loads((self.ws / ".prufgate" / "baseline.json").read_text())["baseline"]), 2)
        self.assertFalse((self.ws / ".prufgate" / "baseline.yaml").exists())

    def test_a_scan_that_fails_writes_nothing(self):
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("version: 1\nexclude: 7\n")
        res = run("baseline", ".", cwd=self.ws)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertFalse((self.ws / ".prufgate" / "baseline.yaml").exists())
        self.assertEqual(run("baseline", "src/pay.ts", cwd=self.ws).returncode, 2)

    def test_a_branch_cannot_baseline_its_own_finding(self):
        git(self.ws, "checkout", "-qb", "topic")
        (self.ws / "src" / "pay.ts").write_text(PAY + REFUND)
        self.assertEqual(run("baseline", ".", cwd=self.ws).returncode, 0)
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "new cheat, baselined")
        res = run("check", "--changed", "--base", "main", ".", "--format", "json", cwd=self.ws)
        self.assertEqual(res.returncode, 1, res.stderr)
        self.assertEqual([f["line"] for f in json.loads(res.stdout)], [11])
        self.assertIn("this change edits the PrufGate baseline; it applies after merge", res.stderr)

    def test_a_broken_baseline_hides_nothing(self):
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "baseline.yaml").write_text("baseline: [unclosed\n")
        res = run("check", ".", cwd=self.ws)
        self.assertEqual(res.returncode, 1)
        self.assertIn("the baseline is ignored", res.stderr)


if __name__ == "__main__":
    unittest.main()
