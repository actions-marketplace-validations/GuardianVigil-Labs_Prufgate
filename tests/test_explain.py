"""`prufgate explain` (prufgate/explain.py): every rule has an explanation, every
explanation is a real rule named in docs/ENGINES.md, and lookups accept the
spellings reports use."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from prufgate import explain
from prufgate.config import RULE_ALIAS_GROUPS
from prufgate.rules import CONFIDENCE

ROOT = Path(__file__).resolve().parent.parent


def run_main(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = explain.main(*args)
    return rc, out.getvalue(), err.getvalue()


class Coverage(unittest.TestCase):
    def test_every_rule_is_explained_and_every_explanation_is_a_rule(self):
        self.assertEqual(set(explain.RULES), set(CONFIDENCE))

    def test_every_rule_is_in_the_engine_docs(self):
        docs = (ROOT / "docs" / "ENGINES.md").read_text(encoding="utf-8")
        named = set(re.findall(r"`([A-Za-z][\w-]+)`", docs))
        missing = sorted(r for r in explain.RULES if r not in named and not r.startswith("pr-") and r != "action-authorization-guard")
        self.assertEqual(missing, [])

    def test_docs_anchors_exist(self):
        docs = (ROOT / "docs" / "ENGINES.md").read_text(encoding="utf-8")
        anchors = set()
        for heading in re.findall(r"^#{2,3} (.+)$", docs, re.M):
            slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
            anchors.add(slug)
        for rule in explain.RULES.values():
            self.assertIn(rule.engine.anchor, anchors, rule.engine.name)

    def test_entries_are_complete(self):
        for name, rule in explain.RULES.items():
            self.assertTrue(rule.what.strip() and rule.fix.strip(), name)
            self.assertTrue(rule.what.rstrip().endswith((".", ")")), name)


class Lookup(unittest.TestCase):
    def test_spellings_reports_use(self):
        self.assertEqual(explain.lookup("canned-error-fallback"), "canned-error-fallback")
        self.assertEqual(explain.lookup("anti-fabrication-canned-error-fallback"), "canned-error-fallback")
        self.assertEqual(explain.lookup("Tautological-Assertion"), "tautological-assertion")
        self.assertEqual(explain.lookup("bola-unguarded-server-action"), "BOLA-UNGUARDED-SERVER-ACTION")

    def test_aliases_without_their_own_entry(self):
        for group in RULE_ALIAS_GROUPS:
            for alias in group:
                self.assertIsNotNone(explain.lookup(alias), alias)
        self.assertEqual(explain.lookup("demo-named-data"), "fake-named-data")

    def test_unknown_rules(self):
        self.assertIsNone(explain.lookup("generic-api-key"))
        self.assertIn("tautological-assertion", explain.suggestions("tautological-asertion"))


class Command(unittest.TestCase):
    def test_text(self):
        rc, out, _ = run_main("anti-fabrication-canned-error-fallback", False, "text")
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("canned-error-fallback  (engine 1: anti-fabrication · confidence: medium"))
        for section in ("What it catches", "How to fix it", "Example", "If the finding is wrong", "More: https://"):
            self.assertIn(section, out)
        self.assertIn("prufgate-ignore: canned-error-fallback -- <reason>", out)
        self.assertIn("#engine-1-anti-fabrication", out)

    def test_low_confidence_rules_say_they_are_off(self):
        _, out, _ = run_main("fake-named-data", False, "text")
        self.assertIn("off by default", out)
        _, out, _ = run_main("tautological-assertion", False, "text")
        self.assertNotIn("off by default", out)

    def test_json(self):
        rc, out, _ = run_main("ghost-symbol", False, "json")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual((doc["rule"], doc["confidence"]), ("ghost-symbol", "high"))
        rc, out, _ = run_main(None, True, "json")
        self.assertEqual(len(json.loads(out)), len(explain.RULES))

    def test_list(self):
        rc, out, _ = run_main(None, True, "text")
        self.assertEqual(rc, 0)
        for rule in explain.RULES:
            self.assertIn(f"  {rule} ", out)

    def test_unknown_rule_exits_2_with_suggestions(self):
        rc, out, err = run_main("tautological-asertion", False, "text")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("Did you mean `tautological-assertion`", err)

    def test_cli(self):
        proc = subprocess.run([sys.executable, str(ROOT / "prufgate" / "cli.py"), "explain", "test-skip-smuggling"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("issue reference", proc.stdout)
        proc = subprocess.run([sys.executable, str(ROOT / "prufgate" / "cli.py"), "explain", "no-such-rule"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
