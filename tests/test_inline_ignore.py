"""Inline `prufgate-ignore`: a reason is required, and honoured ignores are reported."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from prufgate import inline_ignore
from prufgate.anti_fabrication import detector
from prufgate.anti_reward_hacking.test_integrity import scan_diff_for_reward_hacking
from prufgate.bola.bola_engine import run_static_matrix_audit
from prufgate.contract_guard import scan_contract_guard
from prufgate.review import format_review_sarif, run_hybrid_review
from prufgate.review.reviewer import PRComment
from prufgate.synthesizer.parse_results import (
    generate_markdown,
    generate_sarif,
    load_suppressions,
    parse_raw_results,
)

# Built from two parts so the diff guard does not read these fixtures as real suppressions.
IGN = "prufgate-" "ignore"
STUB = "<button onClick={() => {}}>Save</button>"


class ParseTest(unittest.TestCase):
    def test_syntax(self):
        cases = {
            f"// {IGN}: rule-a -- why this is safe": (("rule-a",), "why this is safe"),
            f"# {IGN}: rule-a, rule-b - legacy form": (("rule-a", "rule-b"), "legacy form"),
            f"/* {IGN} -- every rule here */": ((), "every rule here"),
            f"{{/* {IGN}: rule-a -- demo only */}}": (("rule-a",), "demo only"),
            f"// {IGN}: rule-a": (("rule-a",), ""),
            f"// {IGN}": ((), ""),
            f"// {IGN}: rule-a -- */": (("rule-a",), ""),
        }
        for text, want in cases.items():
            self.assertEqual(inline_ignore.parse(text), want, text)

    def test_reason_needs_three_characters(self):
        self.assertEqual(inline_ignore.parse(f"# {IGN}: rule-a -- x"), (("rule-a",), ""))
        self.assertEqual(inline_ignore.parse(f"# {IGN}: rule-a -- x y"), (("rule-a",), ""))
        self.assertEqual(inline_ignore.parse(f"# {IGN}: rule-a -- why"), (("rule-a",), "why"))

    def test_comment_terminator_is_not_the_reason_separator(self):
        self.assertEqual(inline_ignore.parse(f"<!-- {IGN}: r --> {STUB}"), (("r",), ""))
        self.assertEqual(inline_ignore.parse(f"<!-- {IGN}: r -- real reason --> {STUB}"), (("r",), "real reason"))
        self.assertEqual(inline_ignore.parse(f"/* {IGN}: r */ x -- not a reason"), (("r",), ""))

    def test_jsx_comment_line_above_counts(self):
        lines = [f"{{/* {IGN}: r -- placeholder */}}", "bad()"]
        self.assertEqual(len(inline_ignore.context(lines, 2)), 2)

    def test_jsx_apostrophe_does_not_hide_later_ignores(self):
        lines = ["<p>Don't worry</p>", f"{{/* {IGN}: r -- placeholder */}}", "bad()"]
        self.assertIn(IGN, " ".join(inline_ignore.context(lines, 3, "Page.tsx")))

    def test_rust_lifetimes_do_not_hide_later_ignores(self):
        lines = [
            "fn pick<'a>(input: &'a str) -> &'a str { input }",
            f"// {IGN}: r -- placeholder",
            "bad()",
        ]
        self.assertIn(IGN, " ".join(inline_ignore.context(lines, 3, "lib.rs")))
        # Char literals stay literals: a quote inside one does not open a string.
        line = f"let q = '\"'; let e = '\\''; bad() // {IGN}: r -- placeholder"
        self.assertIn(IGN, " ".join(inline_ignore.context([line], 1, "lib.rs")))

    def test_review_rule_ids_are_ignorable_and_match_sarif(self):
        rule = inline_ignore.review_rule_id("Unsanitized HTML Injection (XSS)")
        self.assertEqual(rule, "pr-unsanitized-html-injection-xss")
        self.assertEqual(inline_ignore.parse(f"x; // {IGN}: {rule} -- sanitized upstream"), ((rule,), "sanitized upstream"))
        comment = PRComment(file_path="a.ts", line=1, severity="P1", title="Unsanitized HTML Injection (XSS)", message="m")
        self.assertEqual(json.loads(format_review_sarif([comment]))["runs"][0]["results"][0]["ruleId"], rule)

    def test_near_misses_are_not_ignores(self):
        for text in (f"// {IGN}d: rule-a -- x", f"// {IGN}-next: rule-a -- x", "// ignore: rule-a -- x"):
            self.assertIsNone(inline_ignore.parse(text), text)

    def test_reason_required_and_rule_must_match(self):
        kw = {"engine": "e", "path": "a.ts", "line": 1}
        with inline_ignore.recording() as recs:
            self.assertTrue(inline_ignore.suppressed([f"x // {IGN}: r -- okay"], "r", **kw))
            self.assertFalse(inline_ignore.suppressed([f"x // {IGN}: r"], "r", **kw))
            self.assertFalse(inline_ignore.suppressed([f"x // {IGN}: other -- okay"], "r", **kw))
            self.assertTrue(inline_ignore.suppressed([f"x // {IGN} -- every rule"], "r", **kw))
        self.assertEqual([e["kind"] for e in recs], ["honoured", "missing-reason"])

    def test_comment_line_above_counts_code_line_above_does_not(self):
        kw = {"engine": "e", "path": "a.ts"}
        lines = [f"// {IGN}: r -- okay", "bad()"]
        self.assertTrue(inline_ignore.suppressed_at(lines, 2, "r", **kw))
        lines = [f"call(); // {IGN}: r -- okay", "bad()"]
        self.assertFalse(inline_ignore.suppressed_at(lines, 2, "r", **kw))

    def test_records_go_to_the_suppressions_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "suppressions.jsonl"
            with mock.patch.dict(os.environ, {inline_ignore.SUPPRESSIONS_ENV: str(out)}):
                inline_ignore.suppressed([f"// {IGN}: r -- okay"], "r", engine="e", path="a.ts", line=3)
                inline_ignore.suppressed([f"// {IGN}: r -- okay"], "r", engine="e", path="a.ts", line=3)
            entries = inline_ignore.load(out)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["reason"], "okay")


class EngineTest(unittest.TestCase):
    def rules(self, src: str) -> list[str]:
        return [f.rule for f in detector.scan_text("src/Button.tsx", ".tsx", src)]

    def test_engine1_reasoned_ignore_suppresses_and_is_recorded(self):
        with inline_ignore.recording() as recs:
            self.assertEqual(self.rules(f"{STUB} {{/* {IGN}: stub-click-handler -- placeholder in the demo */}}"), [])
        self.assertEqual(recs[0]["kind"], "honoured")
        self.assertEqual(recs[0]["reason"], "placeholder in the demo")

    def test_engine1_reasonless_ignore_does_not_suppress(self):
        with inline_ignore.recording() as recs:
            self.assertEqual(self.rules(f"{STUB} {{/* {IGN}: stub-click-handler */}}"), ["stub-click-handler"])
        self.assertEqual(recs[0]["kind"], "missing-reason")

    def test_engine4_env_and_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".env.example").write_text("DATABASE_URL=x\n", encoding="utf-8")
            (ws / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
            (ws / "config.ts").write_text(
                f"export const a = process.env.FLAG_A; // {IGN}: undocumented-env-var-drift -- set by the host\n"
                f"export const b = process.env.FLAG_B; // {IGN}: undocumented-env-var-drift\n"
                f"import x from 'left-pad-example'; // {IGN} -- vendored, see docs\n",
                encoding="utf-8",
            )
            with inline_ignore.recording() as recs:
                findings = scan_contract_guard(ws)
        flagged = {(f.rule, f.line) for f in findings}
        self.assertIn(("undocumented-env-var-drift", 2), flagged)
        self.assertNotIn(("undocumented-env-var-drift", 1), flagged)
        self.assertFalse(any(f.rule == "undeclared-or-hallucinated-import" for f in findings))
        self.assertEqual(sorted(e["kind"] for e in recs), ["honoured", "honoured", "missing-reason"])

    def test_engine6_review(self):
        diff = (
            "diff --git a/src/tls.ts b/src/tls.ts\n--- a/src/tls.ts\n+++ b/src/tls.ts\n@@ -0,0 +1,2 @@\n"
            f"+const a = {{ rejectUnauthorized: false }}; // {IGN}: pr-disabled-tls-certificate-verification -- local test server\n"
            f"+const b = {{ rejectUnauthorized: false }}; // {IGN}: pr-disabled-tls-certificate-verification\n"
        )
        with inline_ignore.recording() as recs:
            comments = run_hybrid_review(diff)
        self.assertEqual([c.line for c in comments], [2])
        self.assertEqual(sorted(e["kind"] for e in recs), ["honoured", "missing-reason"])


    def test_engine5_ruleless_ignore_elsewhere_in_handler_does_not_hide_route(self):
        lookup = "  const item = await prisma.vault.findFirst({ where: { id: req.params.vaultId } });\n"
        for extra, flagged in (
            (f"  const debug = process.env.DEBUG_MODE; // {IGN} -- optional flag\n", True),
            (f"  // {IGN}: static-bola-unscoped-access -- public vault, read only\n", False),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "routes.ts").write_text(
                    "app.get('/api/vaults/:vaultId', async (req, res) => {\n" + lookup + extra
                    + "  return res.json(item);\n});\n",
                    encoding="utf-8",
                )
                with mock.patch("builtins.print"):
                    rules = [f.rule_id for f in run_static_matrix_audit(Path(tmp))]
            self.assertEqual("static-bola-unscoped-access" in rules, flagged, extra)

    def test_engine2_special_casing_ignore_on_line_above(self):
        diff = (
            "diff --git a/tests/test_calc.py b/tests/test_calc.py\n--- /dev/null\n+++ b/tests/test_calc.py\n@@ -0,0 +1,2 @@\n"
            "+def test_x():\n+    assert calc(\"special_test_input\") == 1\n"
            "diff --git a/src/calc.py b/src/calc.py\n--- /dev/null\n+++ b/src/calc.py\n@@ -0,0 +1,4 @@\n"
            f"+def calc(x):\n+    # {IGN}: test-input-special-casing -- legacy compatibility\n"
            "+    if x == \"special_test_input\":\n+        return 1\n"
        )
        self.assertEqual([f.rule for f in scan_diff_for_reward_hacking(diff)], [])


class ReportTest(unittest.TestCase):
    def test_report_lists_honoured_and_flags_reasonless(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            raw.mkdir()
            entries = [
                {"kind": "honoured", "engine": "anti-fabrication", "file": "src/a.ts", "line": 4,
                 "rule": "stub-click-handler", "severity": "P0", "message": "stub", "reason": "demo `only`"},
                {"kind": "missing-reason", "engine": "contract-guard", "file": "src/b.ts", "line": 9,
                 "rule": "undocumented-env-var-drift", "severity": "P1", "message": "env", "reason": ""},
            ]
            (raw / "suppressions.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")

            findings = parse_raw_results(raw)
            self.assertEqual([(f.rule_id, f.severity, f.line) for f in findings], [("ignore-without-reason", "P2", 9)])

            suppressed = load_suppressions(raw)
            generate_sarif(findings, Path(tmp) / "out.sarif", suppressed=suppressed)
            results = json.loads((Path(tmp) / "out.sarif").read_text())["runs"][0]["results"]
            hidden = [r for r in results if "suppressions" in r]
            self.assertEqual(len(hidden), 1)
            self.assertEqual(hidden[0]["ruleId"], "anti-fabrication-stub-click-handler")
            self.assertEqual(hidden[0]["suppressions"], [{"kind": "inSource", "justification": "demo 'only'"}])

            generate_markdown(findings, None, Path(tmp) / "out.md", suppressed=suppressed)
            md = (Path(tmp) / "out.md").read_text()
            self.assertIn("| **Inline ignores** | 1 |", md)
            self.assertIn("`src/a.ts:4` `anti-fabrication-stub-click-handler`", md)
            self.assertIn("demo 'only'", md)

    def test_no_file_no_ignores(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_suppressions(Path(tmp)), [])


if __name__ == "__main__":
    unittest.main()
