"""False positives seen on real, reviewed code, as invented fixtures: each rule keeps
firing on the cheat and stays quiet on the near miss."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from prufgate.anti_fabrication import detector, literals
from prufgate.anti_reward_hacking import test_integrity
from prufgate.diff_guard.tamper_detector import scan_diff_for_tampering
from prufgate.review import reviewer


def _rules(rel: str, src: str) -> set[str]:
    detector.apply_settings({})
    return {f.rule for f in detector.scan_text(rel, Path(rel).suffix, src)}


def _diff(path: str, *added: str, context: tuple[str, ...] = ()) -> str:
    body = "".join(f" {c}\n" for c in context) + "".join(f"+{a}\n" for a in added)
    n = len(context)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,{n} +1,{n + len(added)} @@\n{body}"


def _guard(path: str, *added: str, context: tuple[str, ...] = ()) -> dict[str, str]:
    """{rule: severity} the diff guard reports."""
    return {f.rule: f.severity for f in scan_diff_for_tampering(_diff(path, *added, context=context))}


def _review(path: str, *added: str) -> list[str]:
    return [c.title for c in reviewer.analyze_diff(reviewer.parse_diff_hunks(_diff(path, *added)))]


EMPTY = "unhandled-empty-catch"
CANNED = "canned-error-fallback"


class EmptyCatch(unittest.TestCase):
    def test_no_value_answer_is_not_an_empty_catch(self):
        src = "function toUrl(s: string): URL | null {\n  try {\n    return new URL(s);\n  } catch {\n    return null;\n  }\n}\n"
        self.assertNotIn(EMPTY, _rules("src/url.ts", src))
        for value in ("false", "undefined", "{}"):
            self.assertNotIn(EMPTY, _rules("src/url.ts", src.replace("return null;", f"return {value};")), value)

    def test_best_effort_cleanup(self):
        src = "export const pool = {\n  close: async () => { try { await conn.end(); } catch {} },\n};\n"
        self.assertNotIn(EMPTY, _rules("src/pool.ts", src))

    def test_retry_loop(self):
        src = "async function ready() {\n  for (;;) {\n    try { v = await probe(); break; } catch {}\n    await sleep(200);\n  }\n}\n"
        self.assertNotIn(EMPTY, _rules("src/ready.ts", src))

    def test_return_in_try_with_the_failure_path_below(self):
        src = "async function ping() {\n  try { await reach(); return; } catch {}\n  report(\"unreachable\");\n}\n"
        self.assertNotIn(EMPTY, _rules("src/ping.ts", src))
        swallowed = "async function save(o) {\n  try { return await db.insert(o); } catch {}\n}\n"
        self.assertIn(EMPTY, _rules("src/save.ts", swallowed))

    def test_read_into_a_variable_that_holds_its_default(self):
        src = 'function frameOf(r) {\n  let f = "";\n  try { f = r.frame().url(); } catch {}\n  return f;\n}\n'
        self.assertNotIn(EMPTY, _rules("src/frame.ts", src))

    def test_a_comment_giving_a_reason(self):
        src = "try {\n  el.showPopover();\n} catch {\n  // No popover support: the fallback style still applies.\n}\n"
        self.assertNotIn(EMPTY, _rules("src/popover.ts", src))
        for comment in (
            "// ignore",
            "// TODO handle this later",
            "/* noop */",
            "// swallow any errors here",
            "// ignore all errors silently",
            "// do nothing on error",
        ):
            self.assertIn(EMPTY, _rules("src/popover.ts", src.replace("// No popover support: the fallback style still applies.", comment)), comment)

    def test_comment_with_brace_inside_catch_does_not_truncate_body(self):
        src = "try {\n  run();\n} catch (e) { // }\n  throw e;\n}\n"
        self.assertNotIn(EMPTY, _rules("src/run.ts", src))

    def test_swallowed_write_then_success_still_fires(self):
        src = "async function save(o) {\n  try { await db.insert(o); } catch {}\n  return { saved: true };\n}\n"
        self.assertIn(EMPTY, _rules("src/save.ts", src))

    def test_a_promise_catch_on_the_line_does_not_report_a_later_catch(self):
        src = (
            "async function f() {\n  const data = await res.json().catch(() => null);\n  try {\n    return g(data);\n"
            "  } catch {\n    return { success: false, error: \"not confirmed\" };\n  }\n}\n"
        )
        lines = src.split("\n")
        self.assertIsNone(detector.check_empty_catch(lines, 1))


class CannedFallback(unittest.TestCase):
    def test_failure_result_is_not_canned(self):
        for body in (
            '{ success: false, error: "Could not save." }',
            '{ ok: false, status: 0, reason: "unreachable" }',
            '{ state: "unavailable", reason: "could not read" }',
            "{ providerId: raw }",
            '{ ok: false, error: { code: "TIMEOUT", message: "upstream timed out" } }',
        ):
            src = f"function f() {{\n  try {{\n    return load();\n  }} catch {{\n    return {body};\n  }}\n}}\n"
            self.assertNotIn(CANNED, _rules("src/f.ts", src), body)

    def test_canned_success_fires(self):
        for body in (
            "{ success: true, items: [] }",
            "{ inStock: true, count: 100 }",
            '{ valid: true, status: "ok" }',
            '{ ok: true, meta: { retries: 1 }, status: "synced" }',
            "{ charged: true, amount: 100, error: undefined }",
            "{ refunded: true, failed: false }",
            '{ status: "synced", error: null }',
        ):
            src = f"function f() {{\n  try {{\n    return load();\n  }} catch {{\n    return {body};\n  }}\n}}\n"
            self.assertIn(CANNED, _rules("src/f.ts", src), body)

    def test_promise_catch_answering_a_canned_success(self):
        self.assertIn(CANNED, _rules("src/f.ts", "const r = await charge(o).catch(() => ({ ok: true, status: \"success\" }));\n"))
        self.assertNotIn(CANNED, _rules("src/f.ts", "const r = await charge(o).catch((e) => ({ ok: false, error: String(e) }));\n"))

    def test_go_error_carried_in_the_body(self):
        ok = 'func H(c *gin.Context) {\n\tr, err := run()\n\tif err != nil {\n\t\tc.JSON(200, gin.H{"result": r, "error": err.Error()})\n\t\treturn\n\t}\n}\n'
        self.assertNotIn(CANNED, _rules("api/h.go", ok))
        bad = 'func H(c *gin.Context) {\n\t_, err := run()\n\tif err != nil {\n\t\tc.JSON(200, gin.H{"status": "ok"})\n\t\treturn\n\t}\n}\n'
        self.assertIn(CANNED, _rules("api/h.go", bad))
        nil_err = 'func H(c *gin.Context) {\n\t_, err := run()\n\tif err != nil {\n\t\tc.JSON(200, gin.H{"error": nil, "data": "x"})\n\t\treturn\n\t}\n}\n'
        self.assertIn(CANNED, _rules("api/h.go", nil_err))


TIPS = 'const TIPS = ["onClick={() => {}}", "return { ok: true }", "exec(\\`run ${x}\\`)"];'


class StringLiterals(unittest.TestCase):
    def test_spans(self):
        line = "a = 'x' + \"y\" + `z ${w}` // it's"
        self.assertEqual(len(literals.string_spans(line)), 3)
        self.assertEqual(literals.string_spans("const x = a as any; // don't use update() here"), [])

    def test_code_quoted_in_strings_is_not_code(self):
        rules = _rules("src/tips.tsx", TIPS + "\n")
        self.assertFalse(rules & {"stub-click-handler", "simulated-return-value"}, rules)

    def test_the_code_itself_still_fires(self):
        self.assertIn("stub-click-handler", _rules("src/b.tsx", "<button onClick={() => {}}>Save</button>\n"))
        self.assertIn("stub-click-handler", _rules("src/b.tsx", "const el = /* don't */ <button onClick={() => {}}>Save</button>;\n"))


class StringLiteralsDiffGuard(unittest.TestCase):
    def test_a_quoted_directive_is_not_a_suppression(self):
        self.assertNotIn("suppression-comment-smuggling", _guard("src/tips.tsx", 'const TIPS = ["# noqa", "@ts-ignore"];'))
        self.assertIn("suppression-comment-smuggling", _guard("app/x.py", "x = 1  # noqa"))


class StringLiteralsReview(unittest.TestCase):
    def test_quoted_commands_are_not_calls(self):
        self.assertEqual(_review("src/tips.ts", TIPS), [])
        self.assertIn("Shell Command Injection Risk", _review("src/run.ts", "exec(`rm ${userPath}`);"))


class SqlInjection(unittest.TestCase):
    def test_interpolation_in_the_bind_parameters_is_a_value(self):
        line = 'await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`lock:${t}`]);'
        self.assertEqual(_review("src/lock.ts", line), [])

    def test_interpolation_in_the_query_fires(self):
        self.assertIn("SQL Injection Vector", _review("src/notes.ts", "await db.query(`SELECT * FROM notes WHERE id = ${id}`);"))

    def test_multiline_query(self):
        self.assertIn("SQL Injection Vector", _review("src/notes.ts", "await db.query(", "  `SELECT * FROM notes WHERE id = ${id}`,", ");"))
        self.assertIn("SQL Injection Vector", _review("src/notes.ts", "await db.query(`", "  SELECT * FROM notes", "  WHERE id = ${id}`);"))
        self.assertIn("SQL Injection Vector", _review("src/notes.ts", "await db.query( // sql", "  `SELECT * FROM notes WHERE id = ${id}`,", ");"))
        self.assertEqual(_review("src/notes.ts", "await db.query(", "  `SELECT * FROM notes WHERE id = $1`,", "  [id],", ");"), [])


class SkipSmuggling(unittest.TestCase):
    def test_capability_probe_above_the_skip(self):
        got = _guard(
            "pkg/sign_test.go",
            '\t\tt.Skip("openssl not installed")',
            "\t}",
            context=("func TestSign(t *testing.T) {", '\tif _, err := exec.LookPath("openssl"); err != nil {'),
        )
        self.assertNotIn("test-skip-smuggling", got)

    def test_bare_skip_and_non_env_guards_fire(self):
        self.assertIn("test-skip-smuggling", _guard("pkg/sign_test.go", '\tt.Skip("flaky, fix later")', context=("func TestSign(t *testing.T) {",)))
        # os.Stat is not an environment/capability guard.
        self.assertIn(
            "test-skip-smuggling",
            _guard("pkg/sign_test.go", '\t\tt.Skip("flaky")', context=("func TestSign(t *testing.T) {", '\tif _, err := os.Stat("x"); err == nil {')),
        )
        # CI env check is not a legitimate skip guard.
        self.assertIn("test-skip-smuggling", _guard("src/a.test.ts", "  if (process.env.CI) ctx.skip();"))
        # Unrelated process.env / os.environ read on a preceding line does not guard an unconditional skip.
        self.assertIn(
            "test-skip-smuggling",
            _guard("src/a.test.ts", 'const base = process.env.API_URL || "http://localhost";', 'test.skip("broken", () => {});'),
        )
        self.assertIn(
            "test-skip-smuggling",
            _guard("tests/test_a.py", 'HOME = os.environ.get("HOME", "/tmp")', '@pytest.mark.skip(reason="broken")', "def test_a(): pass"),
        )


class Suppressions(unittest.TestCase):
    def test_named_line_disable_in_a_test_is_a_warning(self):
        line = "const raw = load() as any; // eslint-disable-line @typescript-eslint/no-explicit-any"
        self.assertEqual(_guard("src/__tests__/load.test.ts", line).get("suppression-comment-smuggling"), "P2")

    def test_bare_file_disable_in_production_blocks(self):
        self.assertEqual(_guard("src/load.ts", "/* eslint-disable */").get("suppression-comment-smuggling"), "P1")
        mixed = "const x = 1; // eslint-disable-line no-console -- /* eslint-disable */"
        self.assertEqual(_guard("src/__tests__/load.test.ts", mixed).get("suppression-comment-smuggling"), "P1")


class TypeCasts(unittest.TestCase):
    def test_single_double_cast_is_a_warning(self):
        got = _guard("src/limits.ts", "const next = Object.fromEntries(p) as unknown as Limits;", "validateLimits(next);")
        self.assertEqual(got.get("unsafe-type-cast-cascade"), "P2")

    def test_any_blocks(self):
        self.assertEqual(_guard("src/load.ts", "const body = (await res.json()) as any;").get("unsafe-type-cast-cascade"), "P1")
        self.assertEqual(_guard("src/load.ts", "const body = (a as unknown as B) || (b as any);").get("unsafe-type-cast-cascade"), "P1")
        self.assertEqual(_guard("src/load.ts", "const body = a as any; // don't use update()").get("unsafe-type-cast-cascade"), "P1")

    def test_a_run_of_double_casts_blocks(self):
        got = _guard("src/load.ts", "const a = x as unknown as A;", "const b = y as unknown as B;")
        self.assertEqual(got.get("unsafe-type-cast-cascade"), "P1")

    def test_any_in_a_string_is_not_a_cast(self):
        self.assertNotIn("unsafe-type-cast-cascade", _guard("src/help.ts", 'const HELP = "filter mode: any, active or archived";'))


class FormSubmit(unittest.TestCase):
    RULE = "disconnected-form-submit"

    def test_keydown_handler_is_not_a_form(self):
        src = 'el.addEventListener("keydown", (e) => {\n  if (e.key !== "End") return;\n  e.preventDefault();\n  go("last");\n});\n'
        self.assertNotIn(self.RULE, _rules("src/tabs.ts", src))

    def test_submit_handler_that_does_work(self):
        src = 'form.addEventListener("submit", async (e) => {\n  e.preventDefault();\n  const v = input.value.trim();\n  if (!v) return;\n  show(await scanSite(v));\n});\n'
        self.assertNotIn(self.RULE, _rules("src/form.ts", src))

    def test_submit_handler_that_only_prevents_default(self):
        self.assertIn(self.RULE, _rules("src/F.tsx", "<form onSubmit={(e) => { e.preventDefault(); }}>\n"))
        self.assertIn(self.RULE, _rules("src/F.tsx", '<form onSubmit={(e) => { e.preventDefault(); console.log("sent"); }}>\n'))
        self.assertIn(self.RULE, _rules("src/F.tsx", '<form onSubmit={(e) => { e.preventDefault(); console.log(foo("x")); }}>\n'))


class DocumentationAddress(unittest.TestCase):
    RULE = "documentation-address"

    def test_placeholder_ternary_and_example_text(self):
        src = 'placeholder={\n  kind === "url" ? "https://example.com/path"\n  : "name"\n}\n'
        self.assertNotIn(self.RULE, _rules("src/Field.tsx", src))
        self.assertNotIn(self.RULE, _rules("src/hint.ts", 'return "Enter a full URL, for example https://api.example.com/hook.";\n'))

    def test_live_endpoint_fires(self):
        self.assertIn(self.RULE, _rules("src/client.ts", 'const UPSTREAM = "https://example.com/api";\n'))
        self.assertIn(self.RULE, _rules("src/client.ts", 'const UPSTREAM = "https://example.com/api"; // for example in staging\n'))


class RewardHackingRegressions(unittest.TestCase):
    def test_float_backtick_and_in_list_special_casing_fire(self):
        diff = (
            "diff --git a/tests/test_tax.py b/tests/test_tax.py\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/tests/test_tax.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def test_tax():\n"
            '+    assert tax("SPEC-99", 14.25) == 1\n'
            "diff --git a/src/tax.py b/src/tax.py\n"
            "--- a/src/tax.py\n"
            "+++ b/src/tax.py\n"
            "@@ -1,1 +1,5 @@\n"
            " def tax(code, rate):\n"
            '+    if code in ("SPEC-99", "OTHER"):\n'
            "+        return 1\n"
            "+    if rate == 14.25:\n"
            "+        return 1\n"
        )
        fs = test_integrity.scan_diff_for_reward_hacking(diff)
        lines = {f.line for f in fs if f.rule == "test-input-special-casing"}
        self.assertEqual(lines, {2, 4})

    def test_decoy_second_file_still_fires_special_casing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "discount.ts").write_text(
                'export function discount(code: string): number {\n  if (code === "SPRING-7731") {\n    return 25;\n  }\n  return 0;\n}\n'
            )
            (ws / "src" / "labels.ts").write_text('export const LABELS = { promo: "SPRING-7731" };\n')
            (ws / "src" / "discount.test.ts").write_text(
                'import { discount } from "./discount";\ntest("d", () => { expect(discount("x")).toBe(0); });\n'
                'test("s", () => { expect(discount("SPRING-7731")).toBe(25); });\n'
            )
            diff = (
                "diff --git a/src/discount.test.ts b/src/discount.test.ts\n"
                "--- a/src/discount.test.ts\n"
                "+++ b/src/discount.test.ts\n"
                "@@ -2,1 +2,2 @@\n"
                ' test("d", () => { expect(discount("x")).toBe(0); });\n'
                '+test("s", () => { expect(discount("SPRING-7731")).toBe(25); });\n'
                "diff --git a/src/discount.ts b/src/discount.ts\n"
                "--- a/src/discount.ts\n"
                "+++ b/src/discount.ts\n"
                "@@ -1,2 +1,5 @@\n"
                " export function discount(code: string): number {\n"
                '+  if (code === "SPRING-7731") {\n'
                "+    return 25;\n"
                "+  }\n"
                "   return 0;\n"
                "diff --git a/src/labels.ts b/src/labels.ts\n"
                "new file mode 100644\n"
                "--- /dev/null\n"
                "+++ b/src/labels.ts\n"
                "@@ -0,0 +1,1 @@\n"
                '+export const LABELS = { promo: "SPRING-7731" };\n'
            )
            fs = test_integrity.scan_diff_for_reward_hacking(diff, repo_root=ws)
            self.assertEqual([f.rule for f in fs], ["test-input-special-casing"])

    def test_retired_feature_multiline_import_vs_partial_retire(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            # Multiline import of a deleted module is retired cleanly.
            del_diff = (
                "diff --git a/src/old.ts b/src/old.ts\n"
                "deleted file mode 100644\n"
                "--- a/src/old.ts\n"
                "+++ /dev/null\n"
                "@@ -1,1 +0,0 @@\n"
                "-export function gone() { return 1; }\n"
                "diff --git a/src/old.test.ts b/src/old.test.ts\n"
                "deleted file mode 100644\n"
                "--- a/src/old.test.ts\n"
                "+++ /dev/null\n"
                "@@ -1,5 +0,0 @@\n"
                "-import {\n"
                "-  gone,\n"
                '-} from "./old";\n'
                '-test("g", () => { expect(gone()).toBe(1); });\n'
            )
            self.assertEqual(test_integrity.scan_diff_for_reward_hacking(del_diff, repo_root=ws), [])
            # Partial retire (one function stays on disk) still flags test deletion.
            (ws / "src" / "svc.ts").write_text("export function stay() { return 2; }\n")
            partial_diff = (
                "diff --git a/src/svc.ts b/src/svc.ts\n"
                "--- a/src/svc.ts\n"
                "+++ b/src/svc.ts\n"
                "@@ -1,2 +1,1 @@\n"
                "-export function drop() { return 1; }\n"
                " export function stay() { return 2; }\n"
                "diff --git a/src/svc.test.ts b/src/svc.test.ts\n"
                "deleted file mode 100644\n"
                "--- a/src/svc.test.ts\n"
                "+++ /dev/null\n"
                "@@ -1,3 +0,0 @@\n"
                '-import { drop, stay } from "./svc";\n'
                '-test("s", () => { expect(stay()).toBe(2); });\n'
            )
            rules = [f.rule for f in test_integrity.scan_diff_for_reward_hacking(partial_diff, repo_root=ws)]
            self.assertIn("diff-test-file-deleted", rules)

    def test_custom_tsconfig_alias_self_mock_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "tsconfig.json").write_text('{"compilerOptions": {"paths": {"@app/*": ["src/lib/*"]}}}\n')
            tfile = ws / "src" / "lib" / "auth.test.ts"
            tfile.parent.mkdir(parents=True)
            content = (
                'import { vi, test, expect } from "vitest";\n'
                'vi.mock("@app/auth", () => ({ login: () => true }));\n'
                'import { login } from "@app/auth";\n'
                'test("login", () => { expect(login()).toBe(true); });\n'
            )
            tfile.write_text(content)
            rules = {f.rule for f in test_integrity.scan_test_file(tfile, content)}
            self.assertIn("self-mocked-unit-under-test", rules)

    def test_unwrapped_assertion_keeping_call_still_fires_weakening(self):
        diff = (
            "diff --git a/app/calc.py b/app/calc.py\n"
            "--- a/app/calc.py\n"
            "+++ b/app/calc.py\n"
            "@@ -1,5 +1,3 @@\n"
            " def parse_config(text):\n"
            "     data = json.loads(text)\n"
            '-    if "name" not in data:\n'
            '-        raise ValueError("config needs a name")\n'
            "     return data\n"
            "diff --git a/tests/test_calc.py b/tests/test_calc.py\n"
            "--- a/tests/test_calc.py\n"
            "+++ b/tests/test_calc.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def test_parse_config(self):\n"
            '-    self.assertEqual(parse_config(\'{"name": "x"}\')["name"], "x")\n'
            '+    parse_config(\'{"name": "x"}\')\n'
        )
        rules = {f.rule for f in test_integrity.scan_diff_for_reward_hacking(diff)}
        self.assertIn("diff-assertion-weakening", rules)


if __name__ == "__main__":
    unittest.main()
