"""Regression tests for audited defects in Engines 1-3 (anti-fabrication,
test integrity, diff guard). Each test reproduces one defect with an invented
fixture and must keep passing once fixed.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from prufgate.anti_fabrication import detector  # noqa: E402
from prufgate.anti_reward_hacking import test_integrity as ti  # noqa: E402
from prufgate.diff_guard import tamper_detector as dg  # noqa: E402

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=GIT_ENV)


def make_repo(tmp: str) -> Path:
    repo = Path(tmp) / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("x\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def run_engine(script: str, cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / script), *args], cwd=cwd, capture_output=True, text=True, env=GIT_ENV
    )


def diff_rules(diff: str) -> set[str]:
    return {f.rule for f in dg.scan_diff_for_tampering(diff)}


def one_line_diff(path: str, removed: str | None, added: str | None, header: str = "") -> str:
    body = (f"-{removed}\n" if removed is not None else "") + (f"+{added}\n" if added is not None else "")
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@{header}\n{body}"


class Leak03CoreFixtures(unittest.TestCase):
    """LEAK-03: the core detector carries no threat-intelligence vocabulary."""

    def test_core_detector_source_is_domain_neutral(self):
        src = (ROOT / "prufgate/anti_fabrication/detector.py").read_text(encoding="utf-8")
        hits = [
            n
            for n, line in enumerate(src.splitlines(), 1)
            if re.search(r"jarm|\bioc|threat|\bapt\d|lazarus|typhoon|malware|indicator|\bc2", line, re.I)
        ]
        self.assertEqual(hits, [], f"CTI vocabulary in core detector lines {hits}")

    def test_cti_rules_only_with_pack(self):
        detector.apply_settings({})
        try:
            line = "  reputation: 'Malicious', threatScore: 95,"
            for rule_line in (line, "  const cve = 'CVE-2024-12345';"):
                self.assertEqual(detector.raw_findings("src/lib/x.ts", ".ts", rule_line), [])
        finally:
            detector.apply_settings({})


class Bug04CrossDirectory(unittest.TestCase):
    def test_changed_files_runs_git_in_given_workspace_and_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "new.py").write_text("x = 1\n")
            self.assertIn("new.py", detector.changed_files(cwd=repo))
            plain = Path(tmp) / "plain"
            plain.mkdir()
            with self.assertRaises(detector.GitError):
                detector.changed_files(cwd=plain)
            with self.assertRaisesRegex(detector.GitError, "refusing"):
                detector.changed_files("--output=/tmp/x", cwd=repo)

    def test_absolute_path_gets_workspace_relative_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            route = repo / "src/app/api/items/route.ts"
            route.parent.mkdir(parents=True)
            route.write_text(
                "export async function GET() {\n  if (!upstream.ok) {\n"
                '    return NextResponse.json({ items: [{ sku: "a" }] });\n  }\n}\n'
            )
            detector.apply_settings({})
            got = {f.rule for f in detector.scan_file(route)}
            self.assertIn("route-canned-fallback", got)
            self.assertTrue(all(not f.path.startswith("/") for f in detector.scan_file(route)))

    def test_cli_exit_2_when_not_a_git_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = run_engine("prufgate/anti_fabrication/detector.py", Path(tmp), "--changed")
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


class Bug07WholeSegments(unittest.TestCase):
    def test_production_dirs_with_skip_substrings_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "build" / "proj"
            for rel in ("src/checkout/pay.py", "src/layout/view.py", "src/contests/x.py", "src/app/reports/r.py"):
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x = 1\n")
            (root / "tests").mkdir()
            (root / "tests/x.py").write_text("x = 1\n")
            detector.apply_settings({})
            got = {p.relative_to(root).as_posix() for p in detector.collect([str(root)])}
            self.assertEqual(
                got, {"src/checkout/pay.py", "src/layout/view.py", "src/contests/x.py", "src/app/reports/r.py"}
            )

    def test_user_exemption_is_not_a_substring_match(self):
        detector.apply_settings({"exempt": {("a.ts", "demo-named-data"): "#1: x"}})
        try:
            self.assertTrue(detector.scan_text("src/data.ts", ".ts", "const MOCK_USERS = [];"))
            self.assertFalse(detector.scan_text("a.ts", ".ts", "const MOCK_USERS = [];"))
        finally:
            detector.apply_settings({})

    def test_test_integrity_scans_a_users_own_test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "tests").mkdir()
            (repo / "tests/test_cli.py").write_text("def test_cli():\n    run()\n")
            r = run_engine("prufgate/anti_reward_hacking/test_integrity.py", repo, "tests")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("zero-assertion-test", r.stderr)


class Bug03Untracked(unittest.TestCase):
    def test_diff_guard_sees_untracked_new_test_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "auth.test.ts").write_text("it.skip('rejects expired', () => { expect(1).toBe(2); });\n")
            r = run_engine("prufgate/diff_guard/tamper_detector.py", repo, "--changed")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("test-skip-smuggling", r.stderr)

    def test_test_integrity_changed_includes_untracked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "tests").mkdir()
            (repo / "tests/test_new.py").write_text("def test_new():\n    run()\n")
            r = run_engine("prufgate/anti_reward_hacking/test_integrity.py", repo, "--changed")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("zero-assertion-test", r.stderr)


class Bug08DiffGuard(unittest.TestCase):
    def test_coverage_threshold_lowering(self):
        self.assertIn("coverage-threshold-lowering", diff_rules(one_line_diff("pyproject.toml", "fail_under = 90", "fail_under = 60")))
        self.assertIn(
            "coverage-threshold-lowering",
            diff_rules(one_line_diff("vitest.config.ts", "      lines: 85,", "      lines: 40,")),
        )
        self.assertIn(
            "coverage-threshold-lowering",
            diff_rules(one_line_diff(".github/workflows/ci.yml", "  run: pytest --cov-fail-under=90", "  run: pytest")),
        )
        self.assertNotIn("coverage-threshold-lowering", diff_rules(one_line_diff("pyproject.toml", "fail_under = 60", "fail_under = 90")))

    def test_prufgate_config_self_exemption(self):
        self.assertIn(
            "prufgate-config-self-exemption",
            diff_rules(one_line_diff(".prufgate/config.yaml", None, "  src/pay.ts: { canned-error-fallback: '#1: later' }", " exempt:")),
        )
        self.assertIn(
            "prufgate-config-self-exemption",
            diff_rules(one_line_diff(".prufgate/config.yaml", "  - core", None, " packs:")),
        )
        self.assertNotIn(
            "prufgate-config-self-exemption",
            diff_rules(one_line_diff(".prufgate/config.yaml", None, "  - cti", " packs:")),
        )

    def test_skip_scoped_to_test_calls(self):
        self.assertEqual(diff_rules(one_line_diff("src/lib.rs", None, "    let rest = items.iter().skip(1);")), set())
        self.assertEqual(diff_rules(one_line_diff("src/db.js", None, "  return col.find().skip(10).limit(5);")), set())
        self.assertIn("test-skip-smuggling", diff_rules(one_line_diff("a.test.ts", None, "test.describe.skip('x', () => {")))

    def test_acronyms_are_not_ticket_references(self):
        for added in ("it.skip('decodes utf-8 input', () => {", "it.skip('hashes with SHA-256', () => {"):
            self.assertIn("test-skip-smuggling", diff_rules(one_line_diff("a.test.ts", None, added)))
        self.assertEqual(diff_rules(one_line_diff("a.test.ts", None, "it.skip('flaky upstream', () => { // PROJ-42")), set())

    def test_rust_inner_allow(self):
        self.assertIn("suppression-comment-smuggling", diff_rules(one_line_diff("src/lib.rs", None, "#![allow(dead_code)]")))

    def test_git_argument_injection_and_bad_inputs_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            out = Path(tmp) / "pwned"
            r = run_engine("prufgate/diff_guard/tamper_detector.py", repo, f"--base=--output={out}")
            self.assertEqual(r.returncode, 2)
            self.assertFalse(out.exists())
            self.assertEqual(run_engine("prufgate/diff_guard/tamper_detector.py", repo, "--base=no-such-ref").returncode, 2)
            self.assertEqual(run_engine("prufgate/diff_guard/tamper_detector.py", repo, "--diff-file=missing.patch").returncode, 2)
            self.assertEqual(run_engine("prufgate/diff_guard/tamper_detector.py", Path(tmp), "--changed").returncode, 2)
            self.assertEqual(run_engine("prufgate/anti_reward_hacking/test_integrity.py", repo, "--diff-file=missing.patch").returncode, 2)
            self.assertEqual(run_engine("prufgate/anti_reward_hacking/test_integrity.py", repo, "--changed=no-such-ref").returncode, 2)

    def test_non_utf8_diff_does_not_disable_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "a.test.ts").write_bytes(b"// caf\xe9\nit('x', () => { expect(f()).toBe(1); });\n")
            git(repo, "add", ".")
            git(repo, "commit", "-q", "-m", "a")
            (repo / "a.test.ts").write_bytes(b"// caf\xe9\nit.skip('x', () => { expect(f()).toBe(1); });\n")
            r = run_engine("prufgate/diff_guard/tamper_detector.py", repo, "--changed")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)


class TautologyCoverage(unittest.TestCase):
    def test_literal_and_self_comparisons(self):
        for line in ("    assert 1 == 1", "    assert result == result", "    assert 'a' == 'a'"):
            src = f"def test_x():\n    result = f()\n{line}\n"
            self.assertIn("tautological-assertion", {f.rule for f in ti.scan_test_file("tests/test_x.py", src)}, line)
        self.assertEqual(ti.scan_test_file("tests/test_x.py", "def test_x():\n    assert f(1) == 2\n"), [])


class Bug14Coverage(unittest.TestCase):
    def test_comment_with_triple_quote_does_not_hide_rest_of_file(self):
        detector.apply_settings({})
        src = 'x = 1  # a """ inside a comment\ndef score():\n    # placeholder: would normally compute\n    return 0.95\n'
        self.assertIn("simulated-return-value", {f.rule for f in detector.scan_text("app/s.py", ".py", src)})
        src2 = '# a """ comment line\ndef score():\n    # placeholder: would normally compute\n    return 0.95\n'
        self.assertIn("simulated-return-value", {f.rule for f in detector.scan_text("app/s.py", ".py", src2)})

    def test_pytest_fixture_named_test_is_not_a_test(self):
        src = "import pytest\n\n@pytest.fixture\ndef test_user():\n    return make_user()\n\ndef test_ok(test_user):\n    assert test_user.id\n"
        self.assertEqual(ti.scan_test_file("tests/test_u.py", src), [])

    def test_catch_fallbacks_in_more_languages(self):
        detector.apply_settings({})
        cases = {
            "src/main/java/OrderController.java": "try {\n  return svc.list();\n} catch (Exception e) {\n  return ResponseEntity.ok(Map.of(\"ok\", true));\n}\n",
            "app/Http/Controllers/OrderController.php": "try {\n  return $svc->list();\n} catch (Exception $e) {\n  return response()->json(['ok' => true]);\n}\n",
            "Controllers/OrdersController.cs": "try {\n  return Ok(svc.List());\n} catch (Exception) {\n  return Ok(new { success = true });\n}\n",
            "src/main/kotlin/Orders.kt": "try {\n  svc.list()\n} catch (e: Exception) {\n  return mapOf(\"ok\" to true)\n}\n",
            "app/controllers/orders_controller.rb": "def index\n  render json: svc.list\nrescue StandardError\n  render json: { ok: true }\nend\n",
        }
        for rel, src in cases.items():
            got = {f.rule for f in detector.scan_text(rel, Path(rel).suffix, src)}
            self.assertIn("canned-error-fallback", got, rel)
        java_ok = "try {\n  return svc.list();\n} catch (Exception e) {\n  return ResponseEntity.ok(Collections.emptyList());\n}\n"
        self.assertIn("canned-error-fallback", {f.rule for f in detector.scan_text("src/main/java/B.java", ".java", java_ok)})
        logged = "try {\n  return svc.list();\n} catch (Exception e) {\n  log.error(\"x\", e);\n  throw e;\n}\nreturn ResponseEntity.ok(Map.of(\"ok\", true));\n"
        self.assertEqual(detector.scan_text("src/main/java/A.java", ".java", logged), [])

    def test_hollow_tests_in_more_languages(self):
        cases = {
            "tests/OrderTest.php": "class OrderTest extends TestCase {\n  public function testTotal(): void {\n    $o = new Order();\n  }\n}\n",
            "Tests/OrderTests.cs": "public class OrderTests {\n  [Fact]\n  public void Total() {\n    var o = new Order();\n  }\n}\n",
            "spec/order_spec.rb": "describe Order do\n  it 'totals' do\n    o = Order.new\n  end\nend\n",
        }
        for rel, src in cases.items():
            self.assertEqual({f.rule for f in ti.scan_test_file(rel, src)}, {"zero-assertion-test"}, rel)
        good = {
            "tests/OrderTest.php": "class OrderTest extends TestCase {\n  public function testTotal(): void {\n    $this->assertSame(3, (new Order())->total());\n  }\n}\n",
            "Tests/OrderTests.cs": "public class OrderTests {\n  [Fact]\n  public void Total() {\n    Assert.Equal(3, new Order().Total());\n  }\n}\n",
            "spec/order_spec.rb": "describe Order do\n  it 'totals' do\n    if true\n      o = Order.new\n    end\n    expect(o.total).to eq(3)\n  end\nend\n",
        }
        for rel, src in good.items():
            self.assertEqual(ti.scan_test_file(rel, src), [], rel)


if __name__ == "__main__":
    unittest.main()


class ReviewFollowUps(unittest.TestCase):
    """Defects found in review of the first round of fixes."""

    def test_runtime_and_language_specific_skips(self):
        cases = {
            "a.test.js": "  this.skip();",
            "b.test.mjs": "  t.skip('needs network');",
            "c.test.ts": "  ctx.skip();",
            "spec/order_spec.rb": "  xit 'totals' do",
            "Tests/OrderTests.cs": '  [Fact(Skip = "flaky")]',
            "tests/OrderTest.php": "    $this->markTestSkipped('later');",
        }
        for path, added in cases.items():
            self.assertIn("test-skip-smuggling", diff_rules(one_line_diff(path, None, added)), path)

    def test_prufgate_config_more_widening_sections_and_quoted_keys(self):
        for section, line in (("evidence_markers", "  - looksFine"), ("auth_guards", "  - anything"), ("tenant_keys", "  - id")):
            self.assertIn(
                "prufgate-config-self-exemption",
                diff_rules(one_line_diff(".prufgate/config.yaml", None, line, f" {section}:")),
                section,
            )
        self.assertIn(
            "prufgate-config-self-exemption",
            diff_rules(one_line_diff(".prufgate/config.yaml", None, '"exempt": {"canned-error-fallback": ["src/a.py"]}')),
        )

    def test_non_ascii_file_names_are_seen(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            (repo / "tests").mkdir()
            (repo / "tests/test_café.py").write_text("def test_x():\n    run()\n")
            (repo / "señal.py").write_text("x = 1\n")
            self.assertIn("señal.py", detector.changed_files(cwd=repo))
            names = {p.name for p in ti._changed_files(cwd=repo, strict=True)}
            self.assertIn("test_café.py", names)
            self.assertIn("test_café.py", ti._get_git_diff(cwd=repo, strict=True))

    def test_ruby_expression_if_and_one_line_examples(self):
        expr = "describe A do\n  it 'x' do\n    y = if ready? then 1 else 2 end\n    z = case k\n      when 1 then 2\n    end\n    expect(y).to eq(1)\n  end\nend\n"
        self.assertEqual(ti.scan_test_file("spec/a_spec.rb", expr), [])
        one = "describe A do\n  it 'x' do expect(a).to eq(1) end\nend\n"
        self.assertEqual(ti.scan_test_file("spec/a_spec.rb", one), [])
        hollow = "describe A do\n  it 'x' do run end\nend\n"
        self.assertEqual({f.rule for f in ti.scan_test_file("spec/a_spec.rb", hollow)}, {"zero-assertion-test"})

    def test_phpunit_docblock_with_slash(self):
        src = "class OrderTest extends TestCase {\n  /**\n   * @see https://example.com/spec\n   * @test\n   */\n  public function totals(): void {\n    $o = new Order();\n  }\n}\n"
        self.assertEqual({f.rule for f in ti.scan_test_file("tests/OrderTest.php", src)}, {"zero-assertion-test"})

    def test_internal_paths_are_only_fixture_files(self):
        self.assertTrue(ti.is_internal_path(ROOT / "prufgate/diff_guard/tamper_detector.py"))
        self.assertTrue(ti.is_internal_path(ROOT / "tests/test_diff_guard.py"))
        self.assertFalse(ti.is_internal_path(ROOT / "tests/test_new_feature.py"))
        self.assertFalse(ti.is_internal_path(ROOT / "tests/test_cli.py"))

    def test_git_error_prefers_fatal_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(tmp)
            with self.assertRaisesRegex(detector.GitError, "fatal"):
                detector.changed_files("no-such-ref", cwd=repo)
            with self.assertRaisesRegex(ti.GitDiffError, "no-such-ref"):
                ti._get_git_diff("no-such-ref", cwd=repo, strict=True)


class CannedCatchComments(unittest.TestCase):
    """A canned success in a catch is reported whatever comments sit beside it."""

    BASE = "function f(){\n  try { return load(); } catch (e) {\n    return { ok: true, items: [] };%s\n  }\n}\n"

    def rules(self, tail: str) -> set[str]:
        detector.apply_settings({})
        return {f.rule for f in detector.scan_text("src/a.ts", ".ts", self.BASE % tail)}

    def test_canned_object_is_a_canned_fallback(self):
        self.assertEqual(self.rules(""), {"canned-error-fallback"})

    def test_trailing_comment_does_not_hide_it(self):
        self.assertEqual(self.rules(" // a plain comment"), {"canned-error-fallback"})
        self.assertEqual(self.rules(" /* note */"), {"canned-error-fallback"})

    def test_scoped_ignore_for_another_rule_does_not_suppress(self):
        self.assertEqual(self.rules(" // prufgate-ignore: some-other-rule -- legacy path"), {"canned-error-fallback"})
        src = "function f(){\n  // prufgate-ignore: some-other-rule -- legacy path\n  try { return load(); } catch (e) {\n    return { ok: true };\n  }\n}\n"
        self.assertEqual({f.rule for f in detector.scan_text("src/a.ts", ".ts", src)}, {"canned-error-fallback"})
        named = src.replace("some-other-rule", "canned-error-fallback")
        self.assertEqual(detector.scan_text("src/a.ts", ".ts", named), [])

    def test_empty_catch_keeps_its_rule_and_urls_are_not_comments(self):
        detector.apply_settings({})
        empty = "try { load(); } catch (e) {\n}\n"
        self.assertEqual({f.rule for f in detector.scan_text("src/a.ts", ".ts", empty)}, {"unhandled-empty-catch"})
        url = 'try { load(); } catch (e) {\n  return { ok: true, href: "https://example.com/x" };\n}\n'
        self.assertIn("canned-error-fallback", {f.rule for f in detector.scan_text("src/a.ts", ".ts", url)})
