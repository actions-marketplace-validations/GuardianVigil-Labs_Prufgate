"""`prufgate pr-summary` (prufgate/pr_summary.py) and the Action step that runs it:
the SARIF reading, the facts about the change, safe rendering of text that comes
from the repository under review, and the one pull-request comment it keeps."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import yaml

from prufgate import pr_summary
from prufgate.pr_summary import MARKER, FileChange, Finding, Report, SummaryError

ROOT = Path(__file__).resolve().parent.parent

for _ci_var in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF", "PRUFGATE_REPORTS_DIR"):
    os.environ.pop(_ci_var, None)


def sarif_result(rule, severity="P1", uri="src/app.ts", line=3, message="msg", suppressions=None, level=None, **props):
    res = {
        "ruleId": rule,
        "level": level or ("error" if severity in ("P0", "P1") else "warning"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
        "properties": {"severity": severity, **props},
    }
    if severity is None:
        del res["properties"]["severity"]
    if suppressions:
        res["suppressions"] = suppressions
    return res


def write_sarif(directory: Path, results) -> Path:
    path = directory / "prufgate.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": results}]}))
    return path


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout


class ReadSarif(unittest.TestCase):
    def test_findings_sorted_and_suppressions_counted(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_sarif(Path(d), [
                sarif_result("warn-rule", "P2", "b.py", 9),
                sarif_result("block-rule", "P0", "a.py", 4),
                sarif_result("ignored", "P1", suppressions=[{"kind": "inSource", "justification": "why"}]),
                sarif_result("dismissed", "P1", suppressions=[{"kind": "external", "justification": "AI-dismissed: x"}]),
                sarif_result("other-tool", None, level="note"),
            ])
            report = pr_summary.read_sarif(path)
        self.assertEqual([f.rule for f in report.findings], ["block-rule", "warn-rule", "other-tool"])
        self.assertEqual(report.findings[2].severity, "P3")  # from the SARIF level
        self.assertEqual((report.ignored, report.dismissed), (1, 1))
        self.assertEqual(report.count("P0", "P1"), 1)

    def test_missing_or_invalid_report_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SummaryError):
                pr_summary.read_sarif(Path(d) / "absent.sarif")
            bad = Path(d) / "bad.sarif"
            bad.write_text("{not json")
            with self.assertRaises(SummaryError):
                pr_summary.read_sarif(bad)
            bad.write_text(json.dumps({"version": "2.1.0"}))
            with self.assertRaises(SummaryError):
                pr_summary.read_sarif(bad)


class Render(unittest.TestCase):
    def test_verdicts(self):
        blocking = Report([Finding("r", "P0", "a.py", 1, "m"), Finding("r", "P1", "a.py", 2, "m")])
        self.assertIn("### PrufGate: 2 blocking findings", pr_summary.render(blocking))
        self.assertIn("### PrufGate: no blocking findings", pr_summary.render(Report()))
        self.assertIn("### PrufGate: 1 blocking finding\n", pr_summary.render(Report([Finding("r", "P0", "a", 1, "m")])))
        failed = pr_summary.render(Report(), exit_code=2)
        self.assertIn("could not finish the check", failed)
        self.assertIn("this run is not a pass", failed)

    def test_body_starts_with_the_marker(self):
        body = pr_summary.render(Report([Finding("r", "P0", "a.py", 1, MARKER)]))
        self.assertTrue(body.startswith(MARKER + "\n"))

    def test_only_the_first_findings_are_listed(self):
        report = Report([Finding(f"rule-{i}", "P2", "a.py", i + 1, "m") for i in range(13)])
        body = pr_summary.render(report, max_findings=10)
        self.assertIn("the first 10 of 13", body)
        self.assertIn("`rule-9`", body)
        self.assertNotIn("`rule-10`", body)

    def test_repository_text_cannot_mention_link_or_inject_html(self):
        hostile = "ping @octocat <img src=x onerror=alert(1)> [x](https://example.com) `code` | pipe\nnext line"
        report = Report([Finding("rule`x", "P1", "src/@team/`a`.ts", 3, hostile)])
        body = pr_summary.render(report)
        line = next(ln for ln in body.splitlines() if ln.startswith("- **P1**"))
        # Every piece of repository text sits inside one inline code span.
        outside = "".join(part for i, part in enumerate(line.split("`")) if i % 2 == 0)
        for token in ("@octocat", "<img", "](", "@team", "next line"):
            self.assertNotIn(token, outside)
        self.assertEqual(line.count("`") % 2, 0)
        self.assertNotIn("\nnext line", body)

    def test_secrets_are_redacted_and_details_never_read(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        with tempfile.TemporaryDirectory() as d:
            path = write_sarif(Path(d), [sarif_result(
                "generic-api-key", "P0", "config.js", 2, message=f"Secret detected: token = '{token}'",
                details=f"Match: {token}",
            )])
            body = pr_summary.render(pr_summary.read_sarif(path))
        self.assertNotIn(token, body)
        self.assertNotIn("Match:", body)
        self.assertIn("[redacted]", body)

    def test_long_paths_are_not_mistaken_for_keys(self):
        path = "src/app/api/v1/organizations/members/settings/route.ts"
        body = pr_summary.render(Report([Finding("r", "P1", path, 1, "m")]))
        self.assertIn(f"`{path}:1`", body)

    def test_oversized_body_is_cut(self):
        report = Report([Finding(f"rule-{i}", "P2", "a.py", i, "m" * 150) for i in range(2000)])
        body = pr_summary.render(report, max_findings=2000)
        self.assertLessEqual(len(body), pr_summary.MAX_BODY)
        self.assertIn("The summary was cut to fit", body)


DIFF = """\
diff --git a/src/pay.py b/src/pay.py
index 1..2 100644
--- a/src/pay.py
+++ b/src/pay.py
@@ -2 +2,4 @@ def pay(x):
-    return charge(x)
+    try:
+        return charge(x)
+    except Exception:
+        return {"ok": True}
diff --git a/tests/test_pay.py b/tests/test_pay.py
index 1..2 100644
--- a/tests/test_pay.py
+++ b/tests/test_pay.py
@@ -4,2 +4 @@ def test_pay():
-    assert pay(1) == 2
---- a line of text that starts with dashes
+    assert True
diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-a = 1
-b = 2
diff --git a/logo.png b/logo.png
new file mode 100644
Binary files /dev/null and b/logo.png differ
"""


class Changes(unittest.TestCase):
    def test_parse_changes(self):
        files = {c.path: c for c in pr_summary.parse_changes(DIFF)}
        self.assertEqual(set(files), {"src/pay.py", "tests/test_pay.py", "new_name.py", "gone.py", "logo.png"})
        self.assertEqual((files["src/pay.py"].added, files["src/pay.py"].removed), (4, 1))
        t = files["tests/test_pay.py"]
        self.assertEqual((t.added, t.removed, t.asserts_added, t.asserts_removed), (1, 2, 1, 1))
        self.assertEqual((files["gone.py"].added, files["gone.py"].removed), (0, 2))
        self.assertEqual((files["new_name.py"].added, files["logo.png"].added), (0, 0))

    def test_categories(self):
        cases = {
            "tests/test_pay.py": "tests", "src/a.test.ts": "tests", "package.json": "config",
            "requirements-dev.txt": "config", ".github/workflows/ci.yml": "config", "ruff.toml": "config",
            ".prufgate/config.yaml": "config", "jest.config.js": "config", "README.md": "docs",
            "docs/guide.html": "docs", "src/pay.py": "production", "app/page.tsx": "production",
        }
        for path, want in cases.items():
            self.assertEqual(pr_summary.category(path), want, path)

    def test_change_panel(self):
        changes = [FileChange("src/pay.py", 4, 1), FileChange(".github/workflows/ci.yml", 1, 1),
                   FileChange("package.json", 1, 0)]
        body = pr_summary.render(Report(), changes, "origin/main")
        self.assertIn("compared with `origin/main`", body)
        self.assertIn("| Production code | 1 | 4 | 1 |", body)
        self.assertIn("| Build, CI and configuration | 2 | 2 | 1 |", body)
        self.assertIn("Dependency manifests changed: `package.json`", body)
        self.assertIn("configuration changed: `.github/workflows/ci.yml`, `package.json`", body)
        self.assertIn("Production code changed and no test file did", body)
        with_tests = pr_summary.render(Report(), changes + [FileChange("tests/test_pay.py", 3, 0, 2, 0)], "main")
        self.assertNotIn("no test file did", with_tests)
        self.assertIn("Assertion lines in tests: 2 added, 0 removed", with_tests)

    def test_long_file_lists_are_shortened(self):
        changes = [FileChange(f"requirements-{i}.txt", 1, 0) for i in range(14)]
        self.assertIn("and 4 more", pr_summary.render(Report(), changes, "main"))

    def test_change_facts_from_git(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            git(ws, "init", "-q", "-b", "main")
            (ws / "src").mkdir()
            (ws / "src" / "a.py").write_text("x = 1\n")
            git(ws, "add", "-A")
            git(ws, "commit", "-qm", "base")
            git(ws, "checkout", "-qb", "topic")
            (ws / "src" / "a.py").write_text("x = 2\ny = 3\n")
            (ws / "test_a.py").write_text("def test_x():\n    assert 1\n")
            git(ws, "add", "-A")
            git(ws, "commit", "-qm", "change")
            facts = {c.path: c for c in pr_summary.change_facts(ws, "main")}
        self.assertEqual((facts["src/a.py"].added, facts["src/a.py"].removed), (2, 1))
        self.assertEqual(facts["test_a.py"].asserts_added, 1)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGitHub:
    def __init__(self, pages, status=None):
        self.pages = pages
        self.status = status
        self.calls = []

    def __call__(self, req, timeout):
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.get_method(), req.full_url, body, req.get_header("Authorization")))
        if self.status:
            raise urllib.error.HTTPError(req.full_url, self.status, "nope", {}, None)
        if req.get_method() == "GET":
            page = int(req.full_url.rsplit("page=", 1)[1])
            return FakeResponse(json.dumps(self.pages[page - 1] if page <= len(self.pages) else []).encode())
        return FakeResponse(b"{}")


def comment(cid, body, login):
    return {"id": cid, "body": body, "user": {"login": login}}


class PostComment(unittest.TestCase):
    def test_creates_when_none_exists(self):
        gh = FakeGitHub([[comment(1, "hello", "someone")]])
        self.assertEqual(pr_summary.post_comment(MARKER + "\nx", "acme/app", 7, "t0ken", opener=gh), "created")
        method, url, body, auth = gh.calls[-1]
        self.assertEqual((method, url), ("POST", "https://api.github.com/repos/acme/app/issues/7/comments"))
        self.assertEqual(body, {"body": MARKER + "\nx"})
        self.assertEqual(auth, "Bearer t0ken")

    def test_updates_its_own_comment_on_a_later_page(self):
        first = [comment(i, "other", "someone") for i in range(100)]
        gh = FakeGitHub([first, [comment(555, MARKER + "\nold", "github-actions[bot]")]])
        self.assertEqual(pr_summary.post_comment(MARKER + "\nnew", "acme/app", 7, "t", opener=gh), "updated")
        self.assertEqual(gh.calls[-1][:2], ("PATCH", "https://api.github.com/repos/acme/app/issues/comments/555"))

    def test_a_marker_comment_by_someone_else_is_not_touched(self):
        gh = FakeGitHub([[comment(9, MARKER + "\nfake", "mallory")]])
        self.assertEqual(pr_summary.post_comment(MARKER, "acme/app", 7, "t", opener=gh), "created")
        self.assertNotIn("PATCH", [c[0] for c in gh.calls])

    def test_errors_name_no_token(self):
        gh = FakeGitHub([[]], status=403)
        with self.assertRaises(SummaryError) as ctx:
            pr_summary.post_comment(MARKER, "acme/app", 7, "s3cret-value", opener=gh)
        self.assertIn("HTTP 403", str(ctx.exception))
        self.assertIn("pull-requests: write", str(ctx.exception))
        self.assertNotIn("s3cret-value", str(ctx.exception))

    def test_bad_arguments_are_refused_before_any_request(self):
        gh = FakeGitHub([[]])
        for repo, pr, token, api in (
            ("../etc", 7, "t", "https://api.github.com"),
            ("acme/app", 0, "t", "https://api.github.com"),
            ("acme/app", 7, "", "https://api.github.com"),
            ("acme/app", 7, "t", "http://api.example.com"),
        ):
            with self.assertRaises(SummaryError):
                pr_summary.post_comment(MARKER, repo, pr, token, api_url=api, opener=gh)
        self.assertEqual(gh.calls, [])

    def test_pr_number_from_event(self):
        with tempfile.TemporaryDirectory() as d:
            event = Path(d) / "event.json"
            event.write_text(json.dumps({"pull_request": {"number": 42}}))
            self.assertEqual(pr_summary.pr_number_from_event(str(event)), 42)
            event.write_text(json.dumps({"ref": "refs/heads/main"}))
            self.assertIsNone(pr_summary.pr_number_from_event(str(event)))
        self.assertIsNone(pr_summary.pr_number_from_event(None))


class Command(unittest.TestCase):
    def run_main(self, *args, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = pr_summary.main(*args, **kwargs)
        return rc, out.getvalue(), err.getvalue()

    def test_prints_the_summary(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = write_sarif(Path(d), [sarif_result("block-rule", "P0")])
            rc, out, _ = self.run_main(d, str(sarif), exit_code=1)
        self.assertEqual(rc, 0)
        self.assertIn("1 blocking finding", out)
        self.assertIn("no base ref", out)

    def test_reads_the_base_ref_the_gate_used(self):
        with tempfile.TemporaryDirectory() as d:
            raw = Path(d) / "reports" / "raw"
            raw.mkdir(parents=True)
            (raw / "base_ref").write_text("origin/main\n")
            self.assertEqual(pr_summary.resolve_base(Path(d) / "reports", None), "origin/main")
            self.assertEqual(pr_summary.resolve_base(Path(d) / "reports", "dev"), "dev")

    def test_a_missing_report_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out, err = self.run_main(d)
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("cannot read the SARIF report", err)

    def test_posting_without_a_pull_request_exits_2_after_printing(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = write_sarif(Path(d), [])
            env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_EVENT_PATH",)}
            with unittest.mock.patch.dict(os.environ, env, clear=True):
                rc, out, err = self.run_main(d, str(sarif), post=True, repo="acme/app")
        self.assertEqual(rc, 2)
        self.assertIn(MARKER, out)
        self.assertIn("no pull request number", err)

    def test_posting_uses_the_environment_token(self):
        gh = FakeGitHub([[]])
        with tempfile.TemporaryDirectory() as d:
            sarif = write_sarif(Path(d), [])
            with unittest.mock.patch.dict(os.environ, {"PRUFGATE_GITHUB_TOKEN": "env-token"}):
                rc, _, err = self.run_main(d, str(sarif), post=True, repo="acme/app", pr=3, opener=gh)
        self.assertEqual(rc, 0, err)
        self.assertEqual(gh.calls[-1][0], "POST")
        self.assertEqual(gh.calls[-1][3], "Bearer env-token")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = write_sarif(Path(d), [sarif_result("block-rule", "P1")])
            proc = subprocess.run(
                [sys.executable, str(ROOT / "prufgate" / "cli.py"), "pr-summary", d, "--sarif", str(sarif),
                 "--exit-code", "1"],
                capture_output=True, text=True,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.startswith(MARKER))


class ActionStep(unittest.TestCase):
    def setUp(self):
        self.action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        self.step = next(s for s in self.action["runs"]["steps"] if s.get("name") == "Write the PrufGate summary")

    def test_inputs_and_defaults(self):
        inputs = self.action["inputs"]
        self.assertEqual(inputs["job_summary"]["default"], "true")
        self.assertEqual(inputs["pr_comment"]["default"], "false")
        self.assertIn("exit_code", self.action["outputs"])

    def test_the_token_reaches_the_step_only_for_a_comment(self):
        self.assertEqual(
            self.step["env"]["PRUFGATE_GITHUB_TOKEN"],
            "${{ inputs.pr_comment == 'true' && inputs.github_token || '' }}",
        )
        self.assertNotIn("github_token", self.step["run"])

    def test_the_summary_runs_after_a_failed_gate_and_never_changes_its_result(self):
        self.assertTrue(self.step["if"].startswith("always()"))
        self.assertIn("set +e", self.step["run"])
        commands = [ln.strip() for ln in self.step["run"].splitlines()]
        self.assertFalse([c for c in commands if c.startswith("exit") or "&& exit" in c or "|| exit" in c])


if __name__ == "__main__":
    unittest.main()
