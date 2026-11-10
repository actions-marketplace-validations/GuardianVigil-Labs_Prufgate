import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate.cli import main as cli_main
from prufgate.config import PrufGateConfig


class TestPrufGateCLI(unittest.TestCase):
    def test_self_check_subcommand(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--self-check"])
        self.assertEqual(rc, 0)
        self.assertIn("all 6 core engines passed", buf.getvalue())

    def test_init_and_hooks_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["init", str(ws), "--hooks"])
            self.assertEqual(rc, 0)

            cfg_file = ws / ".prufgate" / "config.yaml"
            claude_file = ws / ".claude" / "settings.json"
            cursor_file = ws / ".cursor" / "rules" / "prufgate-guardrails.mdc"
            precommit_file = ws / ".pre-commit-config.yaml"

            self.assertTrue(cfg_file.is_file())
            self.assertTrue(claude_file.is_file())
            self.assertTrue(cursor_file.is_file())
            self.assertTrue(precommit_file.is_file())

            # Verify generated .prufgate/config.yaml parses cleanly via PrufGateConfig.load
            loaded_cfg = PrufGateConfig.load(ws)
            self.assertEqual(loaded_cfg.version, 1)
            self.assertIn("core", loaded_cfg.packs)

            # Verify Claude Stop hook command
            claude_data = json.loads(claude_file.read_text(encoding="utf-8"))
            stop_hooks = claude_data["hooks"]["Stop"]
            self.assertEqual(len(stop_hooks), 1)
            self.assertIn(
                "prufgate check --changed --format agent-hook",
                stop_hooks[0]["hooks"][0]["command"],
            )

    def test_check_clean_and_violation_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "service.py").write_text(
                "def compute_total(items: list[int]) -> int:\n"
                "    return sum(items)\n",
                encoding="utf-8",
            )
            out_clean = io.StringIO()
            with redirect_stdout(out_clean):
                rc_clean = cli_main(["check", str(ws)])
            self.assertEqual(rc_clean, 0)

            # Add a zero-assertion test and undeclared import
            (ws / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            (ws / "bad.ts").write_text("import 'ghost-hallucinated-pkg';\n", encoding="utf-8")
            (ws / "bad.test.ts").write_text(
                "test('fake test', () => {\n  const x = 1 + 1;\n});\n",
                encoding="utf-8",
            )

            # 1. JSON format
            out_json = io.StringIO()
            with redirect_stdout(out_json):
                rc_json = cli_main(["check", str(ws), "--format", "json"])
            self.assertEqual(rc_json, 1)
            findings = json.loads(out_json.getvalue())
            rules = {f["rule"] for f in findings}
            self.assertIn("undeclared-or-hallucinated-import", rules)
            self.assertIn("zero-assertion-test", rules)

            # 2. SARIF format
            out_sarif = io.StringIO()
            with redirect_stdout(out_sarif):
                rc_sarif = cli_main(["check", str(ws), "--format", "sarif"])
            self.assertEqual(rc_sarif, 1)
            sarif = json.loads(out_sarif.getvalue())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 2)

            # 3. Agent Stop Hook format (exits 2 and writes remediation to stderr)
            err_hook = io.StringIO()
            # The hook reads the agent's JSON payload on stdin; give it one so the
            # test never blocks on the runner's own stdin.
            with redirect_stderr(err_hook), patch("sys.stdin", io.StringIO("{}")):
                rc_hook = cli_main(["check", str(ws), "--format", "agent-hook"])
            self.assertEqual(rc_hook, 2)
            self.assertIn("PrufGate Agent Guardrail blocked completion", err_hook.getvalue())

    def test_bola_and_review_subcommands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "routes.ts").write_text(
                "app.get('/api/items/:id', async (req, res) => {\n"
                "  return res.json(await prisma.item.findUnique({ where: { id: req.params.id } }));\n"
                "});\n",
                encoding="utf-8",
            )
            out_bola = io.StringIO()
            with redirect_stdout(out_bola):
                rc_bola = cli_main(["bola", str(ws), "--static-only", "--format", "json"])
            self.assertEqual(rc_bola, 1)
            bola_items = json.loads(out_bola.getvalue())
            self.assertEqual(len(bola_items), 1)
            self.assertEqual(bola_items[0]["rule_id"], "static-bola-unscoped-access")

            diff_file = ws / "sample.diff"
            diff_file.write_text(
                "diff --git a/src/query.ts b/src/query.ts\n"
                "--- a/src/query.ts\n"
                "+++ b/src/query.ts\n"
                "@@ -1,1 +1,2 @@\n"
                "+db.query(`SELECT * FROM accounts WHERE id = ${req.query.id}`);\n",
                encoding="utf-8",
            )
            out_rev = io.StringIO()
            with redirect_stdout(out_rev):
                rc_rev = cli_main(
                    ["review", f"--workspace={ws}", f"--diff-file={diff_file}", "--format=json"]
                )
            self.assertEqual(rc_rev, 1)  # a P0 comment fails the review
            rev_items = json.loads(out_rev.getvalue())
            self.assertEqual(len(rev_items), 1)
            self.assertEqual(rev_items[0]["title"], "SQL Injection Vector")


class ResultOut(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = self.tmp / "real" / "ws"
        self.ws.mkdir(parents=True)
        (self.ws / "service.py").write_text("def total(items):\n    return sum(items)\n", encoding="utf-8")
        (self.tmp / "link").symlink_to(self.tmp / "real")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def check(self, *args: str) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli_main(["check", *args])

    def test_symlinked_parents_outside_the_workspace_are_followed(self) -> None:
        rc = self.check(str(self.tmp / "link" / "ws"), "--result-out", str(self.tmp / "link" / "out" / "res.json"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads((self.tmp / "real" / "out" / "res.json").read_text())["scan_status"], "clean")

    def test_symlink_inside_the_workspace_is_refused_with_exit_2(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        (self.ws / "reports").symlink_to(outside)
        rc = self.check(str(self.ws), "--result-out", str(self.ws / "reports" / "res.json"))
        self.assertEqual(rc, 2)
        self.assertEqual(list(outside.iterdir()), [])

    def test_logical_prefix_cannot_follow_a_symlink_inside_the_workspace(self) -> None:
        # The workspace is resolved; the output keeps the logical (symlinked) prefix.
        outside = self.tmp / "outside"
        outside.mkdir()
        (self.ws / "reports").symlink_to(outside)
        rc = self.check(str(self.tmp / "link" / "ws"), "--result-out", str(self.tmp / "link" / "ws" / "reports" / "res.json"))
        self.assertEqual(rc, 2)
        self.assertEqual(list(outside.iterdir()), [])

    def test_logical_prefix_inside_the_workspace_still_writes(self) -> None:
        rc = self.check(str(self.tmp / "link" / "ws"), "--result-out", str(self.tmp / "link" / "ws" / "out" / "res.json"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads((self.ws / "out" / "res.json").read_text())["scan_status"], "clean")

    def test_dot_dot_in_result_out_is_refused(self) -> None:
        rc = self.check(str(self.ws), "--result-out", str(self.ws / "sub" / ".." / ".." / "res.json"))
        self.assertEqual(rc, 2)
        self.assertFalse((self.tmp / "real" / "res.json").exists())

    def test_final_component_symlink_is_refused(self) -> None:
        victim = self.tmp / "victim.json"
        victim.write_text("keep")
        out = self.tmp / "out"
        out.mkdir()
        for name in ("res.json", "res.status"):
            with self.subTest(name=name):
                link = out / name
                link.symlink_to(victim)
                self.assertEqual(self.check(str(self.ws), "--result-out", str(out / "res.json")), 2)
                self.assertTrue(link.is_symlink())
                self.assertEqual(victim.read_text(), "keep")
                link.unlink()
                for left in out.iterdir():
                    left.unlink()

    def test_failed_result_out_prints_no_passing_result(self) -> None:
        (self.tmp / "file").write_text("x")
        for argv in (["check", str(self.ws)], ["test-audit", str(self.ws)], ["bola", str(self.ws), "--static-only"]):
            with self.subTest(command=argv[0]):
                out = io.StringIO()
                with redirect_stdout(out), redirect_stderr(io.StringIO()):
                    rc = cli_main([*argv, "--format", "result", "--result-out", str(self.tmp / "file" / "r.json")])
                self.assertEqual(rc, 2)
                text = out.getvalue()
                if text.strip():
                    printed = json.loads(text)
                    self.assertEqual(printed["exit_code"], 2)
                    self.assertFalse(printed["passed"])

    def test_unwritable_result_out_exits_2(self) -> None:
        (self.tmp / "file").write_text("x")
        for fmt in ("text", "result"):
            self.assertEqual(self.check(str(self.ws), "--format", fmt, "--result-out", str(self.tmp / "file" / "res.json")), 2)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = cli_main(["test-audit", str(self.ws), "--format", "result", "--result-out", str(self.tmp / "file" / "r.json")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()


class BolaTargetGuard(unittest.TestCase):
    def test_metadata_and_bad_scheme_targets_are_refused_before_any_probe(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch("prufgate.bola.bola_engine.check_server_active") as active:
            for url in ("http://169.254.169.254/latest", "http://metadata.google.internal/", "file:///etc/passwd"):
                err = io.StringIO()
                with self.subTest(url=url), redirect_stderr(err), redirect_stdout(io.StringIO()):
                    self.assertEqual(cli_main(["bola", tmp, "--url", url, "--token-a", "a", "--token-b", "b"]), 2)
                    self.assertIn("prufgate bola:", err.getvalue())
            active.assert_not_called()
