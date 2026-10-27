"""Changed-files scans judge only what the change touched (prufgate/diff_scope.py),
in the CLI (`check --changed`) and in the runner (`prufgate.sh fast`); a full scan
still reports everything. Also zizmor severity and lines, the one-hop BOLA guard
wrapper and wrangler environment variables."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prufgate import diff_scope
from prufgate.bola.bola_engine import run_static_matrix_audit
from prufgate.config import PrufGateConfig
from prufgate.contract_guard.env_guard import scan_file_env_drift
from prufgate.contract_guard.env_sources import (
    load_env_sources,
    wrangler_json_vars,
    wrangler_toml_vars,
)
from prufgate.synthesizer import parse_results

ROOT = Path(__file__).resolve().parent.parent

for _ci_var in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF"):
    os.environ.pop(_ci_var, None)

STORE_BASE = (
    "// Order store.\n"
    "export async function save(db, o) {\n"
    "  try { await db.insert(o) } catch {}\n"
    "  return { saved: true };\n"
    "}\n"
)
NOTES_ROUTE = (
    'app.get("/api/notes/:id", async (req, res) => {\n'
    "  const note = await db.note.findUnique({ where: { id: req.params.id } });\n"
    "  res.json(note);\n"
    "});\n"
)


def git(ws: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ws), "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, text=True,
    ).stdout


def make_repo(head: dict[str, str]) -> tempfile.TemporaryDirectory:
    """main has an old empty catch and an old unguarded route; `feature` writes `head`."""
    tmp = tempfile.TemporaryDirectory()
    ws = Path(tmp.name)
    git(ws, "init", "-q", "-b", "main")
    files = {"src/store.ts": STORE_BASE, "src/routes/notes.ts": NOTES_ROUTE, "package.json": '{"name": "demo"}\n'}
    for rel, text in files.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text, encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "base")
    git(ws, "checkout", "-qb", "feature")
    for rel, text in head.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text, encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "feature")
    return tmp


def check(ws: Path, *args: str) -> list[dict]:
    proc = subprocess.run([sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", *args, "--format", "json"],
                          cwd=ws, capture_output=True, text=True, timeout=300)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


def where(findings: list[dict]) -> set[tuple[str, str]]:
    return {(f["file"], f["rule"]) for f in findings}


ONLY_A_COMMENT = {"src/store.ts": STORE_BASE.replace("// Order store.", "// Order store (orders only).")}
ADDS_BOTH = {
    "src/store.ts": STORE_BASE + "export async function drop(db, o) {\n  try { await db.remove(o) } catch {}\n}\n",
    "src/routes/widgets.ts": NOTES_ROUTE.replace("notes", "widgets").replace("db.note.", "db.widget."),
}


class ParseDiff(unittest.TestCase):
    def test_added_and_deleted_hunks(self):
        diff = "+++ b/a.ts\n@@ -1,0 +2,3 @@\n@@ -9,2 +11,0 @@\n+++ /dev/null\n@@ -1 +0,0 @@\n"
        self.assertEqual(diff_scope.parse_diff(diff), {"a.ts": [(2, 4), (11, 12)]})

    def test_diff_rules_are_kept_whatever_their_line(self):
        ranges = {"src/a.test.ts": [(40, 41)]}
        self.assertTrue(diff_scope.in_scope(ranges, "test-integrity", "diff-test-file-deleted", "src/gone.test.ts", [(1, 1)]))
        self.assertTrue(diff_scope.in_scope(ranges, "diff-guard", "test-skip-smuggling", "x.ts", [(3, 3)]))
        self.assertFalse(diff_scope.in_scope(ranges, "test-integrity", "zero-assertion-test", "src/a.test.ts", [(3, 3)]))

    def test_a_finding_on_a_block_header_covers_the_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "cart.test.ts").write_text('it("counts", () => {\n  const n = items();\n\n});\nit("x", () => {});\n')
            ranges = {"cart.test.ts": [(3, 4)]}  # the expects between lines 2 and 4 were deleted
            self.assertTrue(diff_scope.in_scope(ranges, "test-integrity", "zero-assertion-test", "cart.test.ts", [(1, 1)], ws))
            self.assertFalse(diff_scope.in_scope(ranges, "test-integrity", "zero-assertion-test", "cart.test.ts", [(5, 5)], ws))

    def test_paths_with_spaces_and_c_quoted_names_and_forged_hunk_lines(self):
        diff = (
            "+++ b/src/my dir/pay.ts\t2026-01-01 00:00:00 +0000\n"
            "@@ -1,0 +2,2 @@\n"
            "+const a = 1;\n"
            "+++ b/src/decoy.ts\n"
            '+++ "b/src/q\\"x/pay.ts"\n'
            "@@ -1,0 +4,1 @@\n"
            "+const b = 2;\n"
        )
        self.assertEqual(diff_scope.parse_diff(diff), {"src/my dir/pay.ts": [(2, 3)], 'src/q"x/pay.ts': [(4, 4)]})

    def test_block_end_handles_catch_else_decorators_python_and_ruby(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "pay.ts").write_text(
                "export async function pay() {\n"
                "  try {\n"
                "    return await charge();\n"
                "  } catch (err) {\n"
                "    return { ok: true, status: \"paid\" };\n"
                "  }\n"
                "}\n"
            )
            ranges = {"pay.ts": [(5, 5)]}
            self.assertTrue(diff_scope.in_scope(ranges, "anti-fabrication", "canned-error-fallback", "pay.ts", [(4, 4)], ws))
            (ws / "test_p.py").write_text(
                "@pytest.mark.parametrize(\n"
                '    "x",\n'
                "    [1, 2],\n"
                ")\n"
                "def test_calc(x):\n"
                "    compute(x)\n"
            )
            self.assertTrue(diff_scope.in_scope({"test_p.py": [(6, 6)]}, "test-integrity", "zero-assertion-test", "test_p.py", [(1, 1)], ws))
            (ws / "order_spec.rb").write_text("describe Order do\n  it 'totals' do\n    Order.new\n  end\nend\n")
            self.assertTrue(diff_scope.in_scope({"order_spec.rb": [(3, 3)]}, "test-integrity", "zero-assertion-test", "order_spec.rb", [(2, 2)], ws))


class CheckChanged(unittest.TestCase):
    def test_comment_only_change_reports_nothing_old(self):
        with make_repo(ONLY_A_COMMENT) as tmp:
            ws = Path(tmp)
            found = where(check(ws, "--changed", "--base", "main"))
            self.assertNotIn("src/store.ts", {f for f, _ in found}, found)
            self.assertNotIn("src/routes/notes.ts", {f for f, _ in found}, found)
            # A full scan still reports both.
            full = {f for f, _ in where(check(ws))}
            self.assertIn("src/store.ts", full)
            self.assertIn("src/routes/notes.ts", full)

    def test_added_catch_and_added_route_are_reported(self):
        with make_repo(ADDS_BOTH) as tmp:
            findings = check(Path(tmp), "--changed", "--base", "main")
            lines = {(f["file"], f["line"]) for f in findings}
            self.assertIn(("src/store.ts", 7), lines, findings)
            self.assertNotIn(("src/store.ts", 3), lines, findings)
            self.assertIn("src/routes/widgets.ts", {f for f, _ in lines})
            self.assertNotIn("src/routes/notes.ts", {f for f, _ in lines})


def fake_tool(bin_dir: Path, name: str, version: str, log: Path) -> None:
    """A stand-in scanner that logs its arguments and finds nothing."""
    script = bin_dir / name
    script.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = "--version" ]; then echo "{version}"; exit 0; fi\n'
        f'echo "$@" >> "{log}"\n'
        "echo '[]'\n"
    )
    script.chmod(0o755)


class RunnerScope(unittest.TestCase):
    def gate(self, ws: Path, mode: str, bin_dir: Path) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_BASE_REF", "PRUFGATE_BASE_REF", "TARGET_URL",
                                                                "WORKSPACE", "PRUFGATE_REPORTS_DIR")}
        env["PATH"] = f"{bin_dir}{os.pathsep}{os.path.dirname(sys.executable)}{os.pathsep}{env.get('PATH', '')}"
        env["PRUFGATE_BASE_REF"] = "main"
        return subprocess.run(["bash", str(ROOT / "prufgate.sh"), mode, str(ws)], cwd=tempfile.gettempdir(),
                              capture_output=True, text=True, env=env, timeout=300)

    def setUp(self):
        self._bin = tempfile.TemporaryDirectory()
        self.bin = Path(self._bin.name)
        self.log = self.bin / "calls.log"
        fake_tool(self.bin, "zizmor", "zizmor 1.0.0", self.log)
        fake_tool(self.bin, "ast-grep", "ast-grep 0.1.0", self.log)

    def tearDown(self):
        self._bin.cleanup()

    def results(self, ws: Path) -> set[tuple[str, int]]:
        sarif = json.loads((ws / "reports" / "prufgate.sarif").read_text())
        return {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                 r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in sarif["runs"][0]["results"]}

    def test_fast_reports_only_changed_lines_and_full_reports_all(self):
        workflow = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        head = dict(ADDS_BOTH, **{".github/workflows/ci.yml": workflow})
        with make_repo(head) as tmp:
            ws = Path(tmp)
            (ws / ".github" / "workflows" / "old.yml").write_text(workflow)
            git(ws, "add", "-A")
            git(ws, "commit", "-qm", "old workflow")
            proc = self.gate(ws, "fast", self.bin)
            self.assertIn(proc.returncode, (0, 1), proc.stdout[-3000:] + proc.stderr[-3000:])
            got = self.results(ws)
            self.assertIn(("src/store.ts", 7), got)
            self.assertNotIn(("src/store.ts", 3), got)
            self.assertFalse(any(f == "src/routes/notes.ts" for f, _ in got), got)
            calls = self.log.read_text()
            self.assertIn(".github/workflows/ci.yml", calls)
            self.assertIn(".github/workflows/old.yml", calls)  # it is new on the branch too
            self.assertNotIn(".github/workflows/ ", calls + " ")
            self.assertIn("src/store.ts", calls)  # ast-grep got the changed files
            self.log.unlink()
            proc = self.gate(ws, "full", self.bin)
            got = self.results(ws)
            self.assertIn(("src/store.ts", 3), got)
            self.assertTrue(any(f == "src/routes/notes.ts" for f, _ in got), got)
            self.assertIn(".github/workflows/", self.log.read_text())

    def test_untouched_workflows_are_not_audited(self):
        with make_repo(ONLY_A_COMMENT) as tmp:
            ws = Path(tmp)
            git(ws, "checkout", "-q", "main")
            (ws / ".github" / "workflows").mkdir(parents=True)
            (ws / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
            git(ws, "add", "-A")
            git(ws, "commit", "-qm", "ci")
            git(ws, "checkout", "-q", "feature")
            git(ws, "merge", "-q", "--no-edit", "main")
            self.gate(ws, "fast", self.bin)
            manifest = [json.loads(x) for x in (ws / "reports" / "raw" / "execution_manifest.jsonl").read_text().splitlines()]
            zizmor = next(e for e in manifest if e["tool"] == "zizmor")
            self.assertEqual((zizmor["status"], zizmor["note"]), ("skipped", "no workflow changed"))
            self.assertNotIn("workflows", self.log.read_text() if self.log.exists() else "")


def zizmor_item(ident: str, severity: str, conf: str, rows: list[tuple[str, int, int]]) -> dict:
    return {
        "ident": ident, "desc": ident,
        "determinations": {"severity": severity, "confidence": conf},
        "locations": [
            {"symbolic": {"key": {"Local": {"verbatim_path": ".github/workflows/release.yml"}}, "kind": kind},
             "concrete": {"location": {"start_point": {"row": a}, "end_point": {"row": b}}}}
            for kind, a, b in rows
        ],
    }


class Zizmor(unittest.TestCase):
    def test_severity_and_confidence(self):
        sev = parse_results.zizmor_severity
        self.assertEqual(sev("template-injection", "High", "High"), "P0")  # attacker-controlled title
        self.assertEqual(sev("template-injection", "Informational", "Low"), "P3")  # static matrix value
        self.assertEqual(sev("template-injection", "Low", "Low"), "P3")
        self.assertEqual(sev("cache-poisoning", "High", "Low"), "P1")
        self.assertEqual(sev("excessive-permissions", "Medium", "High"), "P2")
        self.assertEqual(sev("artipacked", "Medium", "Low"), "P3")
        self.assertEqual(sev("unpinned-uses", "High", "High"), "P2")

    def test_primary_location_one_based(self):
        item = zizmor_item("cache-poisoning", "High", "Low", [("Related", 10, 13), ("Primary", 75, 75), ("Hidden", 75, 77)])
        f = parse_results.zizmor_finding(item)
        self.assertEqual((f.file_path, f.line, f.severity), (".github/workflows/release.yml", 76, "P1"))
        # A change to the trigger (a related location) puts it in scope; elsewhere it is not.
        self.assertEqual(parse_results.scope_to_change([f], {".github/workflows/release.yml": [(12, 12)]}, Path.cwd()), [f])
        self.assertEqual(parse_results.scope_to_change([f], {".github/workflows/release.yml": [(30, 31)]}, Path.cwd()), [])
        self.assertEqual(parse_results.scope_to_change([f], None, Path.cwd()), [f])  # a full scan

    def test_gitleaks_from_the_scanned_commits_is_kept(self):
        leak = parse_results.Finding("gitleaks", "generic-api-key", "P0", "secret", "src/a.ts", 3, anchored=True)
        self.assertEqual(parse_results.scope_to_change([leak], {}, Path.cwd()), [leak])


GUARDS = (
    'import { assertStaff } from "./auth";\n\n'
    "export async function staffOnly(scope: string) {\n"
    "  try {\n"
    "    const user = await assertStaff(scope);\n"
    "    return { ok: true as const, user };\n"
    "  } catch {\n"
    '    return { ok: false as const, response: Response.json({ error: "forbidden" }, { status: 403 }) };\n'
    "  }\n"
    "}\n"
)
ROUTE = (
    'import { staffOnly } from "@/lib/guards";\n'
    'import { db } from "@/lib/db";\n\n'
    "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
    'GUARD  const widget = await db.widget.findFirst({ where: { id: params.id, orgId: g.user.orgId } });\n'
    "  return Response.json(widget);\n"
    "}\n"
)


class GuardWrapper(unittest.TestCase):
    def audit(self, guard_line: str, guards: str = GUARDS, cfg: PrufGateConfig | None = None) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src" / "lib").mkdir(parents=True)
            (ws / "src" / "lib" / "guards.ts").write_text(guards)
            route = ws / "src" / "app" / "api" / "widgets" / "[id]" / "route.ts"
            route.parent.mkdir(parents=True)
            route.write_text(ROUTE.replace("GUARD", guard_line))
            return [f for f in run_static_matrix_audit(ws, config=cfg) if f.rule_id == "static-bola-unscoped-access"]

    def test_one_hop_wrapper_counts_as_a_guard(self):
        line = '  const g = await staffOnly("widgets:write");\n  if (!g.ok) return g.response;\n'
        self.assertEqual(self.audit(line), [])

    def test_without_the_wrapper_call_it_fires(self):
        self.assertEqual(len(self.audit("")), 1)

    def test_a_wrapper_that_never_refuses_is_not_a_guard(self):
        lax = 'import { assertStaff } from "./auth";\nexport async function staffOnly(s: string) {\n  void assertStaff;\n  return { ok: true };\n}\n'
        self.assertEqual(len(self.audit('  const g = await staffOnly("w");\n', lax)), 1)
        # An unawaited async wrapper call does not guard the handler.
        self.assertEqual(len(self.audit('  staffOnly("w");\n')), 1)

    def test_configured_auth_guards(self):
        cfg = PrufGateConfig(auth_guards=["staffOnly"])
        self.assertEqual(self.audit('  await staffOnly("w");\n', "export const x = 1;\n", cfg), [])

    def test_changed_files_limit_the_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "notes.ts").write_text(NOTES_ROUTE)
            self.assertEqual(len(run_static_matrix_audit(ws)), 1)
            self.assertEqual(run_static_matrix_audit(ws, changed_files={"src/other.ts"}), [])
            self.assertEqual(run_static_matrix_audit(ws)[0].end_line, 4)


class WranglerVars(unittest.TestCase):
    def test_jsonc_and_toml(self):
        jsonc = '{\n  // settings\n  "name": "w",\n  "vars": {"WIDGET_MODE": "a", /* x */ "WIDGET_URL": "https://example.com",},\n' \
                '  "env": {"staging": {"vars": {"WIDGET_STAGE": "s"}}}\n}\n'
        self.assertEqual(wrangler_json_vars(jsonc), {"WIDGET_MODE", "WIDGET_URL", "WIDGET_STAGE"})
        toml = (
            'name = "w"\n[vars]\nWIDGET_MODE = "a"\n'
            'ALLOWED = [\n  { pattern = "example.com/*" }\n]\n\n'
            '[env.prod.vars]\nWIDGET_PROD = "1"\n[build]\nCOMMAND = "x"\n'
            '[env.dev]\nvars = { WIDGET_DEV = "1", "WIDGET_DBG" = "0" }\n'
        )
        self.assertEqual(wrangler_toml_vars(toml), {"WIDGET_MODE", "ALLOWED", "WIDGET_PROD", "WIDGET_DEV", "WIDGET_DBG"})

    def test_workspace_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "wrangler.jsonc").write_text('{"vars": {"WIDGET_MODE": "a"}}')
            (ws / "worker").mkdir()
            (ws / "worker" / "wrangler.toml").write_text('[vars]\nWORKER_REGION = "eu"\n')
            (ws / ".dev.vars.example").write_text("WIDGET_SECRET=\n")
            self.assertEqual(load_env_sources(ws), {"WIDGET_MODE", "WORKER_REGION", "WIDGET_SECRET"})


class EnvFallback(unittest.TestCase):
    def drift(self, code: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            return [f.text for f in scan_file_env_drift(ws / "src" / "w.ts", code, ws, {"NODE_ENV"})]

    def test_nearby_fallback(self):
        code = ("export function timeoutMs() {\n  const n = Number(process.env.WIDGET_TIMEOUT_MS);\n"
                "  return Number.isFinite(n) && n > 0 ? n : 5000;\n}\n")
        self.assertEqual(self.drift(code), [])
        self.assertEqual(self.drift("const n = Number(process.env.WIDGET_RETRIES) || 3;\n"), [])

    def test_no_fallback_fires(self):
        self.assertEqual(len(self.drift("const key = process.env.WIDGET_KEY;\n")), 1)
        code = 'const n = Number(process.env.WIDGET_LIMIT);\nif (!n) throw new Error("WIDGET_LIMIT is required");\n'
        self.assertEqual(len(self.drift(code)), 1)
        self.assertEqual(len(self.drift("const key = enabled ? process.env.WIDGET_KEY : undefined;\n")), 1)
        self.assertEqual(len(self.drift('const key = process.env.WIDGET_KEY;\nif (!key || key.length < 5) throw new Error("bad");\n')), 1)


if __name__ == "__main__":
    unittest.main()
