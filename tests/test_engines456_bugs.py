"""Regression tests for Engines 4-6 (contract guard, BOLA, PR reviewer).

Each test reproduces a defect found in review; it failed before the fix.
Credential-shaped values are built at run time so the repository hygiene
guard never sees a token-looking literal.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import prufgate.contract_guard as cg
from prufgate.bola import bola_engine
from prufgate.config import PrufGateConfig
from prufgate.contract_guard import dependency_guard, env_guard
from prufgate.contract_guard.route_contract import _route_matches
from prufgate.review import ai_adapter, reviewer


def _git(ws: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=ws,
        check=True,
        capture_output=True,
    )


def _write(ws: Path, rel: str, text: str) -> Path:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **kw)


class ContractGuardBugs(unittest.TestCase):
    def test_changed_includes_untracked_files_in_new_directories(self) -> None:
        # BUG-03: `git status --porcelain` reports a new directory, not its files.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "package.json", json.dumps({"name": "app", "dependencies": {}}))
            _git(ws, "init", "-q")
            _git(ws, "add", ".")
            _git(ws, "commit", "-qm", "init")
            _write(ws, "src/feature/new.ts", "import x from 'ghost-pkg-zz';\n")
            findings = cg.scan_contract_guard(ws, changed_only=True)
            self.assertEqual([f.path for f in findings], ["src/feature/new.ts"])

    def test_changed_with_base_ref_and_option_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "package.json", json.dumps({"name": "app", "dependencies": {}}))
            _git(ws, "init", "-q", "-b", "main")
            _git(ws, "add", ".")
            _git(ws, "commit", "-qm", "init")
            _git(ws, "checkout", "-qb", "feature")
            _write(ws, "src/a.ts", "import x from 'ghost-pkg-zz';\n")
            _git(ws, "add", ".")
            _git(ws, "commit", "-qm", "feat")
            _write(ws, "src/b.ts", "import y from 'ghost-two-zz';\n")
            _git(ws, "add", ".")
            _git(ws, "commit", "-qm", "feat2")
            # HEAD~1 alone would miss src/a.ts: the base ref must be honoured.
            paths = sorted(f.path for f in cg.scan_contract_guard(ws, changed_only=True, base="main"))
            self.assertEqual(paths, ["src/a.ts", "src/b.ts"])
            self.assertEqual(_quiet(cg.main, ["--changed=--output=/tmp/x", f"--workspace={ws}"]), 2)

    def test_p1_only_findings_fail_and_missing_workspace_errors(self) -> None:
        # BUG-13: P1 is a blocker per the documented exit-code contract.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, ".env.example", "A_DOCUMENTED=1\n")
            _write(ws, "app.py", "import os\nX = os.environ['NOT_DOCUMENTED_VAR']\n")
            out = ws / "out.json"
            self.assertEqual(_quiet(cg.main, [f"--workspace={ws}", f"--json-out={out}"]), 1)
            self.assertEqual(json.loads(out.read_text())[0]["severity"], "P1")
            self.assertEqual(_quiet(cg.main, [f"--workspace={ws}/does-not-exist"]), 2)

    def test_crash_is_exit_2_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(cg, "scan_contract_guard", side_effect=RuntimeError("boom")):
                self.assertEqual(_quiet(cg.main, [f"--workspace={tmp}"]), 2)

    def test_leading_space_typos(self) -> None:
        self.assertIn("opencv_python_headless", dependency_guard.PYPI_TO_IMPORT_MAP)
        self.assertIn("typing", dependency_guard.PYTHON_STDLIB)
        self.assertIn("WORKSPACE", env_guard.STANDARD_RUNTIME_ENV_VARS)
        for name in list(dependency_guard.PYPI_TO_IMPORT_MAP) + list(dependency_guard.PYTHON_STDLIB):
            self.assertEqual(name, name.strip())

    def test_stdlib_fallback_without_stdlib_module_names(self) -> None:
        # Python 3.9 has no sys.stdlib_module_names: common stdlib modules must still pass.
        names = dependency_guard._fallback_stdlib_names()
        for mod in ("random", "decimal", "statistics", "queue", "textwrap", "typing", "string", "zlib"):
            self.assertIn(mod, names)

    def test_pyproject_tool_tables_are_not_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "pyproject.toml",
                '[project]\nname = "demo"\ndependencies = [\n  "fastapi>=0.1",\n  "PyYAML",\n]\n'
                '[project.optional-dependencies]\ndev = ["pytest"]\n'
                '[tool.poetry.dependencies]\nhttpx = "^0.27"\n'
                '[tool.ruff]\nselect = ["requests", "E501"]\nline-length = 100\n'
                '[tool.mypy]\nplugins = "numpy"\n'
                '[tool.other]\ndependencies = ["numpy"]\n',
            )
            mf = dependency_guard.load_declared_dependencies(ws)
            for declared in ("fastapi", "yaml", "pytest", "httpx"):
                self.assertIn(declared, mf.python_modules)
            for undeclared in ("requests", "numpy", "e501", "line_length", "demo", "select"):
                self.assertNotIn(undeclared, mf.python_modules)
            src = "import requests\nimport fastapi\n"
            hits = dependency_guard.scan_file_dependencies(ws / "app.py", src, ws, mf)
            self.assertEqual([h.line for h in hits], [1])

    def test_stdlib_imports_are_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "requirements.txt", "flask\n")
            _write(ws, "go.mod", "module example.com/m\n\ngo 1.22\n")
            py = dependency_guard.scan_file_dependencies(ws / "a.py", "import os\nimport random\nimport ghostzz\n", ws)
            self.assertEqual([h.line for h in py], [3])
            go = 'package m\nimport (\n\t"net/http"\n\t"example.com/m/sub"\n\t"github.com/x/ghostzz"\n)\n'
            self.assertEqual([h.line for h in dependency_guard.scan_file_dependencies(ws / "a.go", go, ws)], [5])

    def test_multiline_js_import_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "package.json", json.dumps({"name": "app", "dependencies": {"react": "1"}}))
            src = "import {\n  a,\n  b,\n} from 'ghost-multi-zz';\nimport React from 'react';\n"
            hits = dependency_guard.scan_file_dependencies(ws / "x.ts", src, ws)
            self.assertEqual([h.line for h in hits], [4])

    def test_cargo_dotted_dependency_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "Cargo.toml", '[package]\nname = "app"\n\n[dependencies.serde]\nversion = "1"\n')
            hits = dependency_guard.scan_file_dependencies(ws / "src/lib.rs", "use serde::Serialize;\n", ws)
            self.assertEqual(hits, [])

    def test_workspace_under_a_build_directory_is_still_scanned(self) -> None:
        # BUG-07 class: skip-dirs were matched against absolute path parts.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "build" / "repo"
            _write(ws, "package.json", json.dumps({"name": "app", "dependencies": {}}))
            _write(ws, "src/x.ts", "import g from 'ghost-pkg-zz';\n")
            _write(
                ws,
                "api/routes.ts",
                "app.get('/api/items/:id', async (req, res) => {\n"
                "  return res.json(await prisma.item.findUnique({ where: { id: req.params.id } }));\n"
                "});\n",
            )
            self.assertEqual(len(cg.scan_contract_guard(ws)), 1)
            self.assertEqual(len(_quiet(bola_engine.run_static_matrix_audit, ws)), 1)

    def test_user_directories_named_like_prufgate_internals_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "package.json", json.dumps({"name": "app", "dependencies": {}}))
            _write(ws, "prufgate/api/client.ts", "import g from 'ghost-pkg-zz';\n")
            _write(ws, "src/latest/feed.ts", "import g from 'ghost-pkg-zz';\n")
            _write(ws, "src/contests/a.ts", "import g from 'ghost-pkg-zz';\n")
            _write(ws, "tests/a.test.ts", "import g from 'ghost-pkg-zz';\n")
            paths = sorted(f.path for f in cg.scan_contract_guard(ws))
            self.assertEqual(paths, ["prufgate/api/client.ts", "src/contests/a.ts", "src/latest/feed.ts"])

    def test_route_matches_python39_safe(self) -> None:
        self.assertTrue(_route_matches("/api/{param}", "/api/x"))
        self.assertFalse(_route_matches("/api/a", "/api/b"))


EXPRESS_TWO_ROUTES = (
    "app.get('/api/items/:id', requireAuth, async (req, res) => {\n"
    "  const item = await prisma.item.findFirst({ where: { id: req.params.id, tenantId: req.user.tenantId } });\n"
    "  res.json(item);\n"
    "});\n"
    "app.get('/api/notes/:id', async (req, res) => {\n"
    "  res.json(await prisma.note.findUnique({ where: { id: req.params.id } }));\n"
    "});\n"
)


class BolaBugs(unittest.TestCase):
    def _audit(self, ws: Path, cfg: PrufGateConfig | None = None) -> list:
        return _quiet(bola_engine.run_static_matrix_audit, ws, config=cfg or PrufGateConfig())

    def test_sequelize_and_mongoose_lookups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "routes.js",
                "router.get('/api/invoices/:id', async (req, res) => {\n"
                "  res.json(await Invoice.findByPk(req.params.id));\n"
                "});\n"
                "router.delete('/api/orders/:id', async (req, res) => {\n"
                "  res.json(await Order.findByIdAndDelete(req.params.id));\n"
                "});\n",
            )
            self.assertEqual(sorted(f.line for f in self._audit(ws)), [1, 4])

    def test_url_param_alone_is_not_tenant_scoping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "routes.ts",
                "app.get('/api/orgs/:orgId/invoices/:id', requireAuth, async (req, res) => {\n"
                "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: req.params.orgId } }));\n"
                "});\n"
                "app.get('/api/docs/:id', requireAuth, async (req, res) => {\n"
                "  res.json(await prisma.doc.findFirst({ where: { id: req.params.id, orgId: req.query.orgId } }));\n"
                "});\n"
                "app.get('/api/orgs/:orgId/bills/:id', requireAuth, async (req, res) => {\n"
                "  await assertMembership(req.user.id, req.params.orgId);\n"
                "  res.json(await prisma.bill.findFirst({ where: { id: req.params.id, orgId: req.params.orgId } }));\n"
                "});\n",
            )
            self.assertEqual([f.line for f in self._audit(ws)], [1, 4])

    def test_handler_window_stops_at_next_route_and_auth_is_per_handler(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "routes.ts", EXPRESS_TWO_ROUTES)
            findings = self._audit(ws)
            self.assertEqual([f.line for f in findings], [5])
            self.assertIn("missing both", findings[0].message)

    def test_caller_identity_elsewhere_in_handler_is_not_scoping(self) -> None:
        # Identity must scope the lookup itself (or be compared for ownership), not merely appear.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "routes.ts",
                "app.get('/api/orders/:id', requireAuth, async (req, res) => {\n"
                "  log.info('fetch', req.user.email);\n"
                "  const order = await prisma.order.findUnique({ where: { id: req.params.id } });\n"
                "  res.json(order);\n"
                "});\n"
                "app.get('/api/invoices/:id', requireAuth, async (req, res) => {\n"
                "  if (!req.session.userId) return res.sendStatus(401);\n"
                "  res.json(await Invoice.findByPk(req.params.id));\n"
                "});\n"
                "app.get('/api/docs/:id', requireAuth, async (req, res) => {\n"
                "  const doc = await prisma.doc.findUnique({ where: { id: req.params.id } });\n"
                "  if (doc.ownerId !== req.user.id) return res.sendStatus(404);\n"
                "  res.json(doc);\n"
                "});\n"
                "app.get('/api/files/:id', requireAuth, async (req, res) => {\n"
                "  const file = await prisma.file.findFirst({\n"
                "    where: { id: req.params.id, ownerId: req.user.id },\n"
                "  });\n"
                "  res.json(file);\n"
                "});\n",
            )
            self.assertEqual([f.line for f in self._audit(ws)], [1, 6])

    def test_destructured_route_param_and_mixed_lookups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "routes.ts",
                "app.get('/api/orgs/:orgId/items/:id', requireAuth, async (req, res) => {\n"
                "  const { orgId, id } = req.params;\n"
                "  res.json(await prisma.item.findFirst({ where: { id, orgId } }));\n"
                "});\n"
                "app.get('/api/pairs/:id', requireAuth, async (req, res) => {\n"
                "  const a = await prisma.pair.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });\n"
                "  const b = await prisma.peer.findUnique({ where: { id: req.query.peerId } });\n"
                "  res.json([a, b]);\n"
                "});\n"
                "app.get('/api/orders/:id', requireAuth, async (req, res) => {\n"
                "  const o = await prisma.order.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });\n"
                "  const c = await prisma.customer.findUnique({ where: { id: o.customerId } });\n"
                "  res.json([o, c]);\n"
                "});\n",
            )
            self.assertEqual([f.line for f in self._audit(ws)], [1, 5])

    def test_static_curl_poc_expands_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "routes.ts", EXPRESS_TWO_ROUTES)
            poc = self._audit(ws)[0].curl_poc
            self.assertIn('"Authorization: Bearer $PRUFGATE_TOKEN_A"', poc)
            self.assertIn('"$TARGET_URL/api/notes/{id}"', poc)
            self.assertNotIn("'", poc)

    def test_file_level_middleware_counts_as_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "routes.ts",
                "router.use(requireAuth);\n"
                "router.get('/api/notes/:id', async (req, res) => {\n"
                "  res.json(await prisma.note.findFirst({ where: { id: req.params.id, ownerId: req.user.id } }));\n"
                "});\n",
            )
            self.assertEqual(self._audit(ws), [])

    def test_rails_controller_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "config/routes.rb", "Rails.application.routes.draw do\n  resources :invoices\nend\n")
            _write(
                ws,
                "app/controllers/application_controller.rb",
                "class ApplicationController < ActionController::Base\n  before_action :authenticate_user!\nend\n",
            )
            _write(
                ws,
                "app/controllers/invoices_controller.rb",
                "class InvoicesController < ApplicationController\n"
                "  def show\n"
                "    @invoice = Invoice.find(params[:id])\n"
                "  end\n"
                "\n"
                "  def update\n"
                "    @invoice = current_user.invoices.find(params[:id])\n"
                "  end\n"
                "end\n",
            )
            findings = self._audit(ws)
            self.assertEqual([(f.endpoint_or_file, f.line) for f in findings], [("app/controllers/invoices_controller.rb", 2)])
            self.assertIn("tenant", findings[0].message)

    def test_laravel_controller_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "app/Http/Controllers/InvoiceController.php",
                "<?php\nclass InvoiceController extends Controller\n{\n"
                "    public function __construct() { $this->middleware('auth'); }\n"
                "    public function show($id)\n    {\n        return Invoice::findOrFail($id);\n    }\n"
                "    public function edit($id)\n    {\n"
                "        return Auth::user()->invoices()->findOrFail($id);\n    }\n}\n",
            )
            findings = self._audit(ws)
            self.assertEqual([f.line for f in findings], [5])

    def test_cli_accepts_target_url_and_id_aliases_and_fails_on_findings(self) -> None:
        # BUG-05: --target-url was rejected with exit 2 by argparse.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "routes.ts", EXPRESS_TWO_ROUTES)
            out = ws / "o.json"
            rc = _quiet(
                bola_engine.main,
                [f"--workspace={ws}", f"--output={out}", "--target-url=http://127.0.0.1:9", "--id-a=a", "--id-b=b"],
            )
            self.assertEqual(rc, 2)
            report = json.loads(out.read_text())
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(_quiet(bola_engine.main, [f"--workspace={ws}/nope", f"--output={out}"]), 2)

    def test_no_live_probe_without_explicit_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TARGET_URL", None)
            with mock.patch.object(bola_engine, "check_server_active") as probe:
                _quiet(bola_engine.main, [f"--workspace={tmp}", f"--output={tmp}/o.json"])
                probe.assert_not_called()

    def test_curl_poc_never_contains_live_tokens(self) -> None:
        token_a = "live" + "A" * 30
        token_b = "live" + "B" * 30
        env = {
            "PRUFGATE_TEST_PROBE_TOKEN_A": token_a,
            "PRUFGATE_TEST_PROBE_TOKEN_B": token_b,
            "PRUFGATE_BOLA_PATHS": "/x",
            "PRUFGATE_CROSS_TENANT_PATHS": "/api/v1/invoices/{tenant_id}",
        }

        class _Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self, url: str) -> None:
                self.url = url

            def read(self) -> bytes:
                return json.dumps({"invoice": self.url.rsplit("/", 1)[-1], "amount": 5}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _Opener:
            def open(self, req, timeout=0):
                if not req.headers.get("Authorization"):
                    raise bola_engine.urllib.error.HTTPError(req.full_url, 401, "no", {}, None)
                return _Resp(req.full_url)

        with mock.patch.dict(os.environ, env), mock.patch.object(
            bola_engine.urllib.request, "build_opener", return_value=_Opener()
        ):
            findings = _quiet(bola_engine.run_dynamic_matrix, "http://127.0.0.1:1")
        cross = [f for f in findings if f.rule_id == "BOLA-CROSS-TENANT-ACCESS"]
        self.assertEqual(len(cross), 2)
        blob = json.dumps([f.to_dict() for f in findings])
        self.assertNotIn(token_a, blob)
        self.assertNotIn(token_b, blob)
        self.assertIn("$PRUFGATE_TOKEN_A", blob)
        self.assertIn("$PRUFGATE_TOKEN_B", blob)

    def test_cross_tenant_probe_needs_real_tokens(self) -> None:
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PRUFGATE_")}
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(
            bola_engine.urllib.request, "build_opener"
        ) as opener:
            opener.return_value.open.side_effect = OSError("offline")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), self.assertRaises(bola_engine.ProbeIncomplete) as caught:
                bola_engine.run_dynamic_matrix("http://127.0.0.1:1")
            for call in opener.return_value.open.call_args_list:
                self.assertIsNone(call.args[0].headers.get("Authorization"))
            self.assertIn("token", str(caught.exception).lower())
            opener.return_value.open.assert_not_called()

    def test_server_action_files_anywhere_and_arrow_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "app/settings/actions.ts",
                "'use server';\n"
                "export const deleteThing = async (id: string) => {\n"
                "  await db.thing.delete({ where: { id } });\n"
                "};\n"
                "export async function saveThing(id: string) {\n"
                "  const s = await auth();\n"
                "  await db.thing.update({ where: { id, ownerId: s.user.id } });\n"
                "}\n",
            )
            hits = [f for f in self._audit(ws) if f.rule_id == "BOLA-UNGUARDED-SERVER-ACTION"]
            self.assertEqual([f.line for f in hits], [2])


def _diff(path: str, *added: str) -> str:
    body = "".join(f"+{a}\n" for a in added)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(added)} @@\n{body}"


SQLI = "const q = db.query(`SELECT * FROM t WHERE id = '${id}'`);"


class ReviewerBugs(unittest.TestCase):
    def test_production_paths_containing_test_are_reviewed(self) -> None:
        # BUG-07: `"test" in file` skipped src/contest/, src/latest/, attestation code.
        for path in ("src/contest/db.ts", "src/latest/db.ts", "src/attestation/db.ts", "build/gen/x.ts"):
            hunks = reviewer.parse_diff_hunks(_diff(path, SQLI))
            self.assertEqual(len(reviewer.analyze_diff(hunks)), 1 if not path.startswith("build/") else 0, path)
        for path in ("tests/db.ts", "src/db.test.ts", "src/__tests__/db.ts", "test_db.py"):
            self.assertEqual(reviewer.analyze_diff(reviewer.parse_diff_hunks(_diff(path, SQLI))), [], path)

    def test_exit_code_on_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "x.diff"
            d.write_text(_diff("src/db.ts", SQLI))
            args = [f"--workspace={tmp}", f"--diff-file={d}", f"--output-json={tmp}/o.json", f"--output-md={tmp}/o.md"]
            self.assertEqual(_quiet(reviewer.main, args), 1)
            d.write_text(_diff("src/db.ts", "const ok = 1;"))
            self.assertEqual(_quiet(reviewer.main, args), 0)
            self.assertEqual(_quiet(reviewer.main, [f"--workspace={tmp}", f"--diff-file={tmp}/missing.diff"]), 2)
            self.assertEqual(_quiet(reviewer.main, [f"--workspace={tmp}", "--base=--output=/tmp/pwn"]), 2)

    def test_no_git_repository_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_quiet(reviewer.main, [f"--workspace={tmp}"]), 2)

    def test_reviewer_crash_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "x.diff"
            d.write_text(_diff("src/db.ts", "const a = 1;"))
            with mock.patch.object(reviewer, "run_hybrid_review", side_effect=RuntimeError("boom")):
                self.assertEqual(_quiet(reviewer.main, [f"--workspace={tmp}", f"--diff-file={d}"]), 2)

    def test_github_output_cannot_inject_workflow_commands(self) -> None:
        evil = reviewer.PRComment(
            "src/a,b:c.ts", 3, "P1", "t::x", "line1\n::error file=x::forged\r\n::add-mask::z"
        )
        out = reviewer.format_review_github([evil])
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("::error file=src/a%2Cb%3Ac.ts,line=3,title="))
        stop = [ln for ln in lines if ln.startswith("::stop-commands::")]
        self.assertEqual(len(stop), 1)
        token = stop[0].split("::")[2]
        idx_stop = lines.index(stop[0])
        idx_resume = lines.index(f"::{token}::")
        for i, ln in enumerate(lines):
            if ln.startswith("::") and not (i == 0 or i in (idx_stop, idx_resume)):
                self.assertTrue(idx_stop < i < idx_resume, ln)

    def test_core_rules_fire_and_near_misses_do_not(self) -> None:
        secret = "s" * 20
        cases = {
            "subprocess.run(cmd, shell=True)": "Shell Command Injection Risk",
            "subprocess.run(['ls', path])": None,
            f'password = "{secret}"': "Hardcoded Credential in Code",
            'password = "short"': None,
        }
        for line, title in cases.items():
            got = [c.title for c in reviewer.analyze_diff(reviewer.parse_diff_hunks(_diff("src/a.py", line)))]
            self.assertEqual(got, [title] if title else [], line)

    def test_comment_only_suggestions_never_emitted(self) -> None:
        hunks = reviewer.parse_diff_hunks(_diff("src/log.ts", "console.log('token', token);"))
        comments = reviewer.analyze_diff(hunks)
        self.assertEqual(len(comments), 1)
        self.assertNotIn("```suggestion", reviewer.format_review_markdown(comments))

    def test_ai_comments_must_point_at_added_lines(self) -> None:
        diff = _diff("src/a.ts", "const a = 1;", "const b = 2;")
        fake = ai_adapter.AIReviewResult(
            provider="x",
            status="executed",
            comments=[
                {"file": "src/a.ts", "line": 2, "severity": "P2", "title": "[AI] ok", "message": "m", "suggestion": "// only"},
                {"file": "src/a.ts", "line": 99, "severity": "P0", "title": "[AI] off", "message": "m", "suggestion": None},
                {"file": "/etc/passwd", "line": 1, "severity": "P0", "title": "[AI] x", "message": "m", "suggestion": None},
            ],
        )
        with mock.patch.object(reviewer, "review_diff_with_ai", return_value=fake):
            with self.assertRaisesRegex(reviewer.DiffUnavailableError, "outside the reviewed changed lines"):
                reviewer.run_hybrid_review(diff, enable_ai=True)
        fake.comments = fake.comments[:1]
        with mock.patch.object(reviewer, "review_diff_with_ai", return_value=fake):
            comments = reviewer.run_hybrid_review(diff, enable_ai=True)
        self.assertEqual([(c.file_path, c.line) for c in comments], [("src/a.ts", 2)])
        self.assertIsNone(comments[0].suggestion)

    def test_diff_parser_edge_cases(self) -> None:
        diff = (
            "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,0 +1,2 @@\n+++counter;\n+int x;\n"
            "\\ No newline at end of file\n"
            "diff --git a/gone.ts b/gone.ts\n--- a/gone.ts\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        )
        hunks = reviewer.parse_diff_hunks(diff)
        self.assertEqual([(h["file"], h["line"], h["content"]) for h in hunks], [("a.c", 1, "++counter;"), ("a.c", 2, "int x;")])

    def test_xss_sanitiser_on_a_later_line_does_not_hide_an_earlier_sink(self) -> None:
        hunks = reviewer.parse_diff_hunks(
            _diff("web/a.ts", "el.innerHTML = userInput;", "other.innerHTML = DOMPurify.sanitize(x);")
        )
        self.assertEqual([c.line for c in reviewer.analyze_diff(hunks)], [1])

    def test_go_ignored_error_from_package_function(self) -> None:
        hunks = reviewer.parse_diff_hunks(_diff("svc/main.go", "v, _ := strconv.Atoi(s)"))
        self.assertEqual([c.title for c in reviewer.analyze_diff(hunks)], ["Ignored Error Return in Go"])

    def test_sarif_has_no_unrelated_information_uri(self) -> None:
        sarif = json.loads(reviewer.format_review_sarif([]))
        self.assertNotIn("informationUri", sarif["runs"][0]["tool"]["driver"])


class AiAdapterSafety(unittest.TestCase):
    def test_http_errors_never_echo_the_api_key(self) -> None:
        key = "sk-" + "k" * 40

        def boom(req, timeout=0):
            raise ai_adapter.urllib.error.URLError(f"refused {req.headers}")

        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": key}), mock.patch.object(
            ai_adapter.urllib.request, "urlopen", side_effect=boom
        ):
            ok, note = ai_adapter._invoke_http_llm("openai", "p")
        self.assertFalse(ok)
        self.assertNotIn(key, note)

    def test_cli_agent_output_errors_are_redacted(self) -> None:
        key = "sk-" + "q" * 40
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": key}), mock.patch.object(
            ai_adapter.shutil, "which", return_value="/bin/false"
        ), mock.patch.object(
            ai_adapter.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, stdout="", stderr=f"bad key {key}"),
        ):
            ok, note = ai_adapter._invoke_cli_agent("codex", "p")
        self.assertFalse(ok)
        self.assertNotIn(key, note)


if __name__ == "__main__":
    unittest.main()
