"""Issue #28: in the changed scope the contract guard diffs against the chosen
base ref, so a ghost import added in an earlier commit of a branch is reported
by `prufgate check`, the gate and the MCP tool."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from test_fail_closed_runner import git, run_gate  # noqa: E402

from prufgate.mcp import prufgate_mcp_server as mcp  # noqa: E402

RULE = "undeclared-or-hallucinated-import"


def two_commit_branch() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    ws = Path(tmp.name)
    git(ws, "init", "-q", "-b", "main")
    (ws / "package.json").write_text(json.dumps({"name": "x", "dependencies": {"react": "19.0.0"}}), encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "init")
    git(ws, "checkout", "-qb", "feature")
    (ws / "src").mkdir()
    (ws / "src" / "app.ts").write_text('import x from "leftpad-ultra-fast";\nexport default x;\n', encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "ghost import")
    (ws / "notes.txt").write_text("unrelated\n", encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "unrelated")
    return tmp


class ContractGuardBaseRef(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = two_commit_branch()
        self.ws = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_cli_check_passes_base_to_contract_guard(self) -> None:
        proc = subprocess.run([sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", str(self.ws),
                               "--changed", "--base", "main", "--format", "json"],
                              capture_output=True, text=True, timeout=120)
        rules = {(f["engine"], f["rule"], f["file"]) for f in json.loads(proc.stdout)}
        self.assertIn(("contract-guard", RULE, "src/app.ts"), rules)

    @unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
    def test_gate_passes_base_to_contract_guard(self) -> None:
        proc = run_gate(self.ws, "fast", env={"WORKSPACE": str(self.ws), "PRUFGATE_BASE_REF": "main"})
        raw = json.loads((self.ws / "reports" / "raw" / "contract_guard.json").read_text(encoding="utf-8"))
        self.assertIn(RULE, {f.get("rule") for f in raw}, proc.stdout[-2000:])

    def test_mcp_contract_check_takes_base_ref(self) -> None:
        res = mcp.prufgate_contract_check(str(self.ws), changed_only=True, base_ref="main")
        self.assertEqual(res["status"], "ok", res)
        self.assertIn(RULE, {f["rule"] for f in res["findings"]})


if __name__ == "__main__":
    unittest.main()
