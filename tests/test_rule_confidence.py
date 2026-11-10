"""Rule confidence (high / medium / low): every rule has one, low rules are off by default."""

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate import rules
from prufgate.api import server as api_server
from prufgate.cli import main as cli_main
from prufgate.config import ConfigError, PrufGateConfig
from prufgate.mcp import prufgate_mcp_server as mcp
from prufgate.review import reviewer
from prufgate.review.reviewer import review_rule_id
from prufgate.rules import CONFIDENCE, confidence
from prufgate.synthesizer import parse_results as synth

ROOT = Path(__file__).resolve().parent.parent
ENGINE_DIRS = ("anti_fabrication", "anti_reward_hacking", "diff_guard", "contract_guard", "bola", "review")
# Where an engine names the rule of a finding it emits.
RULE_PATTERNS = (
    re.compile(r'\brule(?:_id)?\s*=\s*"([A-Za-z][\w-]+)"'),
    re.compile(r'(?:Finding|finding_cls)\(\s*[^,()]+,\s*[^,()]+(?:\([^()]*\))?[^,()]*,\s*"([a-z][\w-]+)"'),
    re.compile(r'\brule\s*=\s*"[\w-]+"\s+if\b[^\n]*\belse\s+"([a-z][\w-]+)"'),
)
TITLE_PATTERN = re.compile(r'\btitle="([^"]+)"')
MOCK_LINE = "export const MOCK_USERS = [{ name: 'a' }];\n"


def emitted_rule_ids() -> set[str]:
    out: set[str] = set()
    for d in ENGINE_DIRS:
        for path in (ROOT / "prufgate" / d).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for pat in RULE_PATTERNS:
                out |= set(pat.findall(text))
            if d == "review":
                out |= {review_rule_id(t) for t in TITLE_PATTERN.findall(text)}
    return out


def registered(rule: str) -> bool:
    """Listed in the registry itself or through an alias, never by falling back to the default."""
    saved = dict(CONFIDENCE)
    try:
        for k in CONFIDENCE:
            CONFIDENCE[k] = "sentinel"
        return confidence(rule) == "sentinel"
    finally:
        CONFIDENCE.update(saved)


class TestRuleRegistry(unittest.TestCase):
    def test_every_emitted_rule_has_a_confidence(self) -> None:
        rules = emitted_rule_ids()
        self.assertGreater(len(rules), 55, "the rule walk found too few rules; a pattern broke")
        missing = sorted(r for r in rules if not registered(r))
        self.assertEqual(missing, [], "add these rules to prufgate/rules.py CONFIDENCE")

    def test_levels_are_valid(self) -> None:
        self.assertTrue(set(CONFIDENCE.values()) <= {"high", "medium", "low"})

    def test_aliases_prefixes_and_unknown_rules(self) -> None:
        self.assertEqual(confidence("demo-named-data"), "low")
        self.assertEqual(confidence("anti-fabrication-fake-named-data"), "low")
        self.assertEqual(confidence("pr-test-skip-smuggling"), "high")
        self.assertEqual(confidence("gate-failed-lint"), "high")
        # Another tool's rule is never hidden.
        self.assertEqual(confidence("generic-api-key"), "medium")


class TestConfig(unittest.TestCase):
    def _load(self, body: str) -> PrufGateConfig:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".prufgate").mkdir()
            (Path(tmp) / ".prufgate" / "config.yaml").write_text(body, encoding="utf-8")
            return PrufGateConfig.load(tmp)

    def test_default_off_and_true_on(self) -> None:
        self.assertFalse(PrufGateConfig().enable_low_confidence)
        self.assertFalse(self._load("version: 1\n").enable_low_confidence)
        self.assertTrue(self._load("enable_low_confidence: true\n").enable_low_confidence)

    def test_non_boolean_is_an_error(self) -> None:
        for bad in ('"yes"', "1", "[true]", "low"):
            with self.assertRaisesRegex(ConfigError, "enable_low_confidence must be true or false"):
                self._load(f"enable_low_confidence: {bad}\n")


class TestCheck(unittest.TestCase):
    def _check(self, ws: Path, fmt: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["check", str(ws), "--format", fmt])
        return rc, buf.getvalue()

    def test_low_rule_hidden_by_default_and_shown_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "users.ts").write_text(MOCK_LINE, encoding="utf-8")

            rc, out = self._check(ws, "json")
            self.assertEqual(rc, 0)
            self.assertNotIn("demo-named-data", {f["rule"] for f in json.loads(out)})

            (ws / ".prufgate").mkdir()
            (ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: true\n", encoding="utf-8")
            rc, out = self._check(ws, "json")
            self.assertEqual(rc, 1)
            hits = [f for f in json.loads(out) if f["rule"] == "demo-named-data"]
            self.assertEqual([f["confidence"] for f in hits], ["low"])

            rc, out = self._check(ws, "sarif")
            self.assertEqual(rc, 1)
            run = json.loads(out)["runs"][0]
            result = next(r for r in run["results"] if r["ruleId"] == "demo-named-data")
            self.assertEqual(result["properties"]["confidence"], "low")
            rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "demo-named-data")
            self.assertEqual(rule["properties"]["precision"], "low")
            self.assertEqual(rule["defaultConfiguration"]["rank"], 30.0)


class TestSynthesizer(unittest.TestCase):
    def _run(self, ws: Path) -> tuple[int, Path]:
        raw = ws / "reports" / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        for tool, out in synth.ENGINE_OUTPUTS.items():
            if tool in synth.CORE_ENGINES:
                (raw / out).write_text("[]", encoding="utf-8")
        (raw / "anti_fabrication.json").write_text(
            json.dumps(
                [
                    {"rule": "fake-named-data", "file": "src/users.ts", "line": 1, "snippet": "MOCK_USERS"},
                    {"rule": "unimplemented-production-stub", "file": "src/pay.py", "line": 3, "snippet": "todo"},
                ]
            ),
            encoding="utf-8",
        )
        (raw / "execution_manifest.jsonl").write_text(
            "".join(json.dumps({"tool": t, "status": "executed"}) + "\n" for t in synth.CORE_ENGINES),
            encoding="utf-8",
        )
        env = {"WORKSPACE": str(ws), "PRUFGATE_REPORTS_DIR": str(ws / "reports")}
        with patch.dict(os.environ, env), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                synth.main()
        return int(cm.exception.code or 0), ws / "reports"

    def test_low_rule_hidden_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc, reports = self._run(Path(tmp))
            self.assertEqual(rc, 1)  # the high-confidence stub still blocks
            sarif = json.loads((reports / "prufgate.sarif").read_text(encoding="utf-8"))
            ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
            self.assertEqual(ids, {"anti-fabrication-unimplemented-production-stub"})
            result = sarif["runs"][0]["results"][0]
            self.assertEqual(result["properties"]["confidence"], "high")
            rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
            self.assertEqual(rule["properties"]["precision"], "high")
            self.assertEqual(rule["defaultConfiguration"]["rank"], 90.0)
            md = (reports / "prufgate-review.md").read_text(encoding="utf-8")
            self.assertIn("**Confidence:** high", md)
            self.assertNotIn("fake-named-data", md)

    def test_low_rule_shown_and_blocking_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".prufgate").mkdir()
            (ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: true\n", encoding="utf-8")
            (ws / "src").mkdir()
            rc, reports = self._run(ws)
            self.assertEqual(rc, 1)
            md = (reports / "prufgate-review.md").read_text(encoding="utf-8")
            self.assertIn("anti-fabrication-fake-named-data", md)
            self.assertIn("**Confidence:** low", md)

    def test_only_low_findings_pass_by_default(self) -> None:
        findings = [synth.Finding("anti-fabrication", "anti-fabrication-fake-named-data", "P0", "m")]
        self.assertEqual(synth.filter_confidence(findings, False), [])
        self.assertEqual(len(synth.filter_confidence(findings, True)), 1)
        self.assertEqual(findings[0].to_dict()["confidence"], "low")

    def test_invalid_config_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".prufgate").mkdir()
            (ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: maybe\n", encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                rc, _ = self._run(ws)
            self.assertEqual(rc, 2)


def _enable_low(ws: Path) -> None:
    (ws / ".prufgate").mkdir(exist_ok=True)
    (ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: true\n", encoding="utf-8")


def _quiet(fn, *args, **kwargs):
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        rc = fn(*args, **kwargs)
    return rc, out.getvalue()


class TestEverySurface(unittest.TestCase):
    """Each surface: a low finding is hidden and passes by default, shown and blocking when enabled."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_mcp_tool(self) -> None:
        (self.ws / "src").mkdir()
        (self.ws / "src" / "users.ts").write_text(MOCK_LINE, encoding="utf-8")
        res = mcp.prufgate_anti_fabrication(workspace_path=str(self.ws))
        self.assertEqual((res["status"], res["passed"], res["total_findings"]), ("ok", True, 0))
        _enable_low(self.ws)
        res = mcp.prufgate_anti_fabrication(workspace_path=str(self.ws))
        self.assertFalse(res["passed"])
        self.assertIn("demo-named-data", {f["rule"] for f in res["findings"]})

    def test_mcp_invalid_config_is_an_error(self) -> None:
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: 1\n", encoding="utf-8")
        res = mcp._result("t", self.ws, [], None)
        self.assertEqual(res["status"], "error")
        self.assertFalse(res["passed"])

    def _api_scan(self) -> dict:
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": [
            {"message": {"text": "fixture finding"}, "ruleId": "anti-fabrication-fake-named-data", "properties": {"severity": "P0"}},
            {"message": {"text": "fixture finding"}, "ruleId": "anti-fabrication-unimplemented-production-stub", "properties": {"severity": "P2"}},
        ]}]}

        def fake_run(scan_id, cmd, cwd, env):
            Path(env["PRUFGATE_REPORTS_DIR"], "prufgate.sarif").write_text(json.dumps(sarif))
            return 0, "", ""

        real = api_server.__dict__.get("_real_worker") or api_server.execute_scan_worker
        with api_server.SCANS_LOCK:
            api_server.SCANS["c"] = {"scan_id": "c", "status": "queued"}
        with patch.object(api_server, "run_scan_process", fake_run):
            real("c", "fast", str(self.ws), None)
        with api_server.SCANS_LOCK:
            return dict(api_server.SCANS.pop("c"))

    def test_rest_api(self) -> None:
        scan = self._api_scan()
        self.assertEqual(scan["findings_summary"], {"p0": 0, "p1": 0, "p2": 1, "p3": 0})
        _enable_low(self.ws)
        self.assertEqual(self._api_scan()["findings_summary"]["p0"], 1)

    def _review(self) -> tuple[int, list]:
        diff = self.ws / "change.diff"
        diff.write_text(
            "diff --git a/src/a.ts b/src/a.ts\n--- a/src/a.ts\n+++ b/src/a.ts\n@@ -0,0 +1 @@\n"
            "+console.log('login', password);\n",
            encoding="utf-8",
        )
        rc, out = _quiet(
            cli_main,
            ["review", "--workspace", str(self.ws), "--diff-file", str(diff), "--format", "json"],
        )
        return rc, json.loads(out)

    def test_review_command(self) -> None:
        rc, comments = self._review()
        self.assertEqual((rc, comments), (0, []))
        _enable_low(self.ws)
        rc, comments = self._review()
        self.assertEqual(rc, 1)
        self.assertEqual([c["title"] for c in comments], ["Credential Logging in Console"])

    def test_review_invalid_config_is_an_error(self) -> None:
        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: on-ish\n", encoding="utf-8")
        rc, _ = _quiet(reviewer.main, [f"--workspace={self.ws}", "--diff-file=/nonexistent", "--format=json"])
        self.assertEqual(rc, 2)

    def test_bola_command(self) -> None:
        mig = self.ws / "database" / "migrations"
        mig.mkdir(parents=True)
        (mig / "001.sql").write_text("CREATE TABLE invoices (\n  id serial primary key,\n  total int\n);\n")
        args = ["bola", str(self.ws), "--static-only", "--format", "json"]
        rc, out = _quiet(cli_main, args)
        self.assertEqual((rc, json.loads(out)), (0, []))
        _enable_low(self.ws)
        rc, out = _quiet(cli_main, args)
        self.assertEqual(rc, 1)
        self.assertEqual([f["rule_id"] for f in json.loads(out)], ["BOLA-TABLE-MISSING-TENANT-COLUMN"])

    def test_test_audit_command(self) -> None:
        # Engine 2 has no low rule yet: mark one low for this test to prove the command filters.
        (self.ws / "tests").mkdir()
        (self.ws / "tests" / "test_a.py").write_text("def test_a():\n    x = 1 + 1\n", encoding="utf-8")
        out = self.ws / "ti.json"
        args = ["test-audit", str(self.ws), "--json-out", str(out)]
        with patch.dict(rules.CONFIDENCE, {"zero-assertion-test": "low"}):
            rc, _ = _quiet(cli_main, args)
            self.assertEqual((rc, json.loads(out.read_text())), (0, []))
            _enable_low(self.ws)
            rc, _ = _quiet(cli_main, args)
            self.assertEqual(rc, 1)
            self.assertEqual([f["rule"] for f in json.loads(out.read_text())], ["zero-assertion-test"])


def _git(ws: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=ws, check=True, capture_output=True)


class TestSettingReadAtTheBase(unittest.TestCase):
    """A branch that turns low-confidence rules off must not hide its own low findings."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _git(self.ws, "init", "-q", "-b", "main")
        _enable_low(self.ws)
        _git(self.ws, "add", "-A")
        _git(self.ws, "commit", "-qm", "base")
        _git(self.ws, "checkout", "-qb", "feature")
        (self.ws / ".prufgate" / "config.yaml").write_text("enable_low_confidence: false\n", encoding="utf-8")
        (self.ws / "src").mkdir()
        (self.ws / "src" / "a.ts").write_text("console.log('login', password);\n", encoding="utf-8")
        _git(self.ws, "add", "-A")
        _git(self.ws, "commit", "-qm", "feature")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_review_reads_the_base_setting(self) -> None:
        rc, out = _quiet(reviewer.main, [f"--workspace={self.ws}", "--base=main", "--format=json"])
        self.assertEqual(rc, 1)
        self.assertEqual([c["title"] for c in json.loads(out)], ["Credential Logging in Console"])

    def test_mcp_result_reads_the_base_setting(self) -> None:
        low = [{"rule": "fake-named-data", "severity": "P0"}]
        self.assertTrue(mcp._result("t", self.ws, low, None)["passed"])
        self.assertFalse(mcp._result("t", self.ws, low, None, cfg_ref="main")["passed"])

    def test_rest_api_reads_the_base_setting(self) -> None:
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": [{"message": {"text": "fixture finding"}, "ruleId": "anti-fabrication-fake-named-data", "properties": {"severity": "P0"}}]}]}

        def fake_run(scan_id, cmd, cwd, env):
            reports = Path(env["PRUFGATE_REPORTS_DIR"])
            (reports / "raw").mkdir(parents=True, exist_ok=True)
            (reports / "raw" / "base_ref").write_text("main\n")
            (reports / "prufgate.sarif").write_text(json.dumps(sarif))
            return 1, "", ""

        with api_server.SCANS_LOCK:
            api_server.SCANS["b"] = {"scan_id": "b", "status": "queued"}
        with patch.object(api_server, "run_scan_process", fake_run):
            api_server.execute_scan_worker("b", "fast", str(self.ws), None)
        with api_server.SCANS_LOCK:
            scan = dict(api_server.SCANS.pop("b"))
        self.assertEqual(scan["findings_summary"]["p0"], 1)


class TestEngineScriptsAndApi(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_detector_debt_ceiling_ignores_disabled_low_rules(self) -> None:
        import subprocess
        import sys

        (self.ws / ".prufgate").mkdir()
        (self.ws / ".prufgate" / "config.yaml").write_text("known_debt:\n  fake-named-data: 0\n", encoding="utf-8")
        (self.ws / "src").mkdir()
        (self.ws / "src" / "users.ts").write_text(MOCK_LINE, encoding="utf-8")
        out = self.ws / "af.json"
        res = subprocess.run(
            [sys.executable, str(ROOT / "prufgate/anti_fabrication/detector.py"), "src", f"--json-out={out}"],
            cwd=self.ws, capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(json.loads(out.read_text()), [])

    def test_bola_engine_hides_disabled_low_rules(self) -> None:
        from prufgate.bola import bola_engine

        mig = self.ws / "database" / "migrations"
        mig.mkdir(parents=True)
        (mig / "001.sql").write_text("CREATE TABLE invoices (\n  id serial primary key,\n  total int\n);\n")
        out = self.ws / "bola.json"
        rc, _ = _quiet(bola_engine.main, [f"--workspace={self.ws}", "--static-only", f"--output={out}"])
        self.assertEqual((rc, json.loads(out.read_text())), (0, []))


    def test_rest_api_does_not_count_an_honoured_inline_ignore(self) -> None:
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": [
            {"message": {"text": "fixture finding"}, "ruleId": "unimplemented-production-stub", "properties": {"severity": "P0"},
             "suppressions": [{"kind": "inSource", "justification": "#1: fine"}]},
        ]}]}

        def fake_run(scan_id, cmd, cwd, env):
            Path(env["PRUFGATE_REPORTS_DIR"], "prufgate.sarif").write_text(json.dumps(sarif))
            return 0, "", ""

        with api_server.SCANS_LOCK:
            api_server.SCANS["s"] = {"scan_id": "s", "status": "queued"}
        with patch.object(api_server, "run_scan_process", fake_run):
            api_server.execute_scan_worker("s", "fast", str(self.ws), None)
        with api_server.SCANS_LOCK:
            scan = dict(api_server.SCANS.pop("s"))
        self.assertEqual(scan["findings_summary"]["p0"], 0)


if __name__ == "__main__":
    unittest.main()
