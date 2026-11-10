"""GitLab Code Quality and JUnit XML reports (prufgate/report_formats.py) on every surface."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path

from prufgate.cli import _sarif_findings_doc
from prufgate.cli import main as cli_main
from prufgate.report_formats import gitlab_code_quality, junit_xml
from prufgate.review.reviewer import PRComment, format_review_other
from prufgate.synthesizer.parse_results import Finding, generate_sarif

ROOT = Path(__file__).resolve().parent.parent


def _xml(text: str) -> ET.Element:
    return ET.fromstring(text)  # noqa: S314 -- parses the JUnit XML PrufGate itself just wrote, never untrusted input


SOURCE = "def handler(request):\n    token = request.args['t']\n    return lookup(token)\n"


def _finding(rule: str, severity: str, line: int = 2, message: str = "m", file: str = "app.py") -> dict:
    return {"rule": rule, "severity": severity, "engine": "e", "message": message, "file": file, "line": line}


class ReportFormats(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text(SOURCE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _doc(self, findings, honoured=None):
        return _sarif_findings_doc(findings, self.root, honoured)

    def test_gitlab_schema_and_severity_mapping(self):
        findings = [_finding(f"r{i}", sev, line=i + 1) for i, sev in enumerate(("P0", "P1", "P2", "P3"))]
        issues = json.loads(gitlab_code_quality(self._doc(findings)))
        self.assertEqual([i["severity"] for i in issues], ["blocker", "critical", "major", "minor"])
        for issue in issues:
            self.assertTrue({"description", "check_name", "fingerprint", "severity", "location"} <= issue.keys())
            self.assertEqual(issue["location"]["path"], "app.py")
            self.assertIsInstance(issue["location"]["lines"]["begin"], int)
            self.assertRegex(issue["fingerprint"], r"^[0-9a-f]{32}$")
        self.assertEqual(len({i["fingerprint"] for i in issues}), 4)

    def test_fingerprint_is_the_sarif_one_and_stable(self):
        doc = self._doc([_finding("r1", "P1")])
        sarif_fp = doc["runs"][0]["results"][0]["partialFingerprints"]["prufgateFindingHash/v1"]
        first = json.loads(gitlab_code_quality(doc))[0]["fingerprint"]
        self.assertEqual(first, sarif_fp)
        # Lines inserted above the finding move it, but its fingerprint stays.
        (self.root / "app.py").write_text("import os\n\n" + SOURCE, encoding="utf-8")
        moved = json.loads(gitlab_code_quality(self._doc([_finding("r1", "P1", line=4)])))[0]
        self.assertEqual(moved["fingerprint"], first)
        self.assertEqual(moved["location"]["lines"]["begin"], 4)

    def test_suppressed_findings_are_excluded(self):
        honoured = [dict(_finding("r2", "P0", line=1), kind="honoured", reason="covered elsewhere")]
        doc = self._doc([_finding("r1", "P2")], honoured)
        self.assertEqual([i["check_name"] for i in json.loads(gitlab_code_quality(doc))], ["r1"])
        tree = _xml(junit_xml(doc))
        self.assertEqual([s.get("name") for s in tree.iter("testsuite")], ["r1"])
        self.assertEqual(tree.get("failures"), "0")

    def test_empty_reports(self):
        doc = self._doc([])
        self.assertEqual(json.loads(gitlab_code_quality(doc)), [])
        tree = _xml(junit_xml(doc))
        self.assertEqual((tree.get("tests"), tree.get("failures"), tree.get("skipped")), ("1", "0", "0"))
        case = next(tree.iter("testcase"))
        self.assertEqual(list(case), [])

    def test_junit_failures_skips_and_order(self):
        findings = [_finding("zz-rule", "P3", line=3), _finding("aa-rule", "P2", line=1), _finding("aa-rule", "P0", line=2)]
        tree = _xml(junit_xml(self._doc(findings)))
        self.assertEqual((tree.get("tests"), tree.get("failures"), tree.get("skipped")), ("3", "1", "2"))
        suites = list(tree.iter("testsuite"))
        self.assertEqual([s.get("name") for s in suites], ["aa-rule", "zz-rule"])
        cases = list(suites[0])
        self.assertEqual([c.get("name") for c in cases], ["app.py:1", "app.py:2"])
        self.assertEqual(cases[0][0].tag, "skipped")
        self.assertEqual((cases[1][0].tag, cases[1][0].get("type")), ("failure", "P0"))
        self.assertEqual(cases[1].get("file"), "app.py")
        # Input order does not change the output.
        self.assertEqual(junit_xml(self._doc(findings[::-1])), junit_xml(self._doc(findings)))

    def test_junit_ignores_a_non_boolean_blocking_flag(self):
        doc = self._doc([_finding("r1", "P0"), _finding("r2", "P3")])
        for result in doc["runs"][0]["results"]:
            result.setdefault("properties", {})["blocking"] = "false"
        tree = _xml(junit_xml(doc))
        self.assertEqual((tree.get("failures"), tree.get("skipped")), ("1", "1"))

    def test_junit_escapes_special_characters(self):
        nasty = 'a <tag> & "quote" \'apos\' \x1b[31m \x00 end'
        tree = _xml(junit_xml(self._doc([_finding("r1", "P1", message=nasty, file="dir/<x>&.py")])))
        failure = next(tree.iter("failure"))
        self.assertIn('<tag> & "quote"', failure.get("message"))
        self.assertIn("�", failure.text)
        self.assertNotIn("\x00", failure.text)
        self.assertEqual(next(tree.iter("testcase")).get("file"), "dir/<x>&.py")
        self.assertEqual(json.loads(gitlab_code_quality(self._doc([_finding("r1", "P1", message=nasty)])))[0]["description"].count("<tag>"), 1)

    def test_check_cli_formats(self):
        src = "test('fake test', () => {\n  const x = 1 + 1;\n});\n"
        (self.root / "bad.test.ts").write_text(src, encoding="utf-8")
        for fmt in ("gitlab", "junit"):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli_main(["check", str(self.root / "bad.test.ts"), "--format", fmt])
            self.assertIn(rc, (0, 1))
            if fmt == "gitlab":
                self.assertTrue(json.loads(out.getvalue()))
            else:
                self.assertGreaterEqual(int(_xml(out.getvalue()).get("tests")), 1)

    def test_review_formats(self):
        comment = PRComment(file_path="app.py", line=2, severity="P1", title="Title", message="m")
        issue = json.loads(format_review_other("gitlab", [comment], self.root))[0]
        self.assertEqual((issue["severity"], issue["check_name"]), ("critical", "pr-title"))
        self.assertEqual(_xml(format_review_other("junit", [comment], self.root)).get("failures"), "1")

    def test_synthesizer_writes_both_reports(self):
        reports = self.root / "reports"
        raw = reports / "raw"
        raw.mkdir(parents=True)
        (raw / "anti_fabrication.json").write_text(
            json.dumps([{"rule": "unimplemented-production-stub", "file": "app.py", "line": 2, "text": "x"}])
        )
        (raw / "suppressions.jsonl").write_text(
            json.dumps({"kind": "honoured", "engine": "anti-fabrication", "file": "app.py", "line": 3,
                        "rule": "stub-click-handler", "severity": "P0", "message": "stub", "reason": "a fixture"}) + "\n"
        )
        env = {**os.environ, "WORKSPACE": str(self.root), "PRUFGATE_REPORTS_DIR": str(reports), "NO_COLOR": "1"}
        script = str(ROOT / "prufgate" / "synthesizer" / "parse_results.py")
        res = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True, timeout=60, cwd=self.root)
        self.assertIn(res.returncode, (1, 2), res.stdout + res.stderr)
        issues = json.loads((reports / "gl-code-quality-report.json").read_text(encoding="utf-8"))
        self.assertEqual([i["severity"] for i in issues if "stub" in i["check_name"]], ["blocker"])
        self.assertFalse(any("click" in i["check_name"] for i in issues))
        tree = _xml((reports / "prufgate-junit.xml").read_text(encoding="utf-8"))
        self.assertGreaterEqual(int(tree.get("failures")), 1)

    def test_engine_errors_never_read_as_a_clean_report(self):
        doc = self._doc([])
        errors = {"anti_fabrication": "exited 2"}
        issues = json.loads(gitlab_code_quality(doc, errors))
        self.assertEqual([(i["check_name"], i["severity"]) for i in issues], [("prufgate-engine-error", "blocker")])
        tree = _xml(junit_xml(doc, errors))
        self.assertEqual((tree.get("tests"), tree.get("errors")), ("1", "1"))
        self.assertNotIn("no findings", [c.get("name") for c in tree.iter("testcase")])
        self.assertEqual(len(list(tree.iter("error"))), 1)

    def test_synthesizer_reports_a_missing_manifest_as_an_error(self):
        reports = self.root / "reports"
        (reports / "raw").mkdir(parents=True)
        env = {**os.environ, "WORKSPACE": str(self.root), "PRUFGATE_REPORTS_DIR": str(reports), "NO_COLOR": "1"}
        script = str(ROOT / "prufgate" / "synthesizer" / "parse_results.py")
        res = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True, timeout=60, cwd=self.root)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        tree = _xml((reports / "prufgate-junit.xml").read_text(encoding="utf-8"))
        self.assertEqual(tree.get("errors"), "1")
        issues = json.loads((reports / "gl-code-quality-report.json").read_text(encoding="utf-8"))
        self.assertEqual([i["severity"] for i in issues], ["blocker"])

    def test_synthesizer_sarif_feeds_both(self):
        out = self.root / "out.sarif"
        doc = generate_sarif([Finding("anti-fabrication", "r1", "P3", "note", "app.py", 2)], out, self.root)
        self.assertEqual(json.loads(gitlab_code_quality(doc))[0]["severity"], "minor")
        self.assertEqual(_xml(junit_xml(doc)).get("skipped"), "1")


if __name__ == "__main__":
    unittest.main()
