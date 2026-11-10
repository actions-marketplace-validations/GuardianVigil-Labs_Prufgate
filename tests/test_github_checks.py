"""GitHub Checks payloads and mocked HTTP only: these tests never publish."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from test_review_workflow import commit, finding, git

from prufgate import cli
from prufgate.github_checks import EXTERNAL_ID, NAME, CheckError, NoRedirect, prepare, publish
from prufgate.scan_result import make_result


class Response:
    def __init__(self, data):
        self.data = json.dumps(data).encode()
    def read(self, size=-1):
        return self.data[:size] if size >= 0 else self.data
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q")
        (self.root / "app.py").write_text("def run():\n    return 1\n")
        self.base = commit(self.root)
        (self.root / "app.py").write_text("def run():\n    raise NotImplementedError\n")
        commit(self.root)

    def result(self, items=None, **kw):
        return make_result([finding()] if items is None else items, root=self.root, coverage={"base_ref": self.base}, **kw)

    def test_only_changed_lines_receive_annotations_and_coverage_is_in_the_summary(self):
        result = self.result([finding(), {**finding(), "line": 1}, {**finding(), "file": "../outside.py"}])
        payload = prepare(result, self.root)
        self.assertEqual(len(payload["output"]["annotations"]), 1)
        self.assertEqual(payload["output"]["annotations"][0]["start_line"], 2)
        self.assertEqual(payload["prufgate"]["omitted_annotations"], 2)
        self.assertIn("Coverage:", payload["output"]["summary"])
        self.assertEqual(payload["conclusion"], "failure")

    def test_advisory_and_incomplete_checks_have_distinct_conclusions(self):
        result = self.result(enforcement={"mode": "advisory", "blocking_rules": [], "minimum_confidence": "low"})
        payload = prepare(result, self.root, self.base)
        self.assertEqual(payload["conclusion"], "neutral")
        self.assertEqual(payload["output"]["annotations"][0]["annotation_level"], "warning")
        result = self.result([], incomplete=["Control unavailable"])
        self.assertEqual(prepare(result, self.root)["conclusion"], "failure")

    def test_preview_cli_does_not_use_any_http_opener(self):
        result = self.result()
        reports = self.root / "reports"
        reports.mkdir()
        path = reports / "result.json"
        path.write_text(json.dumps(result))
        with patch("prufgate.github_checks._open") as network, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["github-check", "--workspace", str(self.root), "--result", str(path)]), 0)
        network.assert_not_called()

    def test_failed_scan_with_an_unavailable_base_produces_a_failing_check(self):
        result = make_result([], root=self.root, coverage={"base_ref": "missing-comparison-base"}, errors=["Comparison unavailable"])
        payload = prepare(result, self.root)
        self.assertEqual(payload["conclusion"], "failure")
        self.assertEqual(payload["output"]["annotations"], [])
        self.assertIn("comparison base was unusable", payload["output"]["summary"])

    def test_publication_batches_annotations_and_completes_only_after_upload(self):
        result = self.result()
        payload = prepare(result, self.root)
        payload["output"]["annotations"] *= 121
        calls = []
        def opener(req, timeout):
            body = json.loads(req.data) if req.data else None
            calls.append((req.method, req.full_url, body))
            if req.method == "GET":
                return Response({"check_runs": []})
            return Response({"id": 17})
        reply = publish(payload, result, self.root, "example/project", "invented-auth-value", opener=opener)
        batches = [body["output"]["annotations"] for _, _, body in calls if body and "annotations" in body.get("output", {})]
        self.assertEqual([len(batch) for batch in batches], [50, 50, 21])
        self.assertEqual(calls[-1][2], {"status": "completed", "conclusion": "failure"})
        self.assertEqual(reply["annotations"], 121)

    def test_a_repeated_run_replaces_instead_of_appending_duplicate_annotations(self):
        result = self.result()
        calls = []
        def opener(req, timeout):
            calls.append((req.method, json.loads(req.data) if req.data else {}))
            return Response({"check_runs": [{"id": 9, "name": NAME, "external_id": EXTERNAL_ID}]}) if req.method == "GET" else Response({"id": 10})
        reply = publish(prepare(result, self.root), result, self.root, "example/project", "invented-auth-value", opener=opener)
        self.assertEqual(reply["replaced_check_run_id"], 9)
        self.assertEqual(calls[1], ("PATCH", {"status": "completed", "conclusion": "cancelled"}))

    def test_read_only_tokens_and_partial_uploads_never_finish_as_success(self):
        result = self.result()
        original = copy.deepcopy(result)
        calls = []
        def opener(req, timeout):
            body = json.loads(req.data) if req.data else {}
            calls.append(body)
            if req.method == "GET":
                return Response({"check_runs": []})
            if "annotations" in body.get("output", {}):
                raise urllib.error.HTTPError(req.full_url, 403, "read only", {}, None)
            return Response({"id": 17})
        with self.assertRaises(CheckError):
            publish(prepare(result, self.root), result, self.root, "example/project", "invented-auth-value", opener=opener)
        self.assertFalse(any(body.get("status") == "completed" for body in calls))
        self.assertEqual(result, original)

    def test_dirty_or_stale_results_are_rejected_before_any_network_request(self):
        result = self.result()
        payload = prepare(result, self.root)
        (self.root / "app.py").write_text("changed\n")
        with patch("prufgate.github_checks._open") as network, self.assertRaises(CheckError):
            publish(payload, result, self.root, "example/project", "invented-auth-value", opener=network)
        network.assert_not_called()
        commit(self.root)
        with self.assertRaises(CheckError):
            publish(payload, result, self.root, "example/project", "invented-auth-value", opener=network)
        network.assert_not_called()

    def test_missing_base_and_annotation_cap_are_visible_and_redirects_are_refused(self):
        result = self.result()
        result["coverage"] = {**result["coverage"], "base_ref": None}
        payload = prepare(result, self.root)
        self.assertEqual(payload["output"]["annotations"], [])
        self.assertIn("No comparison base", payload["output"]["summary"])
        with patch("prufgate.github_checks.MAX_ANNOTATIONS", 1):
            result = self.result([finding(), finding()])
            payload = prepare(result, self.root)
        self.assertEqual(payload["prufgate"]["omitted_annotations"], 1)
        with self.assertRaises(CheckError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example")


if __name__ == "__main__":
    unittest.main()
