"""Prepare GitHub Check Runs locally; publish only with explicit --post-check."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable, Optional
from urllib.parse import urlsplit

from prufgate import __version__, diff_scope
from prufgate.config import GitDiffError
from prufgate.pr_summary import workflow_summary
from prufgate.privacy import redact
from prufgate.scan_result import validate_result
from prufgate.workflow import revision

NAME = "PrufGate review"
EXTERNAL_ID = "prufgate-review-v1"
MAX_ANNOTATIONS = 1000
Opener = Callable


class CheckError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckError("GitHub API redirects are refused to protect credentials")


def _open(req, timeout):
    return urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout)


def _api_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise CheckError("GitHub API URL must be HTTPS without credentials, query or fragment")
    return value.rstrip("/")


def _call(opener, method: str, url: str, token: str, body: Optional[dict] = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": f"prufgate/{__version__}"})
    try:
        with opener(req, 20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise CheckError("GitHub API response exceeded the size limit")
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise CheckError(f"GitHub Checks returned HTTP {exc.code}; checks: write is required and fork tokens may be read-only") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if isinstance(exc, CheckError):
            raise
        raise CheckError(f"GitHub Checks request failed ({exc.__class__.__name__})") from None


def _limit(text: str, size: int = 60000) -> str:
    return redact(text).encode("utf-8")[:size].decode("utf-8", "ignore")


def prepare(result: dict, root: Path, base: Optional[str] = None, head_sha: Optional[str] = None) -> dict:
    validate_result(result)
    sha = head_sha or result.get("revision", {}).get("commit") or revision(root)["commit"]
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise CheckError("a full scanned commit SHA is required")
    ref = base or result.get("coverage", {}).get("base_ref")
    base_error = ""
    try:
        ranges = diff_scope.changed_lines(ref, root) if ref else {}
    except GitDiffError:
        if result["scan_status"] not in ("error", "incomplete"):
            raise CheckError("Cannot determine changed lines from the recorded base") from None
        ranges, base_error = {}, "The comparison base was unusable; inline annotations were omitted."
    annotations, omitted = [], 0
    for finding in result["findings"]:
        path = finding["file"].replace("\\", "/")
        target = PurePosixPath(path)
        line = finding["line"]
        if target.is_absolute() or ".." in target.parts or not any(start <= line <= end for start, end in ranges.get(path, [])):
            omitted += 1
            continue
        annotations.append({"path": path, "start_line": line, "end_line": line,
                            "annotation_level": "failure" if finding.get("blocking", finding["severity"] in ("P0", "P1")) else "warning" if finding["severity"] != "P3" else "notice",
                            "title": _limit(f"[{finding['severity']}] {finding['rule']}", 250),
                            "message": _limit(finding.get("message", "") + "\n" + finding.get("explanation", {}).get("suggested_fix", ""))})
    total = len(annotations)
    omitted += max(0, total - MAX_ANNOTATIONS)
    annotations = annotations[:MAX_ANNOTATIONS]
    state = result["scan_status"]
    conclusion = "failure" if state in ("error", "incomplete") or result["summary"]["blockers"] else "neutral" if result["findings"] else "success"
    summary = workflow_summary(result)
    summary += f"\nInline annotations: {len(annotations)}; findings not annotated (unchanged/outside diff or annotation cap): {omitted}. All findings remain in the result artifact.\n"
    if not ref:
        summary += "No comparison base was supplied, so inline annotations were omitted.\n"
    if base_error:
        summary += base_error + "\n"
    return {"name": NAME, "head_sha": sha, "external_id": EXTERNAL_ID, "status": "completed", "conclusion": conclusion,
            "output": {"title": f"PrufGate: {state}", "summary": _limit(summary), "annotations": annotations},
            "prufgate": {"scan_status": state, "omitted_annotations": omitted, "annotations_total": total}}


def publish(payload: dict, result: dict, root: Path, repo: str, token: str, api_url: str = "https://api.github.com", opener: Opener = _open) -> dict:
    """Create or update only this tool's Check Run on the scanned commit; batches contain <=50 annotations."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or "") or ".." in repo or not token:
        raise CheckError("an owner/name repository and a Checks token are required")
    current = revision(root)
    scanned = result.get("revision", {})
    if scanned.get("dirty") is not False or current["dirty"] is not False or current["commit"] != scanned.get("commit") or payload["head_sha"] != scanned.get("commit"):
        raise CheckError("publication requires the same clean committed checkout that produced the result")
    api = _api_url(api_url)
    existing = None
    for page in range(1, 11):
        reply = _call(opener, "GET", f"{api}/repos/{repo}/commits/{payload['head_sha']}/check-runs?per_page=100&page={page}", token)
        checks = reply.get("check_runs") if isinstance(reply, dict) else None
        if not isinstance(checks, list):
            raise CheckError("invalid Check Runs response")
        existing = next((entry["id"] for entry in checks if isinstance(entry, dict) and entry.get("name") == NAME
                         and entry.get("external_id") == EXTERNAL_ID and type(entry.get("id")) is int), None)
        if existing is not None or len(checks) < 100:
            break
    else:
        raise CheckError("Check Run lookup exceeded its pagination limit")
    annotations = payload["output"]["annotations"]
    # Check Runs append annotations on updates. A replacement run avoids duplicates
    # when the previous completed run already contains them.
    if existing is not None:
        _call(opener, "PATCH", f"{api}/repos/{repo}/check-runs/{existing}", token,
              {"status": "completed", "conclusion": "cancelled"})
    initial = {"name": NAME, "head_sha": payload["head_sha"], "external_id": EXTERNAL_ID, "status": "in_progress",
               "output": {"title": payload["output"]["title"], "summary": payload["output"]["summary"]}}
    created = _call(opener, "POST", f"{api}/repos/{repo}/check-runs", token, initial)
    if not isinstance(created, dict) or type(created.get("id")) is not int:
        raise CheckError("Check Run creation did not return an integer ID")
    url = f"{api}/repos/{repo}/check-runs/{created['id']}"
    for start in range(0, len(annotations), 50):
        _call(opener, "PATCH", url, token, {"output": {"title": payload["output"]["title"], "summary": payload["output"]["summary"], "annotations": annotations[start:start + 50]}})
    _call(opener, "PATCH", url, token, {"status": "completed", "conclusion": payload["conclusion"]})
    return {"check_run_id": created["id"], "annotations": len(annotations), "replaced_check_run_id": existing}
