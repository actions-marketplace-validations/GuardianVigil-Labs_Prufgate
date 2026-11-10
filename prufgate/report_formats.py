"""GitLab Code Quality and JUnit XML reports, derived from a PrufGate SARIF document.

Both are built from the SARIF a surface already wrote, so they report exactly the
findings that SARIF does: the same low-confidence filtering, the same rule IDs and the
same `prufgateFindingHash/v1` fingerprint (`prufgate.sarif`). A result carrying an
in-source `suppressions` entry (an honoured `prufgate-ignore`) is left out of both.

- GitLab Code Quality: the CodeClimate subset GitLab reads (`description`,
  `check_name`, `fingerprint`, `severity`, `location.path`, `location.lines.begin`),
  as one JSON array. P0 is `blocker`, P1 `critical`, P2 `major`, P3 `minor`.
- JUnit XML: one `<testsuite>` per rule and one `<testcase>` per finding, so each
  row in a GitLab, Jenkins or Azure test tab names a file and line. P0/P1 findings
  are `<failure>`s; P2/P3 are `<skipped>`, visible without failing the test run. A
  report with no findings holds one passing test case, because Jenkins and Azure
  treat a report without test cases as an error.

`errors` ({engine: reason}, the engines that crashed or wrote nothing readable) adds a
`blocker` issue and an `<error>` test case per engine, so a gate that could not run never
reads as a clean report.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

GITLAB_SEVERITY = {"P0": "blocker", "P1": "critical", "P2": "major", "P3": "minor"}
_LEVEL_SEVERITY = {"error": "P1", "warning": "P2", "note": "P3"}
BLOCKING = ("P0", "P1")
# Characters XML 1.0 cannot hold at all, escaped or not.
_XML_INVALID = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")


def _findings(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    """The unsuppressed results of every run, flattened to the fields both reports use."""
    out = []
    for run in sarif.get("runs") or []:
        for r in run.get("results") or []:
            if r.get("suppressions"):
                continue
            props = r.get("properties") or {}
            loc = ((r.get("locations") or [{}])[0]).get("physicalLocation", {})
            sev = str(props.get("severity") or _LEVEL_SEVERITY.get(str(r.get("level")), "P2")).upper()
            out.append(
                {
                    "rule": str(r.get("ruleId") or "prufgate-finding"),
                    "severity": sev if sev in GITLAB_SEVERITY else "P2",
                    # Only a real boolean overrides the severity: "false" is not False.
                    "blocking": props["blocking"] if isinstance(props.get("blocking"), bool) else sev in BLOCKING,
                    "message": str((r.get("message") or {}).get("text", "")),
                    "path": re.sub(r"^(?:\./)+", "", str(loc.get("artifactLocation", {}).get("uri", ""))) or "PRUFGATE_AUDIT_TARGET",
                    "line": max(1, int(loc.get("region", {}).get("startLine", 1) or 1)),
                    "fingerprint": str((r.get("partialFingerprints") or {}).get("prufgateFindingHash/v1", "")),
                }
            )
    return out


def gitlab_code_quality(sarif: dict[str, Any], errors: dict[str, str] | None = None) -> str:
    """A GitLab Code Quality report (a JSON array) for the SARIF document."""
    issues = [
        {
            "type": "issue",
            "description": f["message"],
            "check_name": f["rule"],
            "fingerprint": f["fingerprint"],
            "severity": GITLAB_SEVERITY[f["severity"]],
            "location": {"path": f["path"], "lines": {"begin": f["line"]}},
        }
        for f in sorted(_findings(sarif), key=lambda f: (f["path"], f["line"], f["rule"], f["fingerprint"]))
    ]
    issues += [
        {
            "type": "issue",
            "description": f"PrufGate could not run {tool}: {reason}. The gate failed; nothing was checked by it.",
            "check_name": "prufgate-engine-error",
            "fingerprint": hashlib.sha256(f"prufgate-engine-error:{tool}".encode()).hexdigest(),
            "severity": "blocker",
            "location": {"path": "PRUFGATE_AUDIT_TARGET", "lines": {"begin": 1}},
        }
        for tool, reason in sorted((errors or {}).items())
    ]
    return json.dumps(issues, indent=2)


def _clean(text: str) -> str:
    return _XML_INVALID.sub("�", text)


def junit_xml(sarif: dict[str, Any], errors: dict[str, str] | None = None) -> str:
    """A JUnit XML report for the SARIF document."""
    findings = sorted(_findings(sarif), key=lambda f: (f["rule"], f["path"], f["line"], f["message"]))
    root = ET.Element("testsuites", name="PrufGate")
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)
    errors = errors or {}
    if errors:
        suite = ET.SubElement(root, "testsuite", name="prufgate-engine-errors", tests=str(len(errors)),
                              failures="0", skipped="0", errors=str(len(errors)))
        for tool, reason in sorted(errors.items()):
            case = ET.SubElement(suite, "testcase", classname="prufgate.engine-error", name=_clean(tool))
            ET.SubElement(case, "error", message=_clean(f"{tool} could not run: {reason}"), type="engine-error")
    if not by_rule and not errors:
        suite = ET.SubElement(root, "testsuite", name="prufgate", tests="1", failures="0", skipped="0", errors="0")
        ET.SubElement(suite, "testcase", classname="prufgate", name="no findings")
    for rule, items in by_rule.items():
        failures = sum(f["blocking"] for f in items)
        suite = ET.SubElement(
            root,
            "testsuite",
            name=_clean(rule),
            tests=str(len(items)),
            failures=str(failures),
            skipped=str(len(items) - failures),
            errors="0",
        )
        for f in items:
            case = ET.SubElement(
                suite,
                "testcase",
                classname=_clean(f"prufgate.{rule}"),
                name=_clean(f"{f['path']}:{f['line']}"),
                file=_clean(f["path"]),
                line=str(f["line"]),
            )
            tag = "failure" if f["blocking"] else "skipped"
            # SARIF messages from `prufgate check` and `review` already start with the severity.
            message = f["message"] if f["message"].startswith(f"[{f['severity']}]") else f"[{f['severity']}] {f['message']}"
            child = ET.SubElement(case, tag, message=_clean(message))
            if tag == "failure":
                child.set("type", f["severity"])
                child.text = _clean(f"{rule} at {f['path']}:{f['line']}\n{message}")
    total = len(findings) + len(errors) or 1
    failed = sum(f["blocking"] for f in findings)
    root.set("tests", str(total))
    root.set("failures", str(failed))
    root.set("skipped", str(len(findings) - failed))
    root.set("errors", str(len(errors)))
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)
