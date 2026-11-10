import * as assert from "node:assert/strict";
import * as path from "node:path";
import { test } from "node:test";
import { parseResult } from "../result";
import { ScanState, statusText } from "../state";

const root = path.resolve("fixture-workspace");
function result(state: string, severity?: string): string {
  const findings = severity ? [{ rule: "fixture-rule", file: "app.py", line: 2, severity, message: "fixture" }] : [];
  const blockers = severity && ["P0", "P1"].includes(severity) ? 1 : 0;
  const code = ["error", "incomplete"].includes(state) ? 2 : blockers ? 1 : 0;
  return JSON.stringify({ schema_version: "1.0", scan_status: state, exit_code: code, passed: code === 0,
    findings, summary: { blockers, advisories: findings.length - blockers, total_findings: findings.length },
    errors: state === "error" ? ["engine crashed"] : [], incomplete_reasons: state === "incomplete" ? ["one probe failed"] : [],
    coverage: { files_checked: 1, lines_checked: 3 }, privacy: {} });
}

test("the editor preserves all four scan states including advisory findings", () => {
  for (const [state, severity, code] of [["clean", undefined, 0], ["findings", "P0", 1], ["findings", "P2", 0], ["incomplete", "P0", 2], ["error", undefined, 2]] as const) {
    const parsed = parseResult(result(state, severity), root, code);
    assert.equal(parsed.scan_status, state);
    assert.match(parsed.coverage, /Files checked: 1/);
  }
});

test("a partial result displays confirmed findings while remaining incomplete", () => {
  const parsed = parseResult(result("incomplete", "P0"), root, 2);
  assert.equal(parsed.findings.length, 1);
  const state = new ScanState();
  state.partial(state.begin(), [1, 0, 0], "incomplete", parsed.reason);
  assert.match(statusText([state]), /incomplete/);
  assert.equal(state.stale, true);
});

test("advisory enforcement preserves P0 severity and displays a warning", () => {
  const doc = JSON.parse(result("findings", "P0"));
  doc.findings[0].blocking = false;
  doc.summary.blockers = 0;
  doc.summary.advisories = 1;
  doc.exit_code = 0;
  doc.passed = true;
  const parsed = parseResult(JSON.stringify(doc), root, 0);
  assert.equal(parsed.scan_status, "findings");
  assert.equal(parsed.findings[0].level, "warning");
  assert.match(parsed.findings[0].message, /\[P0\]/);
});

test("the editor rejects malformed and contradictory scan results", () => {
  assert.throws(() => parseResult("[]", root, 0));
  assert.throws(() => parseResult(result("clean", "P0"), root, 0));
  assert.throws(() => parseResult(result("findings", "P0"), root, 0));
  const doc = JSON.parse(result("findings", "P0"));
  doc.findings[0].file = "../outside.py";
  assert.throws(() => parseResult(JSON.stringify(doc), root, 1));
});
