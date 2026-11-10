import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import * as vm from "node:vm";
import { ScanState, statusText } from "../state";
import { mapFindings, RULES_URL } from "../mapping";
import { parseResult } from "../result";

// Exercise the real extension entry point with a small VS Code host double.
// Child callbacks are controlled so race and failure states remain deterministic.
function host() {
  const uri = (file: string) => ({ fsPath: file, scheme: "file", toString: () => file });
  const folder = { name: "fixture", uri: uri(path.resolve("fixture-workspace")) };
  const status = { text: "", tooltip: "", show() {}, dispose() {} };
  const records = new Map<string, any[]>();
  const events: Record<string, (...args: any[]) => void> = {};
  const callbacks: Array<(error: any, stdout: string, stderr: string) => void> = [];
  let missing = false;
  const diagnostics = {
    get: (u: any) => records.get(u.toString()),
    set: (u: any, ds: any[]) => records.set(u.toString(), ds),
    delete: (u: any) => records.delete(u.toString()), dispose() {},
  };
  const event = (name: string) => (fn: (...args: any[]) => void) => { events[name] = fn; return { dispose() {} }; };
  const vscode = {
    Uri: { file: uri, parse: uri },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 }, StatusBarAlignment: { Left: 0 },
    Diagnostic: class { source = ""; constructor(public range: any, public message: string, public severity: number) {} },
    Range: class {},
    languages: { createDiagnosticCollection: () => diagnostics },
    window: { createStatusBarItem: () => status, showWarningMessage() {} },
    commands: { registerCommand: (_: string, fn: () => void) => { events.check = fn; return { dispose() {} }; } },
    workspace: {
      isTrusted: true, workspaceFolders: [folder],
      getConfiguration: () => ({ get: (_: string, fallback: any) => fallback }),
      getWorkspaceFolder: () => folder,
      onDidSaveTextDocument: event("save"), onDidChangeTextDocument: event("edit"),
      onDidChangeConfiguration: event("config"), onDidChangeWorkspaceFolders: event("folders"),
      onDidGrantWorkspaceTrust: event("trust"),
    },
  };
  const exported: any = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "extension.js"), "utf8"), {
    exports: exported, setTimeout, clearTimeout,
    require: (name: string) => {
      if (name === "vscode") return vscode;
      if (name === "./state") return { ScanState, statusText };
      if (name === "./mapping") return { mapFindings, RULES_URL };
      if (name === "./result") return { parseResult };
      if (name === "./cli") return { resolveProgram: () => missing ? undefined : "fixture-cli", childEnv: () => ({}) };
      if (name === "child_process") return { execFile: (_: any, __: any, ___: any, fn: any) => {
        callbacks.push((error, stdout, stderr) => {
          if (stdout.startsWith("[")) {
            const findings = JSON.parse(stdout).map((f: any) => ({ line: 1, ...f }));
            const blockers = findings.filter((f: any) => ["P0", "P1"].includes(f.severity)).length;
            stdout = JSON.stringify({ schema_version: "1.0", scan_status: findings.length ? "findings" : "clean",
              findings, coverage: {}, privacy: {}, errors: [], incomplete_reasons: [], passed: !blockers,
              exit_code: blockers ? 1 : 0, summary: { blockers, advisories: findings.length - blockers, total_findings: findings.length } });
            if (blockers && !error) error = { code: 1 };
          }
          fn(error, stdout, stderr);
        }); return { kill() {} };
      } };
      throw new Error(`unexpected import: ${name}`);
    },
  });
  exported.activate({ subscriptions: [] });
  return { ...exported, folder, status, events, callbacks, records, missing: () => { missing = true; } };
}

test("a real extension callback keeps scan errors visible until a successful retry", () => {
  const h = host();
  h.callbacks.shift()!({ code: 2, message: "failure" }, "", "engine unavailable");
  assert.match(h.status.text, /scan error/);
  assert.match(h.status.tooltip, /engine unavailable/);
  assert.doesNotMatch(h.status.tooltip, /JSON/);
  assert.match(h.status.tooltip, /no successful scan/);
  h.events.check();
  assert.match(h.status.text, /scan error/);
  h.callbacks.shift()!(null, "[]", "");
  assert.doesNotMatch(h.status.text, /scan error|stale|not checked/);
  h.deactivate();
});

test("old diagnostics are labelled stale after failure and edits invalidate in-flight results", () => {
  const h = host();
  const output = JSON.stringify([{ rule: "fixture-rule", severity: "P1", file: "app.py", line: 1, message: "fixture" }]);
  h.callbacks.shift()!(null, output, "");
  h.events.check();
  h.callbacks.shift()!({ code: 2, message: "timeout", killed: true }, "", "");
  assert.match(h.status.tooltip, /displayed findings are stale/);
  assert.match(h.status.tooltip, /timed out/);
  assert.equal([...h.records.values()][0][0].source, "PrufGate (stale)");
  h.events.check();
  h.events.edit({ document: { uri: h.folder.uri } });
  h.callbacks.shift()!(null, "[]", "");
  assert.match(h.status.text, /scan error/);
  assert.equal(h.records.size, 1);
  h.events.check();
  h.callbacks.shift()!(null, "[]", "");
  assert.equal(h.records.size, 0);
  assert.doesNotMatch(h.status.text, /scan error|stale/);
  h.deactivate();
});

test("CLI absence and workspace removal stay visible and ignore late callbacks", () => {
  const h = host();
  h.callbacks.shift()!(null, "[]", "");
  h.missing();
  h.events.check();
  assert.match(h.status.text, /scan error/);
  assert.match(h.status.tooltip, /CLI not installed/);
  h.events.folders({ removed: [h.folder], added: [] });
  assert.match(h.status.text, /not checked/);
  h.deactivate();
  const late = host();
  late.events.folders({ removed: [late.folder], added: [] });
  late.callbacks.shift()!(null, "[]", "");
  assert.match(late.status.text, /not checked/);
  assert.equal(late.records.size, 0);
  late.deactivate();
});

test("a late callback from a removed folder cannot clear a replacement scan's reservation", () => {
  const h = host();
  const old = h.callbacks.shift()!;
  h.events.folders({ removed: [h.folder], added: [h.folder] });
  old(null, "[]", "");
  h.events.check();
  assert.equal(h.callbacks.length, 1, "the replacement scan must remain the only running scan");
  h.callbacks.shift()!(null, "[]", "");
  assert.equal(h.callbacks.length, 1, "the requested retry starts after the replacement finishes");
  h.callbacks.shift()!(null, "[]", "");
  assert.doesNotMatch(h.status.text, /scan error|stale|checking/);
  h.deactivate();
});

test("a configuration change invalidates results from a running scan", () => {
  const h = host();
  h.events.config({ affectsConfiguration: () => true });
  h.callbacks.shift()!(null, JSON.stringify([{ rule: "fixture-rule", severity: "P1", file: "app.py" }]), "");
  assert.equal(h.records.size, 0, "old settings must not publish findings");
  h.callbacks.shift()!(null, "[]", "");
  assert.doesNotMatch(h.status.text, /stale|checking/);
  h.deactivate();
});
