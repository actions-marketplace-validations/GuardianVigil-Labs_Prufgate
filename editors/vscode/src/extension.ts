import { ChildProcess, execFile } from "child_process";
import * as vscode from "vscode";
import { childEnv, resolveProgram } from "./cli";
import { Level, mapFindings, RULES_URL } from "./mapping";
import { Counts, ScanState, statusText } from "./state";
import { parseResult } from "./result";

const TIMEOUT_MS = 120_000;
const DEBOUNCE_MS = 1_500;
const MAX_OUTPUT = 32 * 1024 * 1024;

const LEVELS: Record<Level, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
};

let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
const owned = new Map<string, vscode.Uri[]>(); // folder -> files it set diagnostics on
const states = new Map<string, ScanState>();
const processes = new Map<string, ChildProcess>();
const running = new Set<string>();
const again = new Set<string>();
const timers = new Map<string, NodeJS.Timeout>();
let disposed = false;

function render(): void {
  if (disposed) return;
  status.text = statusText([...states.values()]);
  status.tooltip = [...states].map(([key, state]) => {
    const name = vscode.workspace.workspaceFolders?.find(f => f.uri.toString() === key)?.name ?? key;
    if (state.error) return `${name}: ${state.scanStatus ?? "error"}: ${state.error}${state.hasResult ? "; displayed findings are stale or partial" : "; no successful scan"}${state.running ? "; retrying" : ""}${state.coverage ? "; " + state.coverage : ""}`;
    if (state.running) return `${name}: checking; previous findings are stale`;
    if (!state.hasResult) return `${name}: not checked`;
    return `${name}: ${state.stale ? "stale results; check again" : state.scanStatus ?? "not checked"}${state.coverage ? "; " + state.coverage : ""}`;
  }).join("\n") || "PrufGate has not checked a workspace. Click to check.";
  status.show();
}

function stale(key: string): void {
  for (const uri of owned.get(key) ?? []) {
    const found = diagnostics.get(uri);
    if (found) {
      for (const d of found) d.source = "PrufGate (stale)";
      diagnostics.set(uri, found);
    }
  }
}

function fail(folder: vscode.WorkspaceFolder, state: ScanState, version: number, why: string): void {
  state.fail(version, why);
  stale(folder.uri.toString());
  void vscode.window.showWarningMessage(`PrufGate could not check ${folder.name}: ${why}`);
}

function check(folder: vscode.WorkspaceFolder): void {
  if (disposed || !vscode.workspace.isTrusted || folder.uri.scheme !== "file") return;
  const key = folder.uri.toString();
  if (running.has(key)) { again.add(key); return; }
  clearTimeout(timers.get(key));
  timers.delete(key);
  const state = states.get(key) ?? new ScanState();
  states.set(key, state);
  const version = state.begin();
  stale(key);
  const cfg = vscode.workspace.getConfiguration("prufgate", folder.uri);
  let program: string | undefined;
  try { program = resolveProgram(cfg.get<string>("path", "prufgate")); }
  catch (e) {
    fail(folder, state, version, e instanceof Error ? e.message : String(e));
    render();
    return;
  }
  if (!program) {
    fail(folder, state, version, "CLI not installed. Install with pipx install prufgate, or set prufgate.path in user settings.");
    render();
    return;
  }
  const args = ["check", ...(cfg.get<string>("scope", "changed") === "workspace" ? [] : ["--changed"]), "--format", "result"];
  running.add(key);
  render();
  const child = execFile(program, args, { cwd: folder.uri.fsPath, timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT, env: childEnv(), windowsHide: true },
    (err, stdout, stderr) => {
      if (disposed || states.get(key) !== state) return;
      processes.delete(key);
      running.delete(key);
      state.running = false;
      // Exit 1 (blocking findings) and exit 2 (an error) print the versioned result.
      // Without one (a timeout, a usage error, an older CLI) the CLI's message is the error.
      const code = err ? (err as { code?: unknown }).code : 0;
      if (!state.current(version)) {
        // An edit or workspace removal invalidated this scan while it ran.
      } else {
        try {
          if (err && (err.killed || (code !== 1 && code !== 2) || !stdout.trim())) throw new Error(err.killed ? "timed out" : (stderr.trim().split("\n").pop() || err.message));
          const result = parseResult(stdout, folder.uri.fsPath, code);
          state.coverage = result.coverage;
          if (result.scan_status === "incomplete" || result.scan_status === "error") {
            if (result.findings.length) {
              state.partial(version, apply(key, result.findings), result.scan_status, result.reason);
              stale(key);
            } else {
              state.fail(version, result.reason || result.scan_status);
              state.scanStatus = result.scan_status;
              stale(key);
            }
          } else {
            state.complete(version, apply(key, result.findings));
          }
        } catch (e) {
          fail(folder, state, version, e instanceof Error ? e.message : String(e));
        }
      }
      render();
      if (again.delete(key)) check(folder);
    });
  processes.set(key, child);
}

function apply(key: string, found: ReturnType<typeof mapFindings>): Counts {
  for (const uri of owned.get(key) ?? []) diagnostics.delete(uri);
  const byFile = new Map<string, vscode.Diagnostic[]>();
  const c: [number, number, number] = [0, 0, 0];
  for (const f of found) {
    const d = new vscode.Diagnostic(new vscode.Range(f.line, 0, f.line, Number.MAX_SAFE_INTEGER), f.message, LEVELS[f.level]);
    d.source = "PrufGate";
    d.code = { value: f.rule, target: vscode.Uri.parse(RULES_URL) };
    c[f.level === "error" ? 0 : f.level === "warning" ? 1 : 2]++;
    byFile.set(f.file, [...(byFile.get(f.file) ?? []), d]);
  }
  const uris: vscode.Uri[] = [];
  for (const [file, ds] of byFile) {
    const uri = vscode.Uri.file(file);
    diagnostics.set(uri, ds);
    uris.push(uri);
  }
  owned.set(key, uris);
  return c;
}

function checkAll(): void {
  for (const f of vscode.workspace.workspaceFolders ?? []) check(f);
}

export function activate(context: vscode.ExtensionContext): void {
  disposed = false;
  diagnostics = vscode.languages.createDiagnosticCollection("prufgate");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "prufgate.checkWorkspace";
  status.name = "PrufGate";
  context.subscriptions.push(
    diagnostics,
    status,
    vscode.commands.registerCommand("prufgate.checkWorkspace", checkAll),
    vscode.workspace.onDidGrantWorkspaceTrust(checkAll),
    vscode.workspace.onDidChangeTextDocument(({ document }) => {
      const folder = vscode.workspace.getWorkspaceFolder(document.uri);
      const key = folder?.uri.toString();
      if (key) {
        states.get(key)?.invalidate();
        stale(key);
        render();
      }
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder || !vscode.workspace.getConfiguration("prufgate", folder.uri).get<boolean>("runOnSave", true)) return;
      const key = folder.uri.toString();
      clearTimeout(timers.get(key));
      timers.set(key, setTimeout(() => { timers.delete(key); check(folder); }, DEBOUNCE_MS));
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration("prufgate")) return;
      for (const [key, state] of states) { state.invalidate(); stale(key); }
      checkAll();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(({ removed, added }) => {
      for (const folder of removed) remove(folder.uri.toString());
      for (const folder of added) check(folder);
      render();
    }),
    { dispose: deactivate },
  );
  render();
  if (vscode.workspace.isTrusted) for (const f of vscode.workspace.workspaceFolders ?? []) check(f);
}

function remove(key: string): void {
  clearTimeout(timers.get(key));
  timers.delete(key);
  again.delete(key);
  states.get(key)?.invalidate();
  states.delete(key);
  for (const uri of owned.get(key) ?? []) diagnostics.delete(uri);
  owned.delete(key);
  processes.get(key)?.kill();
  processes.delete(key);
  running.delete(key);
}

export function deactivate(): void {
  disposed = true;
  for (const key of new Set([...states.keys(), ...timers.keys(), ...processes.keys()])) remove(key);
}
