import { mapFindings, Mapped } from "./mapping";

export type ScanStatus = "clean" | "findings" | "incomplete" | "error";
export interface ReviewResult {
  scan_status: ScanStatus;
  findings: Mapped[];
  reason: string;
  coverage: string;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function parseResult(stdout: string, folder: string, code: unknown): ReviewResult {
  const doc: unknown = JSON.parse(stdout);
  if (!record(doc) || doc.schema_version !== "1.0" || typeof doc.scan_status !== "string" || !["clean", "findings", "incomplete", "error"].includes(doc.scan_status)
      || !Array.isArray(doc.findings) || !record(doc.coverage) || !record(doc.privacy) || !record(doc.summary)
      || !Array.isArray(doc.errors) || !Array.isArray(doc.incomplete_reasons)) throw new Error("CLI did not return a versioned scan result");
  if (![...doc.errors, ...doc.incomplete_reasons].every(reason => typeof reason === "string")) throw new Error("Malformed scan reasons");
  for (const f of doc.findings) {
    if (!record(f) || typeof f.rule !== "string" || !f.rule || typeof f.file !== "string" || !f.file
        || typeof f.severity !== "string" || !["P0", "P1", "P2", "P3"].includes(f.severity) || typeof f.line !== "number" || !Number.isInteger(f.line) || f.line < 1)
      throw new Error("CLI returned a malformed finding");
  }
  const blockers = doc.findings.filter(f => record(f) && (typeof f.blocking === "boolean" ? f.blocking : f.severity === "P0" || f.severity === "P1")).length;
  const state = doc.errors.length ? "error" : doc.incomplete_reasons.length ? "incomplete" : doc.findings.length ? "findings" : "clean";
  const exit = ["incomplete", "error"].includes(state) ? 2 : blockers ? 1 : 0;
  if (state !== doc.scan_status || doc.exit_code !== exit || code !== exit || doc.summary.blockers !== blockers
      || doc.summary.total_findings !== doc.findings.length || doc.summary.advisories !== doc.findings.length - blockers
      || doc.passed !== (exit === 0)) throw new Error("Scan status disagrees with findings or process exit code");
  const findings = mapFindings(JSON.stringify(doc.findings), folder);
  if (findings.length !== doc.findings.length) throw new Error("A finding points outside the workspace");
  return { scan_status: state, findings, reason: [...doc.errors, ...doc.incomplete_reasons].join("; "),
    coverage: `Files checked: ${doc.coverage.files_checked ?? "unknown"}; lines read: ${doc.coverage.lines_checked ?? "unknown"}` };
}
