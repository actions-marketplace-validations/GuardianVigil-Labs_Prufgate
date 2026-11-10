// Scan lifecycle is independent of VS Code so failures and concurrent edits can be tested.
export type Counts = [number, number, number];
import { ScanStatus } from "./result";

export class ScanState {
  counts: Counts = [0, 0, 0];
  hasResult = false;
  stale = true;
  running = false;
  error = "";
  scanStatus: ScanStatus | undefined;
  coverage = "";
  private version = 0;

  begin(): number {
    this.running = true;
    this.stale = true;
    return ++this.version;
  }

  current(version: number): boolean { return this.version === version; }

  complete(version: number, counts: Counts): boolean {
    if (!this.current(version)) return false;
    this.counts = counts;
    this.hasResult = true;
    this.stale = false;
    this.running = false;
    this.error = "";
    this.scanStatus = counts.some(n => n > 0) ? "findings" : "clean";
    return true;
  }

  fail(version: number, reason: string): void {
    if (!this.current(version)) return;
    this.error = reason;
    this.scanStatus = "error";
    this.stale = true;
    this.running = false;
  }

  partial(version: number, counts: Counts, status: "incomplete" | "error", reason: string): void {
    if (!this.current(version)) return;
    this.counts = counts;
    this.hasResult = true;
    this.running = false;
    this.stale = true;
    this.scanStatus = status;
    this.error = reason || "The scan could not complete.";
  }

  invalidate(): void {
    ++this.version;
    this.stale = true;
  }
}

export function statusText(states: ScanState[]): string {
  if (states.some(s => s.error && s.scanStatus !== "incomplete")) return "$(error) PrufGate: scan error";
  if (states.some(s => s.scanStatus === "incomplete")) return "$(warning) PrufGate: incomplete";
  if (states.some(s => s.running)) return "$(sync~spin) PrufGate: checking";
  if (!states.length || states.some(s => !s.hasResult)) return "$(shield) PrufGate: not checked";
  if (states.some(s => s.stale)) return "$(warning) PrufGate: stale results";
  const counts = states.reduce<Counts>((a, s) => a.map((n, i) => n + s.counts[i]) as Counts, [0, 0, 0]);
  return `$(shield) PrufGate: ${counts.some(n => n > 0) ? "findings" : "clean"} $(error) ${counts[0]} $(warning) ${counts[1]} $(info) ${counts[2]}`;
}
