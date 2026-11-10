import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { parseResult } from "../../result";

test("the editor consumes the actual CLI without changing findings, severity or status", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "prufgate-editor-fixture-"));
  const python = process.env.PRUFGATE_TEST_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
  try {
    for (const source of ["def add(a, b):\n    return a + b\n", "def add(a, b):\n    raise NotImplementedError\n"]) {
      fs.writeFileSync(path.join(root, "app.py"), source);
      const run = spawnSync(python, ["-I", path.resolve("../../prufgate/cli.py"), "check", root, "--format", "result"], {
        encoding: "utf8", env: { ...process.env, PRUFGATE_NO_AI_ADJUDICATE: "1" }, timeout: 30_000,
      });
      assert.ok(run.status === 0 || run.status === 1, run.stderr || String(run.error));
      const original = JSON.parse(run.stdout);
      const editor = parseResult(run.stdout, root, run.status);
      assert.equal(editor.scan_status, original.scan_status);
      assert.equal(editor.findings.length, original.findings.length);
      for (let i = 0; i < editor.findings.length; ++i) {
        assert.equal(editor.findings[i].rule, original.findings[i].rule);
        assert.equal(editor.findings[i].line, original.findings[i].line - 1);
        assert.equal(editor.findings[i].file, path.join(root, original.findings[i].file));
        assert.match(editor.findings[i].message, /Reasoning:/);
        assert.match(editor.findings[i].message, /Suggested fix:/);
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
