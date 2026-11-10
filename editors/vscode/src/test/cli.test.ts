import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { childEnv, qualifiedDir, resolveProgram } from "../cli";

test("a bare name resolves from absolute PATH entries only", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pg-bin-"));
  const exe = path.join(dir, path.sep === "\\" ? "prufgate.EXE" : "prufgate");
  fs.writeFileSync(exe, "");
  assert.equal(resolveProgram("prufgate", { PATH: dir, PATHEXT: ".EXE" }), exe);
  // A relative PATH entry is never searched, so a workspace cannot plant the binary. The entry is
  // made relative to a cwd beside it: path.relative across Windows drives returns an absolute path.
  const cwd = process.cwd();
  process.chdir(path.dirname(dir));
  try {
    for (const rel of [path.basename(dir), "." + path.sep + path.basename(dir)]) {
      assert.equal(resolveProgram("prufgate", { PATH: rel, PATHEXT: ".EXE" }), undefined, rel);
    }
    if (process.platform === "win32") {
      // Drive-relative ("\\Users\\...") and drive-current ("C:Users\\...") forms name the same folder.
      assert.equal(resolveProgram("prufgate", { PATH: dir.slice(2), PATHEXT: ".EXE" }), undefined);
    }
  } finally {
    process.chdir(cwd);
  }
  assert.equal(resolveProgram("prufgate", { PATH: "" }), undefined);
});

test("relative paths are refused and absolute paths must exist", () => {
  assert.equal(resolveProgram("./prufgate", { PATH: "" }), undefined);
  assert.equal(resolveProgram("bin/prufgate", { PATH: "" }), undefined);
  assert.equal(resolveProgram(path.join(os.tmpdir(), "no-such-prufgate-binary"), { PATH: "" }), undefined);
});

test("the child environment drops everything outside the allow list", () => {
  const source = { PATH: "/usr/bin", HOME: "/home/prufgate", OPENAI_API_KEY: "x", GITHUB_TOKEN: "y" };
  // Both platforms are checked on every runner; the default follows the host.
  assert.deepEqual(childEnv(source, false), { PATH: "/usr/bin", HOME: "/home/prufgate", PRUFGATE_NO_AI_ADJUDICATE: "1", PYTHONIOENCODING: "utf-8" });
  const win = { Path: "C:\\Windows\\system32", USERPROFILE: "D:\\profile", OPENAI_API_KEY: "x", GITHUB_TOKEN: "y" };
  assert.deepEqual(childEnv(win, true), {
    Path: "C:\\Windows\\system32", USERPROFILE: "D:\\profile", PRUFGATE_NO_AI_ADJUDICATE: "1",
    PYTHONIOENCODING: "utf-8", NoDefaultCurrentDirectoryInExePath: "1",
  });
});

test("relative and empty PATH entries never reach the child", () => {
  assert.equal(childEnv({ PATH: "/usr/bin::.:bin:/opt/x/" }, false).PATH, "/usr/bin:/opt/x/");
  const win = childEnv({ Path: "C:\\Git\\cmd;;.;\\bin;C:bin;\\\\srv\\tools;d:/x" }, true);
  assert.equal(win.Path, "C:\\Git\\cmd;\\\\srv\\tools;d:/x");
  assert.equal(win.NoDefaultCurrentDirectoryInExePath, "1");
  assert.equal(qualifiedDir("\\bin", true), false); // drive-relative
  assert.equal(qualifiedDir("/usr/bin", false), true);
});

test("a workspace cannot change what a check scans or switch off save checks", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "package.json"), "utf8"));
  for (const key of ["prufgate.path", "prufgate.scope", "prufgate.runOnSave"]) {
    assert.equal(pkg.contributes.configuration.properties[key].scope, "machine", key);
  }
});
