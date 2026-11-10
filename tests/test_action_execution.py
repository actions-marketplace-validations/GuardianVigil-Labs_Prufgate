"""Exercise the Action runner's mode selection and fail-on-blocker policy locally."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipIf(sys.platform == "win32", "the composite action requires a POSIX runner")
class ActionExecution(unittest.TestCase):
    def run_action(self, code=0, mode="native", fail="true", native=True, python_ok=True, scan_status="", allow_ai=False,
                   profile="battery"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools, action, workspace = root / "bin", root / "action", root / "workspace"
            for directory in (tools, action, workspace / "reports"):
                directory.mkdir(parents=True)
            stale = workspace / "reports" / "prufgate.sarif"
            stale.write_text("stale report")
            output, called = root / "output", root / "called"
            output.touch()
            status = 'case "$FIXTURE_EXIT" in 0) state=clean;; 1) state=findings;; *) state=error;; esac\n[ -z "$FIXTURE_STATUS" ] || state="$FIXTURE_STATUS"\nprintf "%s\\n" "$state" > "$FIXTURE_WORKSPACE/reports/prufgate-result.status"\n'
            (action / "prufgate.sh").write_text('#!/bin/sh\necho native >> "$FIXTURE_CALLED"\n' + status + 'exit "$FIXTURE_EXIT"\n')
            scripts = {
                "docker": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_CALLED"\n' + status + 'echo "{}"\nexit "$FIXTURE_EXIT"\n',
                # `python3 -I -c` is the dependency probe; any other call is a core scan.
                "python3": '#!/bin/sh\n[ "$2" = -c ] && exit "$FIXTURE_PYTHON_EXIT"\n' + status + 'echo "{}"\nexit "$FIXTURE_EXIT"\n',
                "git": "#!/bin/sh\nexit 0\n",
                "gitleaks": "#!/bin/sh\nexit 0\n",
                "zizmor": "#!/bin/sh\nexit 0\n",
                "sg": "#!/bin/sh\necho ast-grep 0.43.0\n" if native else "#!/bin/sh\nexit 1\n",
            }
            for name, text in scripts.items():
                program = tools / name
                program.write_text(text)
                program.chmod(0o700)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""),
                       ACTION_PATH=str(action), GITHUB_WORKSPACE=str(workspace), GITHUB_OUTPUT=str(output),
                       PRUFGATE_EXECUTION=mode, FAIL_ON_BLOCKER=fail, PRUFGATE_BATTERY="fast",
                       PRUFGATE_IMAGE="example.com/prufgate:fixture", FIXTURE_EXIT=str(code),
                       FIXTURE_CALLED=str(called), FIXTURE_WORKSPACE=str(workspace), FIXTURE_PYTHON_EXIT="0" if python_ok else "1",
                       FIXTURE_STATUS=scan_status, PRUFGATE_PROFILE=profile, ALLOW_EXTERNAL_AI="true" if allow_ai else "false")
            proc = subprocess.run(["bash", str(ROOT / "scripts" / "run_action.sh")],
                                  capture_output=True, text=True, env=env, timeout=10)
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            return proc, outputs, called.read_text() if called.exists() else "", stale.exists()

    def test_only_blocker_findings_can_be_nonfatal(self):
        for code, fail, expected, verdict in ((0, "true", 0, "PASSED"), (1, "true", 1, "FAILED"),
                                             (1, "false", 0, "FAILED"), (2, "false", 2, "ERROR"),
                                             (124, "false", 2, "ERROR"), (137, "true", 2, "ERROR")):
            with self.subTest(code=code, fail=fail):
                proc, outputs, _, _ = self.run_action(code=code, fail=fail)
                self.assertEqual(proc.returncode, expected, proc.stderr)
                self.assertEqual(outputs["verdict"], verdict)
                self.assertEqual(outputs["exit_code"], "2" if code > 1 else str(code))

    def test_forced_container_honors_the_image_despite_python_being_available(self):
        proc, outputs, called, _ = self.run_action(mode="container")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs["execution_mode"], "container")
        self.assertIn("example.com/prufgate:fixture", called)
        self.assertNotIn("native", called)

    def test_auto_falls_back_when_native_tools_or_python_dependencies_are_missing(self):
        for native, python_ok in ((False, True), (True, False)):
            with self.subTest(native=native, python_ok=python_ok):
                proc, outputs, called, _ = self.run_action(mode="auto", native=native, python_ok=python_ok)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(outputs["execution_mode"], "container")
                self.assertIn("example.com/prufgate:fixture", called)

    def test_native_rejects_missing_dependencies_and_clears_stale_artifacts(self):
        proc, outputs, called, stale = self.run_action(native=False, fail="false")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(outputs["verdict"], "ERROR")
        self.assertEqual(called, "")
        self.assertFalse(stale)

    def test_failed_core_scan_leaves_no_empty_sarif_to_upload(self):
        for mode in ("native", "container"):
            with self.subTest(mode=mode):
                proc, outputs, _, sarif = self.run_action(code=2, mode=mode, profile="core")
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertFalse(sarif)

    def test_completed_core_scan_keeps_its_sarif(self):
        for mode in ("native", "container"):
            with self.subTest(mode=mode):
                proc, _, _, sarif = self.run_action(code=1, mode=mode, profile="core", scan_status="findings")
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertTrue(sarif)

    def test_invalid_mode_and_boolean_are_errors(self):
        for mode, fail in (("unknown", "false"), ("native", "no")):
            proc, outputs, _, _ = self.run_action(mode=mode, fail=fail)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(outputs["verdict"], "ERROR")

    def test_advisory_and_incomplete_states_are_not_guessed_from_exit_code(self):
        proc, outputs, _, _ = self.run_action(code=0, scan_status="findings")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(outputs["scan_status"], "findings")
        proc, outputs, _, _ = self.run_action(code=2, fail="false", scan_status="incomplete")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(outputs["scan_status"], "incomplete")

    def test_provider_credentials_are_forwarded_only_after_explicit_consent(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed):
                proc, _, called, _ = self.run_action(mode="container", allow_ai=allowed)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual("-e OPENAI_API_KEY" in called, allowed)
                self.assertEqual("-e ANTHROPIC_API_KEY" in called, allowed)


class ExtensionCI(unittest.TestCase):
    def test_ci_compiles_typechecks_and_tests_the_locked_extension(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = ci["jobs"]["vscode-extension"]
        self.assertEqual(set(job["strategy"]["matrix"]["os"]), {"ubuntu-latest", "windows-latest"})
        steps = "\n".join(step.get("run", "") for step in job["steps"])
        for command in ("npm ci", "npm run build", "npm run typecheck", "npm test"):
            self.assertIn(command, steps)


if __name__ == "__main__":
    unittest.main()
