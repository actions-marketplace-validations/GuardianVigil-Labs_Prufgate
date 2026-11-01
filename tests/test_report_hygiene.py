"""PrufGate's reports and build output stay out of its own findings, and out of
the scanned repository's history.

A directory scan (no usable git metadata, as with a git worktree mounted into
the container) used to read reports/ and .next/: every earlier report
re-quoted the secrets it found, and bundlers copy library code full of PEM
headers into build output, so a real leak in a tracked file drowned in noise.
And reports/ itself got committed by projects that did not ignore it.

The gitleaks tests need the binary, which the image has (CI runs this file
inside it); without it they are skipped, never passed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "configs" / "gitleaks.toml"
# Shaped like a real credential, invented for this test.
FAKE_KEY = 'const apiKey = "q8Zk2Lm9Xr4Tn7Vb1Yc6Hd3Jf5Gs0PaWe8Ru";\n'  # gitleaks:allow
HAS_GITLEAKS = shutil.which("gitleaks") is not None


def lib(workspace: Path, snippet: str) -> subprocess.CompletedProcess:
    """Runs a snippet with runners/lib.sh sourced against a workspace."""
    env = {**os.environ, "WORKSPACE": str(workspace), "TOOL_ROOT": str(ROOT)}
    env.pop("PRUFGATE_REPORTS_DIR", None)
    return subprocess.run(["bash", "-c", f'source "{ROOT}/runners/lib.sh" >/dev/null; {snippet}'],
                          env=env, capture_output=True, text=True)


def gitleaks_files(workspace: Path, config: str) -> list[str]:
    report = workspace / "gl.json"
    subprocess.run(["gitleaks", "detect", "--no-git", "--no-banner", "--config", config,
                    "--report-format", "json", "--report-path", str(report)],
                   cwd=workspace, capture_output=True)
    return sorted(f["File"] for f in json.loads(report.read_text()))


@unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
class ReportsAreNeverCommitted(unittest.TestCase):
    def test_the_reports_folder_ignores_itself(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            subprocess.run(["git", "init", "-q"], cwd=ws, check=True)
            self.assertEqual(lib(ws, "true").returncode, 0)
            self.assertTrue((ws / "reports" / ".gitignore").is_file())
            (ws / "reports" / "raw" / "gitleaks.json").write_text("[]")
            ignored = subprocess.run(["git", "check-ignore", "-q", "reports/raw/gitleaks.json"], cwd=ws)
            self.assertEqual(ignored.returncode, 0, "reports/ would be committed by `git add -A`")
            # The project's own .gitignore is not touched.
            self.assertFalse((ws / ".gitignore").exists())


@unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
class GitRepositoryDetection(unittest.TestCase):
    def test_a_worktree_counts_as_a_git_repository(self):
        with tempfile.TemporaryDirectory() as d:
            main, wt = Path(d) / "main", Path(d) / "wt"
            main.mkdir()

            def run(*a, cwd=main):
                return subprocess.run(a, cwd=cwd, check=True, capture_output=True)

            run("git", "init", "-q")
            run("git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init")
            run("git", "worktree", "add", "-q", str(wt))
            self.assertTrue((wt / ".git").is_file())  # a file, which `[ -d .git ]` missed
            self.assertEqual(lib(wt, "in_git_repo").returncode, 0)
            plain = Path(d) / "plain"
            plain.mkdir()
            self.assertNotEqual(lib(plain, "in_git_repo").returncode, 0)


@unittest.skipUnless(HAS_GITLEAKS, "gitleaks is not installed here; CI runs this inside the image")
class GitleaksScope(unittest.TestCase):
    def _workspace(self, d: str) -> Path:
        ws = Path(d)
        for sub in ("src", "reports/raw", ".next/server", "node_modules/pkg", "dist"):
            (ws / sub).mkdir(parents=True, exist_ok=True)
            (ws / sub / "config.js").write_text(FAKE_KEY)
        return ws

    def test_only_source_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(d)
            self.assertEqual(gitleaks_files(ws, str(CONFIG)), ["src/config.js"])

    def test_a_projects_own_config_is_extended_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(d)
            (ws / ".gitleaks.toml").write_text(
                '[extend]\nuseDefault = true\n\n[[rules]]\nid = "project-token"\nregex = \'\'\'PROJ-[0-9]{12}\'\'\'\n')
            (ws / "src" / "token.txt").write_text("token PROJ-123456789012\n")
            (ws / "reports" / "raw" / "token.txt").write_text("token PROJ-123456789012\n")
            merged = lib(ws, "gitleaks_config").stdout.strip()
            files = gitleaks_files(ws, merged)
            self.assertIn("src/token.txt", files)          # the project's rule still applies
            self.assertIn("src/config.js", files)          # and the default rules
            self.assertFalse([f for f in files if not f.startswith("src/")], files)  # reports, build skipped


if __name__ == "__main__":
    unittest.main()
