"""prufgate shell-guard: the coding-agent PreToolUse hook that blocks hook skipping,
force pushes and removing tests or CI configuration."""

import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from prufgate.cli import main as cli_main
from prufgate.hooks.agent_hooks import SHELL_GUARD_COMMAND, init_workspace
from prufgate.hooks.shell_guard import check_command, run_hook
from tests.support import installed_python

ROOT = Path(__file__).resolve().parent.parent


BLOCKED = [
    "git commit --no-verify -m 'wip'",
    "git commit -n -m wip",
    'git commit -nm "msg"',
    "git commit -am wip -n",
    "git commit --no-veri -m x",
    "git -C sub commit -n -m x",
    "/usr/bin/git commit -n",
    "git -c core.hooksPath=/dev/null commit -m x",
    "git push --no-verify",
    "git push --force",
    "git push -f origin main",
    "git push -uf origin feature",
    "git push --force-with-lease",
    "git push --force-with-lease=main:abc123 origin main",
    "git push origin +main",
    "rm -rf tests",
    "rm -rf ./tests/",
    "rm src/__tests__/app.test.tsx",
    "rm test_payments.py",
    "rm pkg/handler_test.go",
    "rm web/button.spec.ts",
    "rm conftest.py",
    "git rm -r --cached spec/",
    "rm -f .github/workflows/ci.yml",
    "rm -rf .github",
    "rm .gitlab-ci.yml",
    "rm -rf .prufgate",
    "rm .pre-commit-config.yaml",
    "mv tests/test_a.py /tmp/",
    "git mv test_a.py old_a.py",
    "mv -t /tmp tests",
    # chaining, wrappers, nested shells, substitution
    "npm run build && git commit -n -m x",
    "true; git push -f",
    "echo ok | git push --force",
    "cd app\ngit commit --no-verify",
    "FOO=1 git commit -n",
    "sudo env HUSKY=0 git commit -n -m x",
    'sh -c "git push --force"',
    "bash -lc 'rm -rf tests'",
    "eval 'git commit -n'",
    "echo $(rm tests/test_a.py)",
    "echo `git push -f`",
    "rm .pre-commit-config.yaml 2>/dev/null",
    # compound commands and reserved words
    "{ git commit --no-verify; }",
    "if true; then git commit --no-verify; fi",
    "! git commit --no-verify",
    "for i in 1; do git commit --no-verify; done",
    "f(){ git commit --no-verify; }; f",
    "while true; do git push -f; done",
    "until false; do git push -f; done",
    "case x in x) git push -f;; esac",
    "function f { git commit --no-verify; }",
    "(true >) && git commit -n -m x",
    "cat <(git push -f)",
    # wrappers with option values, and more wrappers
    "sudo -u bob git commit --no-verify",
    "nice -n 5 git commit --no-verify",
    "env -u X git commit --no-verify",
    "env -C . rm -rf tests",
    "env -i git push -f",
    "env -S 'git push --force'",
    "ionice -c3 git push -f",
    "chrt -f 10 git push -f",
    "taskset -c 0 git push -f",
    "doas -u bob git push -f",
    "xargs -n 1 rm -rf tests",
    "xargs -I{} git commit --no-verify",
    "timeout 5 git push -f",
    "stdbuf -oL git push -f",
    "watch -n1 git push -f",
    "busybox rm -r tests",
    "command git push -f",
    "builtin eval 'git push -f'",
    "exec git push -f",
    "nohup git push -f",
    "setsid git push -f",
    "time git push -f",
    "2>/dev/null git push --force",
    # shells: -c anywhere in the options, and scripts read from stdin
    "bash -c -l 'git commit --no-verify'",
    "sh -lc 'git push -f'",
    "zsh -ec 'git push -f'",
    "sh -co pipefail 'git push --force'",
    "bash -rcfile /dev/null -c 'rm -rf tests'",
    "echo 'git commit --no-verify' | bash",
    "bash <<< 'git commit --no-verify'",
    "bash <<EOF\ngit push -f\nEOF",
    "sh -s < script.sh",
    # command substitution with nested parentheses
    'echo "$( (git push --force) )"',
    """echo "$(git commit -n -m 'fix (wip)')\"""",
    # hooks turned off without -c
    "git -ccore.hooksPath=/dev/null commit -m x",
    "git -C. commit --no-verify -m wip",
    "git config core.hooksPath /dev/null",
    "git config --global core.hooksPath /dev/null",
    "git config set --local core.hooksPath x",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
    """GIT_CONFIG_PARAMETERS="'core.hooksPath'='/dev/null'" git commit -m x""",
    "HUSKY=0 git commit -m x",
    "HUSKY_SKIP_HOOKS=1 git push",
    "SKIP=ruff git commit -m x",
    "export HUSKY=0",
    # aliases that skip checks
    "git -c alias.ci='commit --no-verify' ci",
    "git config alias.ci 'commit --no-verify'",
    "git config alias.p 'push -f'",
    "git config alias.x '!git push --force'",
    # hooks skipped by other git commands
    "git merge --no-verify feature",
    "git merge -m 'x' --no-verify feature",
    "git pull --no-verify",
    "git rebase --no-verify main",
    "git am --no-verify < fix.patch",
    "git am -n fix.patch",
    # globs, braces, dots and bundled mv options
    "rm -r {tests,x}",
    "rm -rf .",
    "rm .github/./workflows/ci.yml",
    "rm -f .claude/settings.json",
    "rm -rf .git/hooks",
    "mv -ft /tmp tests",
    "mv -t/tmp tests",
    "mv --target-directory=/tmp tests",
    "mv /tmp/empty .pre-commit-config.yaml",
    "mv /tmp/x.py tests/test_a.py",
    "echo '{}' > ~/.cache/prufgate/adjudicate.json",  # the AI adjudication verdict cache
]

ALLOWED = [
    'git commit -m "fix --no-verify docs"',
    "git commit -m -n",
    "git commit --message --no-verify",
    "git commit --amend --no-edit",
    "git commit -m 'remove tests/ from docs'",
    "git -c user.name=x commit -m y",
    "git push",
    "git push -n origin main",
    "git push -u origin feature",
    "git push --follow-tags",
    "git log -n 3",
    "grep -n force src/",
    "rm -rf build/",
    "rm -rf dist node_modules",
    "rm src/contest.py",
    "rm src/latest.py",
    "mv foo.py tests/",
    "mv src/a.py src/b.py",
    "git rm src/old.py",
    "echo 'git push --force'",
    "ls tests/ && cat .gitlab-ci.yml",
    "python3 -m unittest discover -s tests",
    "git commit -m 'docs: do not run `git push --force`'",
    "echo '$(rm -rf tests)'",
    'git commit -m "fix \\`don\'t\\` in docs"',
    "cat <<EOF > notes.txt\nit's fine: git push -f\nEOF",
    "rm *.pyc",
    "rm -rf {build,dist}",
    "rm -rf ./build",
    "bash scripts/build.sh",
    "bash -c 'make test'",
    "sudo -u bob ls",
    "env -u X make",
    "nice -n 5 python3 -m pytest",
    "timeout 5 make test",
    "git config core.hooksPath",
    "git config --unset core.hooksPath",
    "git config alias.st status",
    "git -c alias.st=status st",
    "HUSKY=1 git commit -m x",
    "git merge -n feature",
    "git merge --no-verify-signatures feature",
    "git merge -m '--no-verify' feature",
    "git rebase -n main",
    "git pull -n",
    "mv -t tests/ src/helper.py",
    "mv src/ci.yml .github/workflows/",
    "",
    "rm -rf prufgate",  # a source directory, not the adjudication cache
]


class CheckCommand(unittest.TestCase):
    def test_blocked(self):
        for cmd in BLOCKED:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(check_command(cmd))

    def test_allowed(self):
        for cmd in ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertIsNone(check_command(cmd))

    def test_unparseable_command_is_refused(self):
        self.assertIn("could not parse", check_command("git commit -m 'unterminated"))

    def test_reason_tells_the_agent_not_to_retry(self):
        self.assertIn("ask the user", check_command("git push -f"))


class ReviewBypasses(unittest.TestCase):
    """Ways past the guard found in review: each must be blocked, and the near misses allowed."""

    BLOCKED = [
        # an unquoted command substitution must not split the command
        "git $(true) commit --no-verify",
        "git commit $(true) --no-verify",
        "git push $(true) --force",
        "rm $(true) -rf tests",
        "$(true) git commit -n",
        # paths after a directory change
        "cd .prufgate && rm config.yaml",
        "cd .github/workflows && rm ci.yml",
        "cd .git && cd hooks && rm pre-commit",
        "git -C .prufgate rm config.yaml",
        "env -C .prufgate rm config.yaml",
        "cd .github/workflows && mv new.yml ci.yml",
        "cd .prufgate && echo 'exclude: [x]' > config.yaml",
        # shells reading their script from standard input
        "echo 'git commit -n' | bash -- -",
        "bash /dev/stdin <<< 'rm -rf tests'",
        "sh /dev/fd/0 < script.txt",
        # writes through a redirection
        "echo x > .prufgate/config.yaml",
        "printf 'x' >> .github/workflows/ci.yml",
        "cat x &> .claude/settings.json",
        ": >| .git/hooks/pre-commit",
        # root PrufGate config files, .git/config, case and trailing-dot variants
        "rm .prufgate.yml",
        "echo > .prufgate.yaml",
        "rm .git/config",
        "rm -rf .Claude",
        "rm .GitHub/Workflows/ci.yml",
        "rm .github/workflows./ci.yml",
        "rm Test_Login.py",
    ]
    ALLOWED = [
        "echo $(date) > notes.txt",
        "cd src && rm old.py",
        "cd src && echo x > out.txt",
        "git -C sub status",
        "make 2>&1 >build.log",
        "cmd >&2",
        "bash scripts/build.sh",
        "echo x > tests/test_new.py",  # writing a test is an edit, like the Edit tool
        "cd \"$(mktemp -d)\" && rm x.txt",
    ]

    def test_blocked(self):
        for cmd in self.BLOCKED:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(check_command(cmd, cwd="/"))

    def test_allowed(self):
        for cmd in self.ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertIsNone(check_command(cmd, cwd="/"))


class Globs(unittest.TestCase):
    """Globs in rm/mv targets are expanded in the command's directory, against real files."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        for rel in ("build/out.o", "build/app.js", "src/app.py", "src/tests/test_app.py", "test_root.py",
                    ".github/workflows/ci.yml", "notes.txt"):
            path = Path(self.root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")

    def test_matches_on_disk_are_checked(self):
        for cmd in ("rm -r test*", "rm *.py", "rm -rf .github/*", "rm -r */tests", "rm -rf src/*",
                    "rm -r {src,build}/*", "mv src/* /tmp/", "rm -rf *"):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(check_command(cmd, cwd=self.root))

    def test_harmless_matches_and_unmatched_globs_are_allowed(self):
        for cmd in ("rm -rf build/*", "rm build/*.o", "rm *.txt", "rm -r spec*", "rm -rf {build,dist}/*",
                    "rm -rf src/*.py"):
            with self.subTest(cmd=cmd):
                self.assertIsNone(check_command(cmd, cwd=self.root))

    def test_literal_protected_names_are_blocked_without_files(self):
        for cmd in ("rm -r {tests,x}", "rm -rf spec", "rm -rf .prufgate"):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(check_command(cmd, cwd=self.root))

    def test_unexpandable_globs_are_refused_conservatively(self):
        missing = str(Path(self.root, "missing"))
        for cmd, cwd in (("rm -rf build/*", missing), ("rm -r $DIR/*", self.root),
                         ("cd build && rm -rf ../*", self.root), ("env -C src rm -rf *", self.root),
                         ("rm -rf `pwd`/*", self.root)):
            with self.subTest(cmd=cmd, cwd=cwd):
                self.assertIsNotNone(check_command(cmd, cwd=cwd))

    def test_hook_uses_payload_cwd(self):
        payload = {"tool_name": "Bash", "cwd": self.root, "tool_input": {"command": "rm -rf build/*"}}
        self.assertEqual(run_hook(json.dumps(payload)), (0, ""))
        payload["tool_input"]["command"] = "rm -rf src/*"
        self.assertEqual(run_hook(json.dumps(payload))[0], 2)


class HookProtocol(unittest.TestCase):
    def _payload(self, command):
        return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}})

    def test_block_and_allow(self):
        rc, msg = run_hook(self._payload("git commit --no-verify -m x"))
        self.assertEqual(rc, 2)
        self.assertIn("--no-verify", msg)
        self.assertEqual(run_hook(self._payload("git status")), (0, ""))

    def test_other_tools_are_allowed(self):
        self.assertEqual(run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x"}})), (0, ""))

    def test_malformed_input_blocks(self):
        for bad in ("", "{ broken", "[]", '"x"', json.dumps({"tool_name": "Bash"}),
                    json.dumps({"tool_name": "Bash", "tool_input": {"command": 3}}),
                    json.dumps({"tool_name": "Bash", "tool_input": "git status"})):
            with self.subTest(bad=bad):
                self.assertEqual(run_hook(bad)[0], 2)

    def test_cli_reads_stdin(self):
        err = io.StringIO()
        with patch("sys.stdin", io.StringIO(self._payload("git push --force"))), redirect_stderr(err):
            rc = cli_main(["shell-guard"])
        self.assertEqual(rc, 2)
        self.assertIn("rewrites remote history", err.getvalue())
        with patch("sys.stdin", io.StringIO(self._payload("ls"))):
            self.assertEqual(cli_main(["shell-guard"]), 0)
        with patch("sys.stdin", io.StringIO("not json")), redirect_stderr(io.StringIO()):
            self.assertEqual(cli_main(["shell-guard"]), 2)

    def test_hook_command_end_to_end(self):
        # The installed hook, as Claude Code runs it, with a trusted editable installation.
        # This interpreter's folder comes first: on Windows it holds `python` and no `python3`.
        env = {"PATH": os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"]), "PYTHONPATH": str(ROOT)}
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install:
            python = installed_python(Path(install) / "venv")
            env["PATH"] = str(python.parent) + os.pathsep + env["PATH"]
            env["HOME"] = tmp
            blocked = subprocess.run(["sh", "-c", SHELL_GUARD_COMMAND], cwd=tmp, env=env, capture_output=True,
                                     text=True, input=self._payload("git push -f"))
            self.assertEqual(blocked.returncode, 2, blocked.stderr)
            self.assertIn("shell-guard blocked", blocked.stderr)
            allowed = subprocess.run(["sh", "-c", SHELL_GUARD_COMMAND], cwd=tmp, env=env, capture_output=True,
                                     text=True, input=self._payload("git status"))
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

    @unittest.skipIf(sys.platform == "win32", "builds a POSIX sh shim for python3")
    def test_hook_command_falls_back_to_python(self):
        # Windows has `python` and no `python3`: here `python3` cannot import the engine, `python` can.
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            python = installed_python(Path(install) / "venv")
            launcher = bin_dir / "python"
            launcher.write_text("#!/bin/sh\nexec " + shlex.quote(str(python)) + ' "$@"\n')
            launcher.chmod(0o755)
            shim = bin_dir / "python3"
            shim.write_text("#!/bin/sh\nexit 1\n")
            shim.chmod(0o755)
            env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "PYTHONPATH": str(ROOT), "HOME": tmp}
            blocked = subprocess.run(["sh", "-c", SHELL_GUARD_COMMAND], cwd=tmp, env=env, capture_output=True,
                                     text=True, input=self._payload("git push -f"))
            self.assertEqual(blocked.returncode, 2, blocked.stderr)
            self.assertIn("shell-guard blocked", blocked.stderr)

    def test_hook_command_blocks_when_prufgate_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
            r = subprocess.run(["sh", "-c", SHELL_GUARD_COMMAND], cwd=tmp, env=env, capture_output=True, text=True,
                               input=self._payload("ls"))
            self.assertEqual(r.returncode, 2)
            self.assertIn("not installed", r.stderr)


class InitMerge(unittest.TestCase):
    def test_pre_tool_use_hook_is_merged_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / ".claude" / "settings.json"
            settings.parent.mkdir()
            mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}
            settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}, "hooks": {"PreToolUse": [mine]}}))
            init_workspace(Path(tmp), install_hooks=True)
            init_workspace(Path(tmp), install_hooks=True)
            data = json.loads(settings.read_text())
            self.assertEqual(data["permissions"], {"allow": ["Bash(ls)"]})
            pre = data["hooks"]["PreToolUse"]
            self.assertEqual(len(pre), 3)
            self.assertEqual(pre[0], mine)
            self.assertEqual(pre[1]["matcher"], "Bash")
            self.assertIn("prufgate shell-guard", pre[1]["hooks"][0]["command"])
            self.assertEqual(len(data["hooks"]["Stop"]), 1)

    def test_wrong_shaped_pre_tool_use_is_refused(self):
        from prufgate.hooks.agent_hooks import HookConfigError

        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / ".claude" / "settings.json"
            settings.parent.mkdir()
            settings.write_text(json.dumps({"hooks": {"PreToolUse": {}}}))
            with self.assertRaises(HookConfigError):
                init_workspace(Path(tmp), install_hooks=True)


if __name__ == "__main__":
    unittest.main()
