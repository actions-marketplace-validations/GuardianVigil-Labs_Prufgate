"""prufgate hook <agent> <event>: fail-closed adapters for Claude Code, Codex, Gemini CLI,
GitHub Copilot and Cursor, and the configuration `prufgate init --agent` merges.

Payloads are invented, shaped after each agent's published hook reference."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate.cli import main as cli_main
from prufgate.hooks import adapters
from prufgate.hooks.agent_hooks import HookConfigError, guard_command, init_workspace

ROOT = Path(__file__).resolve().parent.parent

FORCE_PUSH = "git push --force origin main"
SAFE = "git status"


def shell_payload(agent, command):
    if agent == "copilot":  # camelCase, toolArgs is a JSON string
        return {"sessionId": "s1", "timestamp": 1704614400000, "cwd": "/tmp", "toolName": "bash",
                "toolArgs": json.dumps({"command": command})}
    if agent == "cursor":
        return {"tool_name": "Shell", "tool_input": {"command": command, "working_directory": "/tmp"}, "cwd": "/tmp"}
    name = {"claude": "Bash", "codex": "Bash", "gemini": "run_shell_command"}[agent]
    return {"hook_event_name": "PreToolUse", "cwd": "/tmp", "tool_name": name, "tool_input": {"command": command}}


def edit_payload(agent, path):
    if agent == "copilot":
        return {"toolName": "edit", "toolArgs": json.dumps({"path": path, "old_str": "a", "new_str": "b"})}
    if agent == "cursor":
        return {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}}
    if agent == "codex":
        patch_text = f"*** Begin Patch\n*** Update File: {path}\n@@\n-a\n+b\n*** End Patch\n"
        return {"tool_name": "apply_patch", "tool_input": {"command": patch_text}}
    if agent == "gemini":
        return {"tool_name": "replace", "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"}}
    return {"tool_name": "Edit", "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"}}


def is_block(agent, event, result):
    rc, out, _ = result
    if agent == "cursor":
        data = json.loads(out)
        return bool(data.get("followup_message")) if event == "stop" else data.get("permission") == "deny"
    if agent == "copilot" and event == "stop":
        return out != "" and json.loads(out).get("decision") == "block"
    if agent == "copilot":
        return rc == 2 and json.loads(out)["permissionDecision"] == "deny"
    return rc == 2


def run(agent, event, payload):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return adapters.handle(agent, event, text)


class PreTool(unittest.TestCase):
    def test_shell_block_and_allow(self):
        for agent in adapters.AGENTS:
            with self.subTest(agent=agent):
                blocked = run(agent, "pre-tool", shell_payload(agent, FORCE_PUSH))
                self.assertTrue(is_block(agent, "pre-tool", blocked), blocked)
                self.assertIn("rewrites remote history", blocked[1] + blocked[2])
                self.assertFalse(is_block(agent, "pre-tool", run(agent, "pre-tool", shell_payload(agent, SAFE))))

    def test_edit_guard(self):
        for agent in adapters.AGENTS:
            for path in (".github/workflows/ci.yml", "/work/app/.prufgate/config.yaml", ".cursor/hooks.json",
                         ".claude/settings.json", ".github/hooks/prufgate.json"):
                with self.subTest(agent=agent, path=path):
                    self.assertTrue(is_block(agent, "pre-tool", run(agent, "pre-tool", edit_payload(agent, path))))
            for path in ("src/app.py", "/work/app/tests/test_app.py", ".github/CODEOWNERS"):
                with self.subTest(agent=agent, path=path):
                    self.assertFalse(is_block(agent, "pre-tool", run(agent, "pre-tool", edit_payload(agent, path))))

    def test_deleting_tests_is_blocked_editing_them_is_not(self):
        delete = {"tool_name": "Delete", "tool_input": {"file_path": "tests/test_app.py"}}
        self.assertTrue(is_block("cursor", "pre-tool", run("cursor", "pre-tool", delete)))
        patch_text = "*** Begin Patch\n*** Delete File: pkg/handler_test.go\n*** End Patch\n"
        self.assertEqual(run("codex", "pre-tool", {"tool_name": "apply_patch", "tool_input": {"command": patch_text}})[0], 2)
        moved = "*** Begin Patch\n*** Update File: src/a.py\n*** Move to: .github/workflows/a.yml\n*** End Patch\n"
        self.assertEqual(run("codex", "pre-tool", {"tool_name": "apply_patch", "tool_input": {"command": moved}})[0], 2)

    def test_other_tools_are_allowed(self):
        self.assertEqual(run("claude", "pre-tool", {"tool_name": "Read", "tool_input": {"file_path": ".prufgate/config.yaml"}}),
                         (0, "", ""))
        self.assertEqual(run("copilot", "pre-tool", {"toolName": "view", "toolArgs": "{}"}), (0, "", ""))

    def test_malformed_input_blocks(self):
        bad_inputs = ["", "{ broken", "[]", '"x"', json.dumps({"tool_input": {"command": "ls"}})]
        for agent in adapters.AGENTS:
            bad = list(bad_inputs)
            if agent != "copilot":  # Copilot's JSON-string toolArgs are covered below
                bad += [json.dumps(shell_payload(agent, SAFE)).replace('"command"', '"cmd"'),
                        json.dumps(edit_payload(agent, "src/a.py")).replace("path", "pat").replace("File:", "X:")]
            for text in bad:
                with self.subTest(agent=agent, text=text):
                    self.assertTrue(is_block(agent, "pre-tool", run(agent, "pre-tool", text)))
        for args in ("{nope", json.dumps({"cmd": "ls"}), json.dumps({"pat": "src/a.py"})):
            name = "edit" if "pat" in args else "bash"
            self.assertTrue(is_block("copilot", "pre-tool", run("copilot", "pre-tool", {"toolName": name, "toolArgs": args})))

    def test_internal_error_blocks(self):
        for agent in adapters.AGENTS:
            with self.subTest(agent=agent), patch.object(adapters, "check_command", side_effect=RuntimeError("boom")):
                result = run(agent, "pre-tool", shell_payload(agent, SAFE))
                self.assertTrue(is_block(agent, "pre-tool", result))
                self.assertIn("RuntimeError", result[1] + result[2])

    def test_cursor_before_shell_execution(self):
        rc, out, _ = run("cursor", "shell", {"command": "rm -rf tests", "cwd": "/tmp", "sandbox": False})
        self.assertEqual((rc, json.loads(out)["permission"]), (0, "deny"))
        self.assertIn("test directory", json.loads(out)["agent_message"])
        self.assertEqual(json.loads(run("cursor", "shell", {"command": "ls", "cwd": "/tmp"})[1]), {"permission": "allow"})
        self.assertEqual(json.loads(run("cursor", "shell", {"cwd": "/tmp"})[1])["permission"], "deny")
        # `shell` is Cursor's event only: any other agent is refused.
        self.assertEqual(run("claude", "shell", {"command": "ls"})[0], 2)


class ReviewBypasses(unittest.TestCase):
    def test_apply_patch_moving_a_test_away_is_a_deletion(self):
        patch_text = "*** Begin Patch\n*** Update File: tests/test_a.py\n*** Move to: notes/a.txt\n*** End Patch\n"
        result = run("codex", "pre-tool", {"tool_name": "apply_patch", "tool_input": {"command": patch_text}})
        self.assertTrue(is_block("codex", "pre-tool", result), result)
        moved_in = "*** Begin Patch\n*** Update File: src/a.py\n*** Move to: src/b.py\n*** End Patch\n"
        result = run("codex", "pre-tool", {"tool_name": "apply_patch", "tool_input": {"command": moved_in}})
        self.assertFalse(is_block("codex", "pre-tool", result), result)

    def test_more_edit_and_shell_tool_names_are_checked(self):
        edit = {"tool_name": "StrReplace", "tool_input": {"path": ".prufgate/config.yaml", "old_string": "a"}}
        self.assertTrue(is_block("cursor", "pre-tool", run("cursor", "pre-tool", edit)))
        for name in ("shell", "exec_command"):
            with self.subTest(name=name):
                payload = {"tool_name": name, "tool_input": {"command": ["bash", "-lc", FORCE_PUSH]}}
                self.assertTrue(is_block("codex", "pre-tool", run("codex", "pre-tool", payload)))

    def test_root_config_and_case_variants_are_protected(self):
        for path in (".prufgate.yml", ".prufgate.yaml", ".git/config", ".Claude/settings.json",
                     "C:\\repo\\.GitHub\\Workflows\\ci.yml", ".github/workflows./ci.yml",
                     "plugins/prufgate/hooks/hooks.json", ".claude-plugin/marketplace.json", ".cursor/BUGBOT.md"):
            with self.subTest(path=path):
                self.assertTrue(is_block("claude", "pre-tool", run("claude", "pre-tool", edit_payload("claude", path))))
        self.assertFalse(is_block("claude", "pre-tool", run("claude", "pre-tool", edit_payload("claude", "src/config.yml"))))

    def test_unreadable_stdin_blocks_in_the_agent_protocol(self):
        class Broken:
            def read(self):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

        for agent, event in (("cursor", "pre-tool"), ("cursor", "stop"), ("copilot", "stop")):
            out = io.StringIO()
            with self.subTest(agent=agent, event=event), patch("sys.stdin", Broken()), \
                    redirect_stdout(out), redirect_stderr(io.StringIO()):
                rc = adapters.main(agent, event)
                self.assertTrue(is_block(agent, event, (rc, out.getvalue().strip(), "")), out.getvalue())

    def test_written_hooks_match_more_tools_and_block_when_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            init_workspace(Path(tmp), agents=["cursor", "copilot", "codex"])
            cursor = json.loads((Path(tmp) / ".cursor/hooks.json").read_text())["hooks"]
            self.assertIn("StrReplace", cursor["preToolUse"][0]["matcher"])
            self.assertTrue(cursor["stop"][0]["failClosed"])
            copilot = json.loads((Path(tmp) / ".github/hooks/prufgate.json").read_text())["hooks"]
            self.assertIn("str_replace_editor", copilot["preToolUse"][0]["matcher"])
            codex = json.loads((Path(tmp) / ".codex/hooks.json").read_text())["hooks"]
            self.assertIn("exec_command", codex["PreToolUse"][0]["matcher"])
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
            for agent, event, cmd in (("cursor", "pre-tool", cursor["preToolUse"][0]["command"]),
                                      ("cursor", "stop", cursor["stop"][0]["command"]),
                                      ("copilot", "stop", copilot["agentStop"][0]["bash"])):
                with self.subTest(agent=agent, event=event):
                    r = subprocess.run(["sh", "-c", cmd], cwd=tmp, env=env, capture_output=True, text=True, input="{}")
                    self.assertIn("not installed", r.stderr)
                    self.assertTrue(is_block(agent, event, (r.returncode, r.stdout.strip(), "")), r)

    def test_codex_and_gemini_stop_hooks_do_not_loop_when_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            init_workspace(Path(tmp), agents=["codex", "gemini"])
            codex = json.loads((Path(tmp) / ".codex/hooks.json").read_text())["hooks"]["Stop"]
            gemini = json.loads((Path(tmp) / ".gemini/settings.json").read_text())["hooks"]["AfterAgent"]
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
            for agent, entry in (("codex", codex), ("gemini", gemini)):
                cmd = entry[0]["hooks"][0]["command"]
                with self.subTest(agent=agent):
                    first = subprocess.run(["sh", "-c", cmd], cwd=tmp, env=env, capture_output=True, text=True,
                                           input='{"stop_hook_active": false}')
                    self.assertEqual(first.returncode, 2, first)
                    again = subprocess.run(["sh", "-c", cmd], cwd=tmp, env=env, capture_output=True, text=True,
                                           input='{"stop_hook_active": true}')
                    self.assertEqual(again.returncode, 0, again)


class Stop(unittest.TestCase):
    def stop_payload(self, agent, again=False):
        if agent == "cursor":
            return {"status": "completed", "loop_count": 1 if again else 0, "workspace_roots": [tempfile.gettempdir()]}
        # A folder that exists on every system (`/tmp` does not on Windows: the adapter would fall back to the cwd).
        return {"hook_event_name": "Stop", "cwd": tempfile.gettempdir(), "stop_hook_active": again}

    def test_findings_send_the_agent_back_once(self):
        findings = (2, "PrufGate Agent Guardrail blocked completion (1 blocker finding(s)):\n  - [P0] src/a.py:3")
        for agent in adapters.AGENTS:
            with self.subTest(agent=agent), patch.object(adapters, "run_check", return_value=findings) as check:
                result = run(agent, "stop", self.stop_payload(agent))
                self.assertTrue(is_block(agent, "stop", result))
                self.assertIn("src/a.py:3", result[1] + result[2])
                check.assert_called_once_with(tempfile.gettempdir())
                self.assertFalse(is_block(agent, "stop", run(agent, "stop", self.stop_payload(agent, again=True))))

    def test_clean_check_lets_the_agent_stop(self):
        for agent in adapters.AGENTS:
            with self.subTest(agent=agent), patch.object(adapters, "run_check", return_value=(0, "")):
                self.assertFalse(is_block(agent, "stop", run(agent, "stop", self.stop_payload(agent))))

    def test_cursor_aborted_turn_is_not_checked(self):
        with patch.object(adapters, "run_check") as check:
            self.assertEqual(json.loads(run("cursor", "stop", {"status": "aborted", "loop_count": 0})[1]), {})
            check.assert_not_called()

    def test_malformed_stop_input_and_check_crash_block(self):
        for agent in adapters.AGENTS:
            with self.subTest(agent=agent):
                self.assertTrue(is_block(agent, "stop", run(agent, "stop", "not json")))
                with patch.object(adapters, "run_check", side_effect=OSError("gone")):
                    self.assertTrue(is_block(agent, "stop", run(agent, "stop", self.stop_payload(agent))))

    @patch.dict(os.environ, {"GITHUB_BASE_REF": "", "PRUFGATE_BASE_REF": ""})
    def test_run_check_on_a_real_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            (Path(tmp) / "app.py").write_text("def add(a, b):\n    return a + b\n")
            git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@example.com"]
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "init"], check=True)
            (Path(tmp) / "app.py").write_text("def add(a, b):\n    return b + a\n")
            rc, text = adapters.run_check(tmp)
            self.assertEqual(rc, 0, text)
            rc, text = adapters.run_check(str(Path(tmp) / "missing"))
            self.assertNotEqual(rc, 0)
            self.assertIn("could not run", text)


class Cli(unittest.TestCase):
    def test_cli_reads_stdin_and_writes_the_protocol(self):
        out, err = io.StringIO(), io.StringIO()
        payload = json.dumps(shell_payload("copilot", FORCE_PUSH))
        with patch("sys.stdin", io.StringIO(payload)), redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(["hook", "copilot", "pre-tool"])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue())["permissionDecision"], "deny")

    def test_unknown_agent_is_a_usage_error(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli_main(["hook", "notanagent", "pre-tool"])
        self.assertEqual(ctx.exception.code, 2)

    def test_installed_command_end_to_end(self):
        # This interpreter's folder first: on Windows it holds `python` and no `python3`.
        env = {"PATH": os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"]), "PYTHONPATH": str(ROOT)}
        cmd = guard_command("hook cursor shell", "blocked")
        with tempfile.TemporaryDirectory() as tmp:
            env["HOME"] = tmp
            r = subprocess.run(["sh", "-c", cmd], cwd=tmp, env=env, capture_output=True, text=True,
                               input=json.dumps({"command": "git commit --no-verify -m x"}))
            self.assertEqual((r.returncode, json.loads(r.stdout)["permission"]), (0, "deny"), r.stderr)
            missing = subprocess.run(["sh", "-c", cmd], cwd=tmp, env={"PATH": "/usr/bin:/bin", "HOME": tmp},
                                     capture_output=True, text=True, input="{}")
            self.assertEqual(missing.returncode, 2)
            self.assertIn("not installed", missing.stderr)


class InitAgents(unittest.TestCase):
    FILES = {"claude": ".claude/settings.json", "cursor": ".cursor/hooks.json", "copilot": ".github/hooks/prufgate.json",
             "codex": ".codex/hooks.json", "gemini": ".gemini/settings.json"}

    def test_every_agent_is_written_and_merged_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            user = {
                "cursor": {"version": 1, "hooks": {"stop": [{"command": "./mine.sh"}]}, "extra": True},
                "codex": {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}]}},
                "gemini": {"theme": "dark", "hooks": {}},
            }
            for agent, data in user.items():
                (ws / self.FILES[agent]).parent.mkdir(parents=True, exist_ok=True)
                (ws / self.FILES[agent]).write_text(json.dumps(data))
            agents = list(self.FILES)
            init_workspace(ws, agents=agents)
            first = {a: (ws / f).read_text() for a, f in self.FILES.items()}
            init_workspace(ws, agents=agents)
            self.assertEqual(first, {a: (ws / f).read_text() for a, f in self.FILES.items()})

            cursor = json.loads(first["cursor"])
            self.assertTrue(cursor["extra"])
            self.assertEqual(cursor["hooks"]["stop"][0], {"command": "./mine.sh"})
            self.assertIn("prufgate hook cursor stop", cursor["hooks"]["stop"][1]["command"])
            self.assertTrue(cursor["hooks"]["beforeShellExecution"][0]["failClosed"])
            self.assertTrue(cursor["hooks"]["preToolUse"][0]["failClosed"])

            copilot = json.loads(first["copilot"])
            self.assertEqual(copilot["version"], 1)
            self.assertIn("prufgate hook copilot pre-tool", copilot["hooks"]["preToolUse"][0]["bash"])
            self.assertIn("prufgate hook copilot stop", copilot["hooks"]["agentStop"][0]["bash"])

            codex = json.loads(first["codex"])
            self.assertEqual(codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "mine")
            self.assertEqual(len(codex["hooks"]["PreToolUse"]), 2)
            self.assertEqual(len(codex["hooks"]["Stop"]), 1)

            gemini = json.loads(first["gemini"])
            self.assertEqual(gemini["theme"], "dark")
            self.assertIn("BeforeTool", gemini["hooks"])
            self.assertIn("AfterAgent", gemini["hooks"])

            claude = json.loads(first["claude"])
            matchers = [e["matcher"] for e in claude["hooks"]["PreToolUse"]]
            self.assertEqual(matchers, ["Bash", "Edit|Write|MultiEdit|NotebookEdit"])

    def test_default_agents_are_claude_and_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = init_workspace(Path(tmp), install_hooks=True)
            self.assertIn(".claude/settings.json", written)
            self.assertIn(".cursor/hooks.json", written)
            self.assertNotIn(".codex/hooks.json", written)

    def test_malformed_config_is_refused_and_nothing_is_written(self):
        cases = {".cursor/hooks.json": "{ broken", ".github/hooks/prufgate.json": "[]",
                 ".codex/hooks.json": json.dumps({"hooks": []}), ".gemini/settings.json": json.dumps({"hooks": {"BeforeTool": {}}})}
        for rel, text in cases.items():
            agent = next(a for a, f in self.FILES.items() if f == rel)
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / rel).parent.mkdir(parents=True)
                (Path(tmp) / rel).write_text(text)
                with self.assertRaises(HookConfigError):
                    init_workspace(Path(tmp), agents=["claude", agent])
                self.assertEqual((Path(tmp) / rel).read_text(), text)
                self.assertFalse((Path(tmp) / ".claude" / "settings.json").exists())

    def test_wrong_version_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".cursor").mkdir()
            (Path(tmp) / ".cursor" / "hooks.json").write_text(json.dumps({"version": 2, "hooks": {}}))
            with self.assertRaises(HookConfigError):
                init_workspace(Path(tmp), agents=["cursor"])

    def test_cli_agent_flag(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["init", tmp, "--agent", "codex", "--agent", "copilot"]), 0)
            self.assertTrue((Path(tmp) / ".codex" / "hooks.json").is_file())
            self.assertTrue((Path(tmp) / ".github" / "hooks" / "prufgate.json").is_file())
            self.assertFalse((Path(tmp) / ".claude" / "settings.json").exists())


if __name__ == "__main__":
    unittest.main()
