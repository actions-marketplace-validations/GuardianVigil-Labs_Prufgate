#!/usr/bin/env python3
"""Shell-command guard for coding agents (`prufgate shell-guard`).

Inspects a shell command an agent is about to run and blocks the ways agents
get past checks: skipping git hooks, force-pushing, and deleting or moving
tests, test directories or CI configuration.

- `check_command(command)` returns a reason string to block, or None to allow.
- `prufgate shell-guard` reads a Claude Code PreToolUse hook payload on stdin
  (`{"tool_name": "Bash", "tool_input": {"command": "..."}}`) and exits 2 with
  the reason on stderr to block, 0 to allow. Unreadable input blocks.
"""

from __future__ import annotations

import codecs
import contextvars
import fnmatch
import glob
import itertools
import json
import math
import os
import posixpath
import re
import shlex
import sys
from pathlib import PurePosixPath

from prufgate.config import DEFAULT_CONFIG_FILES

RUN_IT_YOURSELF = "If it is really needed, ask the user to run it themselves."

# Shell operators, longest first. Those containing < or > are redirections.
_OPERATORS = sorted(
    [";;&", ";;", ";&", "&&", "||", "|&", "&>>", "&>", ">>", ">&", "<&", "<<<", "<<-", "<<", "<>", ">|",
     ";", "&", "|", "<", ">", "(", ")", "\n"],
    key=len, reverse=True,
)
_OPERATOR_CHARS = set(";&|<>()\n")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_GLOB_CHARS = re.compile(r"[*?\[{]")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "rbash", "fish", "csh", "tcsh", "yash"}
# Reserved words that only give a command structure; the simple command after them is checked.
_RESERVED = {"{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "esac", "coproc"}
# Commands that run the rest of the line as another command:
# name -> (short options taking a value, long options taking a value, words before the command).
_WRAPPERS: dict[str, tuple[str, set[str], int]] = {
    "sudo": ("ugpCDhrtUT", {"--user", "--group", "--host", "--prompt", "--close-from", "--chdir", "--role",
                             "--type", "--other-user", "--command-timeout"}, 0),
    "doas": ("uC", set(), 0),
    "env": ("uCS", {"--unset", "--chdir", "--split-string"}, 0),
    "nice": ("n", {"--adjustment"}, 0),
    "ionice": ("cnp", {"--class", "--classdata", "--pid"}, 0),
    "chrt": ("TPD", {"--sched-runtime", "--sched-period", "--sched-deadline"}, 1),
    "taskset": ("", set(), 1),
    "timeout": ("sk", {"--signal", "--kill-after"}, 1),
    "stdbuf": ("ioe", {"--input", "--output", "--error"}, 0),
    "watch": ("nq", {"--interval", "--equexit"}, 0),
    "xargs": ("adEILnPs", {"--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars",
                           "--process-slot-var"}, 0),
    "time": ("fo", {"--format", "--output"}, 0),
    "exec": ("a", set(), 0),
    "command": ("", set(), 0),
    "builtin": ("", set(), 0),
    "nohup": ("", set(), 0),
    "setsid": ("", set(), 0),
    "busybox": ("", set(), 0),
}

# git options that take a separate value, before the subcommand.
_GIT_GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
_GIT_CONFIG_WITH_VALUE = {"-f", "--file", "--blob", "--type", "--default", "--comment", "--value"}
_PUSH_LONG_WITH_VALUE = {"--repo", "--receive-pack", "--exec", "--push-option"}
_PUSH_SHORT_WITH_VALUE = set("o")

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs"}
_TEST_FILE = re.compile(
    r"^(test_.*\.py|.*_test\.(py|go|rb|rs|exs?)|conftest\.py|.*\.(test|spec)\.[cm]?[jt]sx?|.*_spec\.rb|.*Tests?\.(java|kt|cs))$"
)
_CI_DIRS = (".github/workflows", ".prufgate", ".circleci", ".git/hooks", ".github/hooks", ".cursor/rules",
            ".claude-plugin", "plugins/prufgate")
# Coding-agent hook configuration is included: removing it switches the guard off.
# .git/config can set core.hooksPath; the root PrufGate config files are read like .prufgate/config.yaml.
_CI_FILES = (".gitlab-ci.yml", ".pre-commit-config.yaml", "Jenkinsfile", "azure-pipelines.yml",
             ".claude/settings.json", ".claude/settings.local.json", ".cursor/hooks.json",
             ".codex/hooks.json", ".codex/config.toml", ".gemini/settings.json", ".git/config", ".cursor/BUGBOT.md",
             *(f for f in DEFAULT_CONFIG_FILES if "/" not in f))
_CI_PATHS = _CI_DIRS + _CI_FILES
# Compared lowercased: macOS and Windows file systems ignore case.
_CI_LOWER = tuple(c.lower() for c in _CI_PATHS)
# Names a glob in an rm/mv target is tried against: one example of every protected kind of path.
# ponytail: example names, not a glob-vs-regex intersection; add a name here when a protected kind is added.
_GLOB_SAMPLES = sorted(_TEST_DIRS) + [
    "test_x.py", "x_test.py", "x_test.go", "x_test.rb", "x_test.rs", "x_test.exs", "conftest.py", "x.test.js",
    "x.spec.ts", "x.test.tsx", "x.spec.mjs", "x_spec.rb", "XTest.java", "XTests.cs", "XTest.kt",
    ".github", "workflows", ".gitlab-ci.yml", ".prufgate", ".pre-commit-config.yaml", ".circleci", "Jenkinsfile",
    "azure-pipelines.yml", ".claude", "settings.json", "settings.local.json", ".git", "hooks",
    ".cursor", "hooks.json", ".codex", "config.toml", ".gemini", "config", "rules", ".prufgate.yml", ".prufgate.yaml",
    ".claude-plugin", "marketplace.json", "plugins", "prufgate", "BUGBOT.md", "adjudicate.json",
]


# The directory globs are expanded in; None when unknown (no cwd, or the command changed directory).
_CWD: contextvars.ContextVar[str | None] = contextvars.ContextVar("prufgate_shell_guard_cwd", default=None)
# Where `cd`, `git -C` or `env -C` moved to, relative to the starting directory ("" = not moved); None when the
# target cannot be read (a variable, `cd -`). Relative paths are checked both as written and under it.
_PREFIX: contextvars.ContextVar[str | None] = contextvars.ContextVar("prufgate_shell_guard_prefix", default="")
# Wrapper options that change directory before running the command.
_CHDIR_OPTIONS = {("env", "C"), ("env", "--chdir"), ("sudo", "D"), ("sudo", "--chdir")}
# git subcommands that run hooks a --no-verify skips: (short flag that means --no-verify, short options taking a
# value, long options taking a value). Checked against `git <sub> -h` (git 2.43).
_NO_VERIFY_SUBCOMMANDS: dict[str, tuple[str, str, set[str]]] = {
    "commit": ("n", "mFcCt", {"--message", "--file", "--author", "--date", "--reuse-message", "--reedit-message",
                              "--template", "--fixup", "--squash", "--trailer", "--cleanup", "--pathspec-from-file"}),
    "merge": ("", "mFsX", {"--message", "--file", "--strategy", "--strategy-option", "--cleanup", "--into-name"}),
    "pull": ("", "sX", {"--strategy", "--strategy-option", "--upload-pack", "--depth", "--deepen", "--shallow-since",
                        "--shallow-exclude", "--negotiation-tip"}),
    "rebase": ("", "sXx", {"--onto", "--exec", "--strategy", "--strategy-option", "--whitespace"}),
    "am": ("n", "pC", {"--directory", "--exclude", "--include", "--whitespace", "--patch-format", "--resolvemsg"}),
}


class _Unparseable(ValueError):
    pass


class _Word(str):
    """A shell word with its quotes removed. `glob` is True when it holds an unquoted * ? [ or {."""

    glob = False


def _substitution_end(command: str, i: int) -> int:
    """Index just past the `)` closing the `$(` whose body starts at `i`, counting nested parentheses and quotes."""
    depth, n = 1, len(command)
    while i < n:
        ch = command[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            j = command.find("'", i + 1)
            if j < 0:
                break
            i = j
        elif ch == '"':
            i += 1
            while i < n and command[i] != '"':
                i += 2 if command[i] == "\\" else 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise _Unparseable("unterminated $(...)")


def _backtick_end(command: str, i: int) -> tuple[int, str]:
    """(index past the closing backtick, the inner command) for a backtick whose body starts at `i`."""
    body: list[str] = []
    while i < len(command):
        if command[i] == "\\" and i + 1 < len(command):
            body.append(command[i + 1] if command[i + 1] in "`$\\" else command[i:i + 2])
            i += 2
        elif command[i] == "`":
            return i + 1, "".join(body)
        else:
            body.append(command[i])
            i += 1
    raise _Unparseable("unterminated backtick")


def _tokens(command: str) -> list[tuple[str, str]]:
    """Tokenize with POSIX quoting: [("w", word) | ("op", operator) | ("sub", command substitution)].
    Here-document bodies are skipped; single-quoted text is never treated as a substitution."""
    out: list[tuple[str, str]] = []
    word: list[str] | None = None
    glob = False
    heredocs: list[tuple[str, bool]] = []  # (delimiter, strip leading tabs)
    want_delim: bool | None = None  # after << or <<-, the next word is a delimiter
    i, n = 0, len(command)

    def flush() -> None:
        nonlocal word, glob, want_delim
        if word is not None:
            w = _Word("".join(word))
            w.glob = glob
            out.append(("w", w))
            if want_delim is not None:
                heredocs.append((w, want_delim))
                want_delim = None
        word, glob = None, False

    while i < n:
        ch = command[i]
        if ch in " \t\r":
            flush()
            i += 1
        elif ch == "#" and word is None:
            j = command.find("\n", i)
            i = n if j < 0 else j
        elif ch in _OPERATOR_CHARS:
            op = next(o for o in _OPERATORS if command.startswith(o, i))
            if word is not None and word and "".join(word).isdigit() and ("<" in op or ">" in op) and not glob:
                word = None  # a file descriptor number (2>/dev/null)
            flush()
            out.append(("op", op))
            i += len(op)
            if op in ("<<", "<<-"):
                want_delim = op == "<<-"
            elif op == "\n" and heredocs:
                for delim, strip in heredocs:
                    while i < n:
                        j = command.find("\n", i)
                        line = command[i:] if j < 0 else command[i:j]
                        i = n if j < 0 else j + 1
                        if (line.lstrip("\t") if strip else line) == delim:
                            break
                heredocs = []
        elif ch == "'":
            j = command.find("'", i + 1)
            if j < 0:
                raise _Unparseable("unterminated single quote")
            word = (word or []) + [command[i + 1:j]]
            i = j + 1
        elif ch == "$" and command.startswith("$(", i):
            j = _substitution_end(command, i + 2)
            out.append(("sub", command[i + 2:j - 1]))
            word = (word or []) + [command[i:j]]
            i = j
        elif ch == "$" and command.startswith("$'", i):
            j = i + 2
            while j < n and command[j] != "'":
                j += 2 if command[j] == "\\" else 1
            if j >= n:
                raise _Unparseable("unterminated $'...' quote")
            try:
                text = codecs.decode(command[i + 2:j].encode("latin-1", "backslashreplace"), "unicode_escape")
            except UnicodeDecodeError as exc:
                raise _Unparseable("bad $'...' escape") from exc
            word = (word or []) + [text]
            i = j + 1
        elif ch == "`":
            i, body = _backtick_end(command, i + 1)
            out.append(("sub", body))
            word = (word or []) + ["`"]
        elif ch == '"':
            word = word or []
            i += 1
            while i < n and command[i] != '"':
                if command.startswith("$(", i):
                    j = _substitution_end(command, i + 2)
                    out.append(("sub", command[i + 2:j - 1]))
                    word.append(command[i:j])
                    i = j
                elif command[i] == "`":
                    i, body = _backtick_end(command, i + 1)
                    out.append(("sub", body))
                    word.append("`")
                elif command[i] == "\\" and i + 1 < n and command[i + 1] in '$`"\\\n':
                    if command[i + 1] != "\n":
                        word.append(command[i + 1])
                    i += 2
                else:
                    word.append(command[i])
                    i += 1
            if i >= n:
                raise _Unparseable("unterminated double quote")
            i += 1
        elif ch == "\\":
            if i + 1 < n and command[i + 1] != "\n":
                word = (word or []) + [command[i + 1]]
            i += 2
        else:
            if ch in "*?[{":
                glob = True
            word = (word or []) + [ch]
            i += 1
    flush()
    return out


_WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "<>", ">&"}


def _split(command: str) -> tuple[list[list[str]], list[str]]:
    """Split a command line into simple commands (lists of words), dropping redirections and their targets.
    Also returns the bodies of command substitutions. A file written by a redirection is kept as
    `[">", target]` in the command it belongs to, so it is checked after any `cd` before it."""
    commands: list[list[str]] = [[]]
    subs: list[str] = []
    redirect: str | None = None
    for kind, tok in _tokens(command):
        if kind == "sub":
            subs.append(tok)
        elif kind == "op":
            redirect = tok if "<" in tok or ">" in tok else None
            if redirect is None:
                commands.append([])
        elif redirect is not None:
            if redirect in _WRITE_REDIRECTS and not (redirect == ">&" and (tok.isdigit() or tok == "-")):
                commands.append([_REDIRECT, tok])
                commands.append([])
            redirect = None
        else:
            commands[-1].append(tok)
    return [c for c in commands if c], subs


_REDIRECT = "\0>"  # marks a redirection target in _split's output; never a real word


def _shlex_split(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError as exc:
        raise _Unparseable(str(exc)) from exc


def _skip_wrapper(name: str, words: list[str], env: list[str]) -> list[str]:
    """The command a wrapper (`sudo -u bob`, `timeout 5`, `env -i A=1`) runs, with the wrapper's options removed."""
    short, long_, before = _WRAPPERS[name]
    split: str | None = None
    i = 1
    while i < len(words):
        w = words[i]
        if w == "--":
            i += 1
            break
        if w == "-" or _ASSIGNMENT.match(w):
            if w != "-":
                env.append(w)
            i += 1
        elif w.startswith("--"):
            key, eq, val = w.partition("=")
            if key in long_ and not eq:
                val = words[i + 1] if i + 1 < len(words) else ""
                i += 1
            if key == "--split-string":
                split = val
            if (name, key) in _CHDIR_OPTIONS:
                _chdir(val)
            i += 1
        elif w.startswith("-") and len(w) > 1:
            for j, c in enumerate(w[1:], start=1):
                if c in short:
                    val = w[j + 1:]
                    if not val:
                        val = words[i + 1] if i + 1 < len(words) else ""
                        i += 1
                    if name == "env" and c == "S":
                        split = val
                    if (name, c) in _CHDIR_OPTIONS:
                        _chdir(val)
                    break
            i += 1
        else:
            break
    rest = words[i + before:]
    if split is not None:
        rest = _shlex_split(split) + rest
    if name == "watch" and rest:  # watch runs its arguments through `sh -c`
        rest = ["sh", "-c", " ".join(rest)]
    return rest


def _strip_prefix(words: list[str]) -> tuple[list[str], list[str]]:
    """Drop reserved words, environment assignments and wrappers. Returns (command words, assignments)."""
    env: list[str] = []
    while words:
        w = words[0]
        name = PurePosixPath(w).name
        if _ASSIGNMENT.match(w):
            env.append(w)
            words = words[1:]
        elif w in _RESERVED:
            words = words[1:]
        elif w in ("for", "select", "case"):
            return [], env  # `for i in ...`, `case x in`: words, not a command
        elif w == "function":
            words = words[2:]
        elif name in _WRAPPERS:
            words = _skip_wrapper(name, words, env)
        else:
            break
    return words, env


def _norm(path: str) -> str:
    p = path.strip()
    return posixpath.normpath(p) if p else p


def _canon(path: str) -> str:
    """Normalized, with the trailing dots and spaces Windows drops from each name removed."""
    p = _norm(path.replace("\\", "/"))
    return "/".join(part if part in (".", "..") else (part.rstrip(". ") or part) for part in p.split("/")) if p else p


def _chdir(target: str | None) -> None:
    """Record a directory change. Later globs are not expanded on disk; later paths are also checked under it."""
    _CWD.set(None)
    prefix = _PREFIX.get()
    if prefix is None or not target or target == "-" or any(c in target for c in "$`") or getattr(target, "glob", False):
        _PREFIX.set(None)
    elif target.startswith(("/", "~")):
        _PREFIX.set(_norm(target))
    else:
        _PREFIX.set(_norm(posixpath.join(prefix, target)))


def _in_cwd(path: str) -> list[str]:
    """`path` as written and, after a directory change, where it really is."""
    prefix = _PREFIX.get()
    if not prefix or path.startswith(("/", "~", "\\")) or re.match(r"^[A-Za-z]:", path):
        return [path]
    return [path, posixpath.join(prefix, path)]


def protected_config(path: str) -> str | None:
    """Why an agent must not change `path` (CI, PrufGate or agent-hook configuration), or None."""
    p = _canon(path).lower()
    if not p:
        return None
    # The AI adjudication verdict cache ($XDG_CACHE_HOME/prufgate/adjudicate.json): a
    # planted `real: false` entry would dismiss a finding without asking any provider.
    if ("/" + p).endswith("/prufgate/adjudicate.json"):
        return "PrufGate's AI adjudication cache"
    for ci in _CI_LOWER:
        # The path itself, something inside it, or a directory that contains it.
        if p == ci or p.startswith(ci + "/") or p.endswith("/" + ci) or ("/" + ci + "/") in p or ci.startswith(p + "/"):
            return "CI or PrufGate configuration"
    return None


def protected(path: str) -> str | None:
    """Why `path` must not be removed or moved (tests, CI or hook configuration), or None."""
    p = _canon(path)
    if not p:
        return None
    if p in (".", "..", "/", "~") or p.endswith("/.."):
        return "the whole project, tests and CI configuration included"
    parts = PurePosixPath(p).parts
    if any(part.lower() in _TEST_DIRS for part in parts):
        return "a test directory"
    if parts and _is_test_name(parts[-1]):
        return "a test file"
    return protected_config(p)


_protected = protected


def _is_test_name(name: str) -> bool:
    return bool(_TEST_FILE.match(name) or _TEST_FILE.match(name.lower()))


def _expand_braces(word: str) -> list[str]:
    out, todo = [], [word]
    while todo:
        w = todo.pop()
        m = re.search(r"\{([^{}]*,[^{}]*)\}", w)
        if m:
            todo.extend(w[:m.start()] + alt + w[m.end():] for alt in m.group(1).split(","))
        else:
            out.append(w)
        if len(out) + len(todo) > 256:
            raise _Unparseable("brace expansion too large")
    return out


def _glob_protected(path: str) -> str | None:
    """Why some file a glob such as `test*` or `.github/*` could match must not be removed, or None."""
    choices = []
    for part in _norm(path).split("/"):
        if _GLOB_CHARS.search(part):
            matches = [s for s in _GLOB_SAMPLES if fnmatch.fnmatchcase(s.lower(), part.lower())]
            choices.append(matches or [part])
        else:
            choices.append([part])
    if math.prod(len(c) for c in choices) > 4096:
        return "paths that cannot all be checked"
    for combo in itertools.product(*choices):
        why = _protected("/".join(combo))
        if why:
            return why
    return None


def _expanded_protected(pattern: str) -> str | None:
    """Expand a glob like the shell would, in the command's directory, and say why a match is protected.
    When it cannot be expanded (unknown directory, a variable or substitution in it), fall back to what it could match."""
    cwd = _CWD.get()
    if cwd is None or "$" in pattern or "`" in pattern:
        return _glob_protected(pattern)
    pat = os.path.expanduser(pattern)
    absolute = os.path.isabs(pat)
    for match in glob.glob(pat if absolute else os.path.join(glob.escape(cwd), pat)):
        why = _protected(match if absolute else os.path.relpath(match, cwd))
        if why:
            return why
    return None  # unmatched: the shell passes the word through and the command fails on it


def _check_paths(tool: str, paths: list[str]) -> str | None:
    for path in paths:
        globby = getattr(path, "glob", True)  # words from aliases or env -S were not tokenized here
        for alt in (a for b in (_expand_braces(path) if globby else [path]) for a in _in_cwd(b)):
            why = _expanded_protected(alt) if globby and _GLOB_CHARS.search(alt) else _protected(alt)
            if why:
                return f"`{tool}` on {path!r} removes or moves {why}. Fix the code instead of the check. {RUN_IT_YOURSELF}"
    return None


def _positionals(args: list[str]) -> list[str]:
    out: list[str] = []
    end_of_flags = False
    for a in args:
        if end_of_flags or a == "-" or not a.startswith("-"):
            out.append(a)
        elif a == "--":
            end_of_flags = True
    return out


def _check_mv(tool: str, args: list[str]) -> str | None:
    # Only sources matter: moving a file into tests/ is fine, moving one out is not.
    pos: list[str] = []
    target: str | None = None
    end_of_flags = False
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if end_of_flags or a == "-" or not a.startswith("-"):
            pos.append(a)
        elif a == "--":
            end_of_flags = True
        elif a.startswith("--"):
            if _matches_long(a, "--target-directory", len("--t")):
                if "=" in a:
                    target = a.split("=", 1)[1]
                else:
                    target, i = nxt, i + 1
            elif _matches_long(a, "--suffix", len("--su")) and "=" not in a:
                i += 1
        else:
            for j, c in enumerate(a[1:], start=1):
                if c in "tS":
                    val = a[j + 1:]
                    if not val:
                        val, i = nxt, i + 1
                    if c == "t":
                        target = val
                    break
        i += 1
    if target is None and len(pos) >= 2:
        for dest in (_canon(d) for d in _in_cwd(pos[-1])):
            low = dest.lower()
            if (_is_test_name(PurePosixPath(dest).name) or low in (f.lower() for f in _CI_FILES)
                    or any(low.startswith(d.lower() + "/") for d in _CI_DIRS)):
                return f"`{tool}` onto {pos[-1]!r} overwrites a test or CI file. {RUN_IT_YOURSELF}"
    return _check_paths(tool, pos if target is not None else pos[:-1])


def _matches_long(arg: str, option: str, minimum: int) -> bool:
    """git accepts unambiguous prefixes of long options (`--no-veri`)."""
    name = arg.split("=", 1)[0]
    return len(name) >= minimum and option.startswith(name)


def _check_no_verify(sub: str, args: list[str]) -> str | None:
    """`git commit/merge/pull/rebase/am --no-verify` (and `-n` where it means that) skip hooks."""
    short_n, short_val, long_val = _NO_VERIFY_SUBCOMMANDS[sub]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a.startswith("--"):
            if _matches_long(a, "--no-verify", len("--no-veri")):
                return f"`git {sub} --no-verify` skips the {sub} hooks. Fix what they report. {RUN_IT_YOURSELF}"
            if "=" not in a and a in long_val:
                i += 1
        elif a.startswith("-") and len(a) > 1:
            for j, c in enumerate(a[1:], start=1):
                if c in short_n:
                    return f"`git {sub} -{c}` (--no-verify) skips the {sub} hooks. Fix what they report. {RUN_IT_YOURSELF}"
                if c in short_val:
                    if j == len(a) - 1:
                        i += 1  # value is the next word
                    break
        i += 1
    return None


def _check_push(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a.startswith("--"):
            if _matches_long(a, "--no-verify", len("--no-veri")):
                return f"`git push --no-verify` skips the push hooks. Fix what they report. {RUN_IT_YOURSELF}"
            if _matches_long(a, "--force", len("--forc")) or _matches_long(a, "--force-with-lease", len("--force-w")):
                return f"`git push {a}` rewrites remote history. {RUN_IT_YOURSELF}"
            if "=" not in a and a in _PUSH_LONG_WITH_VALUE:
                i += 1
        elif a.startswith("-") and len(a) > 1:
            for j, c in enumerate(a[1:], start=1):
                if c == "f":
                    return f"`git push -f` rewrites remote history. {RUN_IT_YOURSELF}"
                if c in _PUSH_SHORT_WITH_VALUE:
                    if j == len(a) - 1:
                        i += 1
                    break
        elif a.startswith("+") and len(a) > 1:
            return f"`git push {a}` (a + refspec) force-pushes. {RUN_IT_YOURSELF}"
        i += 1
    return None


def _check_config_entry(key: str, value: str | None, how: str, depth: int) -> str | None:
    """A git configuration key being set: block core.hooksPath and aliases that skip checks."""
    key = key.lower()
    if key == "core.hookspath":
        return f"`{how}` sets core.hooksPath, which turns off the repository's hooks. {RUN_IT_YOURSELF}"
    if key.startswith("alias."):
        if value is None:
            return f"`{how}` defines a git alias PrufGate cannot read. {RUN_IT_YOURSELF}"
        v = value.strip()
        reason = _check(v[1:], depth + 1) if v.startswith("!") else _check_git(_shlex_split(v), depth + 1)
        if reason:
            return f"`{how}` defines the alias `{key[6:]}`, which would run something blocked: {reason}"
    return None


def _check_git_config(args: list[str], depth: int) -> str | None:
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if a in _GIT_CONFIG_WITH_VALUE else 1
            continue
        pos.append(a)
        i += 1
    if pos and pos[0] == "set":
        pos = pos[1:]
    if len(pos) < 2:  # a read, or an unset without a value pattern
        return None
    return _check_config_entry(pos[0], pos[1], f"git config {pos[0]}", depth)


def _check_env(assignments: list[str]) -> str | None:
    """Environment assignments in front of git (or exported) that turn hooks off."""
    for a in assignments:
        name, _, value = a.partition("=")
        name = name.rstrip("+")
        if name == "GIT_CONFIG_PARAMETERS" or name.startswith("GIT_CONFIG_KEY_"):
            if "core.hookspath" in value.lower() or "alias." in value.lower():
                return f"`{name}` sets core.hooksPath or a git alias through the environment. {RUN_IT_YOURSELF}"
        elif (name == "HUSKY" and value.lower() in ("0", "false")) or (name in ("HUSKY_SKIP_HOOKS", "SKIP") and value):
            return f"`{name}={value}` skips the commit hooks. Fix what they report. {RUN_IT_YOURSELF}"
    return None


def _check_git(args: list[str], depth: int) -> str | None:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "-c" or a.startswith("-c"):
            entry = nxt if a == "-c" else a[2:]
            key, eq, value = entry.partition("=")
            reason = _check_config_entry(key, value if eq else "", f"git -c {key}", depth)
            if reason:
                return reason
        elif a == "-C":
            _chdir(nxt)
        elif a == "--config-env" or a.startswith("--config-env="):
            entry = nxt if a == "--config-env" else a.split("=", 1)[1]
            reason = _check_config_entry(entry.split("=", 1)[0], None, "git --config-env", depth)
            if reason:
                return reason
        i += 2 if a in _GIT_GLOBAL_WITH_VALUE else 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]
    if _substituted(sub):  # `git $(true) commit`: the word may expand to nothing, or to any subcommand
        for cand in _NO_VERIFY_SUBCOMMANDS:
            reason = _check_no_verify(cand, rest)
            if reason:
                return reason
        return _check_push(rest) or _check_git(rest, depth)
    if sub in _NO_VERIFY_SUBCOMMANDS:
        return _check_no_verify(sub, rest)
    if sub == "push":
        return _check_push(rest)
    if sub == "config":
        return _check_git_config(rest, depth)
    if sub == "rm":
        return _check_paths("git rm", _positionals(rest))
    if sub == "mv":
        return _check_mv("git mv", rest)
    return None


_STDIN_PATH = re.compile(r"^(-|/dev/stdin|/dev/fd/\d+|/proc/[^/]+/fd/\d+)$")


def _check_shell(tool: str, args: list[str], depth: int) -> str | None:
    """`bash -c '...'` is checked; a shell reading its script from stdin cannot be, so it is refused."""
    command_mode = stdin = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--", "-"):
            stdin = stdin or a == "-"
            i += 1
            break
        if a.startswith("--"):
            if a in ("--version", "--help"):
                return None
            if a.startswith("--command="):
                return _check(a.split("=", 1)[1], depth + 1)
            command_mode = command_mode or a == "--command"
            i += 2 if a in ("--rcfile", "--init-file") else 1
        elif a[:1] in "-+" and len(a) > 1:
            if a[0] == "-":
                command_mode = command_mode or "c" in a[1:]
                stdin = stdin or "s" in a[1:]
            i += 2 if a[-1] in "oO" else 1  # -o pipefail, -O extglob
        else:
            break
    rest = args[i:]
    if command_mode:
        # The script is the first operand; an option PrufGate does not know may have taken one, so check them all.
        for word in rest:
            reason = _check(word, depth + 1)
            if reason:
                return reason
        return None
    if stdin or not rest or _STDIN_PATH.match(rest[0]):
        return (f"`{tool}` would read its commands from standard input, which PrufGate cannot inspect. "
                f"Run the commands directly, or pass them with `{tool} -c '...'`.")
    return None  # a script file: not inspected


def _substituted(word: str) -> bool:
    """The word holds a command substitution, so what it expands to (maybe nothing) is unknown."""
    return "$(" in word or "`" in word


def _check_simple(words: list[str], depth: int) -> str | None:
    words, env = _strip_prefix(words)
    while words and _substituted(words[0]) and words[0] != _REDIRECT:
        words = words[1:]  # `$(true) git commit --no-verify`: the command may be the next word
    if not words:
        return None
    tool, args = PurePosixPath(words[0]).name, words[1:]
    if tool == _REDIRECT:
        for target in _in_cwd(args[0]):
            why = protected_config(target)
            if why:
                return f"Writing to {args[0]!r} with a redirection changes {why}. {RUN_IT_YOURSELF}"
        return None
    if tool in ("cd", "pushd", "popd"):
        operands = [a for a in args if not a.startswith("-") or a == "-"]
        _chdir(None if tool == "popd" else (operands[0] if operands else "~"))
        return None
    if tool == "export":
        return _check_env(env + [a for a in args if _ASSIGNMENT.match(a)])
    if tool in _SHELLS:
        return _check_shell(tool, args, depth)
    if tool == "eval":
        return _check(" ".join(args), depth + 1)
    if tool == "git":
        return _check_env(env) or _check_git(args, depth)
    if tool in ("rm", "rmdir", "unlink", "shred"):
        return _check_paths(tool, _positionals(args))
    if tool == "mv":
        return _check_mv(tool, args)
    return None


def _check(command: str, depth: int) -> str | None:
    if depth > 8:
        return "The command nests shells too deeply to inspect."
    commands, subs = _split(command)
    for sub in subs:
        reason = _check(sub, depth + 1)
        if reason:
            return reason
    for words in commands:
        reason = _check_simple(words, depth)
        if reason:
            return reason
    return None


def check_command(command: str, cwd: str | None = None) -> str | None:
    """Return why `command` must not run, or None when it may. Unparseable commands are refused.
    Globs in rm/mv targets are expanded in `cwd` (default: the current directory)."""
    if cwd is None:
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = None
    token = _CWD.set(cwd if cwd and os.path.isdir(cwd) else None)
    prefix_token = _PREFIX.set("")
    try:
        return _check(command, 0)
    except _Unparseable as exc:
        return f"PrufGate could not parse this command ({exc}), so it was not run. Check its quoting."
    finally:
        _PREFIX.reset(prefix_token)
        _CWD.reset(token)


def run_hook(stdin_text: str) -> tuple[int, str]:
    """Claude Code PreToolUse protocol: (exit code, stderr message). 2 blocks, 0 allows."""
    try:
        payload = json.loads(stdin_text)
    except ValueError as exc:
        return 2, f"prufgate shell-guard: the hook input is not JSON ({exc}); blocking."
    if not isinstance(payload, dict):
        return 2, "prufgate shell-guard: the hook input is not a JSON object; blocking."
    if payload.get("tool_name") != "Bash":
        return 0, ""
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 2, "prufgate shell-guard: tool_input.command is missing or not a string; blocking."
    cwd = payload.get("cwd")
    reason = check_command(command, cwd if isinstance(cwd, str) and cwd else None)
    if reason:
        return 2, f"prufgate shell-guard blocked this command: {reason}"
    return 0, ""


def main() -> int:
    try:
        rc, message = run_hook(sys.stdin.read())
    except Exception as exc:  # fail closed: a crash must never allow the command
        rc, message = 2, f"prufgate shell-guard: could not check the command ({exc.__class__.__name__}); blocking."
    if message:
        print(message, file=sys.stderr)
    return rc


if __name__ == "__main__":
    from prufgate.console import utf8_output  # Windows: piped output is cp1252

    utf8_output()
    sys.exit(main())
