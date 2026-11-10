"""Running commands from the repository under review: shared by `prufgate verify --differential` and
`prufgate verify --mutation`, the only two commands that execute repository code.

Everything here exists to keep that contained: the operator's opt-in, a temporary detached worktree of
the committed HEAD (the user's checkout is never touched), a reduced environment, git with repository
hooks and fsmonitor off, a timeout that kills the whole process group, a Linux subreaper so no detached
descendant survives (elsewhere, a run marker in the environment of everything the command starts, found
with `ps` at the end: a process that clears its own environment can escape it), removal of the worktree on SIGTERM and SIGINT, and pruning of worktrees a killed
(SIGKILL) earlier run left behind. Nothing in `check`, the batteries, the MCP server, the API or the
hooks may import this module.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from prufgate.process import git_command

OPT_IN_ENV = "PRUFGATE_ALLOW_RUN_TESTS"
# The command gets these variables and nothing else unless `--pass-env` names more:
# no tokens, keys or cloud credentials from the operator's environment.
BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "SYSTEMROOT")
# Every temporary directory a run creates starts with this; the worktree inside it is `head`.
TMP_ROOT_PREFIX = "prufgate-"
GIT_SAFE = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")


class RunError(Exception):
    """The run could not complete: exit 2, never a pass."""


def supported() -> bool:
    """Containment needs POSIX process groups (`start_new_session`, `os.killpg`): not on Windows."""
    return hasattr(os, "killpg")


def opted_in(flag: bool) -> bool:
    return flag or os.environ.get(OPT_IN_ENV) == "1"


def env(pass_env: list[str], junit: Path | None = None) -> dict[str, str]:
    out = {k: os.environ[k] for k in (*BASE_ENV, *pass_env) if k in os.environ}
    if junit is not None:
        out["CI"] = "1"
        out["PRUFGATE_JUNIT_XML"] = str(junit)
    return out


def git(cwd: Path, *args: str, binary: bool = False) -> Any:
    """git with repository hooks and fsmonitor off, and without the operator's tokens in its environment."""
    try:
        res = subprocess.run(
            git_command(*args), cwd=cwd, capture_output=True, text=not binary, check=True, env=env([]),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or exc
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        raise RunError(f"git {args[0]} failed: {str(detail).strip()}") from None
    return res.stdout


def _git_quiet(cwd: Path, *args: str) -> None:
    subprocess.run(git_command(*args), cwd=cwd, capture_output=True, env=env([]))


# Linux: PR_SET_CHILD_SUBREAPER makes every orphaned descendant of the command (a
# daemon that double-forked or called setsid) our child, so none survives a run.
_PR_SET_CHILD_SUBREAPER = 36


def _subreaper(on: bool) -> None:
    if sys.platform.startswith("linux"):
        try:
            ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_CHILD_SUBREAPER, int(on), 0, 0, 0)
        except (OSError, AttributeError):
            pass


def _children(pid: int) -> set[int]:
    out: set[int] = set()
    try:
        for task in os.listdir(f"/proc/{pid}/task"):
            with open(f"/proc/{pid}/task/{task}/children", encoding="ascii") as fh:
                out.update(int(c) for c in fh.read().split())
    except (OSError, ValueError):
        # Some procfs implementations expose status/PPid but omit task/children.
        # Subreaper adoption still works there; an empty result would leak detached
        # descendants. Fall back to the kernel's parent IDs, never process names.
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdecimal():
                    continue
                try:
                    with open(f"/proc/{entry}/status", encoding="ascii") as fh:
                        parent = next((line.split()[1] for line in fh if line.startswith("PPid:")), None)
                    if parent == str(pid):
                        out.add(int(entry))
                except (OSError, ValueError, IndexError):
                    continue  # A process may exit while procfs is being read.
        except OSError:
            pass
    return out


def _kill_leftovers(keep: set[int]) -> None:
    """SIGKILL every descendant of this process except `keep` (children that predate the run), and reap them."""
    for _ in range(100):  # ponytail: bounded rounds; a fork bomb outrunning 100 rounds of SIGKILL needs cgroups
        found, todo = set(), list(_children(os.getpid()) - keep)
        while todo:
            pid = todo.pop()
            if pid not in found:
                found.add(pid)
                todo.extend(_children(pid))
        if not found:
            return
        for pid in found:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for pid in found:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass  # not our child (yet): reparented to us on a later round


# Outside Linux there is no subreaper and no /proc: every process the command starts inherits this
# variable, so one that detached (setsid, double fork) is still found with `ps -E` and killed.
RUN_MARK_ENV = "PRUFGATE_RUN_MARK"


def _marked(mark: str) -> set[int]:
    """Processes whose environment carries `RUN_MARK_ENV=mark` (BSD/macOS `ps -E`; own user's only)."""
    try:
        out = subprocess.run(["ps", "-A", "-E", "-ww", "-o", "pid=,command="], capture_output=True,
                             text=True, errors="replace", timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    needle = f"{RUN_MARK_ENV}={mark}"
    found = set()
    for line in out.splitlines():
        pid, _, rest = line.strip().partition(" ")
        if needle in rest.split() and pid.isdigit() and int(pid) != os.getpid():
            found.add(int(pid))
    return found


def _kill_marked(mark: str) -> None:
    for _ in range(20):  # bounded rounds, like _kill_leftovers
        found = _marked(mark)
        if not found:
            return
        for pid in found:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for pid in found:
            try:
                os.waitpid(pid, os.WNOHANG)
            except OSError:
                pass  # not our child: launchd or init reaps it


def run_command(cmd: list[str], cwd: Path, environ: dict[str, str], timeout: int, log: Path) -> tuple[int, str]:
    """Run `cmd` in its own process group, output to a file (a detached child holding a pipe cannot
    stall us). The whole group dies on timeout, and nothing it started outlives the run.
    Returns (exit code, the last 4000 bytes of output)."""
    if not supported():
        raise RunError("running repository code is not available on this system (no process groups)")
    keep = _children(os.getpid())
    mark = None if sys.platform.startswith("linux") else uuid.uuid4().hex
    if mark:
        environ = {**environ, RUN_MARK_ENV: mark}
    with open(log, "wb") as out:
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, env=environ, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            raise RunError(f"could not start {cmd[0]!r}: {exc}") from None
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RunError(f"{Path(cmd[0]).name} did not finish within {timeout}s") from None
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            if proc.returncode is None:
                proc.kill()
                proc.wait()
            _kill_leftovers(keep)
            if mark:
                _kill_marked(mark)
    with open(log, "rb") as fh:
        fh.seek(max(0, log.stat().st_size - 4000))
        return rc, fh.read().decode("utf-8", "replace")


def _owner_alive(tmp: Path) -> bool:
    try:
        os.kill(int((tmp / "owner.pid").read_text()), 0)
    except (ProcessLookupError, FileNotFoundError):
        return False  # a run writes owner.pid before it adds the worktree: none means an older, killed run
    except (OSError, ValueError):
        return True  # unreadable or someone else's process: leave it
    return True


def _prune_stale(root: Path) -> None:
    """Remove the worktrees of earlier runs that were killed (SIGKILL) before they could clean up."""
    tmpdir = Path(tempfile.gettempdir()).resolve()
    for line in git(root, "worktree", "list", "--porcelain").splitlines():
        if not line.startswith("worktree "):
            continue
        wt = Path(line[len("worktree "):])
        tmp = wt.parent
        if (wt.name == "head" and tmp.name.startswith(TMP_ROOT_PREFIX) and tmp.parent.resolve() == tmpdir
                and not _owner_alive(tmp)):
            _git_quiet(root, "worktree", "remove", "--force", str(wt))
            shutil.rmtree(tmp, ignore_errors=True)
    _git_quiet(root, "worktree", "prune")


def _exit_on_signal(signum: int, _frame: Any) -> None:
    raise SystemExit(128 + signum)  # unwinds through every `finally`, so the worktree is removed


@contextmanager
def head_worktree(root: Path, prefix: str) -> Iterator[Path]:
    """A temporary directory holding `head`, a detached worktree of the committed HEAD. The directory and
    the worktree are always removed, also on an error, a timeout, SIGTERM or SIGINT."""
    if not prefix.startswith(TMP_ROOT_PREFIX):
        raise ValueError(f"prefix must start with {TMP_ROOT_PREFIX!r}")
    handlers = {}
    if threading.current_thread() is threading.main_thread():
        handlers = {sig: signal.signal(sig, _exit_on_signal) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        _prune_stale(root)
        tmp = Path(tempfile.mkdtemp(prefix=prefix))
        wt = tmp / "head"
        _subreaper(True)
        try:
            (tmp / "owner.pid").write_text(str(os.getpid()))
            git(root, "worktree", "add", "--detach", "--quiet", str(wt), "HEAD")
            yield tmp
        finally:
            _subreaper(False)
            _git_quiet(root, "worktree", "remove", "--force", str(wt))
            shutil.rmtree(tmp, ignore_errors=True)
            _git_quiet(root, "worktree", "prune")
    finally:
        for sig, old in handlers.items():
            signal.signal(sig, old)
