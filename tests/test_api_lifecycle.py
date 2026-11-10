"""API lifecycle regressions using local subprocesses, sockets and invented artifacts."""
from __future__ import annotations

import contextlib
import datetime
import os
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from prufgate.api import server
from prufgate.safe_fs import safe_remove_tree


class ProcessLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = patch.dict(server.SCANS, {"fixture": {"scan_id": "fixture", "status": "running"}}, clear=True)
        self.store.start()
        self.processes = patch.dict(server.SCAN_PROCESSES, {}, clear=True)
        self.processes.start()

    def tearDown(self):
        server._terminate_scan_process("fixture")
        self.processes.stop()
        self.store.stop()
        self.tmp.cleanup()

    def test_timeout_kills_and_reaps_a_process_that_ignores_termination(self):
        code = "import time; time.sleep(60)"
        if os.name == "posix":
            code = "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); " + code
        real_popen = subprocess.Popen
        launched = []
        def launch(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            launched.append(proc)
            return proc
        with patch.object(server, "SCAN_TIMEOUT", 0.15), patch.object(server, "PROCESS_GRACE_SECONDS", 0.1), \
                patch.object(server.subprocess, "Popen", side_effect=launch):
            result = server.run_scan_process("fixture", [sys.executable, "-c", code], self.root, dict(os.environ))
        self.assertEqual(result[0], 124)
        # The registry is held until wait() and pipe cleanup have completed.
        self.assertNotIn("fixture", server.SCAN_PROCESSES)
        self.assertIn("timed out", result[2])
        if os.name == "posix":
            # waitpid finds no child left to reap, including the SIGTERM-resistant leader.
            with self.assertRaises(ChildProcessError):
                os.waitpid(launched[0].pid, os.WNOHANG)
        self.assertIsNotNone(launched[0].returncode)
        self.assertTrue(launched[0].stdout.closed)

    def test_cancel_before_start_never_launches_a_process(self):
        server.SCANS.clear()
        with patch.object(server.subprocess, "Popen") as launch:
            code, _, _ = server.run_scan_process("fixture", [sys.executable, "-c", "pass"], self.root, dict(os.environ))
        self.assertEqual(code, 130)
        launch.assert_not_called()

    def test_cancel_during_start_waits_for_registration_and_stops_the_process(self):
        entering, release = threading.Event(), threading.Event()
        cancelled = threading.Event()
        real_popen = subprocess.Popen
        launched, results = [], []

        def popen(*args, **kwargs):
            entering.set()
            self.assertTrue(release.wait(3))
            proc = real_popen(*args, **kwargs)
            launched.append(proc)
            return proc

        def cancel():
            with server.SCANS_LOCK:
                server.SCANS.pop("fixture", None)
            server._terminate_scan_process("fixture")
            cancelled.set()

        with patch.object(server.subprocess, "Popen", side_effect=popen):
            worker = threading.Thread(target=lambda: results.append(server.run_scan_process(
                "fixture", [sys.executable, "-c", "import time; time.sleep(60)"], self.root, dict(os.environ))))
            worker.start()
            self.assertTrue(entering.wait(3))
            canceller = threading.Thread(target=cancel)
            canceller.start()
            self.assertFalse(cancelled.wait(0.05))
            release.set()
            worker.join(5)
            canceller.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(canceller.is_alive())
        self.assertIsNotNone(launched[0].returncode)
        self.assertNotEqual(results[0][0], 0)
        self.assertNotIn("fixture", server.SCAN_PROCESSES)


class Retention(unittest.TestCase):
    def test_finished_history_and_files_are_evicted_but_running_scans_stay(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(server.SCANS, {}, clear=True), \
                patch.dict(server.SCAN_PROCESSES, {}, clear=True), patch.object(server, "MAX_SCAN_HISTORY", 1):
            root = Path(tmp)
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for sid in ("old", "new", "active"):
                path = root / "reports" / "scans" / sid
                path.mkdir(parents=True)
                (path / "report.json").write_text("{}")
                server.SCANS[sid] = {"scan_id": sid, "workspace": tmp, "status": "running" if sid == "active" else "completed", "completed_at": stamp}
            server.prune_scan_history(root)
            self.assertEqual(set(server.SCANS), {"new", "active"})
            self.assertFalse((root / "reports" / "scans" / "old").exists())
            self.assertTrue((root / "reports" / "scans" / "active").exists())

    def test_expired_orphaned_artifacts_are_reclaimed_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(server.SCANS, {}, clear=True), \
                patch.dict(server.SCAN_PROCESSES, {}, clear=True), patch.object(server, "REPORT_RETENTION_SECONDS", 1):
            root = Path(tmp)
            expired = root / "reports" / "scans" / str(uuid.uuid4())
            expired.mkdir(parents=True)
            os.utime(expired, (0, 0))
            server.prune_scan_history(root)
            self.assertFalse(expired.exists())

    def test_artifact_cleanup_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, outside = root / "artifact", root / "outside"
            artifact.mkdir()
            outside.mkdir()
            victim = outside / "keep.txt"
            victim.write_text("keep")
            try:
                (artifact / "link").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                # Exercise the regular cleanup path on systems without symlink privileges too.
                self.assertIsInstance(exc, OSError)
            safe_remove_tree(artifact)
            self.assertEqual(victim.read_text(), "keep")
            self.assertFalse(artifact.exists())

    def test_cancelled_worker_does_not_publish_and_removes_its_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(server.SCANS, {"fixture": {"status": "queued"}}, clear=True):
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            shared = reports / "prufgate.sarif"
            shared.write_text("previous report")

            def run(*args):
                server.SCANS.clear()
                return 0, "", ""

            with patch.object(server, "run_scan_process", side_effect=run):
                server.execute_scan_worker("fixture", "full", tmp, None)
            self.assertEqual(shared.read_text(), "previous report")
            self.assertFalse((reports / "scans" / "fixture").exists())


def seconds_until_closed(conn: socket.socket, limit: float) -> float | None:
    """Send one byte every 50 ms; the seconds until the server closed the connection, or None."""
    start = time.monotonic()
    while time.monotonic() - start < limit:
        try:
            conn.sendall(b"a")
            if select.select([conn], [], [], 0.05)[0] and not conn.recv(4096):
                return time.monotonic() - start
        except (BrokenPipeError, ConnectionResetError):
            return time.monotonic() - start
    return None


class HttpLimits(unittest.TestCase):
    @contextlib.contextmanager
    def serving(self):
        accepted = threading.Event()

        class Handler(server.PrufGateAPIHandler):
            def handle(self):
                accepted.set()
                super().handle()

            def log_message(self, *args):
                pass

        with patch.object(server, "HTTP_TIMEOUT", 0.3), patch.object(server, "MAX_CONNECTIONS", 1):
            httpd = server.PrufGateHTTPServer(("127.0.0.1", 0), Handler)
            worker = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                yield httpd.server_address, accepted
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(3)

    def test_overload_gets_503_and_deadline_releases_the_connection_slot(self):
        with self.serving() as (address, accepted), socket.create_connection(address, timeout=1) as first:
            first.sendall(b"GET /api/v1/health HTTP/1.0\r\nX-Slow: ")
            self.assertTrue(accepted.wait(1))
            with socket.create_connection(address, timeout=1) as second:
                second.sendall(b"GET /api/v1/health HTTP/1.0\r\n\r\n")
                self.assertIn(b"503", second.recv(1024))
            # Even an unfinished header expires and frees the only worker slot.
            closed_at = time.monotonic()
            try:
                while first.recv(4096):
                    pass
            except ConnectionResetError:
                self.assertLess(time.monotonic() - closed_at, 1)
            end = time.monotonic() + 1
            while time.monotonic() < end:
                with socket.create_connection(address, timeout=1) as retry:
                    retry.sendall(b"GET /api/v1/health HTTP/1.0\r\n\r\n")
                    if b"200" in retry.recv(4096):
                        break
                time.sleep(0.01)
            else:
                self.fail("deadline did not release the connection slot")

    def test_slow_drip_cannot_extend_the_total_deadline(self):
        # One byte every 50 ms keeps resetting the 0.3 s per-read socket timeout:
        # only the total deadline can close this connection.
        with self.serving() as (address, accepted), socket.create_connection(address, timeout=1) as conn:
            conn.sendall(b"GET /api/v1/health HTTP/1.0\r\nX-Slow: ")
            self.assertTrue(accepted.wait(1))
            closed_after = seconds_until_closed(conn, limit=3)
            self.assertIsNotNone(closed_after, "a slow drip kept the connection open past the deadline")
            self.assertLess(closed_after, 1.5)


class CacheFallback(unittest.TestCase):
    def test_existing_read_only_cache_falls_back_and_cleans_both_private_directories(self):
        from prufgate.review import ai_adapter
        real = tempfile.TemporaryDirectory
        with tempfile.TemporaryDirectory() as tmp:
            cache = str(Path(tmp) / "cache")
            def temporary(*args, **kwargs):
                if kwargs.get("dir") == cache:
                    raise PermissionError("fixture cache is read only")
                return real(*args, **kwargs)
            with patch.object(ai_adapter, "_private_tmp_parent", return_value=cache), \
                    patch.object(ai_adapter.tempfile, "TemporaryDirectory", side_effect=temporary):
                with ai_adapter._private_cli_directory() as cwd:
                    directory = Path(cwd)
                    parent = directory.parent
                    self.assertTrue(directory.is_dir())
                    self.assertNotEqual(parent, Path(tempfile.gettempdir()))
            self.assertFalse(directory.exists())
            self.assertFalse(parent.exists())


if __name__ == "__main__":
    unittest.main()
