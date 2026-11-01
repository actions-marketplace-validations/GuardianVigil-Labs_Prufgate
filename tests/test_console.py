"""Output on a stream that cannot encode PrufGate's characters (prufgate/console.py).

Windows sends output to a pipe or file in cp1252, which has no box drawing or check
marks: printing the summary table crashed the run. PYTHONIOENCODING=cp1252 gives the
same stream on any system."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from prufgate.console import utf8_output

ROOT = Path(__file__).resolve().parent.parent


class Console(unittest.TestCase):
    def test_a_cp1252_stream_is_switched_to_utf8(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", newline="\n")
        with mock.patch.object(sys, "stdout", stream):
            utf8_output()
            print("╔═ ✔ passed")
            stream.flush()
        self.assertEqual(raw.getvalue().decode("utf-8"), "╔═ ✔ passed\n")

    def test_a_utf8_stream_and_a_stream_without_reconfigure_are_left_alone(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
        with mock.patch.object(sys, "stdout", stream), mock.patch.object(sys, "stderr", io.StringIO()):
            utf8_output()
            self.assertEqual((stream.encoding, stream.errors), ("utf-8", "strict"))

    def test_the_gate_and_the_cli_run_on_a_cp1252_stream(self):
        env = {**os.environ, "PYTHONIOENCODING": "cp1252", "NO_COLOR": "1"}
        with tempfile.TemporaryDirectory() as d:
            reports = Path(d) / "reports"
            (reports / "raw").mkdir(parents=True)
            res = subprocess.run(
                [sys.executable, str(ROOT / "prufgate" / "synthesizer" / "parse_results.py")],
                env={**env, "WORKSPACE": d, "PRUFGATE_REPORTS_DIR": str(reports)},
                capture_output=True, timeout=60, cwd=d,
            )
            # No manifest: an error verdict (2), printed, not a crash (1).
            self.assertEqual(res.returncode, 2, res.stderr.decode("utf-8", "replace"))
            self.assertNotIn(b"UnicodeEncodeError", res.stderr)
            (Path(d) / "a.py").write_text("x = 1\n")
            res = subprocess.run([sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", d],
                                 env=env, capture_output=True, timeout=120)
            self.assertEqual(res.returncode, 0, res.stderr.decode("utf-8", "replace"))
            self.assertIn("✔".encode("utf-8"), res.stdout)


if __name__ == "__main__":
    unittest.main()
