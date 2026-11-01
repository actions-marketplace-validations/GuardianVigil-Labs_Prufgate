"""`prufgate bench`: case parsing, TP/FP/FN accounting, output shape and floors."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from prufgate import bench

ROOT = Path(__file__).resolve().parent.parent

LABEL = "-- label.yaml --\ncategory: {cat}\ndescription: {desc}\nmust_fire: [{must}]\nmust_not_fire: []\n"
TEST_BASE = "-- base/shop/calc.py --\ndef add(a, b):\n    return a + b\n"
TAUTOLOGY = (
    "-- head/shop/calc.py --\ndef add(a, b):\n    return a + b\n"
    "-- head/tests/test_calc.py --\nfrom shop.calc import add\n\n\ndef test_add():\n    add(1, 2)\n    assert True\n"
)
REFACTOR = "-- head/shop/calc.py --\ndef add(left, right):\n    return left + right\n"

# One true positive, one false positive (a clean label on a hollow test), one false negative.
CORPUS = {
    "tp.txt": LABEL.format(cat="hollow-test", desc="tautology", must="tautological-assertion") + TEST_BASE + TAUTOLOGY,
    "fp.txt": LABEL.format(cat="clean", desc="labelled clean", must="") + TEST_BASE + TAUTOLOGY,
    "fn.txt": LABEL.format(cat="fabrication", desc="nothing to find", must="canned-error-fallback") + TEST_BASE + REFACTOR,
}


def _corpus(tmp: str, cases: dict[str, str]) -> Path:
    d = Path(tmp)
    for name, text in cases.items():
        (d / name).write_text(text, encoding="utf-8")
    return d


def _main(cases: Path, fmt: str = "json", **floors: float) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        rc = bench.main(str(cases), fmt, None, floors.get("min_precision"), floors.get("min_recall"))
    return rc, out.getvalue()


class BenchAccounting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = _corpus(cls.tmp.name, CORPUS)
        cls.rc, cls.out = _main(cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_tp_fp_fn(self):
        self.assertEqual(self.rc, 0)
        report = json.loads(self.out)
        self.assertEqual(report["overall"], {"tp": 1, "fp": 1, "fn": 1, "precision": 0.5, "recall": 0.5})
        self.assertEqual(report["rules"]["tautological-assertion"]["fp"], 1)
        self.assertEqual(report["rules"]["canned-error-fallback"]["fn"], 1)
        self.assertEqual(
            sorted((m["case"], m["kind"]) for m in report["misses"]), [("fn", "false-negative"), ("fp", "false-positive")]
        )

    def test_json_shape(self):
        report = json.loads(self.out)
        self.assertEqual(set(report), {"cases", "categories", "overall", "rules", "misses"})
        self.assertEqual(report["cases"], 3)
        self.assertEqual(report["categories"], {"clean": 1, "fabrication": 1, "hollow-test": 1})
        for counts in report["rules"].values():
            self.assertEqual(set(counts), {"tp", "fp", "fn", "precision", "recall"})
        self.assertEqual(set(report["misses"][0]), {"case", "category", "rule", "kind"})

    def test_thresholds(self):
        self.assertEqual(_main(self.dir, min_precision=0.5, min_recall=0.5)[0], 0)
        self.assertEqual(_main(self.dir, min_precision=0.6)[0], 1)
        self.assertEqual(_main(self.dir, min_recall=0.9)[0], 1)

    def test_rule_filter(self):
        report = bench.score([{"id": "a", "category": "clean", "must_fire": ["x"], "fired": ["y"]}], only_rule="x")
        self.assertEqual(report["overall"], {"tp": 0, "fp": 0, "fn": 1, "precision": None, "recall": 0.0})

    def test_aliases_are_one_rule(self):
        res = [{"id": "a", "category": "hollow-test", "must_fire": ["zero-assertion-test"], "fired": ["assertion-free-test"]}]
        self.assertEqual(bench.score(res)["rules"], {"zero-assertion-test": {"tp": 1, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0}})


class BenchRefusesBadInput(unittest.TestCase):
    def test_bad_cases_exit_2(self):
        bad = {
            "no-label.txt": TEST_BASE + REFACTOR,
            "bad-category.txt": LABEL.format(cat="other", desc="x", must="") + TEST_BASE + REFACTOR,
            "escape.txt": LABEL.format(cat="clean", desc="x", must="") + "-- head/../evil.py --\nx = 1\n",
            "identical.txt": LABEL.format(cat="clean", desc="x", must="") + TEST_BASE + TEST_BASE.replace("base/", "head/"),
        }
        for name, text in bad.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(_main(_corpus(tmp, {name: text}))[0], 2)

    def test_git_dir_anywhere_is_refused(self):
        for rel in ("sub/.git/config", ".git/config", "a/b/.GIT/HEAD", "sub/.git", ".Git"):
            text = LABEL.format(cat="clean", desc="x", must="") + TEST_BASE + f"-- head/{rel} --\n[core]\n"
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(_main(_corpus(tmp, {"git.txt": text}))[0], 2)

    def test_nested_repo_config_never_runs(self):
        # Past the parser (a hand-built case), the scan's own git settings still
        # keep a nested repository's fsmonitor command from running.
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "ran"
            nested = {
                "sub/.git/HEAD": "ref: refs/heads/main",
                "sub/.git/refs/heads/main": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                "sub/.git/objects/keep": "",
                "sub/.git/config": f'[core]\n\trepositoryformatversion = 0\n\tfsmonitor = "touch {marker}; false"',
                "sub/x.py": "y = 1",
            }
            case = {"id": "nested", "category": "clean", "description": "x", "must_fire": [], "must_not_fire": [],
                    "base": {"a.py": "x = 1\n"}, "head": {"a.py": "x = 2\n", **nested}}
            before = {k: bench.os.environ.get(k) for k in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0")}
            try:
                bench.run([case])
            except subprocess.CalledProcessError:
                # Windows git refuses to add this hand-built nested repository; what this test
                # guards still holds: the nested fsmonitor command never ran.
                if sys.platform != "win32":
                    raise
            self.assertFalse(marker.exists())
            self.assertEqual(before, {k: bench.os.environ.get(k) for k in before})

    def test_missing_corpus_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_main(Path(tmp) / "absent")[0], 2)
            self.assertEqual(_main(Path(tmp))[0], 2)  # no cases


class BenchCorpusFloor(unittest.TestCase):
    """The shipped corpus at the numbers in docs/BENCHMARK.md: a drop fails the build."""

    def test_floor(self):
        # A floor, not a target: new hard cases may land below 1.0 without breaking the build.
        rc, out = _main(ROOT / "bench" / "cases", min_precision=0.95, min_recall=0.95)
        self.assertEqual(rc, 0, out[:2000])
        self.assertGreaterEqual(json.loads(out)["cases"], 60)


if __name__ == "__main__":
    unittest.main()
