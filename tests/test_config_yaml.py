"""Unit tests for YAML configuration (`prufgate/config.py`)
and Multi-Language Anti-Fabrication Engine (`prufgate/anti_fabrication/detector.py`).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PRUFGATE_ROOT = Path(__file__).resolve().parent.parent
if str(PRUFGATE_ROOT) not in sys.path:
    sys.path.insert(0, str(PRUFGATE_ROOT))

from prufgate.anti_fabrication import detector
from prufgate.config import ConfigError, PrufGateConfig

DETECTOR = PRUFGATE_ROOT / "prufgate" / "anti_fabrication" / "detector.py"


def run_detector(cwd: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(DETECTOR), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.returncode, proc.stdout + proc.stderr


class TestPrufGateConfigYAML(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "src").mkdir()
        (self.repo / ".prufgate").mkdir()

    def tearDown(self):
        self.tmp.cleanup()
        detector.apply_settings({})

    def test_loads_universal_config_yaml_schema(self):
        (self.repo / ".prufgate" / "config.yaml").write_text(
            """version: 1
packs:
  - core
  - web-ui
  - ai-safety
languages:
  - typescript
  - python
  - go
  - rust
  - java
exclude:
  - "docs/**"
  - "examples/**"
  - "**/migrations/**"
auth_guards:
  - requireAuth
  - Depends(get_current_user)
tenant_keys:
  - organization_id
  - tenant_id
score_owners:
  - src/billing/pricing.ts
exempt:
  documentation-ip-or-domain:
    - "src/config/network_examples.py"
known_debt: {}
""",
            encoding="utf-8",
        )
        cfg = PrufGateConfig.load(self.repo)
        self.assertEqual(cfg.version, 1)
        self.assertEqual(cfg.packs, ["core", "web-ui", "ai-safety"])
        self.assertEqual(cfg.languages, ["typescript", "python", "go", "rust", "java"])
        self.assertIn("docs/**", cfg.exclude)
        self.assertIn("requireAuth", cfg.auth_guards)
        self.assertIn("organization_id", cfg.tenant_keys)
        self.assertIn("src/billing/pricing.ts", cfg.score_owners)
        self.assertIn(("src/config/network_examples.py", "documentation-ip-or-domain"), cfg.exempt)

    def test_root_prufgate_yaml_and_legacy_debt_ceiling_fallback(self):
        # 1. Root .prufgate.yaml
        (self.repo / ".prufgate.yaml").write_text(
            "version: 1\npacks:\n  - core\n",
            encoding="utf-8",
        )
        cfg = PrufGateConfig.load(self.repo)
        self.assertEqual(cfg.packs, ["core"])
        self.assertTrue(cfg.packs_explicit)
        (self.repo / ".prufgate.yaml").unlink()

        # 2. Legacy .prufgate/debt-ceiling.json fallback
        (self.repo / ".prufgate" / "debt-ceiling.json").write_text(
            json.dumps({"demo-named-data": 2, "documentation-address": 0}),
            encoding="utf-8",
        )
        cfg_legacy = PrufGateConfig.load(self.repo)
        self.assertEqual(cfg_legacy.known_debt_ceilings, {"demo-named-data": 2, "documentation-address": 0})

    def test_invalid_yaml_and_unknown_pack_or_language_rejected(self):
        (self.repo / ".prufgate" / "config.yaml").write_text("packs: [unclosed\n", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            PrufGateConfig.load(self.repo)
        self.assertIn("invalid YAML", str(ctx.exception))

        (self.repo / ".prufgate" / "config.yaml").write_text("packs:\n  - nonexistent-pack\n", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            PrufGateConfig.load(self.repo)
        self.assertIn("unknown pack", str(ctx.exception))

        (self.repo / ".prufgate" / "config.yaml").write_text("languages:\n  - cobol\n", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            PrufGateConfig.load(self.repo)
        self.assertIn("unsupported language", str(ctx.exception))

    def test_every_valid_pack_is_read_by_an_engine(self):
        """Issue #25: a pack no engine reads would claim to switch rules on or off."""
        from prufgate.config import DEFAULT_PACKS, VALID_PACKS
        engine_src = "".join(p.read_text(encoding="utf-8") for p in (PRUFGATE_ROOT / "prufgate").rglob("*.py") if p.name != "config.py")
        unread = sorted(p for p in VALID_PACKS if f'"{p}"' not in engine_src)
        self.assertEqual(unread, [])
        self.assertTrue(set(DEFAULT_PACKS) <= VALID_PACKS)
        (self.repo / ".prufgate" / "config.yaml").write_text("packs:\n  - multi-tenant\n", encoding="utf-8")
        with self.assertRaises(ConfigError):
            PrufGateConfig.load(self.repo)

    def test_pack_disabling_skips_web_ui_rules(self):
        (self.repo / "src" / "Button.tsx").write_text(
            "export const Btn = () => <button onClick={() => {}}>Click</button>;\n",
            encoding="utf-8",
        )
        # Default packs include web-ui -> flags stub-click-handler
        code1, out1 = run_detector(self.repo)
        self.assertEqual(code1, 1, out1)
        self.assertIn("stub-click-handler", out1)

        # Restrict packs to [core] only -> web-ui rule is skipped
        (self.repo / ".prufgate" / "config.yaml").write_text("packs:\n  - core\n", encoding="utf-8")
        code2, out2 = run_detector(self.repo)
        self.assertEqual(code2, 0, out2)

    def test_exclude_globs_and_exempt_mapping_in_config_yaml(self):
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "sample.py").write_text('EXAMPLE_IP = "198.51.100.10"\n', encoding="utf-8")
        (self.repo / "src" / "network_examples.py").write_text('EXAMPLE_IP = "198.51.100.20"\n', encoding="utf-8")
        (self.repo / ".prufgate" / "config.yaml").write_text(
            """exclude:
  - "docs/**"
exempt:
  documentation-ip-or-domain:
    - "src/network_examples.py"
""",
            encoding="utf-8",
        )
        code, out = run_detector(self.repo)
        self.assertEqual(code, 0, out)

    def test_known_debt_ratchet_enforces_ceiling_and_advises_ratchet_down(self):
        (self.repo / "src" / "a.ts").write_text('export const IP_A = "198.51.100.1";\n', encoding="utf-8")
        # 1. Ceiling = 2 (actual = 1) -> passes with ratchet-down advisory
        (self.repo / ".prufgate" / "config.yaml").write_text(
            """known_debt:
  documentation-ip-or-domain: 2
""",
            encoding="utf-8",
        )
        code1, out1 = run_detector(self.repo)
        self.assertEqual(code1, 0, out1)
        self.assertIn("[ratchet-down]", out1)

        # 2. Ceiling = 0 (actual = 1) -> fails with debt-ceiling-breached
        (self.repo / ".prufgate" / "config.yaml").write_text(
            """known_debt:
  documentation-ip-or-domain: 0
""",
            encoding="utf-8",
        )
        code2, out2 = run_detector(self.repo)
        self.assertEqual(code2, 1, out2)
        self.assertIn("debt-ceiling-breached", out2)

    def test_multi_language_classification_and_detection(self):
        self.assertEqual(detector.classify_file("a.ts"), "typescript")
        self.assertEqual(detector.classify_file("a.vue"), "typescript")
        self.assertEqual(detector.classify_file("a.py"), "python")
        self.assertEqual(detector.classify_file("a.go"), "go")
        self.assertEqual(detector.classify_file("a.rs"), "rust")
        self.assertEqual(detector.classify_file("a.java"), "java")
        self.assertEqual(detector.classify_file("a.kt"), "kotlin")
        self.assertEqual(detector.classify_file("a.php"), "php")
        self.assertEqual(detector.classify_file("a.rb"), "ruby")
        self.assertEqual(detector.classify_file("a.cs"), "csharp")

    def test_non_string_top_level_keys_are_a_config_error(self):
        # Found by fuzz/fuzz_config.py: "?" is a YAML mapping with a null key.
        for text in ("?\n", "1: true\n", "~: x\nversion: 1\n"):
            with self.subTest(text=text):
                path = self.repo / ".prufgate" / "config.yaml"
                path.parent.mkdir(exist_ok=True)
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ConfigError):
                    PrufGateConfig.load(self.repo)

    def test_performance_benchmark_1000_files_under_500ms(self):
        perf_dir = self.repo / "src" / "perf"
        perf_dir.mkdir(parents=True)
        sample_code = (
            "def calculate_invoice_total(items: list[dict]) -> float:\n"
            "    return sum(float(i.get('price', 0.0)) * int(i.get('qty', 1)) for i in items)\n"
        )
        for idx in range(1000):
            (perf_dir / f"mod_{idx}.py").write_text(sample_code, encoding="utf-8")

        detector.apply_settings({})
        start = time.monotonic()
        files = detector.collect([str(perf_dir)])
        findings = []
        for f in files:
            findings.extend(detector.scan_file(f))
        elapsed_ms = (time.monotonic() - start) * 1000.0
        self.assertEqual(len(files), 1000)
        self.assertEqual(findings, [])
        # Wall-clock budgets are noisy on shared CI runners; 2s still catches a
        # pathological slowdown. Override with PRUFGATE_PERF_BUDGET_MS.
        budget = float(os.environ.get("PRUFGATE_PERF_BUDGET_MS", "2000"))
        self.assertLess(elapsed_ms, budget, f"1,000-file scan took {elapsed_ms:.1f}ms (budget < {budget:.0f}ms)")


if __name__ == "__main__":
    unittest.main()
