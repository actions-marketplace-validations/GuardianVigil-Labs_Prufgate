"""Unit tests for Engine 2: Anti-Reward-Hacking & Test Integrity (`prufgate/anti_reward_hacking/test_integrity.py`)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from prufgate.anti_reward_hacking.test_integrity import (
    is_test_file,
    main,
    run_self_check,
    scan_diff_for_reward_hacking,
    scan_test_file,
)
from prufgate.config import PrufGateConfig
from prufgate.synthesizer.parse_results import parse_raw_results


class TestAntiRewardHackingEngine(unittest.TestCase):
    """Verify multi-language test integrity and cross-diff EvilGenie detection."""

    def test_builtin_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_is_test_file_classification(self) -> None:
        self.assertTrue(is_test_file("src/auth/login.test.ts"))
        self.assertTrue(is_test_file("src/auth/login.spec.tsx"))
        self.assertTrue(is_test_file("tests/test_billing.py"))
        self.assertTrue(is_test_file("pkg/api/handler_test.go"))
        self.assertTrue(is_test_file("src/test/java/UserServiceTest.java"))
        self.assertTrue(is_test_file("src/lib.rs", "#[cfg(test)]\nmod tests { #[test] fn it_works() {} }"))
        self.assertFalse(is_test_file("tests/conftest.py"))
        self.assertFalse(is_test_file("tests/__init__.py"))
        self.assertFalse(is_test_file("src/billing/service.ts"))

    def test_zero_assertion_detection_across_languages(self) -> None:
        # 1. TypeScript zero-assertion vs valid expect().rejects
        ts_bad = """
        it('processes refund without asserting', async () => {
            const client = new PaymentClient();
            await client.refund('ch_123');
        });
        """
        findings = scan_test_file(Path("src/payment.test.ts"), ts_bad)
        self.assertEqual([f.rule for f in findings], ["zero-assertion-test"])

        ts_good = """
        it('rejects duplicate refund', async () => {
            const client = new PaymentClient();
            await expect(client.refund('ch_123')).rejects.toThrow('Already refunded');
        });
        """
        self.assertEqual(scan_test_file(Path("src/payment.test.ts"), ts_good), [])

        # 2. Python zero-assertion vs valid pytest.raises
        py_bad = "\ndef test_sync_inventory():\n    svc = InventoryService()\n    svc.sync()\n"
        findings_py = scan_test_file(Path("tests/test_inventory.py"), py_bad)
        self.assertEqual([f.rule for f in findings_py], ["zero-assertion-test"])

        py_good = (
            "import pytest\n"
            "def test_sync_inventory_error():\n"
            "    svc = InventoryService()\n"
            "    with pytest.raises(RuntimeError):\n"
            "        svc.sync_invalid()\n"
        )
        self.assertEqual(scan_test_file(Path("tests/test_inventory.py"), py_good), [])

        # 3. Go zero-assertion vs t.Fatalf
        go_bad = (
            "package cache\nimport \"testing\"\n"
            "func TestEvict(t *testing.T) {\n    c := NewCache()\n    c.Evict(\"k\")\n}\n"
        )
        self.assertEqual([f.rule for f in scan_test_file(Path("cache_test.go"), go_bad)], ["zero-assertion-test"])

        # 4. Rust zero-assertion vs #[should_panic]
        rs_bad = "#[test]\nfn test_hash() {\n    let _ = compute_hash(b\"abc\");\n}\n"
        self.assertEqual([f.rule for f in scan_test_file(Path("tests/hash_test.rs"), rs_bad)], ["zero-assertion-test"])

        rs_panic = "#[test]\n#[should_panic]\nfn test_hash_empty() {\n    compute_hash(b\"\");\n}\n"
        self.assertEqual(scan_test_file(Path("tests/hash_test.rs"), rs_panic), [])

        # 5. Java zero-assertion
        java_bad = (
            "class AuthTest {\n"
            "    @Test\n"
            "    void loginUser() {\n"
            "        auth.login(\"u\", \"p\");\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual([f.rule for f in scan_test_file(Path("src/test/AuthTest.java"), java_bad)], ["zero-assertion-test"])

    def test_tautological_assertions(self) -> None:
        ts_taut = """
        it('checks math', () => {
            const total = computeTotal();
            expect(total).toBe(total);
        });
        """
        findings = scan_test_file(Path("src/math.test.ts"), ts_taut)
        self.assertEqual([f.rule for f in findings], ["tautological-assertion"])

        # Single superficial existence check is flagged
        py_superficial = "def test_get_order():\n    order = fetch_order(1)\n    assert order is not None\n"
        findings_sup = scan_test_file(Path("tests/test_order.py"), py_superficial)
        self.assertEqual([f.rule for f in findings_sup], ["tautological-assertion"])

        # Existence check paired with concrete field assertion is clean
        py_thorough = (
            "def test_get_order():\n"
            "    order = fetch_order(1)\n"
            "    assert order is not None\n"
            "    assert order.total == 99.50\n"
        )
        self.assertEqual(scan_test_file(Path("tests/test_order.py"), py_thorough), [])

    def test_self_mocked_unit_under_test(self) -> None:
        # 1. Mocking the subject module in billing.test.ts
        ts_self_mock = """
        import { createInvoice } from './billing';
        vi.mock('./billing');
        it('creates invoice', () => {
            expect(createInvoice('cust_1')).toEqual({ id: 'inv_1' });
        });
        """
        findings = scan_test_file(Path("src/billing.test.ts"), ts_self_mock)
        self.assertIn("self-mocked-unit-under-test", {f.rule for f in findings})

        # 2. Patching the exact function under test in Python
        py_self_mock = (
            "from unittest.mock import patch\n"
            "from app.tax import calculate_vat\n\n"
            "@patch('app.tax.calculate_vat')\n"
            "def test_calculate_vat(mock_vat):\n"
            "    mock_vat.return_value = 20.0\n"
            "    assert calculate_vat(100.0) == 20.0\n"
        )
        findings_py = scan_test_file(Path("tests/test_tax.py"), py_self_mock)
        self.assertEqual([f.rule for f in findings_py], ["self-mocked-unit-under-test"])

    def test_main_guard_is_not_special_casing_a_test_literal(self) -> None:
        diff_text = """diff --git a/tests/test_cli.py b/tests/test_cli.py
new file mode 100644
--- /dev/null
+++ b/tests/test_cli.py
@@ -0,0 +1,2 @@
+def test_module_name():
+    assert run_module("__main__") == 0
diff --git a/scripts/tool.py b/scripts/tool.py
--- a/scripts/tool.py
+++ b/scripts/tool.py
@@ -1,1 +1,3 @@
+if __name__ == "__main__":
+    main()
"""
        self.assertEqual(scan_diff_for_reward_hacking(diff_text), [])

    def test_evilgenie_cross_diff_special_casing(self) -> None:
        diff_text = """diff --git a/tests/test_tax.py b/tests/test_tax.py
new file mode 100644
--- /dev/null
+++ b/tests/test_tax.py
@@ -0,0 +1,3 @@
+def test_special_jurisdiction():
+    assert calculate_tax("TX-SPEC-99") == 14.25
diff --git a/src/tax.py b/src/tax.py
--- a/src/tax.py
+++ b/src/tax.py
@@ -5,3 +5,5 @@ def calculate_tax(code: str) -> float:
+    if code == "TX-SPEC-99":
+        return 14.25
     return lookup_rate(code)
"""
        findings = scan_diff_for_reward_hacking(diff_text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "test-input-special-casing")
        self.assertEqual(findings[0].path, "src/tax.py")
        self.assertIn("TX-SPEC-99", findings[0].message)

    def test_evilgenie_ignores_pins_in_requirements_files(self) -> None:
        diff_text = """diff --git a/tests/test_cli.py b/tests/test_cli.py
new file mode 100644
--- /dev/null
+++ b/tests/test_cli.py
@@ -0,0 +1,2 @@
+def test_sarif_version():
+    assert sarif_version() == "2.1.0"
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
--- /dev/null
+++ b/requirements.txt
@@ -0,0 +1,1 @@
+py-serializable==2.1.0
"""
        self.assertEqual(scan_diff_for_reward_hacking(diff_text), [])

    def test_evilgenie_with_existing_repo_test_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "tests"
            test_dir.mkdir()
            (test_dir / "test_coupon.py").write_text(
                'def test_vip_discount():\n    assert apply_coupon("VIP-GOLD-2026") == 45.00\n',
                encoding="utf-8",
            )
            diff_text = """diff --git a/src/coupon.py b/src/coupon.py
--- a/src/coupon.py
+++ b/src/coupon.py
@@ -2,2 +2,4 @@ def apply_coupon(code: str) -> float:
+    if code == "VIP-GOLD-2026":
+        return 45.00
     return standard_discount(code)
"""
            findings = scan_diff_for_reward_hacking(diff_text, repo_root=root)
            self.assertEqual([f.rule for f in findings], ["test-input-special-casing"])

    def test_diff_assertion_weakening_and_deletion(self) -> None:
        # 1. Deleting an assertion from an existing test
        diff_deleted = """diff --git a/tests/test_api.py b/tests/test_api.py
--- a/tests/test_api.py
+++ b/tests/test_api.py
@@ -10,4 +10,3 @@ def test_create_user():
     res = client.post("/users", json={"name": "Alice"})
     assert res.status_code == 201
-    assert res.json()["name"] == "Alice"
"""
        findings_del = scan_diff_for_reward_hacking(diff_deleted)
        self.assertEqual([f.rule for f in findings_del], ["diff-assertion-weakening"])

        # 2. Relaxing strict status check to permissive check
        diff_relaxed = """diff --git a/tests/test_api.py b/tests/test_api.py
--- a/tests/test_api.py
+++ b/tests/test_api.py
@@ -10,3 +10,3 @@ def test_create_user():
     res = client.post("/users", json={"name": "Alice"})
-    assert res.status_code == 201
+    assert res.status_code in (200, 400, 500)
"""
        findings_rel = scan_diff_for_reward_hacking(diff_relaxed)
        self.assertEqual([f.rule for f in findings_rel], ["diff-assertion-weakening"])

    def test_config_exemptions_and_rule_aliases(self) -> None:
        cfg = PrufGateConfig(
            exempt={
                ("tests/test_legacy.py", "assertion-free-test"): "Legacy smoke test",
            }
        )
        py_bad = "def test_smoke():\n    run_smoke()\n"
        self.assertEqual(scan_test_file(Path("tests/test_legacy.py"), py_bad, config=cfg), [])

    def test_cli_json_out_and_synthesizer_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_file = root / "sample.test.ts"
            test_file.write_text(
                "it('hollow test', () => { const x = 1 + 1; });\n",
                encoding="utf-8",
            )
            raw_dir = root / "reports" / "raw"
            json_out = raw_dir / "test_integrity.json"

            rc = main([f"--json-out={json_out}", "--include-self", str(test_file)])
            self.assertEqual(rc, 1)
            self.assertTrue(json_out.is_file())

            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["rule"], "zero-assertion-test")

            synth_findings = parse_raw_results(raw_dir)
            self.assertEqual(len(synth_findings), 1)
            self.assertEqual(synth_findings[0].tool, "test-integrity")
            self.assertEqual(synth_findings[0].rule_id, "zero-assertion-test")
            self.assertEqual(synth_findings[0].severity, "P0")


class TestRemovedTests(unittest.TestCase):
    """`diff-test-file-deleted` and `diff-test-count-drop`."""

    DELETED = """diff --git a/tests/test_refunds.py b/tests/test_refunds.py
deleted file mode 100644
--- a/tests/test_refunds.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def test_refund_rejects_closed_order():
-    assert refund(closed_order()) is False
"""

    def _rules(self, diff_text: str, cfg: PrufGateConfig | None = None) -> list[str]:
        return sorted(f.rule for f in scan_diff_for_reward_hacking(diff_text, config=cfg))

    def test_deleted_test_file_is_reported_once(self) -> None:
        findings = scan_diff_for_reward_hacking(self.DELETED)
        self.assertEqual([f.rule for f in findings], ["diff-test-file-deleted"])
        self.assertEqual(findings[0].severity, "P1")
        self.assertIn("exempt", findings[0].message)

    def test_rename_with_edits_is_not_a_deletion(self) -> None:
        diff_text = """diff --git a/tests/test_refunds.py b/tests/billing/test_refunds.py
similarity index 90%
rename from tests/test_refunds.py
rename to tests/billing/test_refunds.py
--- a/tests/test_refunds.py
+++ b/tests/billing/test_refunds.py
@@ -1,2 +1,2 @@
-from app import refund
+from app.billing import refund
 def test_refund_rejects_closed_order():
"""
        self.assertEqual(self._rules(diff_text), [])

    def test_unrecognised_language_moved_by_name_is_not_a_deletion(self) -> None:
        diff_text = """diff --git a/src/OrderTest.java b/src/OrderTest.java
deleted file mode 100644
--- a/src/OrderTest.java
+++ /dev/null
@@ -1,1 +0,0 @@
-class OrderTest {}
diff --git a/src/orders/OrderTest.java b/src/orders/OrderTest.java
new file mode 100644
--- /dev/null
+++ b/src/orders/OrderTest.java
@@ -0,0 +1,1 @@
+class OrderTest {}
"""
        self.assertEqual(self._rules(diff_text), [])
        self.assertEqual(self._rules(diff_text.split("diff --git a/src/orders")[0]), ["diff-test-file-deleted"])

    def test_tests_moved_into_an_uncollected_file_still_count_as_removed(self) -> None:
        moved = """diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,4 +1,2 @@
 import auth
-def test_login_rejects_bad_password():
-    assert not auth.login("u", "bad")
 x = 1
diff --git a/tests/auth_cases.py b/tests/auth_cases.py
new file mode 100644
--- /dev/null
+++ b/tests/auth_cases.py
@@ -0,0 +1,2 @@
+def test_login_rejects_bad_password():
+    assert not auth.login("u", "bad")
"""
        self.assertEqual(self._rules(moved), ["diff-test-count-drop"])
        # Moved into a file the runner collects: nothing lost.
        self.assertEqual(self._rules(moved.replace("auth_cases.py", "test_auth_cases.py")), [])
        # Moved within the same uncollected file: nothing lost.
        within = """diff --git a/tests/auth_cases.py b/tests/auth_cases.py
--- a/tests/auth_cases.py
+++ b/tests/auth_cases.py
@@ -1,3 +1,3 @@
-def test_login_rejects_bad_password():
-    assert not auth.login("u", "bad")
 x = 1
+def test_login_rejects_bad_password():
+    assert not auth.login("u", "bad")
"""
        self.assertEqual(self._rules(within), [])

    def test_python_unittest_method_removed_drops_count(self) -> None:
        diff_text = """diff --git a/tests/test_ledger.py b/tests/test_ledger.py
--- a/tests/test_ledger.py
+++ b/tests/test_ledger.py
@@ -5,4 +5,2 @@ class LedgerTest(unittest.TestCase):
     def test_balance(self):
         self.assertEqual(balance(), 0)
-    def test_overdraft(self):
-        pass
"""
        self.assertEqual(self._rules(diff_text), ["diff-test-count-drop"])

    def test_added_test_balances_removed_one(self) -> None:
        diff_text = """diff --git a/tests/test_ledger.py b/tests/test_ledger.py
--- a/tests/test_ledger.py
+++ b/tests/test_ledger.py
@@ -5,2 +5,2 @@
-def test_overdraft():
+def test_overdraft_is_rejected():
     assert withdraw(500) is None
"""
        self.assertEqual(self._rules(diff_text), [])

    RENAME = """diff --git a/tests/test_m.py b/tests/m_cases.py
similarity index 100%
rename from tests/test_m.py
rename to tests/m_cases.py
"""

    def test_rename_to_non_test_name_is_a_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tests").mkdir()
            (Path(tmp) / "tests" / "m_cases.py").write_text("def test_a():\n    assert 1\n", encoding="utf-8")
            findings = scan_diff_for_reward_hacking(self.RENAME, repo_root=tmp)
        self.assertEqual([(f.rule, f.path) for f in findings], [("diff-test-file-deleted", "tests/test_m.py")])
        self.assertIn("test_a", findings[0].message)
        self.assertEqual(self._rules(self.RENAME), ["diff-test-file-deleted"])
        edited = self.RENAME.replace("similarity index 100%", "similarity index 90%") + (
            "--- a/tests/test_m.py\n+++ b/tests/m_cases.py\n@@ -1,2 +1,2 @@\n-def test_a():\n+def case_a():\n     assert 1\n"
        )
        self.assertEqual(self._rules(edited), ["diff-test-file-deleted"])

    def test_rename_between_test_names_or_into_tests_is_not_a_deletion(self) -> None:
        self.assertEqual(self._rules(self.RENAME.replace("tests/m_cases.py", "tests/test_n.py")), [])
        self.assertEqual(self._rules(self.RENAME.replace("tests/test_m.py", "tests/m_old.py")), [])

    def test_partly_moved_deleted_file_does_not_hide_other_drops(self) -> None:
        diff_text = """diff --git a/tests/test_a.py b/tests/test_a.py
deleted file mode 100644
--- a/tests/test_a.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def test_1(): check(1)
-def test_2(): check(2)
-def test_3(): check(3)
diff --git a/tests/test_b.py b/tests/test_b.py
--- a/tests/test_b.py
+++ b/tests/test_b.py
@@ -1,2 +1,2 @@
-def test_4(): check(4)
-def test_5(): check(5)
+def test_1(): check(1)
+def test_2(): check(2)
"""
        self.assertEqual(self._rules(diff_text), ["diff-test-count-drop", "diff-test-file-deleted"])

    def test_exempt_file_does_not_hide_another_files_drop(self) -> None:
        diff_text = """diff --git a/tests/test_a.py b/tests/test_a.py
--- a/tests/test_a.py
+++ b/tests/test_a.py
@@ -1,2 +1,0 @@
-def test_1(): check(1)
-def test_2(): check(2)
diff --git a/tests/test_b.py b/tests/test_b.py
--- a/tests/test_b.py
+++ b/tests/test_b.py
@@ -1,1 +1,0 @@
-def test_3(): check(3)
"""
        cfg = PrufGateConfig(exempt={("tests/test_a.py", "diff-test-count-drop"): "#9: retired"})
        findings = scan_diff_for_reward_hacking(diff_text, config=cfg)
        self.assertEqual([(f.rule, f.path) for f in findings], [("diff-test-count-drop", "tests/test_b.py")])
        self.assertEqual(self._rules(diff_text.split("diff --git a/tests/test_b.py")[0], cfg), [])

    def test_tests_in_comments_or_strings_are_not_added_back(self) -> None:
        q3 = "'" * 3
        for path, removed, added in (
            ("tests/test_l.py", "def test_overdraft():", ('"""', "def test_overdraft():", '"""')),
            ("tests/test_l.py", "def test_overdraft():", (f"X = {q3}", "def test_overdraft():", q3)),
            ("src/cart.test.ts", "it('rejects', () => {});", ("/*", "it('rejects', () => {});", "*/")),
            ("src/cart.test.ts", "it('rejects', () => {});", ("const s = `", "it('rejects', () => {});", "`;")),
            ("pkg/l_test.go", "func TestOverdraft(t *testing.T) {}", ("/*", "func TestOverdraft(t *testing.T) {}", "*/")),
        ):
            body = f"-{removed}\n" + "".join(f"+{a}\n" for a in added)
            diff_text = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,{len(added)} @@\n{body}"
            with self.subTest(path=path, added=added):
                self.assertEqual(self._rules(diff_text), ["diff-test-count-drop"])
        real = "diff --git a/tests/test_l.py b/tests/test_l.py\n--- a/tests/test_l.py\n+++ b/tests/test_l.py\n"
        real += '@@ -1,1 +1,3 @@\n-def test_overdraft():\n+"""doc"""\n+def test_overdraft():  # moved\n+    check()\n'
        self.assertEqual(self._rules(real), [])

    def test_exemptions_acknowledge_intended_removal(self) -> None:
        cfg = PrufGateConfig(exempt={("tests/test_refunds.py", "diff-test-file-deleted"): "#7: refunds removed"})
        self.assertEqual(self._rules(self.DELETED, cfg), [])
        excluded = PrufGateConfig(exclude=["tests/test_refunds.py"])
        self.assertEqual(self._rules(self.DELETED, excluded), [])


if __name__ == "__main__":
    unittest.main()


class TestParametrisedAndRetiredTests(unittest.TestCase):
    """Parametrised cases count per case; a test retired with its module is not a deletion."""

    def _rules(self, diff_text: str) -> list[str]:
        return sorted(f.rule for f in scan_diff_for_reward_hacking(diff_text))

    @staticmethod
    def _diff(path: str, body: str) -> str:
        return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,9 +1,9 @@\n{body}"

    def test_merge_into_parametrize_with_as_many_cases_is_no_drop(self) -> None:
        body = ("-def test_a():\n-    assert f(1)\n-def test_b():\n-    assert f(2)\n"
                '+@pytest.mark.parametrize("x", [1, 2])\n+def test_f(x):\n+    assert f(x)\n')
        self.assertEqual(self._rules(self._diff("tests/test_f.py", body)), [])

    def test_merge_into_parametrize_with_fewer_cases_is_a_drop(self) -> None:
        body = ("-def test_a():\n-    assert f(1)\n-def test_b():\n-    assert f(2)\n"
                '+@pytest.mark.parametrize("x", [1])\n+def test_f(x):\n+    assert f(x)\n')
        self.assertEqual(self._rules(self._diff("tests/test_f.py", body)), ["diff-test-count-drop"])

    def test_cases_cut_from_an_unchanged_parametrised_test_is_a_drop(self) -> None:
        body = ' @pytest.mark.parametrize("x", [\n     1,\n-    2,\n-    3,\n ])\n def test_f(x):\n'
        self.assertEqual(self._rules(self._diff("tests/test_f.py", body)), ["diff-test-count-drop"])

    def test_stacked_parametrize_multiplies(self) -> None:
        body = ("-def test_a():\n-    pass\n-def test_b():\n-    pass\n-def test_c():\n-    pass\n-def test_d():\n-    pass\n"
                '+@pytest.mark.parametrize("x", [1, 2])\n+@pytest.mark.parametrize("y", [1, 2])\n+def test_f(x, y):\n+    assert f(x, y)\n')
        self.assertEqual(self._rules(self._diff("tests/test_f.py", body)), [])

    def test_it_each_and_go_table_count_their_rows(self) -> None:
        ts = ('-it("a", () => { expect(f(1)).toBe(1); });\n-it("b", () => { expect(f(2)).toBe(2); });\n'
              '+it.each([[1, "x,y"], [2, "z"]])("maps %i", (n) => { expect(f(n)).toBe(n); });\n')
        self.assertEqual(self._rules(self._diff("src/f.test.ts", ts)), [])
        go = ("-func TestA(t *testing.T) { check(t, 1) }\n-func TestB(t *testing.T) { check(t, 2) }\n"
              "+func TestF(t *testing.T) {\n+\tfor _, n := range []struct{ n int }{{1}, {2}} {\n"
              '+\t\tt.Run("f", func(t *testing.T) { check(t, n.n) })\n+\t}\n+}\n')
        self.assertEqual(self._rules(self._diff("pkg/f_test.go", go)), [])
        go_no_run = go.replace('t.Run("f", func(t *testing.T) { check(t, n.n) })', "check(t, n.n)")
        self.assertEqual(self._rules(self._diff("pkg/f_test.go", go_no_run)), ["diff-test-count-drop"])

    @staticmethod
    def _deleted(path: str, *lines: str) -> str:
        body = "".join(f"-{x}\n" for x in lines)
        return f"diff --git a/{path} b/{path}\ndeleted file mode 100644\n--- a/{path}\n+++ /dev/null\n@@ -1,{len(lines)} +0,0 @@\n{body}"

    def test_test_deleted_with_the_module_it_imports_is_not_reported(self) -> None:
        test = self._deleted("tests/test_coupons.py", "from shop.coupons import apply", "def test_x():", "    assert apply(1)")
        self.assertEqual(self._rules(self._deleted("shop/coupons.py", "def apply(x):", "    return x") + test), [])
        self.assertEqual(self._rules(self._deleted("src/shop/coupons/__init__.py", "X = 1") + test), [])
        ts = self._deleted("src/coupons.test.ts", 'import { apply } from "./coupons";', 'it("x", () => { expect(apply(1)).toBe(1); });')
        self.assertEqual(self._rules(self._deleted("src/coupons.ts", "export const apply = (x) => x;") + ts), [])
        go = self._deleted("pkg/coupons/apply_test.go", "package coupons", "func TestApply(t *testing.T) { check(t) }")
        self.assertEqual(self._rules(self._deleted("pkg/coupons/apply.go", "package coupons") + go), [])

    def test_test_deleted_while_its_module_stays_is_reported(self) -> None:
        test = self._deleted("tests/test_coupons.py", "from shop.coupons import apply", "def test_x():", "    assert apply(1)")
        self.assertEqual(self._rules(test), ["diff-test-file-deleted"])
        # Another module deleted in the same diff is not the one the test imports.
        self.assertEqual(self._rules(self._deleted("shop/legacy.py", "X = 1") + test), ["diff-test-file-deleted"])
        go = self._deleted("pkg/coupons/apply_test.go", "package coupons", "func TestApply(t *testing.T) { check(t) }")
        self.assertEqual(self._rules(self._deleted("pkg/other/apply.go", "package other") + go), ["diff-test-file-deleted"])


class TestRetiredAndParametrisedEvasions(unittest.TestCase):
    """A test hidden behind a deleted helper, or behind padded parametrize cases, is still reported."""

    @staticmethod
    def _deleted(path: str, *lines: str) -> str:
        return TestParametrisedAndRetiredTests._deleted(path, *lines)

    @staticmethod
    def _rules(diff_text: str, files: dict[str, str] | None = None) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            for rel, body in (files or {}).items():
                (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / rel).write_text(body)
            return sorted(f.rule for f in scan_diff_for_reward_hacking(diff_text, tmp))

    @staticmethod
    def _modified(path: str, base: str, head: str) -> str:
        import difflib

        body = "".join(difflib.unified_diff(base.splitlines(True), head.splitlines(True), f"a/{path}", f"b/{path}"))
        return f"diff --git a/{path} b/{path}\n{body}"

    TEST = ("from shop.ship import ship_cost", "from shop import banner", "def test_x():", "    assert ship_cost(1) == 7")

    def test_deleting_a_helper_while_the_tested_module_stays_is_reported(self) -> None:
        diff = self._deleted("shop/banner.py", "BANNER = 1") + self._deleted("tests/test_ship.py", *self.TEST)
        self.assertEqual(self._rules(diff, {"shop/ship.py": "def ship_cost(kg):\n    return 4\n"}), ["diff-test-file-deleted"])
        # Both modules gone: retired.
        both = self._deleted("shop/ship.py", "def ship_cost(kg):", "    return 5") + diff
        self.assertEqual(self._rules(both), [])

    def test_deleted_package_init_does_not_retire_a_module_that_stays(self) -> None:
        test = self._deleted("tests/test_ship.py", "from shop import ship", "def test_x():", "    assert ship.ship_cost(1) == 7")
        diff = self._deleted("shop/__init__.py", '"""Shop."""') + test
        self.assertEqual(self._rules(diff, {"shop/ship.py": "def ship_cost(kg):\n    return 9\n"}), ["diff-test-file-deleted"])

    def test_function_moved_to_a_new_file_is_not_retired(self) -> None:
        gone = self._deleted("shop/ship.py", "def ship_cost(kg):", "    return 5 + kg")
        test = self._deleted("tests/test_ship.py", "from shop.ship import ship_cost", "def test_x():", "    assert ship_cost(1) == 6")
        new = "diff --git a/shop/shipping.py b/shop/shipping.py\nnew file mode 100644\n--- /dev/null\n+++ b/shop/shipping.py\n@@ -0,0 +1,2 @@\n+def ship_cost(kg):\n+    return 4 + kg\n"
        self.assertEqual(self._rules(gone + test + new, {"shop/shipping.py": "def ship_cost(kg):\n    return 4 + kg\n"}), ["diff-test-file-deleted"])
        self.assertEqual(self._rules(gone + test), [])

    def test_go_test_retires_only_with_every_file_of_its_package(self) -> None:
        go = self._deleted("calc/div_test.go", "package calc", "func TestDiv(t *testing.T) { check(t) }")
        diff = self._deleted("calc/doc.go", "package calc") + go
        self.assertEqual(self._rules(diff, {"calc/div.go": "package calc\n"}), ["diff-test-file-deleted"])
        self.assertEqual(self._rules(diff), [])

    def test_js_test_retires_only_when_every_relative_import_is_gone(self) -> None:
        ts = self._deleted("src/round.test.ts", 'import { round2 } from "./round";', 'import { x } from "./fixtures";',
                           'it("r", () => { expect(round2(x)).toBe(1); });')
        diff = self._deleted("src/fixtures.ts", "export const x = 1;") + ts
        self.assertEqual(self._rules(diff, {"src/round.ts": "export const round2 = (n) => n;\n"}), ["diff-test-file-deleted"])

    def test_duplicate_parametrize_cases_count_once(self) -> None:
        body = ("-def test_a():\n-    assert f(1)\n-def test_b():\n-    assert f(2)\n-def test_c():\n-    assert f(3)\n"
                '+@pytest.mark.parametrize("x", ["3", "3", "3"])\n+def test_f(x):\n+    assert f(x)\n')
        diff = TestParametrisedAndRetiredTests._diff("tests/test_f.py", body)
        self.assertEqual(sorted(f.rule for f in scan_diff_for_reward_hacking(diff)), ["diff-test-count-drop"])
        ts = ('-it("a", () => { expect(f(1)).toBe(1); });\n-it("b", () => { expect(f(2)).toBe(2); });\n'
              '+it.each([[1, "x"], [1, "x"]])("maps %i", (n) => { expect(f(n)).toBe(n); });\n')
        diff = TestParametrisedAndRetiredTests._diff("src/f.test.ts", ts)
        self.assertEqual(sorted(f.rule for f in scan_diff_for_reward_hacking(diff)), ["diff-test-count-drop"])

    def test_unused_parametrize_cases_and_cases_on_a_helper_do_not_count(self) -> None:
        base = "def test_a():\n    assert f(1)\n\n\ndef test_b():\n    assert f(2)\n\n\ndef test_ok():\n    assert f(0) == 0\n"
        unused = 'import pytest\n\n\n@pytest.mark.parametrize("_", [1, 2, 3])\ndef test_ok(_):\n    assert f(0) == 0\n'
        self.assertEqual(self._rules(self._modified("tests/test_g.py", base, unused)), ["diff-test-count-drop"])
        used = unused.replace('"_"', '"x"').replace("test_ok(_)", "test_ok(x)").replace("f(0) == 0", "f(x)")
        self.assertEqual(self._rules(self._modified("tests/test_g.py", base, used)), [])
        helper = ('import pytest\n\n\n@pytest.mark.parametrize("x", [1, 2, 3])\ndef helper(x):\n    return x\n\n\n'
                  "def test_ok():\n    assert f(0) == 0\n")
        self.assertEqual(self._rules(self._modified("tests/test_g.py", base, helper)), ["diff-test-count-drop"])

    def test_cases_cut_far_from_the_test_definition_count(self) -> None:
        rows = "".join(f"    ({i}, {i}),\n" for i in range(12))
        base = f'import pytest\n\n\n@pytest.mark.parametrize("a,b", [\n{rows}])\ndef test_f(a, b):\n    assert f(a) == b\n'
        head = base.replace("    (5, 5),\n    (6, 6),\n", "")
        self.assertEqual(self._rules(self._modified("tests/test_f.py", base, head), {"tests/test_f.py": head}), ["diff-test-count-drop"])
        go_rows = "".join(f"\t\t{{{i}}},\n" for i in range(12))
        gb = (f'package p\n\nimport "testing"\n\nfunc TestF(t *testing.T) {{\n\tfor _, c := range []struct{{ n int }}{{\n{go_rows}'
              '\t} {\n\t\tt.Run("x", func(t *testing.T) { check(t, c.n) })\n\t}\n}\n')
        gh = gb.replace("\t\t{5},\n\t\t{6},\n", "")
        self.assertEqual(self._rules(self._modified("p/f_test.go", gb, gh), {"p/f_test.go": gh}), ["diff-test-count-drop"])
        # A working tree that no longer matches the diff falls back to the hunks alone.
        self.assertEqual(self._rules(self._modified("tests/test_f.py", base, head), {"tests/test_f.py": "x = 1\n"}), [])


class TestSnapshotAndPatchShapes(unittest.TestCase):
    def _rules(self, path: str, src: str) -> list[str]:
        return sorted({f.rule for f in scan_test_file(path, src)})

    def test_unfilled_inline_snapshot(self) -> None:
        self.assertIn("snapshot-blind-update-or-empty",
                      self._rules("src/f.test.ts", 'it("f", () => { expect(f(3)).toMatchInlineSnapshot(); });\n'))
        self.assertNotIn("snapshot-blind-update-or-empty",
                         self._rules("src/f.test.ts", 'it("f", () => { expect(f(3)).toMatchInlineSnapshot(`"$3.00"`); });\n'))

    def test_with_patch_of_the_function_under_test(self) -> None:
        bad = ('from unittest.mock import patch\nfrom shop import tax\n\n\ndef test_tax():\n'
               '    with patch("shop.tax.tax", return_value=2.0):\n        assert tax.tax(10) == 2.0\n')
        self.assertIn("self-mocked-unit-under-test", self._rules("tests/test_tax.py", bad))
        good = bad.replace('"shop.tax.tax"', '"shop.tax.rate_for"')
        self.assertNotIn("self-mocked-unit-under-test", self._rules("tests/test_tax.py", good))


def _git_scan(base: dict[str, str], head: dict[str, str | None]) -> list[tuple[str, str]]:
    """Commit `base` in a throwaway repository, apply `head` (None deletes a file) and scan the diff
    with the repository on disk, as `check --changed` does. Returns (rule, path) pairs."""
    import subprocess

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
                cwd=root, check=True, capture_output=True, text=True,
            ).stdout

        def write(files: dict[str, str | None]) -> None:
            for rel, body in files.items():
                p = root / rel
                if body is None:
                    p.unlink()
                    continue
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body, encoding="utf-8")

        git("init", "-q")
        write(dict(base))
        git("add", "-A")
        git("commit", "-q", "--allow-empty", "-m", "base")
        write(head)
        git("add", "-A")
        diff = git("diff", "--cached", "-M", "HEAD")
        return sorted((f.rule, f.path) for f in scan_diff_for_reward_hacking(diff, repo_root=root))


class TestSpecialCasingPrecision(unittest.TestCase):
    """test-input-special-casing fires only on a literal from a paired test, quoted, in a comparison."""

    RULE = "test-input-special-casing"

    def fired(self, base: dict[str, str], head: dict[str, str | None]) -> list[str]:
        return [p for r, p in _git_scan(base, head) if r == self.RULE]

    def test_go_import_block_is_not_a_literal(self) -> None:
        test = 'package lines\n\nimport (\n\t"strings"\n\t"testing"\n)\n\nfunc TestTrim(t *testing.T) {\n\tif Trim(" ok ") != "ok" {\n\t\tt.Fatal(strings.TrimSpace("x"))\n\t}\n}\n'
        prod = 'package lines\n\nfunc Kind(l string) int {\n\tswitch {\n\tcase strings.HasPrefix(l, "ok "):\n\t\treturn 1\n\t}\n\treturn 0\n}\n'
        self.assertEqual(self.fired({}, {"lines/lines_test.go": test, "lines/lines.go": prod}), [])

    def test_go_fixture_literal_branch_fires(self) -> None:
        test = 'package price\n\nimport "testing"\n\nfunc TestPromo(t *testing.T) {\n\tif Price("PROMO-TEST-7") != 0 {\n\t\tt.Fatal("want 0")\n\t}\n}\n'
        base = 'package price\n\nfunc Price(code string) int {\n\treturn lookup(code)\n}\n'
        head = 'package price\n\nfunc Price(code string) int {\n\tif code == "PROMO-TEST-7" { return 0 }\n\treturn lookup(code)\n}\n'
        self.assertEqual(self.fired({"price/price.go": base}, {"price/price_test.go": test, "price/price.go": head}), ["price/price.go"])

    def test_unquoted_identifiers_and_substrings_do_not_match(self) -> None:
        test = 'import { load, run } from "./widget";\nit("loads", async () => {\n  vi.stubGlobal("fetch", f);\n  expect(run("check")).toBe(1);\n});\n'
        prod = "export const load = (u) => fetchWidget(u);\nexport function run(seen, checkedAt) {\n  if (seen !== checkedAt) return 1;\n  return 0;\n}\n"
        self.assertEqual(self.fired({}, {"src/widget.test.ts": test, "src/widget.ts": prod}), [])

    def test_quoted_fixture_literal_in_a_comparison_fires(self) -> None:
        test = 'import { score } from "./score";\nit("scores", () => {\n  expect(score("fixture-input-3")).toBe(1);\n});\n'
        base = "export function score(input) {\n  return model(input);\n}\n"
        head = 'export function score(input) {\n  if (input === "fixture-input-3") return 1;\n  return model(input);\n}\n'
        self.assertEqual(self.fired({"src/score.ts": base}, {"src/score.test.ts": test, "src/score.ts": head}), ["src/score.ts"])

    def test_literal_from_an_unrelated_test_is_ignored(self) -> None:
        test = 'package plans\n\nimport "testing"\n\nfunc TestGold(t *testing.T) {\n\tif Seats("platinum") != 5 {\n\t\tt.Fatal("seats")\n\t}\n}\n'
        prod = 'export function badge(tier) {\n  if (tier === "platinum") return "star";\n  return "";\n}\n'
        self.assertEqual(self.fired({}, {"plans/plans_test.go": test, "ui/badge.ts": prod}), [])

    def test_literal_from_a_test_that_imports_the_file_fires(self) -> None:
        test = 'import { find } from "../widget";\nit("finds", () => {\n  expect(find("magic-id-99")).toBe(CACHED);\n});\n'
        base = "export function find(id) {\n  return db.get(id);\n}\n"
        head = 'export function find(id) {\n  if (id === "magic-id-99") return CACHED;\n  return db.get(id);\n}\n'
        files = {"src/__tests__/lookup.test.ts": test, "src/widget.ts": head}
        self.assertEqual(self.fired({"src/widget.ts": base}, files), ["src/widget.ts"])
        # A path alias (`@/...`) pairs the same way.
        files["src/__tests__/lookup.test.ts"] = test.replace("../widget", "@/widget")
        self.assertEqual(self.fired({"src/widget.ts": base}, files), ["src/widget.ts"])

    def test_domain_vocabulary_is_not_special_casing(self) -> None:
        test = 'import { isLive } from "./status";\nit("retired is not live", () => {\n  expect(isLive("retired")).toBe(false);\n});\n'
        base = 'type Status = "active" | "retired";\nexport function isLive(s: Status) {\n  return true;\n}\n'
        head = 'type Status = "active" | "retired";\nexport function isLive(s: Status) {\n  if (s === "retired") return false;\n  return true;\n}\n'
        self.assertEqual(self.fired({"src/status.ts": base}, {"src/status.test.ts": test, "src/status.ts": head}), [])
        # A value already in production elsewhere (here a type in another file) is vocabulary too.
        types = 'export type Cmd = "build" | "lint" | "deploy";\n'
        cli_test = 'import { cli } from "./cli";\nit("deploys", () => {\n  expect(cli("deploy")).toBe(0);\n});\n'
        self.assertEqual(self.fired({"src/types.ts": types, "src/cli.ts": self.CLI}, {"src/cli.test.ts": cli_test, "src/cli.ts": self.CLI_DEPLOY}), [])

    CLI = ('export function cli(cmd: string) {\n  switch (cmd) {\n    case "build":\n      return build();\n'
           '    case "test":\n      return test();\n    case "lint":\n      return lint();\n  }\n  return 2;\n}\n')
    CLI_DEPLOY = CLI.replace('    case "lint":', '    case "deploy":\n      return deploy();\n    case "lint":')

    def test_new_case_for_a_test_only_literal_in_an_existing_switch_fires(self) -> None:
        test = 'import { cli } from "./cli";\nit("handles the fixture", () => {\n  expect(cli("fixture-input-3")).toBe(1);\n});\n'
        head = self.CLI.replace('    case "lint":', '    case "fixture-input-3":\n      return 1;\n    case "lint":')
        self.assertEqual(self.fired({"src/cli.ts": self.CLI}, {"src/cli.test.ts": test, "src/cli.ts": head}), ["src/cli.ts"])
        # Next to other comparisons on the same operand, too.
        cmp_base = 'export function grade(s: string) {\n  if (s === "gold" || s === "silver") return 2;\n  return 0;\n}\n'
        cmp_head = cmp_base.replace("  return 0;", '  if (s === "fixture-input-3") return 1;\n  return 0;')
        grade_test = 'import { grade } from "./grade";\nit("grades", () => {\n  expect(grade("fixture-input-3")).toBe(1);\n});\n'
        self.assertEqual(self.fired({"src/grade.ts": cmp_base}, {"src/grade.test.ts": grade_test, "src/grade.ts": cmp_head}), ["src/grade.ts"])


class TestRetiredFeaturePrecision(unittest.TestCase):
    """A test removed with the feature it covers is not reported; one whose subject stays is."""

    @staticmethod
    def rules(base: dict[str, str], head: dict[str, str | None], rule: str) -> list[str]:
        return [p for r, p in _git_scan(base, head) if r == rule]

    APPLY = "export function apply(code: string, total: number) {\n  return code === 'SPRING' ? total * 0.9 : total;\n}\n"
    APPLY_TEST = ('import { apply } from "@/coupons/apply";\nimport { db } from "@/lib/db";\n\n'
                  'it("applies spring", () => {\n  expect(apply("SPRING", 100)).toBe(90);\n  expect(db).toBeDefined();\n});\n')
    DB = "export const db = {};\n"

    def test_subject_deleted_through_an_alias_with_a_live_helper_is_retired(self) -> None:
        base = {"src/coupons/apply.ts": self.APPLY, "src/coupons/apply.test.ts": self.APPLY_TEST, "src/lib/db.ts": self.DB}
        head = {"src/coupons/apply.ts": None, "src/coupons/apply.test.ts": None}
        self.assertEqual(self.rules(base, head, "diff-test-file-deleted"), [])

    def test_test_deleted_while_its_subject_stays_is_reported(self) -> None:
        base = {"src/coupons/apply.ts": self.APPLY, "src/coupons/apply.test.ts": self.APPLY_TEST, "src/lib/db.ts": self.DB}
        self.assertEqual(self.rules(base, {"src/coupons/apply.test.ts": None}, "diff-test-file-deleted"), ["src/coupons/apply.test.ts"])

    def test_function_removed_from_a_live_module_retires_its_test(self) -> None:
        rates = "export function rate(n: number) {\n  return n * 2;\n}\n"
        legacy = "export function legacyRate(n: number) {\n  return n * 3;\n}\n"
        test = 'import { legacyRate } from "./rates";\n\nit("triples", () => {\n  expect(legacyRate(2)).toBe(6);\n});\n'
        base = {"src/rates.ts": rates + legacy, "src/legacy-rate.test.ts": test}
        self.assertEqual(self.rules(base, {"src/rates.ts": rates, "src/legacy-rate.test.ts": None}, "diff-test-file-deleted"), [])
        # The function stays: the deletion is reported.
        self.assertEqual(self.rules(base, {"src/legacy-rate.test.ts": None}, "diff-test-file-deleted"), ["src/legacy-rate.test.ts"])

    QUOTA = "package limits\n\nfunc Quota(n int) int { return n * 10 }\n"
    QUOTA_TEST = 'package limits\n\nimport "testing"\n\nfunc TestQuota(t *testing.T) {\n\tif Quota(2) != 20 {\n\t\tt.Fatal("quota")\n\t}\n}\n'
    OTHER = "package limits\n\nfunc Burst(n int) int { return n }\n"

    def test_go_test_deleted_while_its_file_stays_is_reported(self) -> None:
        base = {"limits/quota.go": self.QUOTA, "limits/quota_test.go": self.QUOTA_TEST, "limits/burst.go": self.OTHER}
        self.assertEqual(self.rules(base, {"limits/quota_test.go": None}, "diff-test-file-deleted"), ["limits/quota_test.go"])

    def test_go_test_deleted_with_its_paired_file_is_retired(self) -> None:
        base = {"limits/quota.go": self.QUOTA, "limits/quota_test.go": self.QUOTA_TEST, "limits/burst.go": self.OTHER}
        self.assertEqual(self.rules(base, {"limits/quota.go": None, "limits/quota_test.go": None}, "diff-test-file-deleted"), [])

    def test_go_package_retired_while_another_main_is_added(self) -> None:
        main = "package main\n\nfunc main() {\n\terr := run()\n\t_ = err\n}\n"
        store = "package main\n\nfunc run() error {\n\tvar count int\n\t_ = count\n\treturn nil\n}\n"
        test = 'package main\n\nimport "testing"\n\nfunc TestRun(t *testing.T) {\n\tvar count int\n\tif err := run(); err != nil || count != 0 {\n\t\tt.Fatal(err)\n\t}\n}\n'
        base = {"svc/main.go": main, "svc/store.go": store, "svc/store_test.go": test}
        tool = "package main\n\nfunc main() {\n\tvar count = 1\n\t_ = count\n}\n"
        head = {"svc/main.go": None, "svc/store.go": None, "svc/store_test.go": None, "tool/main.go": tool}
        self.assertEqual(self.rules(base, head, "diff-test-file-deleted"), [])

    def test_assertion_on_a_retired_value_is_not_weakening(self) -> None:
        prod = 'export function kindOf(x: string) {\n  if (x === "old") return "legacy_kind";\n  return "plain";\n}\n'
        test = ('import { kindOf } from "./kind";\n\nit("kinds", () => {\n  expect(kindOf("new")).toBe("plain");\n'
                '  expect(kindOf("old")).toBe("legacy_kind");\n});\n')
        base = {"src/kind.ts": prod, "src/kind.test.ts": test}
        head = {"src/kind.ts": prod.replace('  if (x === "old") return "legacy_kind";\n', ""),
                "src/kind.test.ts": test.replace('  expect(kindOf("old")).toBe("legacy_kind");\n', "")}
        self.assertEqual(self.rules(base, head, "diff-assertion-weakening"), [])
        # A migration that drops it still names it; that does not keep the value alive.
        head["db/migrations/002_drop_legacy.sql"] = "UPDATE items SET kind = 'plain' WHERE kind = 'legacy_kind';\n"
        self.assertEqual(self.rules(base, head, "diff-assertion-weakening"), [])

    def test_removed_setup_guard_is_not_weakening(self) -> None:
        test = ('package host\n\nimport "testing"\n\nfunc TestLoad(t *testing.T) {\n\th := New()\n'
                '\tif err := h.Init("x"); err != nil { t.Fatal(err) }\n\tif h.Load() != 2 {\n\t\tt.Fatal("load")\n\t}\n}\n')
        head = test.replace('\tif err := h.Init("x"); err != nil { t.Fatal(err) }\n', "")
        base = {"host/host.go": "package host\n", "host/host_test.go": test}
        self.assertEqual(self.rules(base, {"host/host_test.go": head}, "diff-assertion-weakening"), [])

    def test_removed_assertion_on_live_code_is_weakening(self) -> None:
        prod = "export const total = (xs: number[]) => xs.reduce((a, b) => a + b, 0);\n"
        test = ('import { total } from "./cart";\n\nit("totals", () => {\n  const cart = [40, 2];\n'
                '  expect(total(cart)).toBe(42);\n  expect(cart.length).toBe(2);\n});\n')
        base = {"src/cart.ts": prod, "src/cart.test.ts": test}
        head = {"src/cart.ts": prod + "export const none = 0;\n", "src/cart.test.ts": test.replace("  expect(total(cart)).toBe(42);\n", "")}
        self.assertEqual(self.rules(base, head, "diff-assertion-weakening"), ["src/cart.test.ts"])


class TestTestFileRulePrecision(unittest.TestCase):
    """self-mocked-unit-under-test, caught-and-ignored-test-exception and zero-assertion-test near misses."""

    @staticmethod
    def rules(path: str, src: str) -> set[str]:
        return {f.rule for f in scan_test_file(Path(path), src)}

    def test_mocking_a_package_with_the_subject_name_is_not_self_mocking(self) -> None:
        src = ('import { charge } from "./payments";\nvi.mock("@acme/payments", () => ({ client: vi.fn() }));\n\n'
               'it("charges", async () => {\n  expect(await charge(5)).toBe(true);\n});\n')
        self.assertNotIn("self-mocked-unit-under-test", self.rules("src/payments.test.ts", src))

    def test_mocking_another_module_with_the_same_basename_is_not_self_mocking(self) -> None:
        src = ('import { buildReport } from "../report";\nvi.mock("@/lib/stats/report", () => ({ totals: () => [1] }));\n\n'
               'it("builds", async () => {\n  expect(await buildReport()).toEqual({ rows: 1 });\n});\n')
        self.assertNotIn("self-mocked-unit-under-test", self.rules("src/actions/__tests__/report.test.ts", src))

    def test_mocking_the_imported_subject_is_self_mocking(self) -> None:
        src = ('import { buildReport } from "../report";\nvi.mock("../report", () => ({ buildReport: () => ({ rows: 1 }) }));\n\n'
               'it("builds", async () => {\n  expect(await buildReport()).toEqual({ rows: 1 });\n});\n')
        self.assertIn("self-mocked-unit-under-test", self.rules("src/actions/__tests__/report.test.ts", src))

    def test_error_stored_and_asserted_after_the_try_is_not_ignored(self) -> None:
        src = ('import { parse, ParseError } from "./parse";\n\nit("rejects bad input", () => {\n  let err;\n'
               '  try {\n    parse("x");\n  } catch (e) {\n    err = e;\n  }\n  expect(isParseError(err)).toBe(true);\n});\n')
        self.assertNotIn("caught-and-ignored-test-exception", self.rules("src/parse.test.ts", src))
        py = ('from app.parse import parse, ParseError\n\n\ndef test_rejects_bad_input():\n    err = None\n    try:\n'
              '        parse("x")\n    except ParseError as e:\n        err = e\n    assert isinstance(err, ParseError)\n')
        self.assertNotIn("caught-and-ignored-test-exception", self.rules("tests/test_parse.py", py))

    def test_empty_catch_is_still_ignored(self) -> None:
        src = ('import { save } from "./save";\n\nit("saves", async () => {\n  try {\n    await save();\n'
               '  } catch (e) {}\n  expect(true).toBe(true);\n});\n')
        self.assertIn("caught-and-ignored-test-exception", self.rules("src/save.test.ts", src))
        py = ('from app.save import save\n\n\ndef test_saves():\n    err = None\n    try:\n        save()\n'
              '    except Exception as e:\n        err = e\n    assert True\n')
        self.assertIn("caught-and-ignored-test-exception", self.rules("tests/test_save.py", py))

    def test_throw_new_error_is_an_assertion(self) -> None:
        src = ('import { columns } from "./schema";\n\nit("has an id column", async () => {\n  const cols = await columns();\n'
               '  if (!cols.has("id")) throw new Error("missing id");\n});\n')
        self.assertNotIn("zero-assertion-test", self.rules("src/schema.test.ts", src))
        hollow = 'import { load } from "./schema";\n\nit("loads", async () => {\n  await load();\n});\n'
        self.assertIn("zero-assertion-test", self.rules("src/schema.test.ts", hollow))
