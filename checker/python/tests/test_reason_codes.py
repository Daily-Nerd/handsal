"""T4.4: the section 11 reason code index against the checker and the vectors (CF-07, spec 16.9).

The code list comes from `tools/check_catalog.py`, the one owner of how the
spec index is read. A code is the checker's when a row other than a signer
exit code or a pin helper row lists it.
"""
import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "checker" / "python" / "src" / "handsal_check"


def tools_module(name):
    spec = importlib.util.spec_from_file_location("tools_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CATALOG = tools_module("check_catalog")
SPEC = tools_module("manifest").read_profile(ROOT)

def package_strings():
    found = set()
    for path in sorted(PACKAGE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
    return found


class ReasonCodeIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codes, cls.retired, cls.excepted = CATALOG.spec_codes(SPEC)
        cls.mine = CATALOG.checker_codes(SPEC)
        cls.strings = package_strings()
        cls.shown = CATALOG.anchor_codes(ROOT, include_ordering=True)

    def test_every_checker_code_exists_in_the_checker(self):
        missing = [c for c in self.mine if c not in self.strings]
        self.assertEqual(missing, [])

    def test_every_checker_code_is_in_an_anchor_or_excepted(self):
        # No ledger of codes "waiting for a vector": a code the checker returns either has an
        # only-defect vector on disk or is excepted in CF-07 with its reason.
        missing = [c for c in self.mine if c not in self.shown and c not in self.excepted]
        self.assertEqual(sorted(missing), [])

    def test_an_excepted_checker_code_is_a_real_checker_code(self):
        for code in self.excepted & set(self.mine):
            self.assertIn(code, self.strings)

    def test_every_other_excepted_code_belongs_to_the_pin_helper_or_the_signer(self):
        # CF-07 excepts a component code only because no vector input sets it up; the checker never returns it.
        others = self.excepted - set(self.mine)
        self.assertEqual(sorted(others), ["biometric_unavailable", "internal", "key_exists", "key_unavailable",
                                          "no_display", "pin_invalid", "pin_rollback", "prompt_refused", "user_cancel"])
        for code in others:
            self.assertIn(code, self.codes)
            self.assertNotIn(code, self.shown, "a code with a vector needs no exception: %s" % code)

    def test_no_retired_code_is_left_in_the_checker_or_a_vector(self):
        self.assertEqual(self.retired, {"genesis_signer_unknown", "genesis_sig_mismatch", "genesis_head_mismatch"})
        self.assertEqual(sorted(self.retired & self.strings), [])
        self.assertEqual(sorted(self.retired & self.shown), [])
        self.assertFalse(self.retired & set(self.codes))

    def test_the_store_drop_codes_are_indexed_with_their_commands(self):
        """Design 21.9, section 11: `epoch_superseded` (view rule, `enrolled`, `sync`) and `epoch_closed` (`admit`)."""
        self.assertIn("epoch_superseded", self.mine)
        self.assertIn("epoch_closed", self.mine)
        rows = {code: where for row, where in CATALOG._table_rows(CATALOG._section(SPEC, "## 11. Reason codes")) for code in row}
        self.assertIn("VR-12", rows["epoch_superseded"])
        self.assertIn("`sync` (CF-09)", rows["epoch_superseded"])
        self.assertEqual(rows["epoch_closed"], "`admit` (CF-11)")

    def test_every_code_head_can_answer_names_head_in_the_index(self):
        """Design 22.4, VR-19: `head` runs the pin checks, the fold, the view and the witness rules, so the
        rows of those codes name it beside `check-act` and `enrolled`; a code only `head` could use has no row."""
        rows = {code: where for row, where in CATALOG._table_rows(CATALOG._section(SPEC, "## 11. Reason codes")) for code in row}
        for code in ("pin_org_mismatch", "pin_missing", "pin_owner", "pin_malformed", "profile_mismatch", "fixture_profile",
                     "genesis_pin_mismatch", "pin_spec_mismatch", "lineage_broken",
                     "view_in_future", "stale_view", "epoch_superseded",
                     "witness_unexpected", "witness_missing", "stale_witness", "behind_witness",
                     "store_missing", "store_owner", "store_malformed", "store_unavailable"):
            with self.subTest(code=code):
                self.assertIn(code, rows)
                self.assertIn("`head` (VR-19)", rows[code])
        folds = CATALOG._line(CATALOG._section(SPEC, "## 11. Reason codes"), "| fold error codes (below)")
        self.assertIn("`head` (VR-19)", folds)

    def test_no_code_the_checker_returns_is_missing_from_the_index(self):
        # Every literal handed to Refused(...) or used as an {"error": ...} value is in the index.
        index = set(self.codes) | self.retired
        used = set()
        for path in sorted(PACKAGE.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Refused"
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    used.add(node.args[0].value)
        self.assertEqual(sorted(used - index), [])


if __name__ == "__main__":
    unittest.main()
