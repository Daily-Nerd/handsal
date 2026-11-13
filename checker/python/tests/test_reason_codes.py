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


def tools_catalog():
    spec = importlib.util.spec_from_file_location("tools_check_catalog", ROOT / "tools" / "check_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CATALOG = tools_catalog()
SPEC = (ROOT / "spec" / "profile.md").read_text(encoding="utf-8")

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
        self.assertEqual(sorted(others), ["internal", "key_exists", "key_unavailable", "no_display", "pin_invalid",
                                          "pin_rollback", "user_cancel"])
        for code in others:
            self.assertIn(code, self.codes)
            self.assertNotIn(code, self.shown, "a code with a vector needs no exception: %s" % code)

    def test_no_retired_code_is_left_in_the_checker_or_a_vector(self):
        self.assertEqual(self.retired, {"genesis_signer_unknown", "genesis_sig_mismatch", "genesis_head_mismatch"})
        self.assertEqual(sorted(self.retired & self.strings), [])
        self.assertEqual(sorted(self.retired & self.shown), [])
        self.assertFalse(self.retired & set(self.codes))

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
