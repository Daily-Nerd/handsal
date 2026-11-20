"""The reason code class table (`conformance/reason-classes.json`) and its one reader, `tools/reason_classes.py`.

The table is the single owner of which class a reason code belongs to. `classify` is total over the section 11
index: a code outside it raises, and there is no catch-all class.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import check_catalog as cc  # noqa: E402
import manifest  # noqa: E402
import reason_classes as rc  # noqa: E402

CLASSES = {"membership", "freshness", "validity", "time", "environment", "input", "admission", "capacity", "ok"}
INDEX = cc.spec_codes(manifest.read_profile(ROOT))[0]
COMMANDS = ("check-act", "recheck-act", "enrolled", "head", "fold", "sync", "admit", "pool", "compact", "agree-points",
            "genesis-check", "genesis-aids", "render", "emit", "kid", "subset", "x")


class Table(unittest.TestCase):
    def test_the_class_set_is_the_nine_and_has_no_catch_all(self):
        table = rc.load()
        self.assertEqual(set(table["classes"]), CLASSES)
        self.assertEqual(len(table["classes"]), 9)
        self.assertNotIn("other", table["classes"])

    def test_every_default_and_every_override_names_a_class_of_the_set(self):
        table = rc.load()
        rows = list(table["default"].items())
        rows += [item for per in table["by_command"].values() for item in per.items()]
        self.assertEqual([(c, k) for c, k in rows if k not in CLASSES], [])

    def test_a_table_with_a_class_outside_the_set_is_refused(self):
        bad = {"classes": sorted(CLASSES), "default": {"ok": "other"}, "by_command": {}}
        with self.assertRaises(rc.ReasonClassError):
            rc.check(bad)

    def test_an_override_of_a_code_with_no_default_is_refused(self):
        bad = {"classes": sorted(CLASSES), "default": {"ok": "ok"}, "by_command": {"admit": {"ghost": "input"}}}
        with self.assertRaises(rc.ReasonClassError):
            rc.check(bad)

    def test_the_table_file_is_not_a_core_file(self):
        self.assertNotIn("conformance/reason-classes.json", manifest.CORE_FILES)
        self.assertTrue((ROOT / "conformance" / "reason-classes.json").is_file())
        json.loads((ROOT / "conformance" / "reason-classes.json").read_text(encoding="utf-8"))

    def test_a_table_that_adds_a_class_to_the_set_is_refused(self):
        bad = {"classes": sorted(CLASSES | {"other"}), "default": {"ok": "ok"}, "by_command": {}}
        with self.assertRaises(rc.ReasonClassError):
            rc.check(bad)


class Classify(unittest.TestCase):
    def test_every_command_and_every_index_code_resolves_to_a_class_of_the_set(self):
        for command in COMMANDS:
            for code in INDEX:
                with self.subTest(command=command, code=code):
                    self.assertIn(rc.classify(command, code), CLASSES)

    def test_an_unknown_code_raises_and_never_gets_a_default_class(self):
        for command in COMMANDS:
            with self.subTest(command=command):
                with self.assertRaises(rc.ReasonClassError):
                    rc.classify(command, "no_such_code")

    def test_ok_is_its_own_class(self):
        self.assertEqual(rc.classify("check-act", "ok"), "ok")

    def test_a_table_given_by_the_caller_decides(self):
        table = {"classes": sorted(CLASSES), "default": {"alpha": "time"}, "by_command": {"c": {"alpha": "input"}}}
        self.assertEqual(rc.classify("d", "alpha", table), "time")
        self.assertEqual(rc.classify("c", "alpha", table), "input")


if __name__ == "__main__":
    unittest.main()
