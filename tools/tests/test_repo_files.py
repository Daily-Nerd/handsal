"""Hashes cover raw file bytes (CF-01), so nothing may change a byte on checkout.

`.gitattributes` keeps `* -text`: with end-of-line conversion on (core.autocrlf on Windows) every
core file, vector and manifest entry hashes differently and the profile hash moves with no edit.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402
# every core file, from its one owner, and the two generated files the profile hash does not cover but the bundle does
HASHED = list(manifest.CORE_FILES) + ["spec/requirements.json", "spec/MANIFEST.json"]

class RawBytes(unittest.TestCase):
    def test_gitattributes_turns_off_text_conversion_for_every_file(self):
        lines = [l.strip() for l in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()]
        rules = [l for l in lines if l and not l.startswith("#")]
        self.assertIn("* -text", rules)
        for rule in rules:
            self.assertNotRegex(rule, r"(?<!-)\b(text|eol)\b", "a rule that turns conversion back on: %s" % rule)

    def test_no_hashed_file_holds_a_carriage_return(self):
        vectors = ROOT / "conformance" / "vectors"
        files = [ROOT / name for name in HASHED] + sorted(vectors.glob("*.json")) + sorted(vectors.glob("prod/*.json"))
        for path in files:
            with self.subTest(path=path.name):
                self.assertNotIn(b"\r", path.read_bytes())


def uncovered(core, listed):
    """The core files `listed` leaves out: a file that is hashed and is not checked for a carriage return."""
    return sorted(set(core) - set(listed))


class EveryCoreFileIsChecked(unittest.TestCase):
    """`HASHED` is not a second list of the core files: `manifest.CORE_FILES` owns them, and a core part missing here
    would be silently unchecked for carriage returns."""

    def test_no_core_file_is_left_out_of_the_files_checked(self):
        self.assertEqual(uncovered(manifest.CORE_FILES, HASHED), [])

    def test_a_core_part_the_list_does_not_name_is_found(self):
        self.assertEqual(uncovered(manifest.CORE_FILES + ("spec/profile-new-part.md",), HASHED),
                         ["spec/profile-new-part.md"])

    def test_the_two_generated_files_are_checked_too(self):
        self.assertTrue({"spec/requirements.json", "spec/MANIFEST.json"} <= set(HASHED))

    def test_every_file_checked_exists(self):
        for name in HASHED:
            with self.subTest(path=name):
                self.assertTrue((ROOT / name).is_file())


class NoSilentSkips(unittest.TestCase):
    def test_no_python_test_skips_for_a_missing_dependency(self):
        """A test that skips when its oracle is not installed is a check that does not run, and nobody sees it.

        The dependency belongs in the pyproject of the suite (`_gen` declares `cryptography`), and an absent
        module is an error.
        """
        skip = re.compile(r"except\s+(?:Import|Module\w+)Error\b[^\n]*:\s*\n\s*self\.skipTest")
        for path in sorted(ROOT.glob("**/tests/test_*.py")):
            if ".venv" in path.parts:
                continue
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertIsNone(skip.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
