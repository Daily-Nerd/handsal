"""Hashes cover raw file bytes (CF-01), so nothing may change a byte on checkout.

`.gitattributes` keeps `* -text`: with end-of-line conversion on (core.autocrlf on Windows) every
core file, vector and manifest entry hashes differently and the profile hash moves with no edit.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HASHED = ["spec/profile.md", "spec/profile-checks.md", "spec/profile-interfaces.md", "spec/profile-part3.md", "spec/registry.json", "spec/requirements.json", "spec/MANIFEST.json",
          "conformance/CONTRACT.md", "conformance/fixtures/keys.json", "conformance/fixtures/fixture-kids.json"]


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
