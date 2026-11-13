"""Hashes cover raw file bytes (CF-01), so nothing may change a byte on checkout.

`.gitattributes` keeps `* -text`: with end-of-line conversion on (core.autocrlf on Windows) every
core file, vector and manifest entry hashes differently and the profile hash moves with no edit.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HASHED = ["spec/profile.md", "spec/registry.json", "spec/requirements.json", "spec/MANIFEST.json",
          "conformance/CONTRACT.md", "conformance/fixtures/keys.json", "conformance/fixtures/fixture-kids.json"]


class RawBytes(unittest.TestCase):
    def test_gitattributes_turns_off_text_conversion_for_every_file(self):
        lines = [l.strip() for l in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()]
        rules = [l for l in lines if l and not l.startswith("#")]
        self.assertIn("* -text", rules)
        for rule in rules:
            self.assertNotRegex(rule, r"(?<!-)\b(text|eol)\b", "a rule that turns conversion back on: %s" % rule)

    def test_no_hashed_file_holds_a_carriage_return(self):
        files = [ROOT / name for name in HASHED] + sorted((ROOT / "conformance" / "vectors").glob("*.json"))
        for path in files:
            with self.subTest(path=path.name):
                self.assertNotIn(b"\r", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
