import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from public_text import PROCESS_WORDS  # noqa: E402

REQUIREMENTS = ROOT / "spec" / "requirements.json"
PROFILE = ROOT / "spec" / "profile.md"
SPEC_DIR = ROOT / "spec"
TERMS_DEFAULT = Path.home() / ".config" / "handsal" / "public-voice-terms.txt"

# Decision: every file under spec/ stays at or under 256 KiB. The profile is
# one reviewable document; past this size it should be split, not grown.
MAX_SPEC_FILE_BYTES = 256 * 1024

# Ids issued per family over the life of the profile text (active + retired).
ISSUED = {"ACT": 14, "KC": 8, "GP": 21, "FO": 27, "VR": 16, "RN": 12,
          "CF": 8, "SG": 15, "WT": 10}
# Profile section that carries each family.
SECTION_OF = {"ACT": 3, "KC": 4, "GP": 5, "FO": 6, "VR": 7, "RN": 8,
              "CF": 9, "SG": 10, "WT": 13}
ID_RE = re.compile(r"^([A-Z]+)-(\d\d)$")


def load_requirements():
    return json.loads(REQUIREMENTS.read_text(encoding="utf-8"))


class RequirementsFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_requirements()
        cls.active = {r["id"]: r for r in cls.data["active"]}
        cls.retired = {r["id"]: r for r in cls.data["retired"]}

    def test_counts(self):
        self.assertEqual(len(self.data["active"]), 117)
        self.assertEqual(len(self.data["retired"]), 14)
        self.assertEqual(len(self.active), 117, "duplicate active id")
        self.assertEqual(len(self.retired), 14, "duplicate retired id")

    def test_no_id_is_both_active_and_retired(self):
        self.assertEqual(set(self.active) & set(self.retired), set())

    def test_ids_account_for_every_issued_number(self):
        every = {"%s-%02d" % (fam, n) for fam, top in ISSUED.items()
                 for n in range(1, top + 1)}
        self.assertEqual(set(self.active) | set(self.retired), every)

    def test_every_id_has_the_shape_family_dash_two_digits(self):
        for rid in list(self.active) + list(self.retired):
            m = ID_RE.match(rid)
            self.assertTrue(m and m.group(1) in ISSUED, rid)

    def test_each_active_id_names_the_section_of_its_family(self):
        for rid, row in self.active.items():
            fam = ID_RE.match(rid).group(1)
            self.assertEqual(row["section"], SECTION_OF[fam], rid)

    def test_each_retired_id_has_a_disposition_and_a_live_replacement(self):
        for rid, row in self.retired.items():
            by = row["superseded_by"]
            self.assertIn(row["disposition"], {"superseded", "deleted", "retired"}, rid)
            self.assertEqual(bool(by), row["disposition"] == "superseded", rid)
            for new in by:
                self.assertIn(new, self.active, "%s -> %s" % (rid, new))

    def test_lists_are_sorted(self):
        self.assertEqual([r["id"] for r in self.data["active"]], sorted(self.active))
        self.assertEqual([r["id"] for r in self.data["retired"]], sorted(self.retired))


class ProfileText(unittest.TestCase):
    """Compares requirements.json with the headings of spec/profile.md."""

    def headings(self):
        self.assertTrue(PROFILE.is_file(), "spec/profile.md is missing")
        section = None
        found = []
        for line in PROFILE.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^## (\d+)\.", line)
            if m:
                section = int(m.group(1))
                continue
            m = re.match(r"^#{3,4} ([A-Z]+-\d\d)\b", line)
            if m:
                found.append((m.group(1), section))
        return found

    def test_profile_exists(self):
        self.assertTrue(PROFILE.is_file(), "spec/profile.md is missing")

    def test_every_active_id_has_one_heading_in_its_section(self):
        data = load_requirements()
        found = self.headings()
        for row in data["active"]:
            hits = [s for rid, s in found if rid == row["id"]]
            self.assertEqual(hits, [row["section"]], row["id"])

    def test_no_retired_id_is_a_live_heading(self):
        data = load_requirements()
        retired = {r["id"] for r in data["retired"]}
        live = [rid for rid, _ in self.headings() if rid in retired]
        self.assertEqual(live, [])

    def test_no_heading_outside_the_requirement_list(self):
        data = load_requirements()
        active = {r["id"] for r in data["active"]}
        extra = [rid for rid, _ in self.headings() if rid not in active]
        self.assertEqual(extra, [])


class ConsistencyGate(unittest.TestCase):
    """T0.11: one place that fails when the spec text drifts."""

    def spec_files(self):
        return [p for p in sorted(SPEC_DIR.rglob("*")) if p.is_file()]

    def test_all_117_ids_appear_exactly_once_as_headings(self):
        data = load_requirements()
        text = PROFILE.read_text(encoding="utf-8")
        heads = re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M)
        self.assertEqual(len(data["active"]), 117)
        self.assertEqual(sorted(heads), sorted(r["id"] for r in data["active"]))

    def test_no_retired_id_is_a_live_heading(self):
        data = load_requirements()
        retired = {r["id"] for r in data["retired"]}
        text = PROFILE.read_text(encoding="utf-8")
        live = [h for h in re.findall(r"^#{2,6} ([A-Z]+-\d\d)\b", text, re.M) if h in retired]
        self.assertEqual(live, [])

    def test_no_process_words_in_any_spec_file(self):
        for f in self.spec_files():
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                m = PROCESS_WORDS.search(line)
                self.assertIsNone(m, "%s:%d: %s" % (f.name, n, m and m.group(0)))

    def test_process_word_pattern_catches_what_it_names(self):
        for bad in ("iteration 3", "Round 4", "round 12", "judge", "judged", "OT-7", "owner decision"):
            self.assertTrue(PROCESS_WORDS.search(bad), bad)
        for ok in ("the iterator", "a rounded value", "roundtrip", "the owner key"):
            self.assertIsNone(PROCESS_WORDS.search(ok), ok)

    def test_public_voice_gate_is_clean_on_spec(self):
        terms = Path(os.environ.get("HANDSAL_PUBLIC_VOICE_TERMS", TERMS_DEFAULT))
        if not terms.is_file():
            self.fail("terms file not found: %s (the gate fails closed; set HANDSAL_PUBLIC_VOICE_TERMS)" % terms)
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import check_public_voice as gate
        finally:
            sys.path.remove(str(ROOT / "tools"))
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(["--terms", str(terms), str(SPEC_DIR)])
        self.assertEqual((code, out.getvalue()), (0, ""))

    def test_every_spec_file_is_under_the_size_limit(self):
        files = self.spec_files()
        self.assertTrue(files)
        for f in files:
            self.assertLessEqual(f.stat().st_size, MAX_SPEC_FILE_BYTES, f.name)

    def test_registry_is_present_beside_the_profile(self):
        self.assertTrue((SPEC_DIR / "registry.json").is_file())


if __name__ == "__main__":
    unittest.main()
