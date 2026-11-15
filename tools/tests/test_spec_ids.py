import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402

REQUIREMENTS = ROOT / "spec" / "requirements.json"
PROFILES = [ROOT / rel for rel in manifest.PROFILE_FILES]


def profile_text():
    """The profile, whole: every part (the profile is split by section to stay under the size cap)."""
    return manifest.read_profile(ROOT)
SPEC_DIR = ROOT / "spec"

# Decision: every file under spec/ stays at or under 256 KiB. The profile is
# one text in several parts, each a reviewable document; past this size a part
# is split, not grown (test_core_files.py keeps each part under a lower bar).
MAX_SPEC_FILE_BYTES = 256 * 1024

# Ids issued per family over the life of the profile text (active + retired).
ISSUED = {"ACT": 14, "KC": 9, "GP": 21, "FO": 27, "VR": 18, "RN": 12,
          "CF": 14, "SG": 16, "WT": 10}
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
        self.assertEqual(len(self.data["active"]), 127)
        self.assertEqual(len(self.data["retired"]), 14)
        self.assertEqual(len(self.active), 127, "duplicate active id")
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
    """Compares requirements.json with the headings of the profile parts."""

    def headings(self):
        self.assertTrue(all(p.is_file() for p in PROFILES), "a profile part is missing")
        section = None
        found = []
        for line in profile_text().splitlines():
            m = re.match(r"^## (\d+)\.", line)
            if m:
                section = int(m.group(1))
                continue
            m = re.match(r"^#{3,4} ([A-Z]+-\d\d)\b", line)
            if m:
                found.append((m.group(1), section))
        return found

    def test_profile_exists(self):
        self.assertTrue(all(p.is_file() for p in PROFILES), "a profile part is missing")

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

    def test_all_127_ids_appear_exactly_once_as_headings(self):
        data = load_requirements()
        text = profile_text()
        heads = re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M)
        self.assertEqual(len(data["active"]), 127)
        self.assertEqual(sorted(heads), sorted(r["id"] for r in data["active"]))

    def test_no_retired_id_is_a_live_heading(self):
        data = load_requirements()
        retired = {r["id"] for r in data["retired"]}
        text = profile_text()
        live = [h for h in re.findall(r"^#{2,6} ([A-Z]+-\d\d)\b", text, re.M) if h in retired]
        self.assertEqual(live, [])

    def test_every_spec_file_is_under_the_size_limit(self):
        files = self.spec_files()
        self.assertTrue(files)
        for f in files:
            self.assertLessEqual(f.stat().st_size, MAX_SPEC_FILE_BYTES, f.name)

    def test_registry_is_present_beside_the_profile(self):
        self.assertTrue((SPEC_DIR / "registry.json").is_file())


if __name__ == "__main__":
    unittest.main()
