"""One list of core files, and the profile text that is split across several of them (CF-01).

The profile hash covers a list of files. Several tools, a Swift table and a Rust table each need that
list, and none of them can import the others, so the list lives in one owner (`manifest.CORE_FILES`)
and every other place is compared with it here. A tool that hashes or reads a different set fails
this file, not a release.

The profile is one normative text in several files, each at most MAX_PROFILE_PART_BYTES (a part
grows by editing, so it keeps room under the 256 KiB cap of test_spec_ids). The parts are
contiguous runs of sections, so a section number names one place.
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402
import repin  # noqa: E402

MAX_PROFILE_PART_BYTES = 200 * 1024
PROFILE_GLOB = "profile*.md"


def profile_parts():
    return sorted((ROOT / "spec").glob(PROFILE_GLOB))


def core_in_text(text):
    """The paths CF-01 names in its core manifest sentence."""
    sentence = re.search(r"\*\*Core manifest\*\*: (.*?)\.\n", text, re.S).group(1)
    return [path for path in re.findall(r"`([^`]+)`", sentence) if "/" in path]


class OneOwner(unittest.TestCase):
    def setUp(self):
        self.owner = list(manifest.CORE_FILES)

    def test_the_list_is_sorted_and_has_no_duplicate(self):
        self.assertEqual(self.owner, sorted(set(self.owner)))

    def test_every_profile_part_is_a_core_file_and_no_core_spec_file_is_missing(self):
        parts = ["spec/%s" % p.name for p in profile_parts()]
        self.assertGreater(len(parts), 1, "the profile is meant to be split (test_spec_ids, 256 KiB)")
        self.assertEqual([f for f in self.owner if f.startswith("spec/profile")], parts)

    def test_repin_reads_the_same_list(self):
        self.assertEqual(list(repin.CORE_FILES), self.owner)

    def test_the_checker_ships_the_same_list(self):
        text = (ROOT / "checker/python/src/handsal_check/coredata.py").read_text(encoding="utf-8")
        listed = re.search(r"CORE_FILES = \((.*?)\)", text, re.S).group(1)
        self.assertEqual(re.findall(r'"([^"]+)"', listed), self.owner)
        shipped = json.loads((ROOT / "checker/python/src/handsal_check/data/core-manifest.json").read_text())
        self.assertEqual(sorted(shipped), self.owner)

    def test_the_swift_table_has_one_row_per_file(self):
        text = (ROOT / "signer/apple/Sources/HandsalCore/Profiles.swift").read_text(encoding="utf-8")
        self.assertEqual(sorted(re.findall(r'^\s*"((?:conformance|spec)/[^"]+)": "u', text, re.M)), self.owner)

    def test_the_rust_table_embeds_each_file_once(self):
        text = (ROOT / "signer/windows/core/profiles.rs").read_text(encoding="utf-8")
        rows = re.findall(r'\("([^"]+)", include_bytes!\("\.\./\.\./\.\./([^"]+)"\)\)', text)
        self.assertEqual([a for a, _ in rows], self.owner)
        self.assertEqual([a for a, _ in rows], [b for _, b in rows])
        self.assertIn("CORE_FILES: [(&str, &[u8]); %d]" % len(self.owner), text)

    def test_the_spec_names_the_same_list(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in profile_parts())
        self.assertEqual(sorted(core_in_text(text)), self.owner)

    def test_the_errata_file_is_not_a_core_file(self):
        """CF-01 S5: spec/errata.md records editorial fixes between rule editions and moves no hash."""
        errata = ROOT / "spec" / "errata.md"
        self.assertTrue(errata.is_file(), "spec/errata.md is missing")
        self.assertNotIn("spec/errata.md", self.owner)
        self.assertNotIn("spec/errata.md", core_in_text("\n".join(p.read_text(encoding="utf-8") for p in profile_parts()) + "\n"))
        files = json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"]
        self.assertNotIn("spec/errata.md", files)

    def test_the_bundle_manifest_lists_every_core_file(self):
        files = json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"]
        self.assertEqual(sorted(f for f in files if not f.startswith("conformance/vectors/")), self.owner)

    def test_the_contract_names_every_profile_part(self):
        text = (ROOT / "conformance/CONTRACT.md").read_text(encoding="utf-8")
        for path in profile_parts():
            self.assertIn("spec/" + path.name, text)


class SplitProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parts = {p.name: p.read_text(encoding="utf-8") for p in profile_parts()}

    def test_each_part_leaves_room_to_grow(self):
        for name, text in self.parts.items():
            self.assertLessEqual(len(text.encode("utf-8")), MAX_PROFILE_PART_BYTES, name)

    def test_sections_are_contiguous_and_each_belongs_to_one_part(self):
        seen = []
        for name in sorted(self.parts, key=lambda n: (n != "profile.md", n)):
            nums = [int(m) for m in re.findall(r"^## (\d+)\.", self.parts[name], re.M)]
            self.assertEqual(nums, sorted(nums), name)
            seen += nums
        self.assertEqual(seen, list(range(0, 15)))

    def test_every_part_opens_with_a_title_and_names_its_place(self):
        for name, text in self.parts.items():
            self.assertTrue(text.startswith("# handsal profile, version 1"), name)

    def test_the_reading_guide_names_every_part(self):
        guide = self.parts["profile.md"].split("## 1. ")[0]
        for name in self.parts:
            self.assertIn("spec/" + name, guide)

    def test_a_requirement_id_has_one_heading_in_one_part(self):
        heads = [h for text in self.parts.values() for h in re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M)]
        self.assertEqual(len(heads), len(set(heads)))

    def test_every_id_the_text_cites_has_a_heading_or_is_retired(self):
        text = "\n".join(self.parts.values())
        known = set(re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M))
        req = json.loads((ROOT / "spec/requirements.json").read_text())
        known |= {r["id"] for r in req["retired"]}
        cited = set(re.findall(r"\b((?:ACT|KC|GP|FO|VR|RN|CF|SG|WT)-\d\d)\b", text))
        self.assertEqual(sorted(cited - known), [])

    def test_every_section_number_the_text_cites_exists(self):
        text = "\n".join(self.parts.values())
        heads = set(re.findall(r"^#{2,3} (\d+(?:\.\d+)?)\.? ", text, re.M))
        cited = set(re.findall(r"\bsections? (\d+(?:\.\d+)?)\b", text))
        self.assertEqual(sorted(c for c in cited if c not in heads), [])


if __name__ == "__main__":
    unittest.main()
