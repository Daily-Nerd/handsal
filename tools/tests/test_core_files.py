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
from . import test_repin  # noqa: E402

MAX_PROFILE_PART_BYTES = 200 * 1024
PROFILE_GLOB = "profile*.md"


def profile_parts():
    return sorted((ROOT / "spec").glob(PROFILE_GLOB))


def core_in_text(text):
    """The paths CF-01 names in its core manifest sentence."""
    sentence = re.search(r"\*\*Core manifest\*\*: (.*?)\.\n", text, re.S).group(1)
    return [path for path in re.findall(r"`([^`]+)`", sentence) if "/" in path]


def live_table_paths(swift):
    """The rows of the live `coreManifest` table: the rows outside the generated edition region of repin.py, whose
    frozen blocks list the core files of an older edition."""
    live = re.sub(r"^\s*// handsal:editions begin$.*?^\s*// handsal:editions end$", "", swift, flags=re.M | re.S)
    return re.findall(r'^\s*"((?:conformance|spec)/[^"]+)": "u', live, re.M)


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
        self.assertNotIn("CORE_FILES", text.replace("`CORE_FILES`", ""))   # the checker holds no copy of the list
        script = (ROOT / "checker/python/sync_core.py").read_text(encoding="utf-8")
        self.assertIn("tools/manifest.py", script.replace('"tools" / "manifest.py"', "tools/manifest.py"))
        shipped = json.loads((ROOT / "checker/python/src/handsal_check/data/core-manifest.json").read_text())
        self.assertEqual(sorted(shipped), self.owner)

    def test_the_swift_table_has_one_row_per_file(self):
        text = (ROOT / "signer/apple/Sources/HandsalCore/Profiles.swift").read_text(encoding="utf-8")
        self.assertEqual(sorted(live_table_paths(text)), self.owner)

    def test_the_live_table_reading_skips_the_frozen_edition_blocks(self):
        text = ('        "spec/a.md": "uA",\n    // handsal:editions begin\n            "spec/old.md": "uB",\n'
                '    // handsal:editions end\n        "spec/z.md": "uC",\n')
        self.assertEqual(live_table_paths(text), ["spec/a.md", "spec/z.md"])

    def test_the_rust_table_embeds_each_file_once(self):
        text = (ROOT / "signer/windows/core/profiles.rs").read_text(encoding="utf-8")
        rows = re.findall(r'\("([^"]+)", include_bytes!\("\.\./\.\./\.\./([^"]+)"\)\)', text)
        self.assertEqual([a for a, _ in rows], self.owner)
        self.assertEqual([a for a, _ in rows], [b for _, b in rows])
        self.assertIn("CORE_FILES: [(&str, &[u8]); %d]" % len(self.owner), text)

    def test_the_spec_names_the_same_list(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in profile_parts())
        self.assertEqual(sorted(core_in_text(text)), self.owner)

    def not_the_catalog(self, files):
        """GP-22 S8: no list of core files names the catalog or anything under `profiles/`."""
        self.assertEqual([f for f in files if f == "profiles/catalog.json" or f.startswith("profiles/")], [])

    def test_the_catalog_is_not_a_core_file(self):
        """GP-22 S8: a catalog among the core files would move the hash of every older edition (a fixed point)."""
        self.not_the_catalog(self.owner)
        self.not_the_catalog(core_in_text("\n".join(p.read_text(encoding="utf-8") for p in profile_parts()) + "\n"))
        self.not_the_catalog(json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"])
        self.not_the_catalog(json.loads((ROOT / "checker/python/src/handsal_check/data/core-manifest.json").read_text()))
        self.not_the_catalog(repin.CORE_FILES)
        with self.assertRaises(AssertionError):   # the test fails when the catalog is added to a list
            self.not_the_catalog(self.owner + ["profiles/catalog.json"])
        with self.assertRaises(AssertionError):
            self.not_the_catalog(self.owner + ["profiles/edition-1/core-manifest.json"])

    def test_the_errata_file_is_not_a_core_file(self):
        """CF-01 S5: spec/errata.md records editorial fixes between rule editions and moves no hash."""
        errata = ROOT / "spec" / "errata.md"
        self.assertTrue(errata.is_file(), "spec/errata.md is missing")
        self.assertNotIn("spec/errata.md", self.owner)
        self.assertNotIn("spec/errata.md", core_in_text("\n".join(p.read_text(encoding="utf-8") for p in profile_parts()) + "\n"))
        files = json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"]
        self.assertNotIn("spec/errata.md", files)
        self.assertIn("never changes what any verifier, signer or consumer answers", errata.read_text(encoding="utf-8"))

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

    def test_no_part_names_an_ordinal_of_its_own(self):
        """The parts are four, and a title that says "part 2" or "second part" goes stale at the next split."""
        for name, text in self.parts.items():
            head = "\n".join(text.split("\n")[:4])
            self.assertNotRegex(head, r"(?i)\bpart \d\b|\b(second|third|fourth) part\b", name)

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


class CatalogWriters(test_repin.CatalogFixture, unittest.TestCase):
    """CF-01 S4: the tools that write core data write only the current edition and append to the catalog."""

    def test_repin_writes_only_the_current_edition_and_appends_the_catalog(self):
        frozen = {k: v for k, v in test_repin.snapshot(self.tmp).items() if k.startswith("profiles/")}
        self.assertEqual(self.run_tool("--write")[0], 0)
        manifest.write_bundle_manifest(self.tmp)   # the third writer: the bundle manifest
        self.assertEqual({k: v for k, v in test_repin.snapshot(self.tmp).items() if k.startswith("profiles/")}, frozen)
        pins = json.loads((self.tmp / repin.PINS).read_text())
        core_b, pins_b, _o, _w = test_repin.expected(test_repin.CORE_B)
        self.assertEqual(pins["profiles"], [{"label": "edition-1", "production": pins_b["production_profile"],
                                             "fixture": pins_b["fixture_profile"]}])
        self.assertEqual(pins["production_profile"], self.pins["production_profile"])
        self.assertNotEqual(pins["production_profile"], pins_b["production_profile"])
        swift = (self.tmp / repin.SWIFT).read_text()
        for rel, digest in self.core.items():   # the live table is the current edition's
            self.assertIn('        "%s": "%s",' % (rel, digest), swift)
        self.assertEqual(self.blocks(), ["edition-1"])
        block = swift.split("// handsal:edition begin edition-1")[1].split("// handsal:edition end edition-1")[0]
        for rel, digest in core_b.items():
            self.assertIn('"%s": "%s",' % (rel, digest), block)
        self.assertIn(pins_b["production_profile"], block)
        self.assertIn(pins_b["fixture_profile"], block)
        self.assertIn('"k1"', block)
        self.assertIn(test_repin.CORE_B["spec/registry.json"].decode(), block)
        listed = json.loads((self.tmp / manifest.BUNDLE_FILE).read_text())["files"]
        self.assertEqual([f for f in listed if f.startswith("profiles/")], [])


if __name__ == "__main__":
    unittest.main()
