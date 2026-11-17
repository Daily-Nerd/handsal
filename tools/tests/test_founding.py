"""The founded repo (GP-22 S5, SG-02 S3): the cases the empty catalog could only pass trivially.

`test_core_files.EditionTables` compares the five lists of editions and passes while all of them are empty. Here the
real tree must list the founding edition once, equally, in every list, and the Rust table must embed the frozen
directory that its row names.
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402
from . import test_core_files as core  # noqa: E402

LABEL = "edition-1"
FROZEN = ("core-manifest.json", "spec/registry.json", "conformance/fixtures/fixture-kids.json")


class Founded(unittest.TestCase):
    def test_the_checker_swift_and_rust_tables_list_the_catalog_and_it_starts_with_the_founding_edition(self):   # GP-22 S5
        found = core.tables(ROOT)
        pins = json.loads((ROOT / core.PINS).read_text(encoding="utf-8"))
        first = pins["profiles"][0]
        for name, rows in found.items():
            self.assertEqual(rows[0], (LABEL, first["production"], first["fixture"]), name)
        self.assertEqual(core.table_problems(found), [])

    def test_the_signer_version_lists_every_frozen_edition_once_and_then_the_live_core(self):   # SG-02 S3
        pins = json.loads((ROOT / core.PINS).read_text(encoding="utf-8"))
        want = [row["production"] for row in pins["profiles"]]
        if want[-1] != pins["production_profile"]:
            want.append(pins["production_profile"])
        self.assertEqual(core.version_lists(ROOT), {"swift": want, "rust": want, "python": want})

    def test_the_rust_rows_embed_the_frozen_directory_of_their_label(self):   # GP-22 S5
        text = (ROOT / core.RUST_PROFILES).read_text(encoding="utf-8")
        body = re.search(r"pub const VERSIONS: &\[FrozenRow<'static>\] = &\[(.*?)\];", text, re.S).group(1)
        labels = [row["label"] for row in json.loads((ROOT / "profiles" / "catalog.json").read_text(encoding="utf-8"))]
        self.assertEqual(sorted(re.findall(r'include_bytes!\("\.\./\.\./\.\./(profiles/[^"]+)"\)', body)),
                         sorted("profiles/%s/%s" % (label, rel) for label in labels for rel in FROZEN))

    def test_the_catalog_rows_are_no_core_file_and_the_newest_names_the_bundle_of_the_tree_while_it_is_current(self):   # CF-15
        rows = json.loads((ROOT / "profiles" / "catalog.json").read_text(encoding="utf-8"))
        for row in rows:
            self.assertEqual(sorted(row), sorted(manifest.CATALOG_ROW_FIELDS))
        if manifest.production_profile(ROOT) == rows[-1]["production"]:
            self.assertEqual(rows[-1]["bundle"], manifest.bundle_hash(ROOT))
        else:
            self.assertNotEqual(rows[-1]["bundle"], manifest.bundle_hash(ROOT))


if __name__ == "__main__":
    unittest.main()
