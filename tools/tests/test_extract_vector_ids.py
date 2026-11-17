import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import extract_vector_ids as ev  # noqa: E402

COMMITTED_IDS = ROOT / "conformance" / "vector-ids.json"
COMMITTED_ROWS = ROOT / "conformance" / "effective-rows.json"

HDR = "| id | req | input | expect |\n|---|---|---|---|\n"
HDR5 = "| id | req | cmd | input | expect |\n|---|---|---|---|---|\n"
CHG = "| id | was | now |\n|---|---|---|\n"

# retired for the macOS-only first tag (T7.7): the class is not in the registry, so none of the three can ship
WINDOWS_CLASS_IDS = ("cls/pending-class-accepted", "cls/win-hello-biometric-only-maintainer-ok",
                     "cls/win-hello-pin-capable-maintainer-refused")


def make_catalog(root, catalog="", spec3="", part2="", part3="", part4=""):
    files = {
        "spec-vectors-catalog.md": catalog,
        "spec-part3.md": spec3,
        "spec-vectors-catalog-part2.md": part2,
        "spec-vectors-catalog-part3.md": part3,
        "spec-vectors-catalog-part4.md": part4,
    }
    for name, body in files.items():
        (Path(root) / name).write_text(body, encoding="utf-8")


def base_catalog():
    return (
        "# Catalog\n\n## 1. ok\n\n" + HDR
        + "| `ok/a` | R-1 | in a | out a |\n"
        + "| `add/b` | R-2 | in b | out b |\n"
        + "| `old/gone` | R-3 | RETIRED: no longer needed | none |\n"
        + "| `jcs/c` | R-4 | in c | out c |\n"
        + "| `pin/d` | R-5 | pipe in code | `| x`, done |\n"
    )


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def build(self, **kw):
        make_catalog(self.tmp, **kw)
        return ev.build(self.tmp)

    def test_plain_rows_become_effective_rows(self):
        r = self.build(catalog=base_catalog())
        row = r.effective["add/b"]
        self.assertEqual(row, {"covers": "R-2", "input": "in b", "expected": "out b"})

    def test_pipe_inside_code_span_does_not_split_cell(self):
        r = self.build(catalog=base_catalog())
        self.assertEqual(r.effective["pin/d"]["expected"], "`| x`, done")

    def test_orig_retired_row_is_dropped(self):
        r = self.build(catalog=base_catalog())
        self.assertIn("old/gone", r.retired)
        self.assertNotIn("old/gone", r.effective)
        self.assertNotIn("old/gone", r.active)

    def test_section_26_retires_and_replaced_by_does_not(self):
        part3 = (
            "## 26. Deleted\n\n"
            "- Group: `add/b` and `jcs/c` (2).\n"
            "- Later: `ok/a` (note, replaced by `pin/d`) (1).\n"
            "- Plural: `jcs/c` replaced by `pin/d` and `add/b`.\n"
        )
        r = self.build(catalog=base_catalog(), part3=part3)
        self.assertEqual(r.retired >= {"add/b", "jcs/c", "ok/a"}, True)
        self.assertNotIn("pin/d", r.retired)

    def test_26_1_in_part4_retires(self):
        part4 = ("## 26.1 Retired\n\n- `add/b` (28.8): old; replaced by `pin/d`.\n")
        r = self.build(catalog=base_catalog(), part4=part4)
        self.assertIn("add/b", r.retired)
        self.assertNotIn("pin/d", r.retired)

    def test_draft_paragraph_in_26_is_not_a_bullet_and_retires_nothing(self):
        part3 = ("## 26. Deleted\n\n- `add/b` (1).\n\n"
                 "Draft ids never shipped: `jcs/c` by `pin/d`.\n")
        r = self.build(catalog=base_catalog(), part3=part3)
        self.assertNotIn("jcs/c", r.retired)

    def test_later_layer_wins_field_by_field(self):
        part2 = "## 23. Changed\n\n" + CHG + "| `add/b` | out b | out b2 |\n"
        part3 = "## 27. Changed\n\n" + CHG + "| `add/b` | x | input: new in |\n"
        r = self.build(catalog=base_catalog(), part2=part2, part3=part3)
        self.assertEqual(r.effective["add/b"],
                         {"covers": "R-2", "input": "input: new in", "expected": "out b2"})

    def test_full_row_in_later_layer_replaces_all_fields(self):
        part4 = "## 30 Re-anchors\n\n| Id | Covers | Input | Expected |\n|---|---|---|---|\n" \
                "| `jcs/c` | R-9 | in c9 | out c9 |\n"
        r = self.build(catalog=base_catalog(), part4=part4)
        self.assertEqual(r.effective["jcs/c"],
                         {"covers": "R-9", "input": "in c9", "expected": "out c9"})

    def test_anchor_and_mixed_tables(self):
        part3 = (
            "### 27.1 Remap\n\n"
            "| id | new req | anchored input |\n|---|---|---|\n"
            "| `add/b` | R-22 | anchored in |\n"
            "### 27.3 Re-anchor\n\n"
            "| id | req | iteration 4 input or expectation |\n|---|---|---|\n"
            "| `jcs/c` | R-33 | expectation changed: `fork` |\n"
        )
        r = self.build(catalog=base_catalog(), part3=part3)
        self.assertEqual(r.effective["add/b"],
                         {"covers": "R-22", "input": "anchored in", "expected": "out b"})
        self.assertEqual(r.effective["jcs/c"],
                         {"covers": "R-33", "input": "in c", "expected": "expectation changed: `fork`"})

    def test_multi_id_first_cell_applies_to_each_id(self):
        part3 = ("### 27.3 Re-anchor\n\n"
                 "| id | req | iteration 4 input or expectation |\n|---|---|---|\n"
                 "| `add/b`, `jcs/c` | R-44 | shared anchor |\n")
        r = self.build(catalog=base_catalog(), part3=part3)
        self.assertEqual(r.effective["add/b"]["input"], "shared anchor")
        self.assertEqual(r.effective["jcs/c"]["input"], "shared anchor")

    def test_multi_layer_ids_reported(self):
        part2 = "## 23. Changed\n\n" + CHG + "| `add/b` | a | b |\n"
        r = self.build(catalog=base_catalog(), part2=part2)
        self.assertEqual(r.multi_layer, {"add/b": ["catalog", "part2-23"]})

    def test_same_layer_conflict_fails_loudly(self):
        cat = base_catalog() + "\n## 2. jws\n\n" + HDR + "| `add/b` | R-2 | other | out b |\n"
        make_catalog(self.tmp, catalog=cat)
        with self.assertRaises(ev.LayerConflict) as cm:
            ev.build(self.tmp)
        self.assertIn("add/b", str(cm.exception))
        self.assertIn("spec-vectors-catalog.md", str(cm.exception))

    def test_same_layer_identical_rows_are_fine(self):
        cat = base_catalog() + "\n## 2. jws\n\n" + HDR + "| `add/b` | R-2 | in b | out b |\n"
        r = self.build(catalog=cat)
        self.assertEqual(r.effective["add/b"]["input"], "in b")

    def test_amendment_without_base_row_fails(self):
        part2 = "## 23. Changed\n\n" + CHG + "| `zzz/none` | a | b |\n"
        make_catalog(self.tmp, catalog=base_catalog(), part2=part2)
        with self.assertRaises(ev.CatalogError):
            ev.build(self.tmp)

    def test_row_in_unmapped_section_fails(self):
        cat = base_catalog() + "\n## 99. Odd\n\n" + HDR + "| `add/q` | R | i | o |\n"
        make_catalog(self.tmp, catalog=cat)
        with self.assertRaises(ev.CatalogError):
            ev.build(self.tmp)

    def test_unknown_table_shape_fails(self):
        part3 = "### 27.1 Remap\n\n| id | foo | bar | baz | qux | zip |\n|---|---|---|---|---|---|\n" \
                "| `add/b` | 1 | 2 | 3 | 4 | 5 |\n"
        make_catalog(self.tmp, catalog=base_catalog(), part3=part3)
        with self.assertRaises(ev.CatalogError):
            ev.build(self.tmp)

    def test_spec_part3_section_14_is_a_layer_between_catalog_and_part2(self):
        spec3 = ("## 13. Other\n\n" + HDR + "| `zzz/ignored` | x | y | z |\n\n"
                 "## 14. Vectors\n\n" + HDR5 + "| `wit/a` | WT-1 | check-act | in w | out w |\n")
        part2 = "## 23. Changed\n\n" + CHG + "| `wit/a` | out w | out w2 |\n"
        r = self.build(catalog=base_catalog(), spec3=spec3, part2=part2)
        self.assertEqual(r.effective["wit/a"],
                         {"covers": "WT-1", "input": "in w", "expected": "out w2"})
        self.assertNotIn("zzz/ignored", r.effective)

    def test_no_id_is_conditional_and_every_active_id_ships(self):
        r = self.build(catalog=base_catalog())
        self.assertFalse(hasattr(r, "conditional"))
        self.assertFalse(hasattr(r, "ship_count"))

    def test_a_production_key_vector_is_pending_until_the_owner_signs_it(self):
        cat = base_catalog() + "| `fix/prodk-a` | R-6 | in | out |\n| `enr/prodk-b` | R-7 | in | out |\n"
        r = self.build(catalog=cat)
        self.assertEqual(r.pending, ["enr/prodk-b", "fix/prodk-a"])
        self.assertEqual(self.build(catalog=base_catalog()).pending, [])

    def test_a_cross_edition_vector_is_pending_only_when_the_owner_signs_it(self):
        """CF-08: owner-signed is the name, in every group. A `prf/` vector the generator can build is no pending id."""
        cat = (base_catalog() + "| `prf/downgrade-refused` | R-6 | in | out |\n| `fix/prodk-a` | R-7 | in | out |\n"
               "| `prf/prodk-change-ok` | R-8 | in | out |\n")
        r = self.build(catalog=cat)
        self.assertEqual(r.pending, ["fix/prodk-a", "prf/prodk-change-ok"])
        self.assertIn("prf/downgrade-refused", r.active)

    def test_owner_signed_is_the_name_after_the_group(self):
        self.assertTrue(ev.is_owner_signed("fix/prodk-fold-ok"))
        self.assertTrue(ev.is_owner_signed("prf/prodk-change-p1-to-p2-ok"))
        self.assertFalse(ev.is_owner_signed("prf/change-p1-to-p2-ok"))
        self.assertFalse(ev.is_owner_signed("add/ok"))
        self.assertFalse(ev.is_owner_signed("prodk/ok"))

    def test_a_pending_id_still_ships_at_the_tag(self):
        cat = base_catalog() + "| `fix/prodk-a` | R-6 | in | out |\n"
        r = self.build(catalog=cat)
        self.assertIn("fix/prodk-a", r.active)

    def test_main_writes_the_pending_list(self):
        make_catalog(self.tmp, catalog=base_catalog() + "| `fix/prodk-a` | R-6 | in | out |\n")
        out = self.tmp / "o"
        self.assertEqual(ev.main([str(self.tmp), "--out-dir", str(out)]), 0)
        self.assertEqual(json.loads((out / "vector-ids.json").read_text())["pending"], ["fix/prodk-a"])

    def test_main_writes_both_files_deterministically(self):
        make_catalog(self.tmp, catalog=base_catalog())
        out1, out2 = self.tmp / "o1", self.tmp / "o2"
        for o in (out1, out2):
            o.mkdir()
            self.assertEqual(ev.main([str(self.tmp), "--out-dir", str(o)]), 0)
        for name in ("vector-ids.json", "effective-rows.json"):
            self.assertEqual((out1 / name).read_bytes(), (out2 / name).read_bytes())
        data = json.loads((out1 / "vector-ids.json").read_text())
        self.assertEqual(data["active_count"], len(data["ids"]))
        self.assertNotIn("ship_count", data)
        self.assertNotIn("conditional", data)

    def test_scrub_removes_provenance_and_renames_judged(self):
        cat = base_catalog() + (
            "| `add/p` | R-7 | input (iteration 3): c1 (round-5 judge A 3) | "
            "ok (on the judged path; round 6, judge A 14), `fork` |\n")
        r = self.build(catalog=cat)
        row = r.effective["add/p"]
        self.assertIsNone(ev.PROVENANCE.search(" ".join(row.values())), row)
        self.assertIn("examined path", row["expected"])
        self.assertIn("`fork`", row["expected"])
        self.assertIn("add/p", r.scrubbed)

    def test_unscrubbable_cell_fails_naming_the_id(self):
        cat = base_catalog() + "| `add/q` | R-7 | in | the judge liked it |\n"
        make_catalog(self.tmp, catalog=cat)
        with self.assertRaises(ev.CatalogError) as cm:
            ev.build(self.tmp)
        self.assertIn("add/q", str(cm.exception))

    def test_process_word_in_an_id_is_renamed(self):
        cat = base_catalog() + "| `add/on-judged-paths` | R-7 | in | out |\n"
        r = self.build(catalog=cat)
        self.assertIn("add/on-examined-paths", r.effective)
        self.assertNotIn("add/on-judged-paths", r.effective)

    def test_rows_carry_layers_lowest_first(self):
        part2 = "## 23. Changed\n\n" + CHG + "| `add/b` | a | b |\n"
        r = self.build(catalog=base_catalog(), part2=part2)
        self.assertEqual(r.layers["add/b"], ["catalog", "part2-23"])
        self.assertEqual(r.layers["ok/a"], ["catalog"])

    def test_mixed_cell_rows_are_marked_heuristic(self):
        part3 = ("### 27.3 Re-anchor\n\n"
                 "| id | req | iteration 4 input or expectation |\n|---|---|---|\n"
                 "| `jcs/c` | R-33 | expectation changed: `fork` |\n"
                 "| `add/b` | R-34 | a plain anchor |\n")
        r = self.build(catalog=base_catalog(), part3=part3)
        self.assertEqual(r.heuristic["jcs/c"], "expected")
        self.assertEqual(r.heuristic["add/b"], "input")
        self.assertNotIn("ok/a", r.heuristic)

    def test_heuristic_is_dropped_when_a_later_layer_sets_the_field(self):
        part3 = ("### 27.3 Re-anchor\n\n"
                 "| id | req | iteration 4 input or expectation |\n|---|---|---|\n"
                 "| `add/b` | R-34 | a plain anchor |\n")
        part4 = "## 30 Re-anchors\n\n| Id | Covers | Input | Expected |\n|---|---|---|---|\n" \
                "| `add/b` | R-9 | in b9 | out b9 |\n"
        r = self.build(catalog=base_catalog(), part3=part3, part4=part4)
        self.assertNotIn("add/b", r.heuristic)

    def test_main_writes_layers_and_heuristic_into_rows(self):
        part3 = ("### 27.3 Re-anchor\n\n"
                 "| id | req | iteration 4 input or expectation |\n|---|---|---|\n"
                 "| `add/b` | R-34 | a plain anchor |\n")
        make_catalog(self.tmp, catalog=base_catalog(), part3=part3)
        out = self.tmp / "o"
        self.assertEqual(ev.main([str(self.tmp), "--out-dir", str(out)]), 0)
        rows = json.loads((out / "effective-rows.json").read_text())["rows"]
        self.assertEqual(rows["add/b"]["layers"], ["catalog", "part3-27.3"])
        self.assertEqual(rows["add/b"]["heuristic"], "input")
        self.assertEqual(rows["ok/a"]["layers"], ["catalog"])
        self.assertNotIn("heuristic", rows["ok/a"])

    def test_main_missing_dir_is_usage_error(self):
        self.assertEqual(ev.main([str(self.tmp / "nope")]), 2)


class CommittedFiles(unittest.TestCase):
    def test_committed_files_are_clean_and_consistent(self):
        ids = json.loads(COMMITTED_IDS.read_text(encoding="utf-8"))
        rows = json.loads(COMMITTED_ROWS.read_text(encoding="utf-8"))
        # the counts are what the lists say: no number is typed here to be edited by hand at the next retirement
        self.assertEqual(ids["active_count"], len(ids["ids"]))
        self.assertNotIn("ship_count", ids)
        self.assertNotIn("conditional", ids)
        for name in WINDOWS_CLASS_IDS:
            self.assertIn(name, ids["retired"])
            self.assertNotIn(name, ids["ids"])
            self.assertNotIn(name, rows["rows"])
        self.assertEqual(ids["retired_count"], len(ids["retired"]))
        self.assertTrue(ids["pending"])
        for name in ids["pending"]:
            self.assertTrue(ev.is_owner_signed(name), name)
        self.assertEqual(sorted(rows["rows"]), sorted(ids["ids"]))
        self.assertFalse(set(ids["retired"]) & set(ids["ids"]))
        for p in (COMMITTED_IDS, COMMITTED_ROWS):
            text = p.read_text(encoding="utf-8")
            m = ev.PROVENANCE.search(text)
            self.assertIsNone(m, "%s: %s" % (p.name, m and m.group(0)))


if __name__ == "__main__":
    unittest.main()
