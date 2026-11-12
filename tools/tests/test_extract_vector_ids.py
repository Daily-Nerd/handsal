import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import extract_vector_ids as ev  # noqa: E402
from public_text import PROCESS_WORDS  # noqa: E402

VAULT = Path("/Users/kibukx/Documents/Obsidian/kibukx/01-projects/active/handsal/sdd/profile-spec")
COMMITTED_IDS = ROOT / "conformance" / "vector-ids.json"
COMMITTED_ROWS = ROOT / "conformance" / "effective-rows.json"

KNOWN_GROUPS = {
    "ok", "jws", "jcs", "sch", "mth", "bod", "vrd", "ord", "chk", "vtn", "sig",
    "org", "idn", "inp", "rly", "rep", "tim", "frs", "ing", "gen", "pol", "pin",
    "chg", "cls", "fld", "add", "mem", "rem", "cas", "rev", "quo", "end", "lnk",
    "frk", "rsv", "cln", "enr", "rnd", "cli", "cf", "sgn", "wit", "fix", "key",
}

HDR = "| id | req | input | expect |\n|---|---|---|---|\n"
HDR5 = "| id | req | cmd | input | expect |\n|---|---|---|---|---|\n"
CHG = "| id | was | now |\n|---|---|---|\n"

PAIR = ("cls/win-hello-biometric-only-maintainer-ok",
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
        + "| `cls/win-hello-biometric-only-maintainer-ok` | K | win a | ok |\n"
        + "| `cls/win-hello-pin-capable-maintainer-refused` | K | win b | no |\n"
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

    def test_conditional_pair_flagged_and_ship_count(self):
        r = self.build(catalog=base_catalog())
        self.assertEqual(r.conditional, list(PAIR))
        self.assertEqual(r.ship_count, len(r.active) - 1)

    def test_missing_pair_fails(self):
        cat = base_catalog().replace("cls/win-hello-pin-capable-maintainer-refused", "cls/other")
        make_catalog(self.tmp, catalog=cat)
        with self.assertRaises(ev.CatalogError):
            ev.build(self.tmp)

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
        self.assertEqual(data["ship_count"], data["active_count"] - 1)
        self.assertEqual(data["conditional"], list(PAIR))
        self.assertNotIn(chr(0x2014), (out1 / "vector-ids.json").read_text())

    def test_scrub_removes_provenance_and_renames_judged(self):
        cat = base_catalog() + (
            "| `add/p` | R-7 | input (iteration 3): c1 (round-5 judge A 3) | "
            "ok (on the judged path; round 6, judge A 14), `fork` |\n")
        r = self.build(catalog=cat)
        row = r.effective["add/p"]
        self.assertIsNone(PROCESS_WORDS.search(" ".join(row.values())), row)
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


@unittest.skipUnless(VAULT.is_dir(), "real catalog not on this machine")
class RealCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = ev.build(VAULT)

    def test_counts_match_the_third_amendment_of_section_30(self):
        r = self.result
        self.assertEqual(len(r.retired), 106)     # 98 + 8
        self.assertEqual(len(r.active), 873)      # 880 - 8 + 1
        self.assertEqual(r.ship_count, 872)
        self.assertEqual(len(r.conditional), 2)

    def test_third_amendment_retires_production_only_ids_and_makes_resolve_rows_fold_rows(self):
        r = self.result
        production_only = {
            "cli/prod-pin-input-refused", "cli/prod-now-input-refused",
            "cli/prod-fixture-profile-refused", "cli/prod-reads-pin-in-process",
            "cli/conformance-not-on-admin-path", "cli/windows-gate-isolated-python",
            "pin/probe-symlink-ancestor", "rsv/override-entry-non-canonical-hashstr-ignored"}
        self.assertEqual(production_only - r.retired, set())
        self.assertEqual(production_only & set(r.active), set())
        self.assertIn("rsv/stale-head-covers-removal-ignored", r.active)
        for ident in ("override-entry", "override-resolve", "candidate", "head", "choose"):
            row = r.effective["rsv/%s-non-canonical-hashstr" % ident]
            self.assertTrue(row["input"].startswith(("fold", "the bag of")), ident)
            self.assertEqual(row["expected"], "the resolve is ignored; `fork` at the root", ident)
        self.assertIn("grace", r.effective["chg/carried-kid-other-person-device-changed"]["input"])
        self.assertIn("32 characters", r.effective["rnd/prompt-line-max-promote"]["input"])
        self.assertIn("`expect_method` is `local:handsal.record.promote`",
                      r.effective["vrd/record-outputs-not-empty"]["input"])

    def test_second_amendment_retires_renames_and_splits(self):
        r = self.result
        retired = {"frk/two-self-removals-fork", "wit/superseded-by-bag-successor",
                   "wit/ceremony-refuses-fixture-relay-kid", "ing/invalid-not-recorded-by-receipt-id",
                   "ing/record-contains-tip", "sgn/windows-pin-helper-refuses-rollback"}
        retired |= {i for i in r.retired if i.startswith("sgn/pin-helper-")}
        self.assertEqual(len([i for i in r.retired if i.startswith("sgn/pin-helper-")]), 17)
        self.assertEqual(retired - r.retired, set())
        self.assertEqual(retired & set(r.active), set())
        self.assertIn("frk/two-self-removals-no-fork", r.active)
        self.assertEqual(r.effective["rly/uppercase-relay-schema"]["expected"], "`schema`")
        for ident in ("rnd/resolve-candidate-missing", "rnd/resolve-head-attachment-missing"):
            self.assertTrue(r.effective[ident]["expected"].startswith("`attachment_mismatch`"), ident)
        self.assertIn("Resolve fork, keep: ", r.effective["rnd/chain-resolve"]["expected"])
        self.assertNotIn("Resolve fork at", r.effective["rnd/chain-resolve"]["expected"])
        self.assertIn("dave holds no role", r.effective["chg/unaccepted-signer-not-counted"]["input"])
        self.assertIn("bob signs", r.effective["cln/losing-branch-no-effect"]["input"])
        self.assertEqual(r.effective["wit/superseded-epoch-refused"]["input"],
                         "statement for epoch 0 with `next` `\"yes\"`")
        for ident in ("frk/losing-branch-extension-lifted", "frk/r11-override-lifts",
                      "rsv/override-resolve-non-canonical-hashstr", "rnd/prompt-line-max-genesis-change",
                      "vrd/record-outputs-not-empty", "cli/genesis-check-missing-head-acts-invalid"):
            self.assertIn(ident, r.active)

    def test_no_staged_row_states_several_cases_in_one_cell(self):
        """One id, one case: no amended cell lists stages ("after R1: ... after R2: ...")."""
        for ident, row in self.result.effective.items():
            if ident.startswith(("frk/", "rsv/")):
                self.assertNotRegex(row["expected"], r"after [A-Za-z0-9_]+:.*after [A-Za-z0-9_]+:", ident)

    def test_amendment_retires_the_unobservable_ids_and_adds_one_id_per_case(self):
        r = self.result
        unobservable = {
            "vtn/unexpected-vitni-reason", "vtn/unknown-vitni-reason-string",
            "cli/verifier-unavailable", "cli/vitni-env-ignored", "cli/vitni-path-not-root-owned",
            "fld/verifier-unavailable", "sig/s-equals-half", "fld/cycle"}
        self.assertEqual(unobservable & set(r.active), set())
        self.assertEqual(unobservable & r.retired, unobservable)
        added = {"fld/at-0-state", "fld/at-1-state", "fld/at-3-state", "fld/at-4-state",
                 "pin/duplicate-key-differing-values", "pin/lineage-original-not-org"}
        self.assertEqual(added - set(r.active), set())
        self.assertIn("at \"2\"", r.effective["fld/at-prefix-states"]["input"])
        self.assertNotIn("0..4", r.effective["fld/at-prefix-states"]["input"])
        self.assertIn("same value", r.effective["pin/duplicate-key"]["input"])
        self.assertTrue(r.effective["quo/two-lost-persons-unreachable"]["expected"]
                        .startswith("`genesis_change_unauthorized`"))

    def test_no_retired_id_appears(self):
        r = self.result
        self.assertFalse(set(r.retired) & set(r.active))
        self.assertFalse(set(r.retired) & set(r.effective))

    def test_every_id_has_a_known_group_prefix(self):
        for i in self.result.active:
            self.assertRegex(i, r"^[a-z0-9]+/[A-Za-z0-9._-]+$")
            self.assertIn(i.split("/")[0], KNOWN_GROUPS, i)

    def test_one_effective_row_per_id_with_all_fields(self):
        r = self.result
        self.assertEqual(sorted(r.effective), sorted(r.active))
        for i, row in r.effective.items():
            self.assertEqual(set(row), {"covers", "input", "expected"}, i)
            for k, v in row.items():
                self.assertIsInstance(v, str, (i, k))

    def test_multi_layer_ids_resolve_to_exactly_one_row(self):
        r = self.result
        self.assertTrue(r.multi_layer)
        for i in r.multi_layer:
            if i in r.retired:
                continue
            self.assertIn(i, r.effective)
            self.assertIsInstance(r.effective[i], dict)

    def test_known_later_layer_values_win(self):
        row = self.result.effective["jcs/payload-null"]
        self.assertEqual(row["expected"], "`payload_not_canonical_subset`")

    def test_output_has_no_process_words(self):
        r = self.result
        texts = list(r.active) + sorted(r.retired)
        for i, row in r.effective.items():
            texts.extend(row.values())
        for t in texts:
            self.assertIsNone(PROCESS_WORDS.search(t), t)

    def test_committed_json_is_reproduced_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(ev.main([str(VAULT), "--out-dir", d]), 0)
            self.assertEqual((Path(d) / "vector-ids.json").read_bytes(), COMMITTED_IDS.read_bytes())
            self.assertEqual((Path(d) / "effective-rows.json").read_bytes(), COMMITTED_ROWS.read_bytes())


class CommittedFiles(unittest.TestCase):
    def test_committed_files_are_clean_and_consistent(self):
        ids = json.loads(COMMITTED_IDS.read_text(encoding="utf-8"))
        rows = json.loads(COMMITTED_ROWS.read_text(encoding="utf-8"))
        self.assertEqual(ids["ship_count"], 872)
        self.assertEqual(ids["active_count"], 873)
        self.assertEqual(sorted(rows["rows"]), sorted(ids["ids"]))
        self.assertFalse(set(ids["retired"]) & set(ids["ids"]))
        for p in (COMMITTED_IDS, COMMITTED_ROWS):
            text = p.read_text(encoding="utf-8")
            self.assertNotIn(chr(0x2014), text)
            m = PROCESS_WORDS.search(text)
            self.assertIsNone(m, "%s: %s" % (p.name, m and m.group(0)))
            self.assertIsNone(re.search(r"co-author|generated" + r"\s+with|cla" + "ude|anthro" + "pic", text, re.I))

    def test_committed_files_pass_the_public_voice_gate(self):
        terms = Path(os.environ.get("HANDSAL_PUBLIC_VOICE_TERMS",
                                    Path.home() / ".config" / "handsal" / "public-voice-terms.txt"))
        if not terms.is_file():
            self.fail("terms file not found: %s (the gate fails closed)" % terms)
        import check_public_voice as gate
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(["--terms", str(terms), str(COMMITTED_IDS), str(COMMITTED_ROWS)])
        self.assertEqual((code, out.getvalue()), (0, ""))


if __name__ == "__main__":
    unittest.main()
