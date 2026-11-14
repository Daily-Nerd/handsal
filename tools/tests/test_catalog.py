"""The catalog check (CF-07, CF-02): every hole in the vector set is reported.

Synthetic trees prove each hole kind is found; the real tree proves the
structural invariants that hold today.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import check_catalog as cc  # noqa: E402
import manifest  # noqa: E402

SPEC = """\
## 9. Conformance

### CF-07 Coverage rule

Every reason code defined here, except `verifier_unavailable` and `verifier_unexpected`, MUST have at least one vector.

Ordering vectors for VR-02: 1/2 `ord/a-before-b`; 2/3 `ord/b-before-c`; inside 2 `ord/inner`.

Ordering vectors for GP-15: `gen/order-x-before-y`, `gen/order-y-before-z`.

One adjacent pair of GP-15 has no vector: `role_key_class` before `fixture_key` (step 3).

### CF-08 next

## 11. Reason codes

| Code | Where |
|---|---|
| `alpha`, `beta` | step 1 |
| fold error codes (below) | fold |
| `ok` | success |
| `verifier_unavailable`, `verifier_unexpected` | step 9 |

Fold error codes, in GP-15 order where they apply: `gold`, `old_code`; then `silver`.

Retired codes, never reused: `old_code` (gone).

## 12. Vector groups
"""

IDS = ["ord/a-before-b", "ord/b-before-c", "ord/inner", "gen/order-x-before-y",
       "gen/order-y-before-z", "ok/one", "ok/two", "ok/three", "ok/four", "ok/five"]
ANCHORS = {
    "ok/one": '{"reason":"alpha","valid":false}',
    "ok/two": '{"reason":"beta","valid":false}',
    "ok/three": '{"error":"gold"}',
    "ok/four": '{"reason":"silver"}',
    "ok/five": '{"reason":"ok"}',
    "ord/a-before-b": '{"reason":"alpha"}',
    "ord/b-before-c": '{"reason":"beta"}',
    "ord/inner": '{"reason":"beta"}',
    "gen/order-x-before-y": '{"error":"gold"}',
    "gen/order-y-before-z": '{"error":"gold"}',
}


def write_vector(root, name, anchor, file_name=None, owner_signed=False):
    doc = {"name": name, "command": "check-act", "input": {}}
    if anchor is not None:
        doc["anchor"] = anchor
    fname = file_name or name.replace("/", ".") + ".json"
    folder = Path(root) / "conformance" / "vectors" / ("prod" if owner_signed else "")
    folder.mkdir(exist_ok=True)
    (folder / fname).write_text(json.dumps(doc), encoding="utf-8")


def make_tree(root, ids=IDS, anchors=ANCHORS, pending=()):
    root = Path(root)
    (root / "spec").mkdir()
    (root / "spec" / "profile.md").write_text(SPEC, encoding="utf-8")
    (root / "spec" / "profile-interfaces.md").write_text("# part 2\n", encoding="utf-8")
    (root / "conformance" / "vectors").mkdir(parents=True)
    listing = {
        "active_count": len(ids), "pending": sorted(pending),
        "ids": sorted(ids), "retired": [], "retired_count": 0,
    }
    (root / "conformance" / "vector-ids.json").write_text(json.dumps(listing), encoding="utf-8")
    for name in ids:
        if name not in pending:
            write_vector(root, name, anchors[name])
    (root / "spec" / "registry.json").write_text(json.dumps({"key_classes": [
        {"id": "apple-se-bio", "status": "active"}]}), encoding="utf-8")


def kinds(holes):
    return sorted({h.kind for h in holes})


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        make_tree(self.tmp)

    def survey(self):
        return cc.survey(self.tmp, steps=3)

    def test_a_complete_tree_has_no_holes(self):
        self.assertEqual(self.survey(), [])

    def test_a_deleted_vector_is_a_missing_file(self):
        (self.tmp / "conformance/vectors/ok.two.json").unlink()
        holes = self.survey()
        self.assertIn(("missing-file", "ok/two"), [(h.kind, h.subject) for h in holes])

    def test_deleting_the_only_defect_vector_uncovers_its_code(self):
        (self.tmp / "conformance/vectors/ok.three.json").unlink()
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("code-uncovered", "gold"), got)

    def test_an_uncovered_code_names_the_catalog_rows_that_plan_it(self):
        rows = {"rows": {"ok/three": {"expected": "`gold` fold error", "input": "x"},
                         "ok/other": {"expected": "`silver`", "input": "y"}}}
        (self.tmp / "conformance/effective-rows.json").write_text(json.dumps(rows))
        (self.tmp / "conformance/vectors/ok.three.json").unlink()
        details = {h.subject: h.detail for h in self.survey() if h.kind == "code-uncovered"}
        self.assertIn("ok/three", details["gold"])
        self.assertNotIn("ok/other", details["gold"])
    def test_an_extra_file_is_reported(self):
        write_vector(self.tmp, "ok/extra", '{"reason":"alpha"}')
        self.assertIn(("extra-file", "ok/extra"), [(h.kind, h.subject) for h in self.survey()])

    def test_a_vector_without_anchor_is_reported(self):
        write_vector(self.tmp, "ok/one", None)
        self.assertIn(("no-anchor", "ok/one"), [(h.kind, h.subject) for h in self.survey()])

    def test_a_file_name_that_does_not_match_its_name_is_reported(self):
        (self.tmp / "conformance/vectors/ok.one.json").rename(
            self.tmp / "conformance/vectors/ok.uno.json")
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("name-mismatch", "ok.uno.json"), got)

    def test_ordering_vector_alone_does_not_cover_a_code(self):
        # `beta` is in ord/b-before-c, ord/inner and ok/two; drop ok/two.
        (self.tmp / "conformance/vectors/ok.two.json").unlink()
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("code-uncovered", "beta"), got)

    def test_excepted_and_retired_codes_need_no_vector(self):
        subjects = [h.subject for h in self.survey() if h.kind == "code-uncovered"]
        for code in ("verifier_unavailable", "verifier_unexpected", "old_code", "ok"):
            self.assertNotIn(code, subjects)

    def test_a_missing_ordering_vector_is_reported(self):
        (self.tmp / "conformance/vectors/ord.b-before-c.json").unlink()
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("order-missing", "ord/b-before-c"), got)

    def test_a_pair_without_any_ordering_entry_is_reported(self):
        spec = (self.tmp / "spec/profile.md")
        spec.write_text(spec.read_text().replace("2/3 `ord/b-before-c`; ", ""), encoding="utf-8")
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("pair-uncovered", "VR-02 2/3"), got)

    def test_the_gp15_exemption_is_checked_against_the_spec_text(self):
        spec = (self.tmp / "spec/profile.md")
        spec.write_text(spec.read_text().replace("has no vector", "has a vector"), encoding="utf-8")
        with self.assertRaises(cc.CatalogCheckError):
            self.survey()

    def test_count_mismatch_is_reported(self):
        path = self.tmp / "conformance/vector-ids.json"
        doc = json.loads(path.read_text())
        doc["active_count"] += 1
        path.write_text(json.dumps(doc))
        self.assertIn("count-mismatch", kinds(self.survey()))

    def test_duplicate_ids_are_reported(self):
        path = self.tmp / "conformance/vector-ids.json"
        doc = json.loads(path.read_text())
        doc["ids"].append(doc["ids"][0])
        path.write_text(json.dumps(doc))
        self.assertIn("duplicate-id", kinds(self.survey()))

    def test_the_cli_exits_one_with_holes_and_zero_without(self):
        argv = ["--root", str(self.tmp), "--vr02-steps", "3"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cc.main(argv), 0)
            (self.tmp / "conformance/vectors/ok.two.json").unlink()
            self.assertEqual(cc.main(argv), 1)

    def test_a_tree_without_the_spec_fails_loudly(self):
        (self.tmp / "spec/profile.md").unlink()
        with self.assertRaises(cc.CatalogCheckError):
            self.survey()


class Pending(unittest.TestCase):
    """An id that waits for an owner step is listed in `pending` and is no hole until `--final`."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        extra = {"pro/one": '{"reason":"alpha"}', "pro/two": '{"reason":"beta"}'}
        make_tree(self.tmp, ids=IDS + sorted(extra), anchors={**ANCHORS, **extra},
                  pending=["pro/one", "pro/two"])
        self.pin("uProfileNow")

    def survey(self, final=False):
        return cc.survey(self.tmp, steps=3, final=final)

    def test_a_pending_id_without_a_file_is_no_hole(self):
        self.assertEqual(self.survey(), [])

    def test_the_final_check_makes_every_pending_id_a_hole(self):
        got = [(h.kind, h.subject) for h in self.survey(final=True)]
        self.assertIn(("missing-file", "pro/one"), got)
        self.assertIn(("missing-file", "pro/two"), got)

    def test_a_missing_id_that_is_not_listed_as_pending_is_a_hole(self):
        (self.tmp / "conformance/vectors/ok.one.json").unlink()
        self.assertIn(("missing-file", "ok/one"), [(h.kind, h.subject) for h in self.survey()])

    def test_a_pending_id_that_has_a_file_is_stale(self):
        write_vector(self.tmp, "pro/one", '{"reason":"alpha"}')
        self.assertIn(("pending-stale", "pro/one"), [(h.kind, h.subject) for h in self.survey()])

    def test_a_pending_id_the_owner_signed_is_done_and_no_hole_even_at_the_tag(self):
        self.signed_for("uProfileNow")
        self.assertEqual(self.survey(), [])
        got = [(h.kind, h.subject) for h in self.survey(final=True)]
        self.assertEqual(got, [("missing-file", "pro/two")])

    def test_a_vector_in_the_owner_directory_whose_id_is_not_pending_is_a_hole(self):
        write_vector(self.tmp, "ok/one", '{"reason":"alpha"}', owner_signed=True)
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertIn(("owner-misplaced", "ok/one"), got)

    def test_the_owner_directory_holds_no_other_kind_of_file_unnoticed(self):
        (self.tmp / "conformance/vectors/prod").mkdir()
        (self.tmp / "conformance/vectors/prod/notes.json").write_text("[]")
        self.assertIn("unreadable", kinds(self.survey()))

    def signed_for(self, profile, name="pro/one"):
        """An owner-signed vector whose genesis names `profile`, as the real ones do."""
        doc = {"name": name, "command": "fold", "anchor": '{"reason":"alpha"}',
               "input": {"lineage": [{"doc": {"profile": profile}, "sigs": []}]}}
        folder = self.tmp / "conformance/vectors/prod"
        folder.mkdir(exist_ok=True)
        (folder / (name.replace("/", ".") + ".json")).write_text(json.dumps(doc), encoding="utf-8")

    def pin(self, production):
        (self.tmp / "conformance/pins.json").write_text(json.dumps({"production_profile": production}))

    def test_an_owner_signed_vector_naming_the_current_production_profile_is_not_stale(self):
        self.signed_for("uProfileNow")
        self.assertEqual(self.survey(), [])

    def test_an_owner_signed_vector_names_one_profile_and_a_changed_profile_makes_it_stale(self):   # CF-08
        self.signed_for("uProfileThen")
        self.pin("uProfileNow")
        got = [(h.kind, h.subject) for h in self.survey()]
        self.assertEqual(got, [("owner-stale", "pro/one")])
        self.assertIn("uProfileThen", [h.detail for h in self.survey()][0])
        self.assertIn("uProfileNow", [h.detail for h in self.survey()][0])

    def test_the_stale_vector_is_a_hole_whether_or_not_it_is_the_final_check(self):
        self.signed_for("uProfileThen")
        self.pin("uProfileNow")
        self.assertIn(("owner-stale", "pro/one"), [(h.kind, h.subject) for h in self.survey(final=True)])

    def test_removing_the_stale_vector_makes_its_id_pending_again_and_the_final_check_wants_it(self):
        self.signed_for("uProfileThen")
        self.pin("uProfileNow")
        (self.tmp / "conformance/vectors/prod/pro.one.json").unlink()
        self.assertEqual(self.survey(), [])
        self.assertIn(("missing-file", "pro/one"), [(h.kind, h.subject) for h in self.survey(final=True)])

    def test_an_owner_signed_vector_that_names_no_profile_is_stale(self):
        write_vector(self.tmp, "pro/one", '{"reason":"alpha"}', owner_signed=True)   # input {}: no genesis
        self.assertEqual([(h.kind, h.subject) for h in self.survey()], [("owner-stale", "pro/one")])

    def test_an_owner_signed_vector_that_names_two_profiles_is_stale(self):
        self.signed_for("uProfileNow")
        path = self.tmp / "conformance/vectors/prod/pro.one.json"
        doc = json.loads(path.read_text())
        doc["input"]["lineage"].append({"doc": {"profile": "uProfileThen"}, "sigs": []})
        path.write_text(json.dumps(doc))
        self.assertEqual([(h.kind, h.subject) for h in self.survey()], [("owner-stale", "pro/one")])

    def test_owner_signed_vectors_cannot_be_judged_without_the_pins_file(self):
        self.signed_for("uProfileNow")
        (self.tmp / "conformance/pins.json").unlink()
        with self.assertRaises(cc.CatalogCheckError):
            self.survey()

    def test_without_an_owner_signed_vector_the_pins_file_is_not_needed(self):
        (self.tmp / "conformance/pins.json").unlink()
        self.assertEqual(self.survey(), [])

    def test_the_cli_prints_as_pending_only_the_ids_still_without_a_file(self):
        self.signed_for("uProfileNow")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cc.main(["--root", str(self.tmp), "--vr02-steps", "3"])
        self.assertEqual(code, 0)
        self.assertIn("pro/two", out.getvalue())
        self.assertNotIn("pro/one", out.getvalue())
        self.assertIn("0 holes, 1 pending", out.getvalue())

    def test_a_pending_id_that_is_no_active_id_is_stale(self):
        path = self.tmp / "conformance/vector-ids.json"
        doc = json.loads(path.read_text())
        doc["pending"].append("ok/nowhere")
        path.write_text(json.dumps(doc))
        self.assertIn(("pending-stale", "ok/nowhere"), [(h.kind, h.subject) for h in self.survey()])

    def test_the_final_check_refuses_a_registry_class_that_is_pending_the_spike(self):
        reg = self.tmp / "spec/registry.json"
        reg.write_text(json.dumps({"key_classes": [{"id": "apple-se-bio", "status": "active"},
                                                    {"id": "win-hello-hw", "status": "pending-spike"}]}))
        self.assertNotIn("class-pending", kinds(self.survey()))
        self.assertIn(("class-pending", "win-hello-hw"), [(h.kind, h.subject) for h in self.survey(final=True)])

    def test_the_cli_final_flag_turns_pending_ids_into_exit_one(self):
        argv = ["--root", str(self.tmp), "--vr02-steps", "3"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cc.main(argv), 0)
            self.assertEqual(cc.main(argv + ["--final"]), 1)


class RealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.holes = cc.survey(ROOT)

    def test_the_spec_codes_parse(self):
        spec = manifest.read_profile(ROOT)
        codes, retired, excepted = cc.spec_codes(spec)
        for code in ("jws_shape", "genesis_unsigned", "at_beyond_tip", "witness_missing", "ok"):
            self.assertIn(code, codes)
        self.assertEqual(retired, {"genesis_signer_unknown", "genesis_sig_mismatch", "genesis_head_mismatch"})
        self.assertEqual(excepted, {"verifier_unavailable", "verifier_unexpected", "pin_invalid", "pin_rollback",
                                    "internal", "user_cancel", "key_unavailable", "key_exists", "no_display",
                                    "prompt_refused", "biometric_unavailable", "class_pending",
                                    "store_missing", "store_owner", "store_malformed", "store_unavailable",
                                    "store_full"})
        self.assertFalse(retired & set(codes))

    def test_the_ordering_lists_parse(self):
        spec = manifest.read_profile(ROOT)
        vr02, gp15 = cc.ordering_vectors(spec)
        self.assertEqual([p for p, _ in vr02 if "/" in p][:2], ["1/2", "2/3"])
        self.assertIn("ord/dup-before-class", [i for _, ids in vr02 for i in ids])
        self.assertEqual(len(gp15), 7)

    def test_checker_codes_leave_out_the_signer_and_pin_helper_rows(self):
        spec = manifest.read_profile(ROOT)
        got = set(cc.checker_codes(spec))
        for code in ("user_cancel", "schema_refused", "key_exists", "pin_invalid", "pin_rollback", "internal"):
            self.assertNotIn(code, got)
        for code in ("unparseable_input", "malformed_input", "ok", "genesis_unsigned", "verifier_unavailable",
                     "attachment_missing", "local_key_unknown"):
            self.assertIn(code, got)

    def test_anchor_codes_on_disk_can_include_the_ordering_vectors(self):
        with_ord = cc.anchor_codes(ROOT, include_ordering=True)
        without = cc.anchor_codes(ROOT, include_ordering=False)
        self.assertLessEqual(without, with_ord)
        self.assertIn("duplicate_receipt", with_ord)
    def test_no_extra_file_no_missing_anchor_no_name_mismatch_no_count_drift(self):
        bad = [h for h in self.holes
               if h.kind in ("extra-file", "no-anchor", "name-mismatch", "count-mismatch", "duplicate-id")]
        self.assertEqual(bad, [])

    def test_every_ordering_vector_on_disk_and_every_pair_listed(self):
        bad = [h for h in self.holes if h.kind in ("order-missing", "pair-uncovered")]
        self.assertEqual(bad, [])

    def test_the_real_tree_has_no_hole_only_explicit_pending_ids(self):
        self.assertEqual(self.holes, [])

    def test_the_pending_ids_are_the_production_key_vectors(self):
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        self.assertTrue(doc["pending"])
        for ident in doc["pending"]:
            self.assertTrue(ident.startswith(("enr/prodk-", "fix/prodk-")), ident)

    def test_the_final_check_lists_only_the_production_key_ids_the_owner_has_not_signed(self):
        """T7.7: the first tag is macOS only, so no Windows class or vector is left to hold the tag back.
        What `--final` lists is the production-key vectors the owner has not signed yet (T7.2): six before the
        owner step and none after it, and never anything else."""
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        signed = {p.name for p in (ROOT / "conformance/vectors/prod").glob("*.json")} \
            if (ROOT / "conformance/vectors/prod").is_dir() else set()
        unsigned = sorted(n for n in doc["pending"] if n.replace("/", ".") + ".json" not in signed)
        got = [(h.kind, h.subject) for h in cc.survey(ROOT, final=True)]
        self.assertEqual(got, sorted(("missing-file", name) for name in unsigned))
        self.assertIn(len(got), (0, 6))

    def test_the_listing_has_no_conditional_and_no_ship_count(self):
        """One count: every active id ships. A second count would be a place for the two to drift."""
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        self.assertEqual(set(doc), {"active_count", "ids", "pending", "retired", "retired_count"})


if __name__ == "__main__":
    unittest.main()
