"""The catalog check (CF-07, CF-02): every hole in the vector set is reported.

Synthetic trees prove each hole kind is found; the real tree proves the
structural invariants that hold today.
"""
import ast
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
    (root / "spec" / "profile-checks.md").write_text("# checks\n", encoding="utf-8")
    (root / "spec" / "profile-interfaces.md").write_text("# part 2\n", encoding="utf-8")
    (root / "spec" / "profile-part3.md").write_text("# part 3\n", encoding="utf-8")
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


def write_catalog(root, productions, registry=None):
    """`profiles/catalog.json` with one entry per production hash, oldest first (GP-22), and each frozen edition's
    `profiles/<label>/spec/registry.json` (a copy of the tree's registry unless `registry` names the document)."""
    root = Path(root)
    folder = root / "profiles"
    folder.mkdir(exist_ok=True)
    rows = [{"label": "edition-%d" % n, "production": p, "fixture": "uf%d" % n, "bundle": "ub%d" % n,
             "tag": "v%d" % n} for n, p in enumerate(productions, 1)]
    (folder / "catalog.json").write_text(json.dumps(rows), encoding="utf-8")
    text = json.dumps(registry) if registry is not None else (root / "spec" / "registry.json").read_text(encoding="utf-8")
    for row in rows:
        frozen = folder / row["label"] / "spec"
        frozen.mkdir(parents=True, exist_ok=True)
        (frozen / "registry.json").write_text(text, encoding="utf-8")


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

    def signed_for(self, *profiles, name="pro/one"):
        """An owner-signed vector whose genesis documents name `profiles`, as the real ones do."""
        doc = {"name": name, "command": "fold", "anchor": '{"reason":"alpha"}',
               "input": {"lineage": [{"doc": {"profile": p}, "sigs": []} for p in profiles]}}
        folder = self.tmp / "conformance/vectors/prod"
        folder.mkdir(exist_ok=True)
        (folder / (name.replace("/", ".") + ".json")).write_text(json.dumps(doc), encoding="utf-8")

    def pin(self, production):
        (self.tmp / "conformance/pins.json").write_text(json.dumps({"production_profile": production}))

    def test_an_owner_signed_vector_naming_the_current_production_profile_is_not_stale(self):
        self.signed_for("uProfileNow")
        self.assertEqual(self.survey(), [])

    def catalog(self, *productions):
        write_catalog(self.tmp, productions)

    def signed_under(self, label, *profiles, name="pro/one"):
        """An owner-signed vector kept under `prod/<label>/`, its genesis documents naming `profiles` in order."""
        doc = {"name": name, "command": "fold", "anchor": '{"reason":"alpha"}',
               "input": {"lineage": [{"doc": {"profile": p}, "sigs": []} for p in profiles]}}
        folder = self.tmp / "conformance/vectors/prod" / label
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (name.replace("/", ".") + ".json")).write_text(json.dumps(doc), encoding="utf-8")

    def stale(self, final=False):
        return [(h.kind, h.subject) for h in self.survey(final=final) if h.kind == "owner-stale"]

    def test_an_owner_signed_vector_naming_a_profile_outside_the_catalog_is_stale(self):   # CF-08 S3
        self.signed_for("uProfileThen")
        self.pin("uProfileNow")
        self.assertEqual(self.stale(), [("owner-stale", "pro/one")])      # before founding: only the current core
        self.catalog("uEdition1")
        self.assertEqual(self.stale(), [("owner-stale", "pro/one")])      # a profile in no entry and not current
        detail = [h.detail for h in self.survey() if h.kind == "owner-stale"][0]
        for text in ("uProfileThen", "uProfileNow", "uEdition1"):
            self.assertIn(text, detail)
        self.assertEqual(self.stale(final=True), [("owner-stale", "pro/one")])

    def test_an_owner_signed_vector_of_a_supported_edition_is_never_stale(self):   # CF-08 S3
        self.pin("uProfileNow")
        self.catalog("uEdition1", "uEdition2")
        for named in (("uEdition1",), ("uEdition2",), ("uEdition1", "uEdition2"), ("uProfileNow",),
                      ("uEdition1", "uProfileNow")):
            with self.subTest(named=named):
                self.signed_for(*named)
                self.assertEqual(self.stale(), [])
                self.assertEqual(self.stale(final=True), [])

    def test_a_catalog_edition_stays_supported_after_the_core_moves_on(self):
        """The unreleased core is a new hash; the signed set of the released edition is not stale and not removed."""
        self.pin("uProfileMovedOn")
        self.catalog("uProfileNow")
        self.signed_for("uProfileNow")
        self.assertEqual(self.stale(), [])

    def test_a_file_kept_for_one_edition_that_names_another_is_stale(self):   # CF-08 S3
        self.pin("uEdition2")
        self.catalog("uEdition1", "uEdition2")
        self.signed_under("edition-1", "uEdition1", "uEdition1")
        self.signed_under("edition-2", "uEdition2", name="pro/two")
        self.assertEqual(self.stale(), [])
        self.signed_under("edition-2", "uEdition1", name="pro/two")        # P1 only, kept under P2
        self.assertEqual(self.stale(), [("owner-stale", "pro/two")])
        self.signed_under("edition-1", "uEdition2")                         # P2 only, kept under P1
        self.assertEqual(self.stale(), [("owner-stale", "pro/one"), ("owner-stale", "pro/two")])

    def test_a_cross_edition_set_is_kept_under_the_newer_edition_it_names(self):
        self.pin("uEdition2")
        self.catalog("uEdition1", "uEdition2")
        self.signed_under("edition-2", "uEdition1", "uEdition2")
        self.assertEqual(self.stale(), [])
        self.signed_under("edition-1", "uEdition1", "uEdition2", name="pro/two")   # P1's signing run cannot know P2
        self.assertEqual(self.stale(), [("owner-stale", "pro/two")])

    def test_a_directory_that_is_no_catalog_edition_holds_only_stale_files(self):
        self.pin("uProfileNow")
        self.catalog("uProfileNow")
        self.signed_under("edition-9", "uProfileNow")
        self.assertEqual(self.stale(), [("owner-stale", "pro/one")])

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


class Editions(unittest.TestCase):
    """CF-08 S8, CF-07: the one switch. While the catalog has fewer than two editions, the group `prf` is pending by
    rule: its ids are no hole at `--final`, and a `prf/` row that shows exactly one code counts as that code's
    only-defect vector. With two editions both revert. No code is named in the tool."""

    SPEC_WITH_PRF = SPEC.replace("`alpha`, `beta` | step 1", "`alpha`, `beta`, `delta` | step 1").replace(
        "`gen/order-y-before-z`.", "`gen/order-y-before-z`, `prf/order-d-before-a`.")
    ROWS = {
        "prf/delta-refused": "`delta`",
        "prf/order-d-before-a": "`delta`",
        "prf/two-codes": "`alpha`, then `delta`",
        "prf/ok-state": "state; the P2 epoch",
    }

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        ids = IDS + ["prf/delta-refused", "prf/order-d-before-a", "prf/two-codes", "prf/ok-state"]
        make_tree(self.tmp, ids=ids, anchors=ANCHORS, pending=[i for i in ids if i.startswith("prf/")])
        (self.tmp / "spec" / "profile.md").write_text(self.SPEC_WITH_PRF, encoding="utf-8")
        self.rows(self.ROWS)

    def rows(self, rows):
        doc = {"rows": {i: {"expected": text} for i, text in rows.items()}}
        (self.tmp / "conformance" / "effective-rows.json").write_text(json.dumps(doc), encoding="utf-8")

    def editions(self, count):
        write_catalog(self.tmp, ["up%d" % n for n in range(1, count + 1)])

    def survey(self, final=False):
        return [(h.kind, h.subject) for h in cc.survey(self.tmp, steps=3, final=final)]

    def test_the_cross_edition_ids_are_holes_only_with_two_editions(self):
        """CF-08 S8."""
        self.assertEqual(self.survey(final=True), [])
        self.editions(1)
        self.assertEqual(self.survey(final=True), [])
        self.editions(2)
        got = self.survey(final=True)
        for name in ("prf/delta-refused", "prf/order-d-before-a", "prf/two-codes", "prf/ok-state"):
            self.assertIn(("missing-file", name), got)

    def test_the_owner_run_ids_are_the_pending_ids_that_are_not_pending_by_rule(self):
        """CF-08 S8: `pending` holds ids that wait for the owner and ids that wait for a second edition; the owner
        run selects the first kind by the one rule the check uses for the second."""
        path = self.tmp / "conformance/vector-ids.json"
        listing = json.loads(path.read_text())
        listing["pending"].append("ok/five")
        path.write_text(json.dumps(listing))
        waiting = set(listing["pending"])
        by_rule = {n for n in waiting if n.startswith("prf/")}
        self.assertTrue(by_rule and waiting - by_rule)
        self.assertEqual(cc.owner_signed_ids(self.tmp), waiting - by_rule)
        self.editions(1)
        self.assertEqual(cc.owner_signed_ids(self.tmp), waiting - by_rule)
        self.editions(2)
        self.assertEqual(cc.owner_signed_ids(self.tmp), waiting)

    def test_a_pending_id_of_another_group_stays_a_hole_at_the_tag_with_one_edition(self):
        path = self.tmp / "conformance/vector-ids.json"
        doc = json.loads(path.read_text())
        doc["pending"].append("ok/five")
        path.write_text(json.dumps(doc))
        (self.tmp / "conformance/vectors/ok.five.json").unlink()
        self.editions(1)
        got = self.survey(final=True)
        self.assertIn(("missing-file", "ok/five"), got)
        self.assertEqual([h for h in got if h[0] == "missing-file"], [("missing-file", "ok/five")])

    def test_a_prf_row_that_shows_one_code_counts_as_the_anchor_of_that_code_with_fewer_than_two_editions(self):
        self.assertNotIn(("code-uncovered", "delta"), self.survey())
        self.editions(1)
        self.assertNotIn(("code-uncovered", "delta"), self.survey())
        self.assertIn("delta", cc.anchor_codes(self.tmp, include_ordering=True))
        self.editions(2)
        self.assertIn(("code-uncovered", "delta"), self.survey())
        self.assertNotIn("delta", cc.anchor_codes(self.tmp, include_ordering=True))

    def test_an_ordering_row_and_a_row_that_shows_two_codes_never_cover_a_code(self):
        self.rows({"prf/order-d-before-a": "`delta`", "prf/two-codes": "`alpha`, then `delta`", "prf/ok-state": "state"})
        self.assertIn(("code-uncovered", "delta"), self.survey())
        self.assertNotIn("delta", cc.anchor_codes(self.tmp, include_ordering=True))

    def test_a_row_of_a_group_other_than_prf_never_counts_as_an_anchor(self):
        self.rows({"pro/delta": "`delta`"})
        path = self.tmp / "conformance/vector-ids.json"
        doc = json.loads(path.read_text())
        doc["ids"] = sorted(doc["ids"] + ["pro/delta"])
        doc["active_count"] = len(doc["ids"])
        doc["pending"].append("pro/delta")
        path.write_text(json.dumps(doc))
        self.assertIn(("code-uncovered", "delta"), self.survey())

    def test_an_ordering_vector_that_is_pending_is_not_a_missing_ordering_vector(self):
        """The GP-15 line names `prf/order-d-before-a`, which has no file until a second edition exists."""
        for count in (0, 1, 2):
            if count:
                self.editions(count)
            self.assertNotIn(("order-missing", "prf/order-d-before-a"), self.survey())
        self.assertIn(("missing-file", "prf/order-d-before-a"), self.survey(final=True))

    def test_a_named_ordering_vector_that_is_not_pending_and_has_no_file_is_still_missing(self):
        (self.tmp / "conformance/vectors/gen.order-x-before-y.json").unlink()
        self.assertIn(("order-missing", "gen/order-x-before-y"), self.survey())

    def test_a_catalog_that_is_not_a_list_fails_loudly(self):
        (self.tmp / "profiles").mkdir()
        (self.tmp / "profiles" / "catalog.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(cc.CatalogCheckError):
            cc.survey(self.tmp, steps=3)


class Wire(unittest.TestCase):
    """GP-23 S4, I3: the catalog check fails an edition whose wire part of the registry differs. The evaluation part
    (the key classes, the fixture-only classes, the policy bounds and the registry's own label) may differ."""

    REGISTRY = {
        "registry_version": "1", "binding": "b1", "enums": {"alg": ["ES256"]},
        "key_classes": [{"id": "apple-se-bio", "status": "active"}],
        "fixture_only": [{"id": "fixture-key"}],
        "methods": [{"method": "approve", "body": "b"}],
        "act_extra_key_types": {"k": "string"},
        "constants": {"MAX_PAYLOAD": "4096", "persons": "9", "relays": "3", "clock_skew_s": "60",
                      "max_validity_s": "10", "max_view_age_s": "20", "max_tip_age_s": "30"},
    }

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        make_tree(self.tmp)
        self.current(self.REGISTRY)

    def current(self, doc):
        (self.tmp / "spec" / "registry.json").write_text(json.dumps(doc), encoding="utf-8")

    def frozen(self, label, doc):
        (self.tmp / "profiles" / label / "spec" / "registry.json").write_text(json.dumps(doc), encoding="utf-8")

    def wire_holes(self):
        return [(h.kind, h.subject) for h in cc.survey(self.tmp, steps=3) if h.kind == "wire-differs"]

    def edited(self, **change):
        doc = json.loads(json.dumps(self.REGISTRY))
        for key, value in change.items():
            doc[key] = value
        return doc

    def test_an_edition_does_not_change_the_wire(self):   # GP-23 S4
        write_catalog(self.tmp, ["up1", "up2"], registry=self.REGISTRY)
        self.assertEqual(self.wire_holes(), [])
        consts = dict(self.REGISTRY["constants"], MAX_PAYLOAD="8192")
        changes = {
            "a wire constant": self.edited(constants=consts),
            "a method": self.edited(methods=[{"method": "approve", "body": "other"}]),
            "an enum": self.edited(enums={"alg": ["ES256", "ES384"]}),
            "the binding": self.edited(binding="b2"),
            "an act key type": self.edited(act_extra_key_types={"k": "number"}),
            "a key nobody classified": self.edited(unclassified="x"),
        }
        for what, doc in changes.items():
            with self.subTest(changed=what):
                self.frozen("edition-2", doc)
                self.assertEqual(self.wire_holes(), [("wire-differs", "edition-2")])
        self.frozen("edition-2", self.REGISTRY)
        self.assertEqual(self.wire_holes(), [])

    def test_the_evaluation_part_may_differ_between_editions(self):
        consts = dict(self.REGISTRY["constants"], persons="12", relays="1", clock_skew_s="5", max_validity_s="1",
                      max_view_age_s="2", max_tip_age_s="3")
        other = self.edited(registry_version="2", constants=consts,
                            key_classes=[{"id": "apple-se-bio", "status": "retired"}, {"id": "new"}],
                            fixture_only=[])
        write_catalog(self.tmp, ["up1", "up2"], registry=self.REGISTRY)
        self.frozen("edition-2", other)
        self.assertEqual(self.wire_holes(), [])

    def test_the_unreleased_current_registry_is_held_to_the_catalog_too(self):
        write_catalog(self.tmp, ["up1"], registry=self.REGISTRY)
        self.current(self.edited(binding="b2"))
        self.assertEqual(self.wire_holes(), [("wire-differs", "spec/registry.json")])

    def test_a_hole_names_what_differs(self):
        write_catalog(self.tmp, ["up1", "up2"], registry=self.REGISTRY)
        self.frozen("edition-2", self.edited(binding="b2", constants=dict(self.REGISTRY["constants"], MAX_PAYLOAD="1")))
        detail = [h.detail for h in cc.survey(self.tmp, steps=3) if h.kind == "wire-differs"][0]
        self.assertIn("binding", detail)
        self.assertIn("constants.MAX_PAYLOAD", detail)

    def test_with_no_edition_there_is_nothing_to_compare(self):
        self.assertEqual(self.wire_holes(), [])

    def test_a_frozen_registry_that_is_missing_or_unreadable_fails_loudly(self):
        write_catalog(self.tmp, ["up1", "up2"], registry=self.REGISTRY)
        path = self.tmp / "profiles" / "edition-2" / "spec" / "registry.json"
        path.write_text("not json", encoding="utf-8")
        with self.assertRaises(cc.CatalogCheckError):
            cc.survey(self.tmp, steps=3)
        path.unlink()
        with self.assertRaises(cc.CatalogCheckError):
            cc.survey(self.tmp, steps=3)

    def test_the_wire_rule_is_the_one_the_checker_projects(self):
        """The two lists live in `registry.py` (the checker) and in the tool: a hidden link made a shown one."""
        tree = ast.parse((ROOT / "checker/python/src/handsal_check/registry.py").read_text(encoding="utf-8"))
        found = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in ("NOT_WIRE_KEYS", "EVALUATION_CONSTANTS"):
                    found[node.targets[0].id] = ast.literal_eval(node.value)
        self.assertEqual(set(found), {"NOT_WIRE_KEYS", "EVALUATION_CONSTANTS"})
        self.assertEqual(found["NOT_WIRE_KEYS"], cc.NOT_WIRE_KEYS)
        self.assertEqual(found["EVALUATION_CONSTANTS"], cc.EVALUATION_CONSTANTS)

    def test_the_real_registry_has_no_key_the_wire_rule_does_not_know(self):
        doc = json.loads((ROOT / "spec" / "registry.json").read_text(encoding="utf-8"))
        part = cc.wire_part(doc)
        self.assertEqual(sorted(part), sorted(set(doc) - set(cc.NOT_WIRE_KEYS)))
        self.assertEqual(sorted(doc["constants"]), sorted(set(part["constants"]) | set(cc.EVALUATION_CONSTANTS)))


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
                                    "prompt_refused", "biometric_unavailable", "profile_not_current", "class_pending",
                                    "store_missing", "store_owner", "store_malformed", "store_unavailable",
                                    "store_full"})
        self.assertFalse(retired & set(codes))

    def test_the_six_admission_codes_are_checker_codes_with_a_vector_each(self):
        """CF-11, CF-12: the new codes need only-defect vectors. `store_full` from `admit` is the one exception."""
        spec = manifest.read_profile(ROOT)
        codes, _retired, excepted = cc.spec_codes(spec)
        checker = set(cc.checker_codes(spec))
        for code in ("parent_unknown", "already_stored", "act_not_valid", "not_chain_act", "kid_repeated", "not_in_pool"):
            self.assertIn(code, codes)
            self.assertIn(code, checker)
            self.assertNotIn(code, excepted)
        self.assertIn("store_full", excepted)

    def test_the_ordering_lists_parse(self):
        spec = manifest.read_profile(ROOT)
        vr02, gp15 = cc.ordering_vectors(spec)
        self.assertEqual([p for p, _ in vr02 if "/" in p][:2], ["1/2", "2/3"])
        self.assertIn("ord/dup-before-class", [i for _, ids in vr02 for i in ids])
        self.assertEqual(len(gp15), 9)
        # the two cross-edition pairs sit on the one ordering line and stay pending by rule (CF-07, CF-08 S8)
        self.assertEqual([i for i in gp15 if str(i).startswith("prf/")],
                         ["prf/order-fixture-before-downgrade", "prf/order-downgrade-before-class"])

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
            # GP-22: the cross-edition group waits for a second edition, the production-key ids for the owner
            self.assertTrue(ident.startswith(("enr/prodk-", "fix/prodk-", "prf/")), ident)

    def test_the_final_check_lists_only_the_production_key_ids_the_owner_has_not_signed(self):
        """T7.7: the first tag is macOS only, so no Windows class or vector is left to hold the tag back.
        What `--final` lists is the production-key vectors the owner has not signed yet (T7.2): six before the
        owner step and none after it, and never anything else. The group `prf` waits for a second edition
        (CF-08 S8), so with fewer than two editions it is no hole."""
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        signed = {p.name for p in (ROOT / "conformance/vectors/prod").glob("*.json")} \
            if (ROOT / "conformance/vectors/prod").is_dir() else set()
        unsigned = sorted(n for n in doc["pending"] if n.replace("/", ".") + ".json" not in signed
                          and not (n.startswith("prf/") and cc.edition_count(ROOT) < 2))
        got = [(h.kind, h.subject) for h in cc.survey(ROOT, final=True)]
        self.assertEqual(got, sorted(("missing-file", name) for name in unsigned))
        self.assertIn(len(got), (0, 6))

    def test_no_generator_code_writes_a_prf_id_before_a_second_edition(self):   # T16.12 (e)
        """The `prf/` ids stay pending until a second edition exists; without one the generator has nothing to read
        a frozen directory's fixture hash from, so any code for the group would be surplus."""
        if cc.edition_count(ROOT) >= cc.EDITIONS_NEEDED:
            self.skipTest("a second edition exists: the group is written now")
        holders = [path.relative_to(ROOT).as_posix()
                   for path in sorted((ROOT / "conformance" / "vectors" / "_gen").rglob("*.py"))
                   if ".venv" not in path.parts and "tests" not in path.parts
                   and cc.CROSS_EDITION_GROUP in path.read_text(encoding="utf-8")]
        self.assertEqual(holders, [])
        self.assertEqual(sorted((ROOT / "conformance" / "vectors").glob("prf.*.json")), [])

    def test_the_listing_has_no_conditional_and_no_ship_count(self):
        """One count: every active id ships. A second count would be a place for the two to drift."""
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        self.assertEqual(set(doc), {"active_count", "ids", "pending", "retired", "retired_count"})


if __name__ == "__main__":
    unittest.main()
