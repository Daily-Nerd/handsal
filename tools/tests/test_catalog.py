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


def write_vector(root, name, anchor, file_name=None):
    doc = {"name": name, "command": "check-act", "input": {}}
    if anchor is not None:
        doc["anchor"] = anchor
    fname = file_name or name.replace("/", ".") + ".json"
    (Path(root) / "conformance" / "vectors" / fname).write_text(json.dumps(doc), encoding="utf-8")


def make_tree(root, ids=IDS, anchors=ANCHORS):
    root = Path(root)
    (root / "spec").mkdir()
    (root / "spec" / "profile.md").write_text(SPEC, encoding="utf-8")
    (root / "conformance" / "vectors").mkdir(parents=True)
    listing = {
        "active_count": len(ids), "ship_count": len(ids), "conditional": [],
        "ids": sorted(ids), "retired": [], "retired_count": 0,
    }
    (root / "conformance" / "vector-ids.json").write_text(json.dumps(listing), encoding="utf-8")
    for name in ids:
        write_vector(root, name, anchors[name])


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
        doc["ship_count"] += 1
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


class RealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.holes = cc.survey(ROOT)

    def test_the_spec_codes_parse(self):
        spec = (ROOT / "spec/profile.md").read_text(encoding="utf-8")
        codes, retired, excepted = cc.spec_codes(spec)
        for code in ("jws_shape", "genesis_unsigned", "at_beyond_tip", "witness_missing", "ok"):
            self.assertIn(code, codes)
        self.assertEqual(retired, {"genesis_signer_unknown", "genesis_sig_mismatch", "genesis_head_mismatch"})
        self.assertEqual(excepted, {"verifier_unavailable", "verifier_unexpected"})
        self.assertFalse(retired & set(codes))

    def test_the_ordering_lists_parse(self):
        spec = (ROOT / "spec/profile.md").read_text(encoding="utf-8")
        vr02, gp15 = cc.ordering_vectors(spec)
        self.assertEqual([p for p, _ in vr02 if "/" in p][:2], ["1/2", "2/3"])
        self.assertIn("ord/dup-before-class", [i for _, ids in vr02 for i in ids])
        self.assertEqual(len(gp15), 7)

    def test_checker_codes_leave_out_the_signer_and_pin_helper_rows(self):
        spec = (ROOT / "spec/profile.md").read_text(encoding="utf-8")
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

    def test_the_ship_count_is_the_active_count_minus_the_conditional_drop(self):
        doc = json.loads((ROOT / "conformance/vector-ids.json").read_text())
        self.assertEqual(doc["ship_count"], doc["active_count"] - 1)


if __name__ == "__main__":
    unittest.main()
