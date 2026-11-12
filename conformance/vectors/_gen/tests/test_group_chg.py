"""T3.25, T3.26 vectors chg/*, genesis-change rows of other groups, cli/genesis-check-*, wit change rows.

Per row the test states, from GP-15, GP-19, GP-20 and GP-07, the outcome of the fold: the
state of the last lineage document (a valid change), or the code of the first failing step.
A state row's anchor is checked against `lib/state.py` built from the last document; an
error row's code against the catalog.
"""
import json
import unittest

from lib import base, forge, inputs, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
UNAUTH, UNSIGNED = "genesis_change_unauthorized", "genesis_unsigned"
STATE_ROWS = {
    "chg/ok-2-of-3", "chg/junk-sig-ignored", "chg/signer-revoked-after-head",
    "chg/backdate-through-fork-residual", "chg/head-older-clean-ok",
    "chg/unlisted-clean-signer-counts", "chg/full-key-rotation-ok", "chg/signer-revoked-on-branch",
    "chg/head-on-side-branch-clean-rule", "chg/old-epoch-act-after-head-ignored",
    "chg/old-epoch-fork-after-head-ignored", "chg/old-epoch-fork-before-head-path-selects",
    "chg/old-epoch-retroactive-act-no-effect", "chg/removal-in-losing-branch-no-effect",
    "chg/carry-revoked-after-head", "chg/three-epochs", "chg/sibling-branch-removal-no-effect",
    "wit/change-none-to-relay-quorum", "wit/change-relay-key-rotation-ok",
    "chg/two-heads-one-authorized",
    # later rows
    "frk/genesis-change-recovers", "frk/conflicting-resolves-genesis-exit",
    "chg/r11-branch-change-valid", "chg/large-snapshot-small-diff-ok",
    "chg/carry-newly-accepted-class-ok",
}
ERROR_ROWS = {
    "chg/quorum-unmet-1-of-3": UNAUTH, "chg/two-devices-one-person": UNAUTH,
    "chg/signer-revoked-before-head": UNAUTH, "chg/signer-listed-in-prev-doc-revoked-in-chain": UNAUTH,
    "chg/unlisted-signer-wrong-performer-ignored": UNAUTH, "chg/signer-not-in-prev": UNAUTH,
    "chg/heads-differ": UNAUTH, "chg/policy-change-needs-old-quorum": UNAUTH,
    "chg/head-unknown": "genesis_head_unknown",
    "chg/carried-device-no-pop": UNSIGNED, "chg/new-key-no-pop": UNSIGNED,
    "chg/possession-sig-other-head-ignored": UNSIGNED,
    "chg/org-mismatch": "lineage_broken", "chg/prev-hash-mismatch": "lineage_broken",
    "chg/lineage-missing-doc": "lineage_broken", "chg/document-head-missing-schema": "genesis_schema",
    "chg/original-with-head-schema": "genesis_schema",
    "chg/lineage-last-not-pinned": "genesis_pin_mismatch",
    "chg/profile-unimplemented-in-middle": "profile_mismatch",
    "chg/carry-entry-changed": "genesis_device_changed",
    "chg/carry-removed-kid-returns": "genesis_device_revoked",
    "gen/order-revoked-before-changed": "genesis_device_revoked",
    "gen/order-unauthorized-before-carry": UNAUTH, "quo/two-lost-persons-unreachable": UNAUTH,
    "wit/change-none-to-relay-one-signer": UNAUTH, "wit/change-none-to-relay-revoked-signer": UNAUTH,
    "wit/change-relay-to-none-one-signer": UNAUTH,
    # later rows
    "chg/render-too-large-diff": "genesis_render_too_large",
    "chg/device-unaccepted-class": "genesis_schema",
    "chg/carried-kid-other-person-device-changed": "genesis_device_changed",
    "chg/carry-kid-removed-two-epochs-ago": "genesis_device_revoked",
}
# GP-15 steps 1 to 3: a row that expects one of these may hold a document of that defect
EARLY_CODES = {"genesis_schema", "profile_mismatch", "policy_unreachable"}
EPOCH_ONE_BAG = {"fld/epochs-in-one-bag": 1, "add/kid-removed-in-earlier-epoch": 0,
                 "mem/id-reused-across-epochs": 0}
CHECK_ACT = {"chg/old-epoch-head-stale": "stale_view",
             "wit/change-after-repin-needs-statement": "witness_missing",
             "wit/change-before-repin-old-mode": "ok"}
GENESIS_CHECK = {"cli/genesis-check-original-ok", "cli/genesis-check-forged-middle-link",
                 "cli/genesis-check-change-revoked-signer",
                 "cli/genesis-check-missing-head-acts-invalid",
                 "cli/genesis-check-extra-acts-same-result"}
OLD_PIN = {"chg/old-pin-still-valid"}
WRITTEN = (STATE_ROWS | set(ERROR_ROWS) | set(EPOCH_ONE_BAG) | set(CHECK_ACT) | GENESIS_CHECK
           | OLD_PIN)
NOT_WRITTEN = {
    # registry v1 has one active biometric-only class, so no second class passes GP-15 step 3
    # for a role holder: the carried device cannot change class and still reach step 9
    "chg/carry-class-change-refused",
    # KC-08 and FO-22 give an unaccepted device no authority at all, so "not counted" has no
    # only-defect form in which dave's device is not also refused earlier (catalog follow-up)
    "chg/unaccepted-signer-not-counted",
}
PREFIXES = ["chg", "gen", "fld", "add", "mem", "quo", "cli", "wit", "frk"]
MODULES = ["chg_auth", "chg_carry", "wit_change"]


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = {k: v for k, v in catalog.generate_modules(MODULES, PREFIXES).items()}

    def test_rows(self):
        self.assertEqual(set(self.v), WRITTEN)

    def test_written_and_skipped_are_catalog_ids(self):
        self.assertTrue(WRITTEN <= set(catalog.ROWS))
        self.assertTrue(NOT_WRITTEN <= set(catalog.ROWS))
        self.assertFalse(WRITTEN & NOT_WRITTEN)

    def test_state_rows_are_the_state_of_the_last_document_at_position_zero(self):
        for name in STATE_ROWS:
            v = self.v[name]
            self.assertEqual(v["command"], "fold", name)
            last = v["input"]["lineage"][-1]["doc"]
            self.assertEqual(v["anchor"], state.anchor(state.State(last)), name)
            self.assertEqual(json.loads(v["anchor"])["tip"]["n"], "0", name)
            self.assertGreaterEqual(len(v["input"]["lineage"]), 2, name)

    def test_error_rows_carry_their_code(self):
        for name, code in ERROR_ROWS.items():
            v = self.v[name]
            self.assertEqual(v["command"], "fold", name)
            self.assertEqual(json.loads(v["anchor"]), {"error": code}, name)

    def test_the_catalog_agrees_with_the_error_rows(self):
        for name, code in ERROR_ROWS.items():
            self.assertEqual(catalog.catalog_code(name), code, name)

    def test_the_pin_is_at_the_last_document_unless_the_row_is_about_the_pin(self):
        for name in set(STATE_ROWS) | set(ERROR_ROWS):
            if name == "chg/lineage-last-not-pinned":
                continue
            v = self.v[name]
            last = inputs.doc_id(v["input"]["lineage"][-1]["doc"]) \
                if name != "chg/document-head-missing-schema" else None
            if last is None:
                continue
            line = json.loads(__import__("base64").b64decode(v["input"]["pin"]["bytes_b64"]))
            self.assertEqual(line["genesis"], last, name)

    def test_epoch_one_rows_hold_acts_of_both_epochs_or_the_refused_act(self):
        for name, n in EPOCH_ONE_BAG.items():
            v = self.v[name]
            out = json.loads(v["anchor"])
            self.assertEqual(out["tip"]["n"], str(n), name)
            last = v["input"]["lineage"][-1]["doc"]
            self.assertEqual(out["tip"]["genesis"], inputs.doc_id(last), name)
            self.assertEqual(out["org"], inputs.doc_id(v["input"]["lineage"][0]["doc"]), name)
        mixed = self.v["fld/epochs-in-one-bag"]["input"]["acts"]
        roots = {json.loads(forge.parts(a)[1])["parent_receipt_hash"] for a in mixed}
        self.assertEqual(len(roots - {None}) >= 2, True)

    def test_check_act_rows(self):
        for name, code in CHECK_ACT.items():
            v = self.v[name]
            self.assertEqual(v["command"], "check-act", name)
            self.assertEqual(catalog.anchor_code(v), code, name)

    def test_the_acts_on_the_path_to_h_rows(self):
        gap = self.v["cli/genesis-check-missing-head-acts-invalid"]
        self.assertEqual(json.loads(gap["anchor"]),
                         {"pin": None, "reason": "genesis_head_unknown", "valid": False})
        change = gap["input"]["lineage"][1]["doc"]
        primaries = [a for a in gap["input"]["acts"]
                     if json.loads(forge.parts(a)[1])["method"] == "local:handsal.device.add"]
        ids = {inputs.receipt_id(a) for a in primaries}
        self.assertEqual(len(ids), 2)  # positions 1 and 3 only: position 2 is the hole
        root = inputs.doc_id(gap["input"]["lineage"][0]["doc"])
        self.assertIn(change["head"], ids)  # the head act is there, its parent is not
        head_act = next(a for a in primaries if inputs.receipt_id(a) == change["head"])
        parent = json.loads(forge.parts(head_act)[1])["parent_receipt_hash"]
        self.assertNotIn(parent, ids | {root})
        extra = self.v["cli/genesis-check-extra-acts-same-result"]
        out = json.loads(extra["anchor"])
        self.assertEqual((out["reason"], out["valid"]), ("ok", True))
        last = inputs.doc_id(extra["input"]["lineage"][-1]["doc"])
        self.assertEqual(out["pin"], inputs.pin_line(inputs.doc_id(extra["input"]["lineage"][0][
            "doc"]), last, extra["input"]["lineage"][0]["doc"]["profile"]).decode())
        removal = json.loads(forge.parts(extra["input"]["acts"][0])[1])
        self.assertEqual(removal["method"], "local:handsal.device.remove")

    def test_the_old_pin_row_is_the_previous_epoch_state_with_its_acts(self):
        v = self.v["chg/old-pin-still-valid"]
        self.assertEqual(len(v["input"]["lineage"]), 1)
        out = json.loads(v["anchor"])
        self.assertEqual(out["tip"]["n"], "1")
        self.assertEqual(out["tip"]["genesis"], inputs.doc_id(v["input"]["lineage"][0]["doc"]))

    def test_the_large_snapshot_row_is_a_fifth_change_over_a_40_device_document(self):
        v = self.v["chg/large-snapshot-small-diff-ok"]
        lineage = v["input"]["lineage"]
        self.assertEqual(len(lineage), 6)
        self.assertEqual(len(lineage[4]["doc"]["devices"]), 40)
        self.assertEqual(len(lineage[5]["doc"]["devices"]), 41)

    def test_the_too_large_diff_row_adds_twelve_members_with_a_device_each(self):
        v = self.v["chg/render-too-large-diff"]
        prev, doc = (e["doc"] for e in v["input"]["lineage"])
        self.assertEqual(len(doc["devices"]) - len(prev["devices"]), 12)
        self.assertEqual(len(doc["members"]) - len(prev["members"]), 12)

    def test_the_newly_accepted_class_row_accepts_daves_pin_device(self):
        v = self.v["chg/carry-newly-accepted-class-ok"]
        out = json.loads(v["anchor"])
        dave2 = FX.key("dave2").kid
        self.assertEqual(out["devices"]["dave"][dave2]["accepted"], True)
        first = v["input"]["lineage"][0]["doc"]
        self.assertNotIn("fixture-pin", [c["class"] for c in first["policy"]["classes"]])

    def test_genesis_check_rows(self):
        ok = self.v["cli/genesis-check-original-ok"]
        self.assertEqual(ok["command"], "genesis-check")
        out = json.loads(ok["anchor"])
        self.assertEqual((out["reason"], out["valid"]), ("ok", True))
        doc = ok["input"]["lineage"][0]["doc"]
        self.assertEqual(out["pin"], inputs.pin_line(inputs.doc_id(doc), inputs.doc_id(doc),
                                                     doc["profile"]).decode())
        for name in ("cli/genesis-check-forged-middle-link", "cli/genesis-check-change-revoked-signer"):
            v = self.v[name]
            self.assertEqual(json.loads(v["anchor"]),
                             {"pin": None, "reason": UNAUTH, "valid": False}, name)
            self.assertEqual(sorted(v["input"]), ["acts", "lineage"], name)
        self.assertEqual(len(self.v["cli/genesis-check-forged-middle-link"]["input"]["lineage"]), 3)

    def test_an_error_row_after_step_3_has_no_unreachable_policy_in_any_document(self):
        """GP-02, GP-15 step 3: `policy_unreachable` outranks every later code, so a row
        that expects a later code (links, size, possession, authority, carry) must list in
        every document more role holders than each rule's `persons`."""
        for name, code in ERROR_ROWS.items():
            if code in EARLY_CODES:
                continue
            for entry in self.v[name]["input"]["lineage"]:
                doc = entry["doc"]
                if not isinstance(doc.get("policy"), dict) or not isinstance(doc.get("members"), list):
                    continue
                for rule, spec in doc["policy"]["rules"].items():
                    holders = [m for m in doc["members"] if m["role"] in spec["roles"]]
                    self.assertLess(int(spec["persons"]), len(holders), (name, rule))


if __name__ == "__main__":
    unittest.main()
