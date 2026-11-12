"""T3.22 vectors fld/*, chk/*, end/*, lnk/*, rev/* (FO-01 to FO-08, FO-15, FO-16, FO-21, SG-09).

Each expectation is stated from the spec per row: which devices are in the state, which are
removed, how many positions the tip has, and which act of the bag is the tip. The expected
output is built with lib/state.py from those statements, never from the generator group.

Not written, with the reason: fld/cycle (a receipt id that equals its own ancestor's needs a
SHA-256 fixed point; retired from the catalog, CF-07) and fld/verifier-unavailable (a vector
cannot remove vitni; retired, CF-07), and fld/epochs-in-one-bag (needs a change document, see
the chg groups). Each `at` of FO-16 S1 is one id: at 0, 1, 2, 3 and 4.
"""
import json
import unittest

from lib import base, forge, inputs, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
ROOT = FX.org_id


def _id(jws):
    return base.hashstr(forge.parts(jws)[1])


def _expected(added=(), removed=(), n=0, tip=None, at=None):
    """The fold output line from the statements of a row."""
    s = state.State(FX.org)
    for name in added:
        entry = FX.device_entry(name)
        s.add_device(entry["person"], entry)
    for name in removed:
        s.remove_device(FX.key(name).kid)
    s.n = n
    if tip:
        s.tip_id = tip
    return state.anchor(s)


def _check(case, name, v, added=(), removed=(), n=0, tip_idx=None):
    tip = _id(v["input"]["acts"][tip_idx]) if tip_idx is not None else None
    case.assertEqual(v["command"], "fold", name)
    case.assertEqual(v["anchor"], _expected(added, removed, n, tip), name)


# row -> (devices added, devices removed, positions, index in the bag of the tip primary)
FOLD_ROWS = {
    "fld/agree-equals-sign": ((), (), 0, None),
    "fld/agree-not-in-keys": ((), (), 0, None),
    "fld/dangling-parent": ((), (), 0, None),
    "fld/duplicate-act-twice": (("alice2",), (), 1, 0),
    "fld/empty-bag-tip-0": ((), (), 0, None),
    "fld/forged-sig-ignored": ((), (), 0, None),
    "fld/garbage-twin-does-not-shadow": (("alice2",), (), 1, 1),
    "fld/garbage-twin-only": ((), (), 0, None),
    "fld/junk-appended": (("alice2",), (), 1, 0),
    "fld/link-mismatch": (("alice2",), (), 1, 0),
    "fld/orphan-ignored": ((), (), 0, None),
    "fld/parent-performer-mismatch": (("alice2",), (), 1, 0),
    "fld/parent-performer-null-non-root": (("alice2",), (), 1, 0),
    "fld/primary-parent-null": ((), (), 0, None),
    "fld/removed-stays-revoked": ((), ("carol",), 1, 0),
    "fld/root-child-parent-performer-set": ((), (), 0, None),
    "fld/same-payload-other-key-not-counted": ((), (), 0, None),
    "end/body-act-mismatch": ((), (), 0, None),
    "end/endorse-endorsement": ((), (), 0, None),
    "end/endorse-unknown-id": ((), (), 0, None),
    "end/head-binding": ((), (), 0, None),
    "end/parent-performer-mismatch": ((), (), 0, None),
    "end/same-person-twice": (("alice2",), (), 1, 0),
    "lnk/code-hash-format": ((), (), 0, None),
    "lnk/ok": (("alice2",), (), 1, 0),
    "lnk/reused-code": (("alice2",), (), 1, 0),
    "rev/act-after-revocation-ignored": ((), ("carol",), 1, 0),
    "rev/act-before-revocation-kept": (("carol2",), ("carol",), 2, 3),
}
ALL = {"fld": {n for n in FOLD_ROWS if n.startswith("fld/")} | {
    "fld/at-0-state", "fld/at-1-state", "fld/at-3-state", "fld/at-4-state",
    "fld/at-beyond-fork-parent", "fld/at-beyond-tip", "fld/at-fork-parent-state",
    "fld/at-prefix-states", "fld/fork-error-no-keys", "fld/shuffle-same-output",
    "fld/unaccepted-not-in-keys"},
    "chk": {"chk/lineage-invalid", "chk/pin-owner-false", "chk/request-id-input-missing",
            "chk/state-is-error"},
    "end": {n for n in FOLD_ROWS if n.startswith("end/")},
    "lnk": {n for n in FOLD_ROWS if n.startswith("lnk/")},
    "rev": {n for n in FOLD_ROWS if n.startswith("rev/")}}


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = {}
        for group in ("fld", "chk", "end", "lnk", "rev"):
            cls.v.update(catalog.generate_group(group, [group]))

    def test_rows(self):
        want = set().union(*ALL.values())
        self.assertEqual(set(self.v), want)

    def test_table_rows_state(self):
        for name, (added, removed, n, tip_idx) in FOLD_ROWS.items():
            _check(self, name, self.v[name], added, removed, n, tip_idx)

    def test_junk_is_a_hundred_strings_after_the_valid_acts(self):
        acts = self.v["fld/junk-appended"]["input"]["acts"]
        self.assertEqual(len(acts), 3 + 100)
        self.assertEqual(len(set(acts[3:])), 100)

    def test_duplicate_act_twice_lists_every_act_twice(self):
        acts = self.v["fld/duplicate-act-twice"]["input"]["acts"]
        self.assertEqual(len(acts), 6)
        self.assertEqual(acts[:3], acts[3:])

    def test_garbage_twin_has_the_payload_of_the_primary_and_a_bad_signature(self):
        acts = self.v["fld/garbage-twin-does-not-shadow"]["input"]["acts"]
        twin, primary = acts[0], acts[1]
        self.assertEqual(forge.parts(twin)[:2], forge.parts(primary)[:2])
        self.assertNotEqual(forge.parts(twin)[2], forge.parts(primary)[2])
        only = self.v["fld/garbage-twin-only"]["input"]["acts"]
        self.assertNotIn(primary, only)
        self.assertEqual(len(only), 3)

    def test_the_link_rows_point_the_primary_at_the_wrong_place(self):
        def payloads(name):
            return [json.loads(forge.parts(j)[1]) for j in self.v[name]["input"]["acts"]]

        def primaries(name):
            return [p for p in payloads(name) if p["method"] == "local:handsal.device.add"]
        p = primaries("fld/primary-parent-null")[0]
        self.assertIsNone(p["parent_receipt_hash"])
        p = primaries("fld/root-child-parent-performer-set")[0]
        self.assertEqual((p["parent_receipt_hash"], p["parent_performer_id"]), (ROOT, "alice"))
        second = primaries("fld/parent-performer-mismatch")[1]
        self.assertEqual(second["parent_performer_id"], "bob")  # the parent primary is alice's
        second = primaries("fld/parent-performer-null-non-root")[1]
        self.assertIsNone(second["parent_performer_id"])
        known = {_id(j) for j in self.v["fld/dangling-parent"]["input"]["acts"]} | {ROOT}
        self.assertNotIn(primaries("fld/dangling-parent")[0]["parent_receipt_hash"], known)

    def test_orphan_has_only_the_child_of_an_undelivered_act(self):
        acts = self.v["fld/orphan-ignored"]["input"]["acts"]
        parent = json.loads(forge.parts(acts[0])[1])["parent_receipt_hash"]
        self.assertNotEqual(parent, ROOT)
        self.assertNotIn(parent, {_id(j) for j in acts})

    def test_same_payload_other_key_is_signed_by_another_key_over_the_same_payload(self):
        acts = self.v["fld/same-payload-other-key-not-counted"]["input"]["acts"]
        endorse = json.loads(forge.parts(acts[1])[1])
        self.assertEqual(endorse["ext"]["dev.handsal/act"]["kid"], FX.key("carol").kid)
        self.assertEqual(json.loads(forge.parts(acts[1])[0])["kid"], FX.key("alice").kid)

    def test_shuffle_row_holds_six_acts_in_an_order_the_chain_does_not_follow(self):
        v = self.v["fld/shuffle-same-output"]
        acts = v["input"]["acts"]
        self.assertEqual(len(acts), 6)
        s = state.State(FX.org)
        for name in ("alice2", "bob2"):
            e = FX.device_entry(name)
            s.add_device(e["person"], e)
        prim = {_id(j): json.loads(forge.parts(j)[1]) for j in acts}
        second = [i for i, p in prim.items() if p["method"] == "local:handsal.device.add"
                  and p["parent_receipt_hash"] != ROOT][0]
        s.n, s.tip_id = 2, second
        self.assertEqual(v["anchor"], state.anchor(s))
        first = json.loads(forge.parts(acts[0])[1])
        self.assertEqual(first["method"], "local:handsal.act.endorse")  # reversed chain order

    def test_at_rows(self):
        beyond = self.v["fld/at-beyond-tip"]
        self.assertEqual((beyond["input"]["at"], beyond["anchor"]), ("9", '{"error":"at_beyond_tip"}'))
        prefix = self.v["fld/at-prefix-states"]
        self.assertEqual(prefix["input"]["at"], "2")
        out = json.loads(prefix["anchor"])
        self.assertEqual(out["tip"]["n"], "2")
        acts = prefix["input"]["acts"]
        primaries = [_id(j) for j in acts
                     if json.loads(forge.parts(j)[1])["method"] == "local:handsal.device.add"]
        self.assertEqual(len(primaries), 4)  # the chain has 4 positions
        self.assertEqual(out["tip"]["id"], primaries[1])
        fork = self.v["fld/at-fork-parent-state"]
        self.assertEqual(fork["input"]["at"], "2")
        self.assertEqual(json.loads(fork["anchor"])["tip"]["n"], "2")
        beyond_fork = self.v["fld/at-beyond-fork-parent"]
        self.assertEqual(beyond_fork["input"]["at"], "3")
        self.assertEqual(beyond_fork["input"]["acts"], fork["input"]["acts"])
        obj = json.loads(beyond_fork["anchor"])
        self.assertEqual(obj["error"], "fork")
        self.assertEqual(obj["fork"]["parent"], json.loads(fork["anchor"])["tip"]["id"])

    def test_one_id_per_at_over_one_chain_of_four(self):
        names = ("alice2", "bob2", "carol2", "alice3")
        ids = {0: "fld/at-0-state", 1: "fld/at-1-state", 2: "fld/at-prefix-states",
               3: "fld/at-3-state", 4: "fld/at-4-state"}
        bag = self.v["fld/at-prefix-states"]["input"]["acts"]
        primaries = [_id(j) for j in bag
                     if json.loads(forge.parts(j)[1])["method"] == "local:handsal.device.add"]
        self.assertEqual(len(primaries), 4)
        for at, name in ids.items():
            v = self.v[name]
            self.assertEqual(v["input"]["at"], str(at), name)
            self.assertEqual(v["input"]["acts"], bag, name)
            tip = primaries[at - 1] if at else None
            self.assertEqual(v["anchor"], _expected(names[:at], (), at, tip), name)

    def test_fork_error_has_no_keys(self):
        obj = json.loads(self.v["fld/fork-error-no-keys"]["anchor"])
        self.assertEqual(sorted(obj), ["error", "fork"])
        self.assertEqual(obj["fork"]["parent"], ROOT)

    def test_unaccepted_device_is_in_devices_only(self):
        out = json.loads(self.v["fld/unaccepted-not-in-keys"]["anchor"])
        kid = FX.key("dave2").kid
        self.assertEqual(out["devices"]["dave"][kid]["accepted"], False)
        self.assertNotIn(kid, out["keys"]["dave"])
        self.assertEqual(out["tip"]["n"], "2")

    def test_chk_rows(self):
        for name, code in (("chk/lineage-invalid", "genesis_unsigned"),
                           ("chk/pin-owner-false", "pin_owner"),
                           ("chk/state-is-error", "pin_missing")):
            v = self.v[name]
            self.assertEqual(v["command"], "check-act", name)
            obj = json.loads(v["anchor"])
            self.assertEqual((obj["reason"], obj["class"], obj["valid"]), (code, None, False), name)
            self.assertEqual(obj["receipt_id"], inputs.receipt_id(v["input"]["jws"]), name)
        self.assertEqual(self.v["chk/lineage-invalid"]["input"]["lineage"][0]["sigs"], [])
        pin = self.v["chk/pin-owner-false"]["input"]["pin"]
        self.assertEqual((pin["owner_ok"], pin["reason"]), (False, "pin_owner"))
        pin = self.v["chk/state-is-error"]["input"]["pin"]
        self.assertEqual((pin["owner_ok"], pin["reason"]), (False, "pin_missing"))
        v = self.v["chk/request-id-input-missing"]
        self.assertNotIn("request_id", v["input"])
        self.assertEqual(v["anchor"], '{"error":"malformed_input"}')

    def test_lnk_rows(self):
        acts = self.v["lnk/code-hash-format"]["input"]["acts"]
        code = json.loads(forge.parts(acts[0])[1])["ext"]["dev.handsal/act"]["body"]["link_code_hash"]
        self.assertFalse(base.is_hashstr(code))
        reused = self.v["lnk/reused-code"]["input"]["acts"]
        codes = [json.loads(forge.parts(j)[1])["ext"]["dev.handsal/act"]["body"].get("link_code_hash")
                 for j in reused
                 if json.loads(forge.parts(j)[1])["method"] == "local:handsal.device.add"]
        self.assertEqual(len(codes), 2)
        self.assertEqual(codes[0], codes[1])


if __name__ == "__main__":
    unittest.main()
