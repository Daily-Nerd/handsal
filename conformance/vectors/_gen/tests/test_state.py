"""FO-01 to FO-03 fold-state anchors, authored without any checker (CF-06).

The expected values are written out from the spec text (FO-01 output keys, FO-02
keys shape, FO-03 devices shape, ACT-08 tip), not copied from a fold.
"""
import json
import unittest

from lib import base, inputs, result, state

FX = base.Fixtures(base.fixture_profile())


def _entry(name, **kw):
    entry = FX.device_entry(name)
    entry.update(kw)
    return entry


class GenesisState(unittest.TestCase):
    def setUp(self):
        self.out = state.State(FX.org).output()

    def test_top_level_keys_are_exactly_those_of_fo01(self):
        self.assertEqual(sorted(self.out),
                         ["devices", "keys", "org", "org_name", "policy", "spec", "tip"])

    def test_org_name_spec_and_policy_come_from_the_tip_document(self):
        self.assertEqual(self.out["org"], FX.org_id)
        self.assertEqual(self.out["org_name"], "example")
        self.assertEqual(self.out["spec"], FX.profile)
        self.assertEqual(self.out["policy"], FX.org["policy"])

    def test_tip_at_position_zero_is_the_document_hash(self):
        self.assertEqual(self.out["tip"], {"genesis": FX.org_id, "id": FX.org_id, "n": "0"})

    def test_devices_have_the_fo03_shape_per_member_and_kid(self):
        self.assertEqual(sorted(self.out["devices"]), ["alice", "bob", "carol"])
        alice = FX.key("alice")
        got = self.out["devices"]["alice"][alice.kid]
        self.assertEqual(got, {"accepted": True, "agree": FX.key("alice", "agree").point(),
                               "class": "apple-se-bio", "label": "alice se-bio",
                               "sign": alice.point(), "status": "active"})

    def test_keys_have_the_fo02_shape_and_no_agree_key(self):
        alice = FX.key("alice")
        self.assertEqual(self.out["keys"]["alice"], {alice.kid: {
            "alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active",
            "x": alice.x, "y": alice.y}})

    def test_the_output_is_a_result_line(self):
        self.assertEqual(json.loads(state.anchor(state.State(FX.org))), self.out)
        self.assertEqual(state.anchor(state.State(FX.org)), result.line(self.out))


class Edits(unittest.TestCase):
    def setUp(self):
        self.s = state.State(FX.org)

    def test_add_device_is_accepted_and_active(self):
        self.s.add_device("alice", _entry("alice2"))
        kid = FX.key("alice2").kid
        out = self.s.output()
        self.assertTrue(out["devices"]["alice"][kid]["accepted"])
        self.assertEqual(out["keys"]["alice"][kid]["status"], "active")

    def test_remove_keeps_the_entry_removed_and_the_key_revoked(self):
        kid = FX.key("carol").kid
        self.s.remove_device(kid)
        out = self.s.output()
        self.assertEqual(out["devices"]["carol"][kid]["status"], "removed")
        self.assertTrue(out["devices"]["carol"][kid]["accepted"])
        self.assertEqual(out["keys"]["carol"][kid]["status"], "revoked")

    def test_a_device_of_a_class_not_in_the_policy_is_in_devices_only(self):
        self.s.add_device("alice", _entry("alice-pin", **{"class": "fixture-pin"}))
        kid = FX.key("alice-pin").kid
        out = self.s.output()
        self.assertFalse(out["devices"]["alice"][kid]["accepted"])
        self.assertNotIn(kid, out["keys"]["alice"])
        self.assertIn(FX.key("alice").kid, out["keys"]["alice"])

    def test_add_member_creates_the_member_with_a_device(self):
        self.s.add_device("dave", _entry("dave"))
        self.assertIn("dave", self.s.output()["devices"])

    def test_a_person_with_no_accepted_device_has_no_keys_entry(self):
        # FO-02: "has no entry in `keys`, not even an empty object"
        self.s.add_device("dave", _entry("dave", **{"class": "fixture-pin"}))
        out = self.s.output()
        self.assertNotIn("dave", out["keys"])
        self.assertIn("dave", out["devices"])
        self.assertEqual(sorted(out["keys"]), ["alice", "bob", "carol"])

    def test_advance_moves_the_tip_and_counts_positions(self):
        self.s.advance("uEiAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        self.assertEqual(self.s.output()["tip"], {
            "genesis": FX.org_id, "id": "uEiAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "n": "1"})

    def test_snapshot_is_independent_of_later_edits(self):
        before = self.s.snapshot()
        self.s.remove_device(FX.key("alice").kid)
        self.assertEqual(before.output()["devices"]["alice"][FX.key("alice").kid]["status"],
                         "active")

    def test_unknown_kid_removal_is_refused(self):
        with self.assertRaises(KeyError):
            self.s.remove_device("nope")

    def test_duplicate_kid_is_refused(self):
        with self.assertRaises(ValueError):
            self.s.add_device("alice", _entry("alice"))


class ChangedEpoch(unittest.TestCase):
    def test_a_change_document_gives_org_of_the_original_and_its_own_genesis(self):
        change = inputs.change_doc(FX)
        out = state.State(change, org=FX.org_id).output()
        cid = inputs.doc_id(change)
        self.assertEqual(out["org"], FX.org_id)
        self.assertEqual(out["tip"], {"genesis": cid, "id": cid, "n": "0"})


if __name__ == "__main__":
    unittest.main()
