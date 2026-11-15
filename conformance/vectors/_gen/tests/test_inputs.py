"""Command inputs and anchors for check-act, fold and enrolled (VR-01, GP-13, GP-14, CF-03).

The inputs are assembled from the base fixtures; the anchors are authored here
from the expected behaviour. No checker code is involved (CF-06).
"""
import base64
import json
import unittest

from lib import base, forge, inputs, jcs, result

PROFILE = base.fixture_profile()


class CheckInput(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)
        self.jws = self.fx.approve()

    def test_verdict_input_has_exactly_the_keys_vr01_requires(self):
        got = inputs.check_input(self.fx, self.jws)
        self.assertEqual(sorted(got), sorted(
            "acts expect_method jws lineage now org pin recipient request_b64 request_id "
            "seen synced_at tip_statement".split()))   # VR-01: the relay is read from the policy, never given
        self.assertEqual(got["expect_method"], "local:handsal.request.approve")
        self.assertEqual(got["org"], self.fx.org_id)
        self.assertEqual(got["now"], base.NOW)
        self.assertEqual(got["synced_at"], base.NOW)
        self.assertEqual(got["pin"], self.fx.pin_ok())
        self.assertEqual(got["lineage"], self.fx.lineage())
        self.assertIsNone(got["tip_statement"])
        self.assertEqual((got["acts"], got["seen"]), ([], []))
        self.assertEqual(base64.b64decode(got["request_b64"]), base.REQUEST)
        self.assertEqual((got["request_id"], got["recipient"]), (base.REQUEST_ID, "alice"))
        self.assertNotIn("relay", got)

    def test_decision_input_carries_the_content_and_the_words_not_the_verdict_keys(self):
        got = inputs.check_input(self.fx, self.fx.decision(), method=inputs.DECISION)
        self.assertEqual(base64.b64decode(got["decision_b64"]), base.DECISION_BODY)
        self.assertEqual((got["action"], got["consumer"], got["subject"]),
                         (base.DECISION_ACTION, base.DECISION_CONSUMER, base.DECISION_SUBJECT))
        for key in ("request_b64", "request_id", "recipient", "relay"):
            self.assertNotIn(key, got)

    def test_a_method_without_an_input_form_is_a_bug_not_a_default(self):
        with self.assertRaises(ValueError):
            inputs.check_input(self.fx, self.fx.approve(), method="local:handsal.record.promote")

    def test_override_replaces_and_drop_removes(self):
        got = inputs.check_input(self.fx, self.jws, recipient="bob", org=inputs.DROP)
        self.assertEqual(got["recipient"], "bob")
        self.assertNotIn("org", got)

    def test_a_relay_is_an_input_only_as_an_override_that_a_row_shows_refused(self):   # VR-01, VR-08 S2
        got = inputs.check_input(self.fx, self.jws, relay=base.RELAY_HOST)
        self.assertEqual(got["relay"], base.RELAY_HOST)

    def test_witness_org_variant(self):
        got = inputs.check_input(self.fx, self.fx.approve(wit=True), wit=True)
        self.assertEqual(got["org"], self.fx.wit_org_id)
        self.assertEqual(got["lineage"], self.fx.lineage(wit=True))


class Anchors(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)
        self.jws = self.fx.approve()

    def line(self, reason, jws=None):
        return inputs.check_anchor(jws or self.jws, reason)

    def test_ok_has_class_and_receipt_id(self):
        rid = base.hashstr(forge.parts(self.jws)[1])
        self.assertEqual(self.line("ok"), result.line(
            {"class": "apple-se-bio", "reason": "ok", "receipt_id": rid, "valid": True}))
        self.assertEqual(inputs.receipt_id(self.jws), rid)

    def test_before_the_payload_parses_receipt_id_and_class_are_null(self):
        for reason in ("jws_shape", "payload_not_canonical_subset", "payload_too_large"):
            self.assertEqual(json.loads(self.line(reason)), {
                "class": None, "reason": reason, "receipt_id": None, "valid": False})

    def test_parsed_but_before_the_state_has_an_id_and_no_class(self):
        # VR-01: receipt_id from step 3 on; class null for steps 1 to 6
        for reason in ("schema", "method_unknown", "chain_method", "body_schema", "pin_malformed",
                       "fixture_key", "genesis_unsigned"):
            got = json.loads(self.line(reason))
            self.assertEqual(got["class"], None, reason)
            self.assertEqual(got["receipt_id"], inputs.receipt_id(self.jws), reason)
            self.assertFalse(got["valid"])

    def test_from_step_7_the_class_is_the_pinned_state_device_class_or_null(self):
        # VR-01: step 9 reasons report the class of the device whose kid is the header kid
        for reason in ("unknown_key", "verifier_unexpected", "revoked_key", "bad_signature",
                       "context_mismatch"):
            got = json.loads(inputs.check_anchor(self.jws, reason, "apple-se-bio"))
            self.assertEqual(got["class"], "apple-se-bio", reason)
            self.assertEqual(got["receipt_id"], inputs.receipt_id(self.jws), reason)
            none = json.loads(inputs.check_anchor(self.jws, reason, None))
            self.assertIsNone(none["class"], reason)

    def test_verifier_unavailable_needs_its_step_stated(self):
        # it is a fold error at step 6 (i) and a vitni failure at step 9: two classes
        with self.assertRaises(ValueError):
            inputs.check_anchor(self.jws, "verifier_unavailable")
        self.assertIsNone(json.loads(inputs.check_anchor(
            self.jws, "verifier_unavailable", in_fold=True))["class"])
        self.assertEqual(json.loads(inputs.check_anchor(
            self.jws, "verifier_unavailable", "apple-se-bio", in_fold=False))["class"],
            "apple-se-bio")

    def test_before_the_state_a_stated_class_is_refused(self):
        # a step 1 to 6 reason with a class would write a wrong anchor
        for reason in ("schema", "jws_shape", "genesis_unsigned"):
            with self.assertRaises(ValueError):
                inputs.check_anchor(self.jws, reason, "apple-se-bio")

    def test_after_the_fold_the_signer_class_is_reported(self):
        for reason in ("org_mismatch", "bad_signature", "outputs_mismatch", "expired",
                       "stale_view", "duplicate_receipt", "unproven_class", "revoked_key"):
            got = json.loads(self.line(reason))
            self.assertEqual(got["class"], "apple-se-bio", reason)
            self.assertEqual(got["reason"], reason)

    def test_unclassified_reason_is_refused(self):
        with self.assertRaises(ValueError):
            self.line("not_a_reason")

    def test_error_and_enrolled_anchors(self):
        self.assertEqual(inputs.error_anchor("fork"), '{"error":"fork"}')
        self.assertEqual(inputs.enrolled_anchor(False, "fixture_profile"),
                         '{"enrolled":false,"reason":"fixture_profile"}')


class PinsAndDocs(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)

    def test_probe_for_matches_the_base_probe(self):
        self.assertEqual(inputs.probe_for(self.fx.lineage()), self.fx.pin_ok())
        self.assertEqual(inputs.probe_for(self.fx.lineage(wit=True)), self.fx.pin_ok(wit=True))

    def test_probe_overrides(self):
        org = self.fx.org_id
        line = inputs.pin_line(org, org, PROFILE)
        self.assertEqual(jcs.recognize(line[:-1]), (True, None))
        p = inputs.probe(org, line, owner_ok=False, reason="pin_owner", filename="x.pin",
                         probe_org=self.fx.wit_org_id)
        self.assertEqual((p["owner_ok"], p["reason"], p["filename"], p["org"]),
                         (False, "pin_owner", "x.pin", self.fx.wit_org_id))
        self.assertEqual(base64.b64decode(p["bytes_b64"]), line)

    def test_derive_copies_and_edits(self):
        doc = inputs.derive(self.fx.org, lambda d: d.update(name="other"))
        self.assertEqual(doc["name"], "other")
        self.assertEqual(self.fx.org["name"], base.ORG_NAME)

    def test_original_lineage_signs_every_listed_device(self):
        doc = inputs.derive(self.fx.org, lambda d: d.update(name="other"))
        lin = inputs.original_lineage(self.fx, doc)
        self.assertEqual(len(lin), 1)
        self.assertEqual(len(lin[0]["sigs"]), 3)
        for jws in lin[0]["sigs"]:
            self.assertEqual(json.loads(forge.parts(jws)[1])["inputs_hash"], inputs.doc_id(doc))

    def test_change_doc_names_the_original_and_its_head(self):
        change = inputs.change_doc(self.fx)
        self.assertEqual((change["org"], change["prev"], change["head"]),
                         (self.fx.org_id, self.fx.org_id, self.fx.org_id))
        self.assertEqual(base.check_genesis_shape(change), [])

    def test_fold_input_defaults_org_and_pin_from_the_lineage(self):
        lin = self.fx.lineage()
        got = inputs.fold_input(lin)
        self.assertEqual(sorted(got), ["acts", "lineage", "org", "pin"])
        self.assertEqual((got["org"], got["pin"]), (self.fx.org_id, self.fx.pin_ok()))

    def test_enrolled_input_keys(self):
        got = inputs.enrolled_input(self.fx)
        self.assertEqual(sorted(got), sorted(
            "acts device_kid lineage now org pin synced_at tip_statement".split()))
        self.assertEqual(got["device_kid"], self.fx.key("alice").kid)


if __name__ == "__main__":
    unittest.main()
