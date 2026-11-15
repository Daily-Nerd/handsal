"""`lib/retired.py` owns the shape of the retired record method (ACT-09, S9).

The generator no longer builds the method anywhere else: the three regression vectors that prove a
verifier refuses it (`mth/`, `rnd/` and `sgn/record-promote-retired*`) read their act, payload and draft
from this one module, so the old bytes exist once.
"""
import base64
import json
import unittest

from lib import base, es256, forge, retired

FX = base.Fixtures(base.fixture_profile())
METHOD = "local:handsal.record.promote"


class Shape(unittest.TestCase):
    def test_the_method_and_the_body_bytes(self):
        self.assertEqual(retired.METHOD, METHOD)
        self.assertEqual(retired.BODY, b"record body v1")
        self.assertEqual(len(retired.BODY), 14)

    def test_the_payload_has_the_shape_the_method_had(self):
        p = retired.payload(FX)
        act = p["ext"]["dev.handsal/act"]
        self.assertEqual(p["method"], METHOD)
        self.assertEqual(act["body"], {"anchors": ["anchor-1"], "record_id": "rec-0001"})
        self.assertEqual(act["org"], FX.org_id)
        self.assertEqual(act["head"], {"id": FX.org_id, "kind": "chain"})
        self.assertEqual(act["expires"], base.shift(p["ts"], 3600))
        self.assertEqual(p["inputs_hash"], base.hashstr(b"record body v1"))
        self.assertEqual(p["outputs_hash"], base.EMPTY_HASH)
        self.assertIsNone(p["parent_receipt_hash"])
        self.assertEqual(p["performer_id"], "alice")

    def test_the_act_is_signed_by_alice_with_a_low_s_signature(self):
        jws = retired.jws(FX)
        k = FX.key("alice")
        h, raw, sig = forge.parts(jws)
        self.assertEqual(json.loads(h)["kid"], k.kid)
        self.assertEqual(json.loads(raw), retired.payload(FX))
        self.assertTrue(es256.verify((k.x_int, k.y_int), jws.rsplit(".", 1)[0].encode(), sig))
        self.assertTrue(es256.is_low_s(sig))

    def test_the_draft_and_the_attachment(self):
        d = retired.draft(FX)
        self.assertEqual(d["method"], METHOD)
        self.assertEqual(d["body"], {"anchors": ["anchor-1"], "record_id": "rec-0001"})
        self.assertEqual((d["expires_in_s"], d["org"]), ("3600", FX.org_id))
        self.assertEqual(retired.attachments(), {"record_body_b64": base64.b64encode(b"record body v1").decode()})

    def test_the_check_act_input_is_what_a_caller_of_the_old_method_sent(self):
        got = retired.check_input(FX)
        self.assertEqual(got["jws"], retired.jws(FX))
        self.assertEqual(got["expect_method"], METHOD)
        self.assertEqual(base64.b64decode(got["record_body_b64"]), b"record body v1")
        for key in ("action", "consumer", "decision_b64", "subject", "request_b64", "request_id", "recipient", "relay"):
            self.assertNotIn(key, got)
        self.assertEqual(sorted(got), ["acts", "expect_method", "jws", "lineage", "next", "now", "org", "pin",
                                       "record_body_b64", "seen", "synced_at", "tip_statement"])

    def test_the_hash12_of_the_body_has_a_dash_at_a_group_edge(self):
        # RN-03 S3: the content hash of these 14 bytes is what `rnd/decision-hash12-dash` renders
        self.assertEqual(base.hashstr(retired.BODY)[3:15], "AnLrsJDp-lmi")


if __name__ == "__main__":
    unittest.main()
