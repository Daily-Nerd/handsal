"""Vectors sgn/*: the signer `emit` rows (CF-04, SG-01, SG-04, SG-13, ACT-14).

CF-04 gives a signer the `render` and `emit` vectors only, through `handsal-sign-conformance`;
the other 39 `sgn` ids are signer, ceremony or installer tests (CF-07). Every row here is an
`emit` vector: the input is `{attachments, draft, fixed}` (SG-04), the output `{payload_hex}` or
`{"error":code}` with exit 2 (SG-08).
"""
import base64
import json
import unittest

import generate
from lib import base, forge, jcs, signer_emit
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
OK = {"sgn/emit-act-kid-filled"}
REFUSED = {
    "sgn/chain-draft-recipient-refused": "schema_refused",
    "sgn/expires-in-s-refused-for-chain-method": "schema_refused",
    "sgn/expires-in-s-zero-refused": "schema_refused",
    "sgn/decision-action-grammar-refused": "schema_refused",
    "sgn/decision-attachment-missing-refused": "attachment_missing",
    "sgn/decision-draft-recipient-refused": "schema_refused",
    "sgn/expires-over-30d": "schema_refused",
    "sgn/genesis-head-before-org-refused": "schema_refused",
    "sgn/genesis-document-missing-before-head-refused": "attachment_missing",
    "sgn/unsupported-method-before-bad-fixed-refused": "unsupported_method",
    "sgn/genesis-org-not-document-hash-refused": "attachment_mismatch",
    "sgn/identity-before-attachment-refused": "identity_mismatch",
    "sgn/parent-performer-required": "schema_refused",
    "sgn/refuse-auth-handle": "schema_refused",
    "sgn/refuse-display-text": "schema_refused",
    "sgn/refuse-nonce-input": "schema_refused",
    "sgn/refuse-schema-violation": "schema_refused",
    "sgn/refuse-ts-input": "schema_refused",
    "sgn/record-promote-retired-refused": "unsupported_method",
    "sgn/refuse-unknown-method": "unsupported_method",
    "sgn/signer-stdin-over-max-input-refused": "schema_refused",
    "sgn/verdict-draft-missing-relay-refused": "schema_refused",
    "sgn/verdict-recipient-not-performer-refused": "identity_mismatch",
}
WRITTEN = OK | set(REFUSED)
# the signer, ceremony and installer ids (CF-07): no vector
RETIRED_PREFIXES = ("sgn/pin-helper", "sgn/ceremony", "sgn/windows")


def _act(raw):
    return json.loads(raw)["ext"]["dev.handsal/act"]


class Sgn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("sgn", ["sgn"])

    def test_rows(self):
        self.assertEqual(set(self.v), WRITTEN)

    def test_written_ids_are_the_active_sgn_ids(self):
        # CF-04: the active `sgn` ids are exactly the `emit` vectors
        active = {i for i in generate.shipping_ids() if i.startswith("sgn/")}
        self.assertEqual(WRITTEN, active)
        for name in WRITTEN:
            self.assertIn("`emit`", catalog.ROWS[name]["input"], name)

    def test_every_row_is_an_emit_vector_with_the_three_input_keys(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "emit", name)
            self.assertEqual(sorted(v["input"]), ["attachments", "draft", "fixed"], name)
            self.assertEqual(sorted(v["input"]["fixed"]), ["kid", "nonce", "performer", "ts"], name)

    def test_a_refusal_exits_2_with_the_catalog_code(self):
        for name, code in REFUSED.items():
            v = self.v[name]
            self.assertEqual(v["exit"], 2, name)
            self.assertEqual(json.loads(v["anchor"]), {"error": code}, name)
            self.assertEqual(catalog.catalog_code(name), code, name)

    def test_the_success_row_exits_0_and_its_act_object_carries_fixed_kid(self):
        v = self.v["sgn/emit-act-kid-filled"]
        self.assertNotIn("exit", v)
        raw = bytes.fromhex(json.loads(v["anchor"])["payload_hex"])
        self.assertEqual(_act(raw)["kid"], v["input"]["fixed"]["kid"])
        self.assertEqual(json.loads(raw)["method"], "local:handsal.request.approve")

    def test_the_success_row_is_the_payload_a_base_fixture_signs(self):
        v = self.v["sgn/emit-act-kid-filled"]
        fixed = v["input"]["fixed"]
        jws = FX.verdict("approve", "bob", request_id=v["input"]["draft"]["request_id"])
        self.assertEqual(forge.parts(jws)[1], bytes.fromhex(json.loads(v["anchor"])["payload_hex"]))
        self.assertEqual(fixed["kid"], FX.key("bob").kid)

    def test_each_row_is_the_model_s_answer_for_the_stdin_the_harness_builds(self):
        import run
        for name, v in self.v.items():
            code, obj = signer_emit.run(run.build_stdin(v))
            self.assertEqual((code, signer_emit.line(obj)), (v.get("exit", 0), v["anchor"]), name)

    def test_the_padded_row_is_padded_inside_one_string_of_an_otherwise_valid_draft(self):
        v = self.v["sgn/signer-stdin-over-max-input-refused"]
        self.assertEqual(v["pad"], ["attachments", "request_b64"])
        self.assertIsInstance(v["input"]["attachments"]["request_b64"], str)
        ok = dict(v["input"])
        self.assertEqual(signer_emit.run(signer_emit.padded_stdin(ok, v["pad"]))[1], {"error": "schema_refused"})
        # without the padding the same input is a good approve draft
        self.assertEqual(signer_emit.run(json.dumps(ok, sort_keys=True, separators=(",", ":")).encode())[0], 0)

    def draft(self, name):
        return self.v[name]["input"]["draft"]

    def test_each_refusal_carries_the_one_defect_its_id_names(self):
        d = self.draft
        self.assertEqual(d("sgn/chain-draft-recipient-refused")["method"], "local:handsal.device.remove")
        self.assertIn("recipient", d("sgn/chain-draft-recipient-refused"))
        self.assertEqual(d("sgn/expires-in-s-refused-for-chain-method")["method"], "local:handsal.device.add")
        self.assertIn("expires_in_s", d("sgn/expires-in-s-refused-for-chain-method"))
        self.assertEqual(d("sgn/expires-in-s-zero-refused")["expires_in_s"], "0")
        self.assertEqual(d("sgn/expires-over-30d")["expires_in_s"], "2592001")
        self.assertNotIn("performer", d("sgn/parent-performer-required")["parent"])
        self.assertIn("id", d("sgn/parent-performer-required")["parent"])
        for name, key in (("sgn/refuse-auth-handle", "auth_context"), ("sgn/refuse-display-text", "prompt"),
                          ("sgn/refuse-nonce-input", "nonce"), ("sgn/refuse-ts-input", "ts")):
            self.assertIn(key, d(name), name)
            self.assertEqual(d(name)["method"], "local:handsal.request.approve", name)
        self.assertNotEqual(d("sgn/refuse-schema-violation")["body"], {})
        self.assertEqual(d("sgn/refuse-unknown-method")["method"], "local:handsal.request.send")
        self.assertNotIn("relay", d("sgn/verdict-draft-missing-relay-refused"))
        recipient = self.v["sgn/verdict-recipient-not-performer-refused"]["input"]
        self.assertEqual((recipient["draft"]["recipient"], recipient["fixed"]["performer"]), ("bob", "alice"))

    def test_the_retired_record_draft_is_unsupported_with_its_attachment_sent(self):
        v = self.v["sgn/record-promote-retired-refused"]["input"]
        self.assertEqual(v["draft"]["method"], "local:handsal.record.promote")
        self.assertEqual(sorted(v["draft"]["body"]), ["anchors", "record_id"])
        self.assertEqual(base64.b64decode(v["attachments"]["record_body_b64"]), b"record body v1")
        self.assertEqual(sorted(v["fixed"]), ["kid", "nonce", "performer", "ts"])

    def test_the_genesis_row_is_an_original_whose_org_is_another_hash(self):
        v = self.v["sgn/genesis-org-not-document-hash-refused"]["input"]
        doc = v["attachments"]["document"]
        self.assertIsNone(doc["prev"])
        self.assertTrue(base.is_hashstr(v["draft"]["org"]))
        self.assertNotEqual(v["draft"]["org"], base.hashstr(jcs.emit(doc)))
        self.assertNotIn("head", v["draft"])

    def test_the_order_rows_each_carry_two_defects_and_the_first_one_decides(self):
        # SG-08: identity before any attachment is read, head presence before org
        v = self.v["sgn/identity-before-attachment-refused"]["input"]
        self.assertEqual((v["draft"]["recipient"], v["fixed"]["performer"]), ("bob", "alice"))
        self.assertEqual(v["attachments"], {})
        g = self.v["sgn/genesis-head-before-org-refused"]["input"]
        doc = g["attachments"]["document"]
        self.assertIsNone(doc["prev"])
        self.assertIn("head", g["draft"])
        self.assertNotEqual(g["draft"]["org"], base.hashstr(jcs.emit(doc)))

    def test_the_step_one_and_three_order_rows_carry_two_defects_each(self):
        # SG-08: an absent document is missing whatever the head says; the method is decided
        # before the forms of `fixed`
        g = self.v["sgn/genesis-document-missing-before-head-refused"]["input"]
        self.assertNotIn("document", g["attachments"])
        self.assertIn("head", g["draft"])
        u = self.v["sgn/unsupported-method-before-bad-fixed-refused"]["input"]
        self.assertEqual(u["draft"]["method"], "local:handsal.request.send")
        self.assertFalse(base.is_hashstr(u["fixed"]["nonce"]))

    def test_no_ceremony_pin_helper_or_installer_id_is_a_vector(self):
        self.assertFalse([n for n in self.v if n.startswith(RETIRED_PREFIXES)])


if __name__ == "__main__":
    unittest.main()
