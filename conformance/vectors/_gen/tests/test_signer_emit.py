"""The generator's model of the signer `emit` command (CF-04, SG-01, SG-04, SG-13, ACT-05).

`lib/signer_emit.py` is written from the spec alone. Its payload for a draft must equal the
payload the base builders sign for the same act (two derivations of one fact), and every refusal
the vectors state must be one the model gives for exactly that defect.
"""
import base64
import copy
import json
import unittest

from lib import base, forge, jcs, signer_emit

FX = base.Fixtures(base.fixture_profile())
MAX_INPUT = 16777216


def stdin_of(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def payload_of(jws):
    return forge.parts(jws)[1]


def fixed_of(jws):
    payload = json.loads(payload_of(jws))
    return {"kid": json.loads(forge.parts(jws)[0])["kid"], "nonce": payload["nonce"],
            "performer": payload["performer_id"], "ts": payload["ts"]}


def approve_input(kind="approve"):
    jws = FX.verdict(kind)
    return {
        "attachments": {"request_b64": FX.request_b64()},
        "draft": {"body": {}, "expires_in_s": "3600", "head": {"id": FX.org_id, "kind": "chain"},
                  "method": "local:handsal.request.%s" % kind, "org": FX.org_id,
                  "recipient": "alice", "relay": base.RELAY_HOST, "request_id": base.REQUEST_ID},
        "fixed": fixed_of(jws)}, jws


def add_input(label=None):
    first = FX.device_add("alice2", ("alice", "bob"))
    second = FX.device_add("bob2", ("bob", "carol"), parent=first, label=label)
    entry = FX.device_entry("bob2")
    body = {"agree": entry["agree"], "class": entry["class"], "kid": entry["kid"],
            "label": label or entry["label"],
            "link_code_hash": base.hashstr(b"link-code/bob2"), "person": "bob",
            "sign": entry["sign"]}
    return {
        "attachments": {},
        "draft": {"body": body, "method": "local:handsal.device.add", "org": FX.org_id,
                  "parent": {"id": first.id, "performer": "alice"}},
        "fixed": fixed_of(second.acts[0])}, second.acts[0]


def run(value):
    code, obj = signer_emit.run(stdin_of(value))
    return code, obj


def edit(value, mutate):
    out = copy.deepcopy(value)
    mutate(out)
    return out


class Payload(unittest.TestCase):
    def test_a_verdict_draft_emits_the_payload_the_base_builder_signs(self):
        for kind in ("approve", "reject", "needs-info"):
            inp, jws = approve_input(kind)
            self.assertEqual(run(inp), (0, {"payload_hex": payload_of(jws).hex()}), kind)

    def test_a_device_add_draft_emits_the_payload_the_base_builder_signs(self):
        inp, jws = add_input()
        self.assertEqual(run(inp), (0, {"payload_hex": payload_of(jws).hex()}))

    def test_a_slash_is_written_raw(self):
        inp, jws = add_input("a/b")
        code, out = run(inp)
        self.assertEqual(code, 0)
        self.assertIn(b'"label":"a/b"', bytes.fromhex(out["payload_hex"]))
        self.assertEqual(bytes.fromhex(out["payload_hex"]), payload_of(jws))

    def test_the_emitted_bytes_are_canonical_and_the_act_object_names_fixed_kid(self):
        inp, _jws = approve_input()
        raw = bytes.fromhex(run(inp)[1]["payload_hex"])
        self.assertEqual(jcs.recognize(raw), (True, None))
        act = json.loads(raw)["ext"]["dev.handsal/act"]
        self.assertEqual(act["kid"], inp["fixed"]["kid"])

    def test_expires_is_ts_plus_expires_in_s(self):
        inp, _jws = approve_input()
        inp["draft"]["expires_in_s"] = "60"
        act = json.loads(bytes.fromhex(run(inp)[1]["payload_hex"]))["ext"]["dev.handsal/act"]
        self.assertEqual(act["expires"], base.shift(inp["fixed"]["ts"], 60))

    def test_the_largest_allowed_expiry_is_accepted(self):
        inp, _jws = approve_input()
        inp["draft"]["expires_in_s"] = "2592000"
        self.assertEqual(run(inp)[0], 0)


REFUSED = (2, {"error": "schema_refused"})


class Framing(unittest.TestCase):
    def test_one_trailing_lf_is_framing_and_two_are_refused(self):
        inp, _jws = approve_input()
        compact = stdin_of(inp)
        self.assertEqual(signer_emit.run(compact[:-1])[0], 0)
        self.assertEqual(signer_emit.run(compact)[0], 0)
        self.assertEqual(signer_emit.run(compact + b"\n"), REFUSED)

    def test_a_number_a_space_or_unsorted_keys_are_refused(self):
        inp, _jws = approve_input()
        self.assertEqual(run(edit(inp, lambda v: v["draft"].__setitem__("expires_in_s", 3600))), REFUSED)
        text = json.dumps(inp, separators=(",", ": ")).encode() + b"\n"
        self.assertEqual(signer_emit.run(text), REFUSED)
        unsorted = b'{"fixed":' + json.dumps(inp["fixed"], separators=(",", ":")).encode() + b',"draft":{}}'
        self.assertEqual(signer_emit.run(unsorted), REFUSED)

    def test_input_over_max_input_is_refused_before_it_is_read(self):
        self.assertEqual(signer_emit.run(b"x" * (MAX_INPUT + 1)), REFUSED)

    def test_the_top_level_keys_are_exactly_attachments_draft_fixed(self):
        inp, _jws = approve_input()
        for mutate in (lambda v: v.pop("fixed"), lambda v: v.pop("attachments"),
                       lambda v: v.__setitem__("extra", {})):
            self.assertEqual(run(edit(inp, mutate)), REFUSED)


class Draft(unittest.TestCase):
    def refused_with(self, inp, mutate, want=REFUSED):
        self.assertEqual(run(edit(inp, mutate)), want)

    def test_a_key_outside_the_draft_set_is_refused(self):
        inp, _jws = approve_input()
        for key in ("ts", "nonce", "prompt", "auth_context", "inputs_hash", "outputs_hash"):
            self.refused_with(inp, lambda v, key=key: v["draft"].__setitem__(key, "x"))

    def test_a_missing_key_is_refused(self):
        inp, _jws = approve_input()
        for key in ("relay", "recipient", "request_id", "expires_in_s", "head", "org", "body"):
            self.refused_with(inp, lambda v, key=key: v["draft"].pop(key))

    def test_a_body_with_an_extra_key_is_refused(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"]["body"].__setitem__("x", "y"))

    def test_a_method_outside_the_registry_is_unsupported_method(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"].__setitem__("method", "local:handsal.request.send"),
                          (2, {"error": "unsupported_method"}))

    def test_a_chain_draft_with_recipient_expires_or_head_is_refused(self):
        inp, _jws = add_input()
        self.assertEqual(run(inp)[0], 0)
        self.refused_with(inp, lambda v: v["draft"].__setitem__("recipient", "alice"))
        self.refused_with(inp, lambda v: v["draft"].__setitem__("expires_in_s", "3600"))
        self.refused_with(inp, lambda v: v["draft"].__setitem__("head", {"id": FX.org_id, "kind": "chain"}))

    def test_a_parent_needs_exactly_id_and_performer(self):
        inp, _jws = add_input()
        self.refused_with(inp, lambda v: v["draft"]["parent"].pop("performer"))
        self.refused_with(inp, lambda v: v["draft"]["parent"].pop("id"))
        self.refused_with(inp, lambda v: v["draft"].pop("parent"))
        self.refused_with(inp, lambda v: v["draft"]["parent"].__setitem__("extra", "x"))

    def test_expires_in_s_is_a_decimal_string_from_1_to_max(self):
        inp, _jws = approve_input()
        for bad in ("0", "2592001", "01", "+1", "-1", "1.0", "", "1e3", " 1"):
            self.refused_with(inp, lambda v, bad=bad: v["draft"].__setitem__("expires_in_s", bad))
        for good in ("1", "2592000"):
            self.assertEqual(run(edit(inp, lambda v, good=good: v["draft"].__setitem__("expires_in_s", good)))[0], 0)

    def test_the_forms_of_the_draft_values_are_checked(self):
        inp, _jws = approve_input()
        for key, bad in (("org", "not a hashstr"), ("recipient", "Alice"), ("relay", "R.example"),
                         ("relay", "a..b"), ("relay", "-a.example"), ("request_id", "short"),
                         ("head", {"id": "x", "kind": "chain"}),
                         ("head", {"id": FX.org_id, "kind": "merkle"})):
            self.refused_with(inp, lambda v, key=key, bad=bad: v["draft"].__setitem__(key, bad))

    def test_a_recipient_that_is_not_the_performer_is_identity_mismatch(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"].__setitem__("recipient", "bob"),
                          (2, {"error": "identity_mismatch"}))
        self.refused_with(inp, lambda v: v["fixed"].__setitem__("performer", "bob"),
                          (2, {"error": "identity_mismatch"}))

    def test_a_schema_defect_is_reported_before_the_identity_one(self):
        inp, _jws = approve_input()

        def both(v):
            v["draft"]["recipient"] = "bob"
            v["draft"].pop("relay")
        self.refused_with(inp, both)


def genesis_input(org):
    return {"attachments": {"document": FX.org},
            "draft": {"body": {}, "method": "local:handsal.genesis.sign", "org": org},
            "fixed": {"kid": FX.key("alice").kid, "nonce": base.hashstr(b"n"), "performer": "alice",
                      "ts": base.NOW}}


class Genesis(unittest.TestCase):
    def test_an_original_whose_org_is_not_the_document_hash_is_attachment_mismatch(self):
        self.assertEqual(run(genesis_input(base.hashstr(b"another"))),
                         (2, {"error": "attachment_mismatch"}))

    def test_an_original_draft_has_no_head(self):
        inp = genesis_input(base.hashstr(b"another"))
        inp["draft"]["head"] = {"id": FX.org_id, "kind": "chain"}
        self.assertEqual(run(inp), REFUSED)

    def test_the_model_does_not_derive_what_no_vector_needs(self):
        with self.assertRaises(signer_emit.NotModeled):
            run(genesis_input(FX.org_id))


class Padding(unittest.TestCase):
    def test_a_row_padded_to_max_input_plus_one_is_refused(self):
        inp, _jws = approve_input()
        stdin = signer_emit.padded_stdin(inp, ["attachments", "request_b64"])
        self.assertEqual(len(stdin), MAX_INPUT + 1)
        self.assertEqual(signer_emit.run(stdin), REFUSED)
        self.assertTrue(base64.b64decode(inp["attachments"]["request_b64"]))


if __name__ == "__main__":
    unittest.main()
