"""T3.10 envelope (ACT-01, ACT-06, ACT-08, ACT-12, ACT-13, ACT-14) and the act object of step 5.

Step 3 is the envelope only; step 5 is the act object and the body, ordered
`schema` before `body_schema` (VR-02). Rows follow the `sch/*`, `ord/*` and `bod/*` ids.
"""
import copy
import json
import unittest
from pathlib import Path

from handsal_check import emit, encoding, envelope, errors, registry

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
KID = KEYS["alice.sign"]["kid"]
REG = registry.load()
H = encoding.hashstr(b"head")
ORG = encoding.hashstr(b"org")
NONCE = encoding.hashstr(bytes(32))
APPROVE = "local:handsal.request.approve"
PROMOTE = "local:handsal.record.promote"
DEVICE_ADD = "local:handsal.device.add"
GENESIS_SIGN = "local:handsal.genesis.sign"
ENDORSE = "local:handsal.act.endorse"


def point(name):
    return {"x": KEYS[name]["x"], "y": KEYS[name]["y"]}


def verdict(method=APPROVE):
    return {
        "action_ref": None, "binding": "local",
        "cost": {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
        "ext": {"dev.handsal/act": {
            "body": {}, "expires": "2026-11-08T13:00:00Z", "head": {"id": H, "kind": "chain"},
            "kid": KID, "org": ORG, "recipient": "alice", "relay": "r.example",
            "request_id": "req-00000001"}},
        "inputs_hash": H, "log_policy": "best_effort", "method": method, "nonce": NONCE,
        "outputs_hash": H, "parent_performer_id": None, "parent_receipt_hash": None,
        "performer_id": "alice", "reason": None, "requester_id": None, "status": "OK",
        "ts": "2026-11-08T11:59:00Z", "v": "vitni/0.2"}


def promote():
    p = verdict(PROMOTE)
    act = p["ext"]["dev.handsal/act"]
    for key in ("recipient", "relay", "request_id"):
        del act[key]
    act["body"] = {"anchors": ["a1"], "record_id": "rec-1"}
    return p


def device_add():
    p = verdict(DEVICE_ADD)
    act = {"body": {"agree": point("alice2.agree"), "class": "apple-se-bio",
                    "kid": KEYS["alice2.sign"]["kid"], "label": "laptop", "link_code_hash": H,
                    "person": "alice", "sign": point("alice2.sign")},
           "kid": KID, "org": ORG}
    p["ext"] = {"dev.handsal/act": act}
    p["parent_receipt_hash"] = H
    p["parent_performer_id"] = None
    return p


def genesis_sign(with_head):
    p = verdict(GENESIS_SIGN)
    act = {"body": {}, "kid": KID, "org": ORG}
    if with_head:
        act["head"] = {"id": H, "kind": "chain"}
    p["ext"] = {"dev.handsal/act": act}
    return p


def endorse():
    p = verdict(ENDORSE)
    p["ext"] = {"dev.handsal/act": {"body": {"act": H}, "head": {"id": H, "kind": "chain"},
                                    "kid": KID, "org": ORG}}
    p["parent_receipt_hash"] = H
    p["parent_performer_id"] = "bob"
    return p


def edit(payload, path, value):
    """A deep copy of `payload` with the value at `path` replaced (or deleted if `value` is DELETE)."""
    out = copy.deepcopy(payload)
    node = out
    for step in path[:-1]:
        node = node[step]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return out


DELETE = object()
ACT = ("ext", "dev.handsal/act")


def step3(payload):
    try:
        envelope.check_envelope(payload)
    except errors.Refused as err:
        return err.code
    return None


def step5(payload, head_present=None, kid=KID):
    try:
        envelope.check_act_object(payload, kid, REG, head_present)
    except errors.Refused as err:
        return err.code
    return None


class Step2Payload(unittest.TestCase):
    def test_object_root_parses(self):
        self.assertEqual(envelope.parse_payload(emit.emit_subset({"a": "b"})), {"a": "b"})

    def test_root_must_be_an_object(self):
        for raw in (b"null", b"[]", b'"a"', b'["a"]'):
            with self.assertRaises(errors.Refused) as ctx:
                envelope.parse_payload(raw)
            self.assertEqual(ctx.exception.code, "payload_not_canonical_subset", raw)

    def test_grammar_and_size_codes_pass_through(self):
        with self.assertRaises(errors.Refused) as ctx:
            envelope.parse_payload(b'{"a":1}')
        self.assertEqual(ctx.exception.code, "payload_not_canonical_subset")
        with self.assertRaises(errors.Refused) as ctx:
            envelope.parse_payload(b'{"a":"' + b"x" * 16384 + b'"}')
        self.assertEqual(ctx.exception.code, "payload_too_large")


class Step3Envelope(unittest.TestCase):
    def test_valid_envelopes(self):
        for payload in (verdict(), promote(), device_add(), genesis_sign(True), endorse()):
            self.assertIsNone(step3(payload))

    def test_constants(self):
        for key, bad in (("status", "FAILED"), ("binding", "mcp"), ("v", "vitni/0.1"),
                         ("log_policy", "strict"), ("reason", "x"), ("action_ref", "x"),
                         ("requester_id", "x")):
            self.assertEqual(step3(edit(verdict(), [key], bad)), "schema", key)

    def test_cost_is_exactly_the_constant_object(self):
        for cost in ({"rail_ref": None, "tokens": "0", "usd_micros": "5", "wall_ms": "0"},
                     {"rail_ref": None, "tokens": "0", "usd_micros": "0"},
                     {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0", "x": "y"},
                     {"rail_ref": "x", "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
                     None, []):
            self.assertEqual(step3(edit(verdict(), ["cost"], cost)), "schema", cost)

    def test_key_set_is_exact(self):
        self.assertEqual(step3(edit(verdict(), ["seq"], "1")), "schema")
        self.assertEqual(step3(edit(verdict(), ["log_policy"], DELETE)), "schema")
        self.assertEqual(step3(edit(verdict(), ["parent_performer_id"], DELETE)), "schema")
        self.assertEqual(step3(edit(verdict(), ["ext"], DELETE)), "schema")

    def test_hashstr_fields(self):
        good = encoding.hashstr(b"y")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        spare = good[:-1] + alphabet[alphabet.index(good[-1]) | 1]
        wrong_code = "u" + encoding.b64u_encode(b"\x13\x20" + bytes(32))
        for field in ("inputs_hash", "outputs_hash", "nonce"):
            for bad in (spare, wrong_code, good[:-1], good.replace("u", "", 1), "plain", None, 3):
                self.assertEqual(step3(edit(verdict(), [field], bad)), "schema", (field, bad))

    def test_parent_receipt_hash_is_null_or_a_hashstr(self):
        self.assertIsNone(step3(edit(verdict(), ["parent_receipt_hash"], H)))
        self.assertEqual(step3(edit(verdict(), ["parent_receipt_hash"], "nope")), "schema")

    def test_parent_performer_id_is_null_or_a_member_id(self):
        self.assertIsNone(step3(edit(verdict(), ["parent_performer_id"], "bob")))
        self.assertEqual(step3(edit(verdict(), ["parent_performer_id"], "Bob")), "schema")

    def test_ts_forms(self):
        for bad in ("2026-11-08T12:00:00", "2026-11-08T12:00:00+00:00", "2026-11-08T12:00:00.5Z",
                    "2026-02-30T00:00:00Z", "2026-11-08T12:00:60Z", "2026-11-08t12:00:00Z", 5):
            self.assertEqual(step3(edit(verdict(), ["ts"], bad)), "schema", bad)

    def test_performer_forms(self):
        for bad in ("Alice", "x" * 33, "", "a", None):
            self.assertEqual(step3(edit(verdict(), ["performer_id"], bad)), "schema", bad)

    def test_method_must_be_a_string_here_and_is_judged_at_step_4(self):
        self.assertIsNone(step3(edit(verdict(), ["method"], "local:handsal.request.send")))
        self.assertEqual(step3(edit(verdict(), ["method"], 5)), "schema")

    def test_ext_is_one_object_under_one_key(self):
        act = verdict()["ext"]["dev.handsal/act"]
        for ext in ({"dev.handsal/act": act, "x.other": {}}, {}, {"x.other": act},
                    {"dev.handsal/act": []}, {"dev.handsal/act": None}, [], None):
            self.assertEqual(step3(edit(verdict(), ["ext"], ext)), "schema", ext)

    def test_the_act_object_contents_are_not_judged_before_step_5(self):
        self.assertIsNone(step3(edit(verdict(), [*ACT, "extra"], "x")))


class Step5ActObject(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(step5(verdict()))
        self.assertIsNone(step5(verdict("local:handsal.request.reject")))
        self.assertIsNone(step5(verdict("local:handsal.request.needs-info")))
        self.assertIsNone(step5(promote()))
        self.assertIsNone(step5(device_add()))
        self.assertIsNone(step5(genesis_sign(True), head_present=True))
        self.assertIsNone(step5(genesis_sign(False), head_present=False))
        self.assertIsNone(step5(endorse()))

    def test_act_object_keys(self):
        self.assertEqual(step5(edit(verdict(), [*ACT, "extra"], "x")), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "org"], DELETE)), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "head"], DELETE)), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "body"], DELETE)), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "relay"], DELETE)), "schema")

    def test_head_shape(self):
        for head in ({"id": H, "kind": "merkle"}, {"id": H, "kind": "chain", "n": "3"},
                     {"kind": "chain"}, {"id": "nope", "kind": "chain"}, None, "x", []):
            self.assertEqual(step5(edit(verdict(), [*ACT, "head"], head)), "schema", head)

    def test_head_is_absent_where_the_registry_says_never(self):
        p = edit(device_add(), [*ACT, "head"], {"id": H, "kind": "chain"})
        self.assertEqual(step5(p), "schema")

    def test_conditional_head_follows_the_document(self):
        self.assertEqual(step5(genesis_sign(False), head_present=True), "schema")
        self.assertEqual(step5(genesis_sign(True), head_present=False), "schema")

    def test_conditional_head_needs_the_caller_to_say(self):
        with self.assertRaises(ValueError):
            step5(genesis_sign(True), head_present=None)

    def test_kid_matches_the_header(self):
        self.assertEqual(step5(verdict(), kid=KEYS["bob.sign"]["kid"]), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "kid"], DELETE)), "schema")
        self.assertEqual(step5(edit(verdict(), [*ACT, "kid"], "nope")), "schema")

    def test_extra_key_forms(self):
        for key, bad in (("expires", "2026-11-08T13:00:00"), ("recipient", "Alice"),
                         ("relay", "R.example"), ("relay", "r.example."), ("request_id", "short"),
                         ("org", "nope")):
            self.assertEqual(step5(edit(verdict(), [*ACT, key], bad)), "schema", (key, bad))

    def test_parent_fields_per_method_ACT_13(self):
        v = verdict()
        self.assertEqual(step5(edit(v, ["parent_receipt_hash"], H)), "schema")
        self.assertEqual(step5(edit(v, ["parent_performer_id"], "bob")), "schema")
        self.assertEqual(step5(edit(promote(), ["parent_receipt_hash"], H)), "schema")
        self.assertEqual(step5(edit(genesis_sign(True), ["parent_receipt_hash"], H), True), "schema")
        self.assertEqual(step5(edit(device_add(), ["parent_receipt_hash"], None)), "schema")
        self.assertEqual(step5(edit(endorse(), ["parent_receipt_hash"], None)), "schema")
        self.assertEqual(step5(edit(endorse(), ["parent_performer_id"], None)), "schema")
        self.assertIsNone(step5(edit(device_add(), ["parent_performer_id"], "bob")))

    def test_performer_not_equal_to_recipient_is_not_step_5(self):
        self.assertIsNone(step5(edit(verdict(), ["performer_id"], "bob")))


class Step5Body(unittest.TestCase):
    def test_verdict_body_is_empty(self):
        self.assertEqual(step5(edit(verdict(), [*ACT, "body"], {"x": "y"})), "body_schema")

    def test_record_promote_body(self):
        body = lambda **kw: edit(promote(), [*ACT, "body"], {**{"anchors": ["a1"], "record_id": "rec-1"}, **kw})
        self.assertEqual(step5(body(anchors=["a"] * 17)), "body_schema")
        self.assertEqual(step5(body(anchors=[""])), "body_schema")
        self.assertEqual(step5(body(anchors=[])), "body_schema")
        self.assertEqual(step5(body(record_id="Rec")), "body_schema")
        self.assertEqual(step5(body(extra="x")), "body_schema")
        self.assertIsNone(step5(body(anchors=["a"] * 16)))

    def test_label_alphabet_ACT_10(self):
        for bad in ('a"b', "a\\b", "café", "x" * 65, "", "a\x7fb"):
            p = edit(device_add(), [*ACT, "body", "label"], bad)
            self.assertEqual(step5(p), "body_schema", repr(bad))

    def test_body_hashstr_form_is_schema_not_body_schema(self):
        p = edit(device_add(), [*ACT, "body", "link_code_hash"], "nope")
        self.assertEqual(step5(p), "schema")

    def test_schema_defect_is_reported_before_a_body_defect(self):
        p = edit(verdict(), [*ACT, "body"], {"x": "y"})
        p = edit(p, [*ACT, "org"], "nope")
        self.assertEqual(step5(p), "schema")
        p = edit(verdict(), [*ACT, "body"], {"x": "y"})
        p = edit(p, ["parent_receipt_hash"], H)
        self.assertEqual(step5(p), "schema")

    def test_body_key_missing_or_extra(self):
        self.assertEqual(step5(edit(device_add(), [*ACT, "body", "link_code_hash"], DELETE)), "body_schema")
        self.assertEqual(step5(edit(device_add(), [*ACT, "body", "x"], "y")), "body_schema")


class Tables(unittest.TestCase):
    def test_every_registry_method_has_an_ACT_13_row_and_no_other_does(self):
        self.assertEqual(set(envelope._PARENTS), set(REG.methods))

    def test_every_extra_act_key_has_a_form(self):
        for method in REG.methods.values():
            for key in method.act_extra_keys:
                self.assertIn(key, REG.act_extra_key_types)


class ReceiptId(unittest.TestCase):
    def test_receipt_id_is_the_hashstr_of_the_payload_bytes(self):
        raw = emit.emit_subset(verdict())
        self.assertEqual(envelope.receipt_id(raw), encoding.hashstr(raw))

    def test_same_payload_is_one_id_whatever_the_signature(self):
        raw = emit.emit_subset(verdict())
        self.assertEqual(envelope.receipt_id(raw), envelope.receipt_id(bytes(raw)))

    def test_the_signing_kid_is_inside_the_identity(self):
        a = emit.emit_subset(verdict())
        b = emit.emit_subset(edit(verdict(), [*ACT, "kid"], KEYS["alice2.sign"]["kid"]))
        self.assertNotEqual(envelope.receipt_id(a), envelope.receipt_id(b))


if __name__ == "__main__":
    unittest.main()
