"""T3.38 the tip statement (WT-02): its exact shape, parsed once. Every violation is `witness_malformed`
(WT-05 step 2); the signature is not looked at here (step 4)."""
import unittest

from handsal_check import encoding, errors, witness_stmt

from .act_builder import GOOD, HIGH, head_of
from .witness_fixtures import RELAY_KID, statement

ORG = encoding.hashstr(b"org")
EPOCH = encoding.hashstr(b"epoch")
TIP = encoding.hashstr(b"tip")


def stmt(**over):
    fields = dict(epoch=EPOCH, tip=TIP, org=ORG)
    fields.update(over)
    return statement(**fields)


def code(text):
    try:
        witness_stmt.parse(text)
    except errors.Refused as err:
        return err.code
    return None


def drop(*path):
    def edit(payload):
        node = payload
        for step in path[:-1]:
            node = node[step]
        del node[path[-1]]
    return edit


def put(path, value):
    def edit(payload):
        node = payload
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    return edit


ACT = ("ext", "dev.handsal/act")


class Parse(unittest.TestCase):
    def test_a_good_statement(self):
        act = stmt()
        got = witness_stmt.parse(act.jws)
        self.assertEqual((got.kid, got.org, got.epoch, got.next, got.tip, got.ts),
                         (RELAY_KID, ORG, EPOCH, "no", TIP, "2026-11-08T11:59:00Z"))
        self.assertEqual(len(got.signature), 64)
        self.assertEqual(stmt(next="yes").jws and witness_stmt.parse(stmt(next="yes").jws).next, "yes")

    def test_a_high_s_statement_still_parses_the_signature_is_step_4(self):
        self.assertIsNone(code(stmt(sig=HIGH).jws))

    def test_every_violation_is_witness_malformed(self):
        cases = {
            "not a jws": "junk",
            "not a string": 5,
            "body also carries time": stmt(body={"epoch": EPOCH, "next": "no", "tip": TIP, "time": "x"}),
            "body without next": stmt(body={"epoch": EPOCH, "tip": TIP}),
            "body without epoch": stmt(body={"next": "no", "tip": TIP}),
            "body without tip": stmt(body={"epoch": EPOCH, "next": "no"}),
            "next null": stmt(body={"epoch": EPOCH, "next": None, "tip": TIP}),
            "next true string": stmt(next="true"),
            "next other string": stmt(next="maybe"),
            "next upper": stmt(next="YES"),
            "epoch not a hashstr": stmt(epoch="nope"),
            "tip not a hashstr": stmt(tip="nope"),
            "head present": stmt(head=head_of(TIP)),
            "act kid present": stmt(edit=put(ACT + ("kid",), RELAY_KID)),
            "act object extra key": stmt(edit=put(ACT + ("extra",), "x")),
            "org not a hashstr": stmt(org="nope"),
            "org missing": stmt(edit=drop(*ACT, "org")),
            "wrong method": stmt(edit=put(("method",), "local:handsal.request.approve")),
            "method of another family": stmt(edit=put(("method",), "local:handsal.relay.other")),
            "performer not relay": stmt(performer="alice"),
            "parent receipt set": stmt(edit=put(("parent_receipt_hash",), TIP)),
            "parent performer set": stmt(edit=put(("parent_performer_id",), "alice")),
            "inputs_hash not empty": stmt(edit=put(("inputs_hash",), TIP)),
            "outputs_hash not empty": stmt(edit=put(("outputs_hash",), TIP)),
            "envelope constant": stmt(edit=put(("v",), "vitni/0.3")),
            "extra envelope key": stmt(edit=put(("extra",), "x")),
            "bad ts": stmt(ts="yesterday"),
            "nonce not a hashstr": stmt(edit=put(("nonce",), "x")),
            "ext with a second key": stmt(edit=put(("ext", "other"), {})),
        }
        for label, text in cases.items():
            self.assertEqual(code(text if isinstance(text, (str, int)) else text.jws), "witness_malformed", label)

    def test_a_payload_over_the_maximum_is_malformed(self):
        head, payload, sig = stmt().jws.split(".")
        raw = encoding.b64u_decode(payload)
        padded = raw[:-1] + b',"zz":"' + b"x" * 17000 + b'"}'   # canonical order aside, it is over 16384 bytes
        self.assertGreater(len(padded), 16384)
        self.assertEqual(code(".".join((head, encoding.b64u_encode(padded), sig))), "witness_malformed")

    def test_a_json_boolean_next_fails_the_subset_before_anything_else(self):
        head, payload, sig = stmt().jws.split(".")
        raw = encoding.b64u_decode(payload).replace(b'"next":"no"', b'"next":false')
        self.assertNotEqual(raw, encoding.b64u_decode(payload))
        self.assertEqual(code(".".join((head, encoding.b64u_encode(raw), sig))), "witness_malformed")

    def test_a_non_canonical_payload_is_malformed(self):
        act = stmt()
        head, payload, sig = act.jws.split(".")
        raw = encoding.b64u_decode(payload)
        spaced = raw.replace(b'"v":', b'"v": ')
        text = ".".join((head, encoding.b64u_encode(spaced), sig))
        self.assertEqual(code(text), "witness_malformed")

    def test_a_statement_is_not_an_act_it_has_no_registry_method(self):
        from handsal_check import registry
        self.assertIsNone(registry.load().method("local:handsal.relay.tip"))


if __name__ == "__main__":
    unittest.main()
