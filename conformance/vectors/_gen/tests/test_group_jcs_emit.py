"""T3.1 vectors jcs/emit-roundtrip-* seen through `subset` (ACT-05).

The payload bytes are those the base builders sign, so emit, recognize,
compare is the identity on real acts (ACT-05). Every method of ACT-09 has a row.
"""
import base64
import json
import tempfile
import unittest
from pathlib import Path

import generate
from lib import base, jcs, result

OK = result.line({"canonical": True, "reason": "ok"})
ROWS = {"jcs/emit-roundtrip-approve", "jcs/emit-roundtrip-device-add",
        "jcs/emit-roundtrip-endorse", "jcs/emit-roundtrip-genesis-sign",
        "jcs/emit-roundtrip-device-remove", "jcs/emit-roundtrip-member-add",
        "jcs/emit-roundtrip-reject", "jcs/emit-roundtrip-needs-info",
        "jcs/emit-roundtrip-record-promote", "jcs/emit-roundtrip-chain-resolve",
        "jcs/emit-roundtrip-decision"}
METHOD_ROWS = {  # ACT-05 S1: one signer `emit` row per method that has no other `emit` vector
    "jcs/emit-device-remove": "device.remove", "jcs/emit-member-add": "member.add",
    "jcs/emit-chain-resolve": "chain.resolve", "jcs/emit-endorse": "act.endorse",
    "jcs/emit-reject": "request.reject", "jcs/emit-needs-info": "request.needs-info",
    "jcs/emit-record-promote": "record.promote", "jcs/emit-decision": "decision",
    "jcs/emit-genesis-sign-original": "genesis.sign",
    "jcs/emit-genesis-sign-change": "genesis.sign"}
EMIT = {"jcs/emit-sorted", "jcs/emit-slash-raw", "jcs/emit-value-with-number-refused"} | set(METHOD_ROWS)


def payload(jws):
    seg = jws.split(".")[1]
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class Emit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name)
        import groups.jcs_emit as module
        generate.run(out, registry=[module], known_ids=generate.shipping_ids())
        cls.v = {}
        for path in sorted(out.glob("jcs.*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            cls.v[doc["name"]] = doc
        cls.fx = base.Fixtures(base.fixture_profile())

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_rows(self):
        self.assertEqual(set(self.v), ROWS | EMIT)

    def test_every_roundtrip_row_is_subset_over_the_payload_bytes_and_canonical(self):
        for name, v in self.v.items():
            if name in EMIT:
                continue
            self.assertEqual(v["command"], "subset", name)
            self.assertEqual(v["anchor"], OK, name)
            raw = v["input_raw"].encode("ascii")
            self.assertEqual(jcs.recognize(raw), (True, None), name)
            self.assertEqual(jcs.emit(json.loads(raw)), raw)

    def test_the_signer_emit_rows(self):
        # ACT-05 S1, CF-04 S3: `emit` through the signer conformance executable
        for name in EMIT:
            v = self.v[name]
            self.assertEqual(v["command"], "emit", name)
            self.assertEqual(sorted(v["input"]), ["attachments", "draft", "fixed"], name)
        sorted_row, slash = self.v["jcs/emit-sorted"], self.v["jcs/emit-slash-raw"]
        for v in (sorted_row, slash):
            self.assertNotIn("exit", v)
            self.assertEqual(v["input"]["draft"]["method"], "local:handsal.device.add")
            raw = bytes.fromhex(json.loads(v["anchor"])["payload_hex"])
            self.assertEqual(jcs.recognize(raw), (True, None))
            self.assertEqual(jcs.emit(json.loads(raw)), raw)
        self.assertEqual(slash["input"]["draft"]["body"]["label"], "a/b")
        self.assertIn(b'"label":"a/b"', bytes.fromhex(json.loads(slash["anchor"])["payload_hex"]))
        self.assertNotEqual(sorted_row["input"]["draft"]["body"]["label"], "a/b")
        number = self.v["jcs/emit-value-with-number-refused"]
        self.assertEqual(number["exit"], 2)
        self.assertEqual(json.loads(number["anchor"]), {"error": "schema_refused"})
        self.assertIsInstance(number["input"]["draft"]["expires_in_s"], int)

    def test_each_method_row_emits_the_payload_the_base_builders_sign(self):
        from lib import emitrows
        fx = self.fx
        built = {"jcs/emit-device-remove": emitrows.device_remove_input(fx),
                 "jcs/emit-member-add": emitrows.member_add_input(fx),
                 "jcs/emit-chain-resolve": emitrows.chain_resolve_input(fx),
                 "jcs/emit-endorse": emitrows.endorse_input(fx),
                 "jcs/emit-reject": emitrows.verdict_input(fx, "reject"),
                 "jcs/emit-needs-info": emitrows.verdict_input(fx, "needs-info"),
                 "jcs/emit-record-promote": emitrows.record_promote_input(fx),
                 "jcs/emit-decision": emitrows.decision_input(fx),
                 "jcs/emit-genesis-sign-original": emitrows.genesis_original_input(fx),
                 "jcs/emit-genesis-sign-change": emitrows.genesis_change_input(fx)}
        for name, method in METHOD_ROWS.items():
            v = self.v[name]
            self.assertEqual(v["command"], "emit", name)
            self.assertNotIn("exit", v)
            self.assertEqual(v["input"]["draft"]["method"], "local:handsal." + method, name)
            self.assertEqual(json.loads(v["anchor"])["payload_hex"],
                             payload(built[name][1]).hex(), name)
            self.assertEqual(v["input"], json.loads(json.dumps(built[name][0], sort_keys=True)))

    def test_the_genesis_rows_differ_in_head_and_attachments(self):
        original = self.v["jcs/emit-genesis-sign-original"]["input"]
        change = self.v["jcs/emit-genesis-sign-change"]["input"]
        self.assertNotIn("head", original["draft"])
        self.assertEqual(list(original["attachments"]), ["document"])
        self.assertIn("head", change["draft"])
        self.assertEqual(sorted(change["attachments"]), ["document", "previous"])

    def test_the_emit_rows_are_the_payloads_the_base_builders_sign(self):
        fx = self.fx
        first = fx.device_add("alice2", ["alice", "bob"])
        plain = fx.device_add("bob2", ["bob", "carol"], parent=first)
        slashed = fx.device_add("bob2", ["bob", "carol"], parent=first, label="a/b")
        for name, built in (("jcs/emit-sorted", plain), ("jcs/emit-slash-raw", slashed)):
            self.assertEqual(json.loads(self.v[name]["anchor"])["payload_hex"],
                             payload(built.acts[0]).hex(), name)

    def test_bytes_are_the_signed_payloads(self):
        fx = self.fx
        add = fx.device_add("alice2", ["alice", "bob"])
        self.assertEqual(self.v["jcs/emit-roundtrip-device-add"]["input_raw"].encode(),
                         payload(add.acts[0]))
        self.assertEqual(self.v["jcs/emit-roundtrip-endorse"]["input_raw"].encode(),
                         payload(add.acts[1]))
        self.assertEqual(self.v["jcs/emit-roundtrip-approve"]["input_raw"].encode(),
                         payload(fx.approve()))

    def test_the_methods_are_the_ones_named(self):
        for name, method in (("device-add", "device.add"), ("endorse", "act.endorse"),
                             ("approve", "request.approve"), ("genesis-sign", "genesis.sign"),
                             ("device-remove", "device.remove"), ("member-add", "member.add"),
                             ("reject", "request.reject"), ("needs-info", "request.needs-info"),
                             ("record-promote", "record.promote"),
                             ("chain-resolve", "chain.resolve")):
            obj = json.loads(self.v["jcs/emit-roundtrip-" + name]["input_raw"])
            self.assertEqual(obj["method"], "local:handsal." + method)

    def test_genesis_sign_row_is_a_change_with_a_head(self):
        obj = json.loads(self.v["jcs/emit-roundtrip-genesis-sign"]["input_raw"])
        act = obj["ext"]["dev.handsal/act"]
        self.assertIn("head", act)


if __name__ == "__main__":
    unittest.main()
