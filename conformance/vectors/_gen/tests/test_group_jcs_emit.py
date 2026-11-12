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
        "jcs/emit-roundtrip-record-promote", "jcs/emit-roundtrip-chain-resolve"}


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
        self.assertEqual(set(self.v), ROWS)

    def test_every_row_is_subset_over_the_payload_bytes_and_canonical(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "subset", name)
            self.assertEqual(v["anchor"], OK, name)
            raw = v["input_raw"].encode("ascii")
            self.assertEqual(jcs.recognize(raw), (True, None), name)
            self.assertEqual(jcs.emit(json.loads(raw)), raw)

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
