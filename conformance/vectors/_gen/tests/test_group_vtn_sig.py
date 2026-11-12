"""T3.20 vectors vtn/* and sig/* (VR-03, VR-04, ACT-14).

Left the catalog (CF-07), with the reason: vtn/unexpected-vitni-reason, vtn/unknown-vitni-reason-string,
cli/verifier-unavailable, cli/vitni-env-ignored, cli/vitni-path-not-root-owned (a vector has
no way to stub or remove vitni: the command-line input has no such field), and
sig/s-equals-half (no valid ECDSA signature has a chosen S).
"""
import json
import unittest

from lib import base, es256, forge, inputs, p256
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
VTN = {"vtn/bad-signature", "vtn/context-mismatch", "vtn/missing-expect-method",
       "vtn/revoked-key", "vtn/unaccepted-bad-sig", "vtn/unaccepted-map-keyed-by-person",
       "vtn/unknown-key"}
SIG = {"sig/high-s", "sig/low-s-ok", "sig/r-ge-n", "sig/r-zero", "sig/s-ge-n", "sig/s-zero"}


def _sig(v):
    return forge.parts(v["input"]["jws"])[2]


class Vtn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("vtn", ["vtn"])

    def test_rows(self):
        self.assertEqual(set(self.v), VTN)

    def test_every_row_is_check_act_with_the_catalog_code(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act", name)
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)

    def test_class_is_the_class_of_the_pinned_state_device_with_the_header_kid(self):
        # VR-01: a kid the state does not have gives null; a kid it has gives its class
        cls = {n: json.loads(v["anchor"]).get("class") for n, v in self.v.items()
               if "error" not in json.loads(v["anchor"])}
        self.assertIsNone(cls["vtn/unknown-key"])
        self.assertEqual(cls["vtn/bad-signature"], "apple-se-bio")
        self.assertEqual(cls["vtn/context-mismatch"], "apple-se-bio")
        self.assertEqual(cls["vtn/revoked-key"], "apple-se-bio")
        self.assertEqual(cls["vtn/unaccepted-bad-sig"], "fixture-pin")
        self.assertEqual(cls["vtn/unaccepted-map-keyed-by-person"], "fixture-pin")

    def test_missing_expect_method_input_lacks_the_key(self):
        v = self.v["vtn/missing-expect-method"]
        self.assertNotIn("expect_method", v["input"])
        self.assertEqual(v["anchor"], '{"error":"malformed_input"}')

    def test_context_mismatch_is_a_reject_checked_as_approve(self):
        v = self.v["vtn/context-mismatch"]
        self.assertEqual(v["input"]["expect_method"], inputs.APPROVE)
        self.assertEqual(json.loads(forge.parts(v["input"]["jws"])[1])["method"], inputs.REJECT)

    def test_bad_signature_flips_one_byte_of_s(self):
        v = self.v["vtn/bad-signature"]
        good = FX.approve()
        diff = [i for i, (a, b) in enumerate(zip(_sig(v), forge.parts(good)[2])) if a != b]
        self.assertEqual(len(diff), 1)
        self.assertGreaterEqual(diff[0], 32)

    def test_revoked_key_has_the_removal_in_the_bag(self):
        v = self.v["vtn/revoked-key"]
        methods = [json.loads(forge.parts(j)[1])["method"] for j in v["input"]["acts"]]
        self.assertIn("local:handsal.device.remove", methods)

    def test_unaccepted_rows_have_dave_added_with_a_pin_class_device(self):
        for name in ("vtn/unaccepted-bad-sig", "vtn/unaccepted-map-keyed-by-person"):
            v = self.v[name]
            methods = [json.loads(forge.parts(j)[1])["method"] for j in v["input"]["acts"]]
            self.assertEqual(methods.count("local:handsal.member.add"), 1)
            self.assertEqual(methods.count("local:handsal.device.add"), 1)
            self.assertEqual(json.loads(forge.parts(v["input"]["jws"])[0])["kid"],
                             FX.key("dave2").kid)
        p = json.loads(forge.parts(self.v["vtn/unaccepted-map-keyed-by-person"]["input"]["jws"])[1])
        self.assertEqual(p["performer_id"], "alice")

    def test_vitni_is_asked_about_every_negative(self):
        import groups.vtn as module
        import generate
        import tempfile
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[module], known_ids=generate.shipping_ids(), stats=stats)
        self.assertGreaterEqual(stats["negatives"], 6)


class Sig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("sig", ["sig"])

    def test_rows(self):
        self.assertEqual(set(self.v), SIG)

    def test_codes_match_the_catalog(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act", name)
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)
            self.assertEqual(json.loads(v["anchor"])["class"], "apple-se-bio", name)

    def test_high_s_is_the_twin_of_the_low_s_signature(self):
        high, low = _sig(self.v["sig/high-s"]), _sig(self.v["sig/low-s-ok"])
        self.assertFalse(es256.is_low_s(high))
        self.assertTrue(es256.is_low_s(low))
        self.assertEqual(high[:32], low[:32])
        self.assertEqual(int.from_bytes(high[32:], "big"), p256.N - int.from_bytes(low[32:], "big"))
        self.assertEqual(forge.parts(self.v["sig/high-s"]["input"]["jws"])[1],
                         forge.parts(self.v["sig/low-s-ok"]["input"]["jws"])[1])

    def test_the_low_s_row_has_a_real_signature(self):
        v = self.v["sig/low-s-ok"]
        k = FX.key("alice")
        jws = v["input"]["jws"]
        self.assertTrue(es256.verify((k.x_int, k.y_int), jws.rsplit(".", 1)[0].encode(),
                                     _sig(v)))

    def test_degenerate_r_and_s(self):
        n = p256.N
        want = {"sig/r-zero": (0, None), "sig/r-ge-n": (n, None),
                "sig/s-zero": (None, 0), "sig/s-ge-n": (None, n)}
        good = FX.approve()
        gr, gs = (int.from_bytes(forge.parts(good)[2][:32], "big"),
                  int.from_bytes(forge.parts(good)[2][32:], "big"))
        for name, (r, s) in want.items():
            sig = _sig(self.v[name])
            self.assertEqual(len(sig), 64, name)
            self.assertEqual(int.from_bytes(sig[:32], "big"), gr if r is None else r, name)
            self.assertEqual(int.from_bytes(sig[32:], "big"), gs if s is None else s, name)


if __name__ == "__main__":
    unittest.main()
