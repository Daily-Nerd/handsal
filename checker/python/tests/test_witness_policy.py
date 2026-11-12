"""WT-01 policy field `witness`: shape (policy_invalid) and bounds (policy_out_of_bounds)."""
import unittest

from handsal_check import encoding, errors, registry, witness_policy

from .genesis_fixtures import KEYS, device, edit, relay_witness

REG = registry.load()
DEVICES = [device("alice"), device("bob"), device("carol")]


def shape(witness, devices=DEVICES):
    try:
        witness_policy.shape(witness, devices)
    except errors.Refused as err:
        return err.code
    return None


def bounds(witness):
    try:
        witness_policy.bounds(witness, REG)
    except errors.Refused as err:
        return err.code
    return None


class Shape(unittest.TestCase):
    def test_mode_none(self):
        self.assertIsNone(shape({"mode": "none"}))

    def test_mode_none_takes_no_other_key(self):
        self.assertEqual(shape({"mode": "none", "max_tip_age_s": "60"}), "policy_invalid")

    def test_relay_ok(self):
        self.assertIsNone(shape(relay_witness()))

    def test_not_an_object_or_unknown_mode(self):
        for bad in (None, "none", [], {}, {"mode": "relays"}, {"mode": "None"}, {"mode": 1},
                    {"mode": None}):
            self.assertEqual(shape(bad), "policy_invalid", bad)

    def test_relay_keys_are_exact(self):
        w = relay_witness()
        for key in ("max_tip_age_s", "relay_kid", "relay_pub_jwk"):
            self.assertEqual(shape(edit(w, [key], delete=True)), "policy_invalid", key)
        self.assertEqual(shape({**w, "extra": "x"}), "policy_invalid")

    def test_jwk_is_exactly_the_thumbprint_input(self):
        w = relay_witness()
        self.assertEqual(shape(edit(w, ["relay_pub_jwk", "alg"], "ES256")), "policy_invalid")
        self.assertEqual(shape(edit(w, ["relay_pub_jwk", "crv"], "P-384")), "policy_invalid")
        self.assertEqual(shape(edit(w, ["relay_pub_jwk", "kty"], "OKP")), "policy_invalid")
        self.assertEqual(shape(edit(w, ["relay_pub_jwk", "x"], delete=True)), "policy_invalid")

    def test_jwk_point_on_the_curve_and_canonical(self):
        w = relay_witness()
        y = encoding.b64u_decode(w["relay_pub_jwk"]["y"])
        off = encoding.b64u_encode(y[:-1] + bytes([y[-1] ^ 1]))
        moved = edit(w, ["relay_pub_jwk", "y"], off)
        moved["relay_kid"] = encoding.thumbprint(w["relay_pub_jwk"]["x"], off)
        self.assertEqual(shape(moved), "policy_invalid")
        short = edit(w, ["relay_pub_jwk", "x"], w["relay_pub_jwk"]["x"][:-1])
        self.assertEqual(shape(short), "policy_invalid")

    def test_kid_must_be_the_thumbprint(self):
        self.assertEqual(shape(edit(relay_witness(), ["relay_kid"], KEYS["alice.sign"]["kid"])),
                         "policy_invalid")
        self.assertEqual(shape(edit(relay_witness(), ["relay_kid"], 5)), "policy_invalid")

    def test_tip_age_is_a_decimal_string(self):
        for bad in ("060", "-1", "", "1e3", 3600, None, "3600 "):
            self.assertEqual(shape(edit(relay_witness(), ["max_tip_age_s"], bad)), "policy_invalid", bad)

    def test_relay_key_is_disjoint_from_the_devices(self):
        alice = device("alice")
        as_sign = {"max_tip_age_s": "3600", "mode": "relay", "relay_kid": alice["kid"],
                   "relay_pub_jwk": {"crv": "P-256", "kty": "EC", **alice["sign"]}}
        self.assertEqual(shape(as_sign), "policy_invalid")
        as_agree = {"max_tip_age_s": "3600", "mode": "relay",
                    "relay_kid": encoding.thumbprint(alice["agree"]["x"], alice["agree"]["y"]),
                    "relay_pub_jwk": {"crv": "P-256", "kty": "EC", **alice["agree"]}}
        self.assertEqual(shape(as_agree), "policy_invalid")

    def test_relay_kid_equal_to_a_device_kid_is_refused_even_with_another_point(self):
        w = edit(relay_witness(), ["relay_kid"], DEVICES[0]["kid"])
        self.assertEqual(shape(w), "policy_invalid")   # also fails the thumbprint rule: one code

    def test_none_mode_never_looks_at_devices(self):
        self.assertIsNone(shape({"mode": "none"}, devices=[]))


class Bounds(unittest.TestCase):
    def test_none_has_no_bounds(self):
        self.assertIsNone(bounds({"mode": "none"}))

    def test_tip_age_bounds(self):
        for ok in ("60", "3600", "86400"):
            self.assertIsNone(bounds(relay_witness(ok)), ok)
        for bad in ("0", "59", "86401", "999999999"):
            self.assertEqual(bounds(relay_witness(bad)), "policy_out_of_bounds", bad)


if __name__ == "__main__":
    unittest.main()
