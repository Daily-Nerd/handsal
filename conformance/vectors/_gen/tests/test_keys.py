"""T2.1 fixture keys (KC-07, GP-18, CF-06).

The fixture scalars are public test material. These tests pin the three
properties the generator relies on: scalars are valid P-256 scalars, kids are
unique, and every kid is the RFC 7638 thumbprint of its key (spec KC-04 /
section 2 "thumbprint"), recomputed here independently of lib.keys.
"""
import base64
import hashlib
import json
import unittest
from pathlib import Path

from lib import keys, p256

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def thumb(x: str, y: str) -> str:
    # RFC 7638: required members only, lexicographic order, no whitespace.
    text = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (x, y)
    return b64u(hashlib.sha256(text.encode("ascii")).digest())


def load():
    with open(FIXTURES / "keys.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    with open(FIXTURES / "fixture-kids.json", encoding="utf-8") as fh:
        kids = json.load(fh)
    return doc, kids


class P256Arithmetic(unittest.TestCase):
    def test_generator_is_d1(self):
        self.assertEqual(p256.mul(1), (p256.GX, p256.GY))

    def test_rfc6979_a25_public_point(self):
        d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        x, y = p256.mul(d)
        self.assertEqual(x, 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6)
        self.assertEqual(y, 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)

    def test_order_times_generator_is_infinity(self):
        self.assertIsNone(p256.mul(p256.N))

    def test_agrees_with_cryptography(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        for d in (1, 2, p256.N - 1, 0xDEADBEEF1234567890ABCDEF):
            nums = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
            self.assertEqual(p256.mul(d), (nums.x, nums.y))


class FixtureKeys(unittest.TestCase):
    def test_scalars_in_range(self):
        doc, _ = load()
        self.assertTrue(doc["keys"])
        for label, entry in doc["keys"].items():
            d = int(entry["d"], 16)
            self.assertEqual(len(entry["d"]), 64, label)
            self.assertTrue(1 <= d <= p256.N - 1, label)

    def test_public_point_matches_scalar_and_is_43_chars(self):
        doc, _ = load()
        for label, entry in doc["keys"].items():
            x, y = p256.mul(int(entry["d"], 16))
            self.assertEqual(entry["x"], b64u(x.to_bytes(32, "big")), label)
            self.assertEqual(entry["y"], b64u(y.to_bytes(32, "big")), label)
            self.assertEqual(len(entry["x"]), 43, label)
            self.assertEqual(len(entry["y"]), 43, label)

    def test_scalars_and_points_unique(self):
        doc, _ = load()
        ds = [e["d"] for e in doc["keys"].values()]
        pts = [(e["x"], e["y"]) for e in doc["keys"].values()]
        self.assertEqual(len(set(ds)), len(ds))
        self.assertEqual(len(set(pts)), len(pts))

    def test_kids_unique_and_equal_thumbprint(self):
        doc, _ = load()
        kids = []
        for label, entry in doc["keys"].items():
            if "kid" not in entry:
                self.assertTrue(label.endswith(".agree"), label)
                continue
            self.assertEqual(entry["kid"], thumb(entry["x"], entry["y"]), label)
            self.assertEqual(len(entry["kid"]), 43, label)
            kids.append(entry["kid"])
        self.assertEqual(len(set(kids)), len(kids))

    def test_every_signing_key_and_relay_has_a_kid(self):
        doc, _ = load()
        for label, entry in doc["keys"].items():
            if label.endswith(".agree"):
                self.assertNotIn("kid", entry, label)
            else:
                self.assertIn("kid", entry, label)

    def test_fixture_kids_list_is_exactly_the_kids(self):
        doc, listed = load()
        expected = sorted(e["kid"] for e in doc["keys"].values() if "kid" in e)
        self.assertEqual(listed, expected)

    def test_agree_key_never_equals_sign_key(self):
        doc, _ = load()
        for label, entry in doc["keys"].items():
            if label.endswith(".sign"):
                other = doc["keys"][label[: -len(".sign")] + ".agree"]
                self.assertNotEqual((entry["x"], entry["y"]), (other["x"], other["y"]))

    def test_required_principals_present(self):
        doc, _ = load()
        labels = set(doc["keys"])
        for device in ("alice", "alice2", "alice3", "bob", "bob2", "carol",
                       "dave", "frank", "grace", "X1", "X2"):
            self.assertIn(device + ".sign", labels)
            self.assertIn(device + ".agree", labels)
        # KC-08 role-holder PIN class case: alice and frank hold a pin device.
        self.assertIn("alice-pin.sign", labels)
        self.assertIn("frank-pin.sign", labels)
        # KC-07: exactly one relay key, labelled relay-fixture.
        self.assertIn("relay-fixture", labels)
        self.assertNotIn("relay-fixture.agree", labels)

    def test_committed_files_equal_regeneration(self):
        doc, listed = load()
        self.assertEqual(doc, keys.build_keys_doc())
        self.assertEqual(listed, keys.build_kids_list())

    def test_derivation_is_label_hash_reduced(self):
        n = p256.N
        h = hashlib.sha256(b"handsal-fixture-v1/alice.sign").digest()
        expected = int.from_bytes(h, "big") % (n - 1) + 1
        self.assertEqual(keys.derive_scalar("alice.sign"), expected)

    def test_no_production_key_material(self):
        doc, _ = load()
        for label in doc["keys"]:
            self.assertNotIn("prod", label.lower())


class EntryPoint(unittest.TestCase):
    def test_importing_make_keys_does_not_rewrite_the_fixtures(self):
        """The entry script rewrites core files, so only running it may do that."""
        import importlib
        import sys
        calls = []
        original = keys.write
        keys.write = lambda *a, **k: calls.append(a)
        sys.modules.pop("make_keys", None)
        try:
            importlib.import_module("make_keys")
        finally:
            keys.write = original
            sys.modules.pop("make_keys", None)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
