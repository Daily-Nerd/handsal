"""T2.3 ES256 signing (CF-06, SG-06, VR-04).

Known answers are RFC 6979 appendix A.2.5 (P-256, SHA-256). The `sample`
signature there has a high S, which is exactly why the raw RFC output and the
profile output (low-S) are separate functions.
"""
import base64
import hashlib
import json
import unittest
from pathlib import Path

from lib import es256, keys, p256

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"

D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
PUB = p256.mul(D)
HALF = p256.N // 2

# RFC 6979 A.2.5, P-256 with SHA-256
SAMPLE = dict(
    msg=b"sample",
    k=0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
    r=0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
    s=0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
)
TEST = dict(
    msg=b"test",
    k=0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
    r=0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
    s=0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083,
)


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def rs(sig):
    return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")


class Rfc6979(unittest.TestCase):
    def test_nonce_sample(self):
        h = hashlib.sha256(SAMPLE["msg"]).digest()
        self.assertEqual(es256.rfc6979_k(D, h), SAMPLE["k"])

    def test_nonce_test(self):
        h = hashlib.sha256(TEST["msg"]).digest()
        self.assertEqual(es256.rfc6979_k(D, h), TEST["k"])

    def test_raw_signature_sample(self):
        self.assertEqual(es256.sign_raw(D, SAMPLE["msg"]), (SAMPLE["r"], SAMPLE["s"]))

    def test_raw_signature_test(self):
        self.assertEqual(es256.sign_raw(D, TEST["msg"]), (TEST["r"], TEST["s"]))

    def test_sample_is_high_s_and_test_is_low_s(self):
        self.assertGreater(SAMPLE["s"], HALF)
        self.assertLessEqual(TEST["s"], HALF)


class Signing(unittest.TestCase):
    MSG = b"eyJhbGciOiJFUzI1NiJ9.e30"

    def test_length_and_range(self):
        sig = es256.sign(D, self.MSG)
        self.assertEqual(len(sig), 64)
        r, s = rs(sig)
        self.assertTrue(0 < r < p256.N and 0 < s < p256.N)

    def test_always_low_s(self):
        for i in range(40):
            sig = es256.sign(D, b"message-%d" % i)
            self.assertTrue(es256.is_low_s(sig))
            self.assertLessEqual(rs(sig)[1], HALF)

    def test_sample_normalized(self):
        sig = es256.sign(D, SAMPLE["msg"])
        self.assertEqual(rs(sig), (SAMPLE["r"], p256.N - SAMPLE["s"]))

    def test_test_message_unchanged_by_normalization(self):
        sig = es256.sign(D, TEST["msg"])
        self.assertEqual(rs(sig), (TEST["r"], TEST["s"]))

    def test_repeat_run_is_byte_identical(self):
        self.assertEqual(es256.sign(D, self.MSG), es256.sign(D, self.MSG))

    def test_different_messages_differ(self):
        self.assertNotEqual(es256.sign(D, b"a"), es256.sign(D, b"b"))

    def test_verifies_mathematically(self):
        sig = es256.sign(D, self.MSG)
        self.assertTrue(es256.verify(PUB, self.MSG, sig))
        self.assertFalse(es256.verify(PUB, self.MSG + b"x", sig))
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertFalse(es256.verify(PUB, self.MSG, bytes(bad)))

    def test_verify_rejects_out_of_range(self):
        zero = bytes(64)
        self.assertFalse(es256.verify(PUB, self.MSG, zero))
        big = p256.N.to_bytes(32, "big") + (1).to_bytes(32, "big")
        self.assertFalse(es256.verify(PUB, self.MSG, big))
        self.assertFalse(es256.verify(PUB, self.MSG, bytes(63)))

    def test_scalar_range_checked(self):
        for bad in (0, p256.N, -1):
            with self.assertRaises(ValueError):
                es256.sign(bad, self.MSG)

    def test_agrees_with_cryptography(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        doc = json.loads((FIXTURES / "keys.json").read_text(encoding="utf-8"))
        for label in ("alice.sign", "bob.sign", "relay-fixture"):
            d = int(doc["keys"][label]["d"], 16)
            pub = ec.derive_private_key(d, ec.SECP256R1()).public_key()
            for msg in (b"", self.MSG, b"x" * 1000):
                for sig in (es256.sign(d, msg), es256.high_s_twin(es256.sign(d, msg))):
                    r, s = rs(sig)
                    pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
                    with self.assertRaises(InvalidSignature):
                        pub.verify(encode_dss_signature(r, s), msg + b"!", ec.ECDSA(hashes.SHA256()))

    def test_cryptography_signs_to_the_same_verdict(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        priv = ec.derive_private_key(D, ec.SECP256R1())
        r, s = decode_dss_signature(priv.sign(self.MSG, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self.assertTrue(es256.verify(PUB, self.MSG, sig))


class HighSTwin(unittest.TestCase):
    MSG = b"payload-for-the-twin"

    def test_differs_only_in_s(self):
        low = es256.sign(D, self.MSG)
        high = es256.high_s_twin(low)
        self.assertEqual(low[:32], high[:32])
        self.assertNotEqual(low[32:], high[32:])
        self.assertEqual(rs(low)[1] + rs(high)[1], p256.N)

    def test_is_high_s_and_fails_the_low_s_check(self):
        high = es256.high_s_twin(es256.sign(D, self.MSG))
        self.assertGreater(rs(high)[1], HALF)
        self.assertFalse(es256.is_low_s(high))

    def test_still_verifies_mathematically(self):
        high = es256.high_s_twin(es256.sign(D, self.MSG))
        self.assertTrue(es256.verify(PUB, self.MSG, high))

    def test_twin_refuses_a_high_input(self):
        high = es256.high_s_twin(es256.sign(D, self.MSG))
        # defined from the low-S form only; twin of a twin is refused, not undone
        with self.assertRaises(ValueError):
            es256.high_s_twin(high)

    def test_half_boundary(self):
        edge = (1).to_bytes(32, "big") + HALF.to_bytes(32, "big")
        over = (1).to_bytes(32, "big") + (HALF + 1).to_bytes(32, "big")
        self.assertTrue(es256.is_low_s(edge))
        self.assertFalse(es256.is_low_s(over))


class Jws(unittest.TestCase):
    HEADER = b'{"alg":"ES256","kid":"K"}'
    PAYLOAD = b'{"a":null}'

    def test_compact_form_and_signing_input(self):
        token = es256.sign_jws(D, self.HEADER, self.PAYLOAD)
        h, p, s = token.split(".")
        self.assertEqual(h, b64u(self.HEADER))
        self.assertEqual(p, b64u(self.PAYLOAD))
        sig = base64.urlsafe_b64decode(s + "==")
        self.assertEqual(len(sig), 64)
        self.assertEqual(s, b64u(sig))
        self.assertTrue(es256.verify(PUB, (h + "." + p).encode("ascii"), sig))
        self.assertTrue(es256.is_low_s(sig))

    def test_high_s_form_same_first_two_segments(self):
        low = es256.sign_jws(D, self.HEADER, self.PAYLOAD)
        high = es256.sign_jws(D, self.HEADER, self.PAYLOAD, high_s=True)
        self.assertEqual(low.split(".")[:2], high.split(".")[:2])
        sig = base64.urlsafe_b64decode(high.split(".")[2] + "==")
        self.assertFalse(es256.is_low_s(sig))
        h, p, _ = high.split(".")
        self.assertTrue(es256.verify(PUB, (h + "." + p).encode("ascii"), sig))

    def test_receipt_id_inputs_are_stable(self):
        a = es256.sign_jws(D, self.HEADER, self.PAYLOAD)
        b = es256.sign_jws(D, self.HEADER, self.PAYLOAD)
        self.assertEqual(a, b)

    def test_fixture_key_helper(self):
        doc = keys.build_keys_doc()
        d = int(doc["keys"]["alice.sign"]["d"], 16)
        token = es256.sign_jws(d, self.HEADER, self.PAYLOAD)
        x, y = p256.mul(d)
        h, p, s = token.split(".")
        self.assertTrue(es256.verify((x, y), (h + "." + p).encode(), base64.urlsafe_b64decode(s + "==")))


if __name__ == "__main__":
    unittest.main()
