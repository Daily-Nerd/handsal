"""Known answers of the signer command `agree` (SG-16, KC-09): the third, independent derivation.

The Swift and Rust signers read `conformance/fixtures/agree-kat.json`. The file is written by
`lib/agree.py` (pure Python P-256 and HMAC), and this test recomputes every answer with the
`cryptography` package, which shares no code with either. All keys are the public fixture keys.
"""
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lib import agree

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


def load():
    return json.loads((FIXTURES / "agree-kat.json").read_text(encoding="utf-8"))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def oracle(own, peer, context):
    """ECDH and HKDF-SHA-256 by the `cryptography` package, with the info layout written out again."""
    private = ec.derive_private_key(int(own["d"], 16), ec.SECP256R1())
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64u(peer["x"]), "big"), int.from_bytes(unb64u(peer["y"]), "big"), ec.SECP256R1()
    ).public_key()
    secret = private.exchange(ec.ECDH(), public)
    points = sorted([b"\x04" + unb64u(own["x"]) + unb64u(own["y"]), b"\x04" + unb64u(peer["x"]) + unb64u(peer["y"])])
    info = b"handsal-agree/1" + b"\x00" + points[0] + points[1] + context.encode("ascii")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret), info


class AgreeKnownAnswers(unittest.TestCase):
    def test_the_committed_file_equals_a_fresh_derivation(self):
        self.assertEqual(load(), agree.build())

    def test_every_answer_is_the_one_cryptography_derives(self):
        for vector in load()["vectors"]:
            key, info = oracle(vector["own"], vector["peer"], vector["context"])
            with self.subTest(vector=vector["id"]):
                self.assertEqual(vector["key"], b64u(key))
                self.assertEqual(vector["info_hex"], info.hex())
                self.assertEqual(len(unb64u(vector["key"])), 32)

    def test_the_two_sides_of_one_pair_derive_the_same_key(self):
        by_id = {v["id"]: v for v in load()["vectors"]}
        self.assertEqual(by_id["basic"]["key"], by_id["other-side"]["key"])
        self.assertEqual(by_id["basic"]["info_hex"], by_id["other-side"]["info_hex"])
        public = lambda side: {k: side[k] for k in ("label", "x", "y")}  # noqa: E731
        self.assertEqual(public(by_id["basic"]["own"]), public(by_id["other-side"]["peer"]))
        self.assertEqual(public(by_id["basic"]["peer"]), public(by_id["other-side"]["own"]))

    def test_the_context_and_the_pair_each_change_the_key(self):
        keys = [v["key"] for v in load()["vectors"] if v["id"] != "other-side"]
        self.assertEqual(len(set(keys)), len(keys))

    def test_the_context_form_is_the_signed_alphabet_without_space_1_to_128(self):
        for vector in load()["vectors"]:
            with self.subTest(vector=vector["id"]):
                self.assertTrue(agree.context_ok(vector["context"]))
        self.assertTrue(agree.context_ok("a"))
        self.assertTrue(agree.context_ok("~" * 128))
        for bad in ("", "x" * 129, "has space", "tab\t", "café", "\x7f", "new\nline", 'quo"te', "back\\slash"):
            with self.subTest(bad=bad):
                self.assertFalse(agree.context_ok(bad))

    def test_the_longest_context_is_a_vector(self):
        self.assertIn(128, [len(v["context"]) for v in load()["vectors"]])

    def test_the_raw_shared_secret_is_in_no_vector(self):
        text = (FIXTURES / "agree-kat.json").read_text(encoding="utf-8")
        for vector in load()["vectors"]:
            private = ec.derive_private_key(int(vector["own"]["d"], 16), ec.SECP256R1())
            public = ec.EllipticCurvePublicNumbers(
                int.from_bytes(unb64u(vector["peer"]["x"]), "big"), int.from_bytes(unb64u(vector["peer"]["y"]), "big"), ec.SECP256R1()
            ).public_key()
            secret = private.exchange(ec.ECDH(), public)
            for form in (secret.hex(), b64u(secret)):
                self.assertNotIn(form, text)

    def test_the_peer_of_a_vector_is_a_fixture_key_and_the_label_is_the_pinned_one(self):
        keys = json.loads((FIXTURES / "keys.json").read_text(encoding="utf-8"))["keys"]
        for vector in load()["vectors"]:
            for side in ("own", "peer"):
                entry = keys[vector[side]["label"]]
                self.assertEqual({k: vector[side][k] for k in ("x", "y")}, {k: entry[k] for k in ("x", "y")})
                self.assertTrue(vector[side]["label"].endswith(".agree"))
        self.assertEqual(load()["label"], "handsal-agree/1")


if __name__ == "__main__":
    unittest.main()
