"""T3.2 encodings (ACT-03, ACT-07 hashstr, ACT-10, ACT-11).

Known answers come from openssl over the same bytes, not from this code.
"""
import json
import unittest
from pathlib import Path

from handsal_check import encoding

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]


class Base64Url(unittest.TestCase):
    def test_encode_has_no_padding_and_uses_the_url_alphabet(self):
        self.assertEqual(encoding.b64u_encode(b"\xfb\xff"), "-_8")
        self.assertEqual(encoding.b64u_encode(b""), "")
        self.assertEqual(encoding.b64u_encode(b"a"), "YQ")

    def test_decode_round_trips(self):
        for raw in (b"", b"a", b"ab", b"abc", bytes(range(256))):
            self.assertEqual(encoding.b64u_decode(encoding.b64u_encode(raw)), raw)

    def test_decode_refuses_what_does_not_re_encode_to_itself(self):
        for bad in ("-_9",        # nonzero spare bits in the last character
                    "YQ==",       # padding
                    "YQ=",
                    "+/8",        # standard alphabet
                    "Y",          # impossible length
                    "YQ A",
                    "éééé"):
            with self.assertRaises(ValueError, msg=bad):
                encoding.b64u_decode(bad)

    def test_decode_refuses_non_strings(self):
        with self.assertRaises(ValueError):
            encoding.b64u_decode(b"YQ")


class Hashstr(unittest.TestCase):
    def test_empty_hash_known_answer(self):
        self.assertEqual(encoding.EMPTY_HASH, "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ")

    def test_abc_known_answer(self):
        self.assertEqual(encoding.hashstr(b"abc"),
                         "uEiC6eBa_jwHP6kFBQN5driIjsANho5YXepy0EP9h8gAVrQ")

    def test_is_hashstr(self):
        self.assertTrue(encoding.is_hashstr(encoding.EMPTY_HASH))
        for bad in ("", "x", encoding.EMPTY_HASH[1:], encoding.EMPTY_HASH + "A",
                    "uEjDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",   # multihash prefix wrong
                    "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VR",   # spare bits
                    "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4V=",
                    None, 7):
            self.assertFalse(encoding.is_hashstr(bad), repr(bad))


class Thumbprint(unittest.TestCase):
    ALICE = KEYS["alice.sign"]

    def test_known_answer_from_openssl(self):
        self.assertEqual(encoding.thumbprint(self.ALICE["x"], self.ALICE["y"]),
                         "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI")

    def test_every_fixture_kid_is_its_key_thumbprint(self):
        listed = json.loads((ROOT / "conformance" / "fixtures" / "fixture-kids.json").read_text())
        seen = set()
        for label, entry in KEYS.items():
            if "kid" in entry:
                self.assertEqual(encoding.thumbprint(entry["x"], entry["y"]), entry["kid"], label)
                seen.add(entry["kid"])
        self.assertEqual(sorted(seen), listed)

    def test_member_order_is_crv_kty_x_y(self):
        self.assertEqual(encoding.thumbprint_input("X", "Y"),
                         b'{"crv":"P-256","kty":"EC","x":"X","y":"Y"}')


class PlainText(unittest.TestCase):
    def test_signed_string_alphabet(self):
        for ch in (" ", "a", "~", "/", "{"):
            self.assertTrue(encoding.is_plain_char(ch), ch)
        for ch in ('"', "\\", "\x1f", "\x7f", "é", " ", ""):
            self.assertFalse(encoding.is_plain_char(ch), repr(ch))

    def test_is_plain_text(self):
        self.assertTrue(encoding.is_plain_text("a/b c"))
        self.assertFalse(encoding.is_plain_text("a\nb"))


if __name__ == "__main__":
    unittest.main()
