"""T3.9 JWS shape and header (ACT-02, ACT-03, KC-05)."""
import json
import unittest
from pathlib import Path

from handsal_check import encoding, errors, jws

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
KID = KEYS["alice.sign"]["kid"]
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
PAYLOAD = b'{"a":"b"}'
SIG = bytes(range(64))


def header(kid=KID):
    return ('{"alg":"ES256","kid":"%s"}' % kid).encode()


def seg(raw):
    return encoding.b64u_encode(raw)


def make(h=None, p=PAYLOAD, s=SIG):
    return ".".join((seg(header() if h is None else h), seg(p), seg(s)))


def spare(segment):
    """The same segment with a spare bit set in its last character (never canonical)."""
    last = ALPHABET.index(segment[-1])
    return segment[:-1] + ALPHABET[last | 1]


def refused(text):
    try:
        jws.parse(text)
    except errors.Refused as err:
        return err.code
    return None


class Accepts(unittest.TestCase):
    def test_a_well_formed_act_parses(self):
        got = jws.parse(make())
        self.assertEqual(got.kid, KID)
        self.assertEqual(got.payload, PAYLOAD)
        self.assertEqual(got.signature, SIG)

    def test_an_empty_payload_segment_is_a_shape_the_canonical_step_judges_later(self):
        got = jws.parse(make(p=b""))
        self.assertEqual(got.payload, b"")


class Segments(unittest.TestCase):
    def test_wrong_number_of_segments(self):
        good = make()
        for bad in (".".join(good.split(".")[:2]), good + "." + seg(b"x"), "", ".", "..x", good + "."):
            self.assertEqual(refused(bad), "jws_shape", bad)

    def test_padding_is_refused(self):
        h, p, s = make().split(".")
        self.assertEqual(refused(".".join((h, p + "=", s))), "jws_shape")

    def test_other_alphabet_and_non_ascii_are_refused(self):
        h, p, s = make().split(".")
        for bad in (p + "+", p + "/", p + "é", p + " ", p + "\n"):
            self.assertEqual(refused(".".join((h, bad, s))), "jws_shape", repr(bad))

    def test_spare_bits_in_any_segment(self):
        h, p, s = make(p=b"null").split(".")
        self.assertEqual(refused(".".join((spare(h), p, s))), "jws_shape")
        self.assertEqual(refused(".".join((h, spare(p), s))), "jws_shape")
        self.assertEqual(refused(".".join((h, p, spare(s)))), "jws_shape")

    def test_signature_is_exactly_64_bytes(self):
        self.assertEqual(refused(make(s=bytes(63))), "jws_shape")
        self.assertEqual(refused(make(s=bytes(65))), "jws_shape")
        self.assertEqual(refused(make(s=b"")), "jws_shape")
        self.assertIsNone(refused(make(s=bytes(64))))


class Header(unittest.TestCase):
    def test_the_header_is_one_exact_byte_string(self):
        bad_headers = [
            ('{"alg":"ES256","kid":"%s","typ":"JWT"}' % KID).encode(),     # extra member
            ('{"kid":"%s","alg":"ES256"}' % KID).encode(),                  # order
            ('{"alg": "ES256","kid":"%s"}' % KID).encode(),                 # whitespace
            ('{"alg":"ES256","kid":"%s"} ' % KID).encode(),                 # trailing space
            ('{"alg":"EdDSA","kid":"%s"}' % KID).encode(),                  # algorithm
            ('{"alg":"none","kid":"%s"}' % KID).encode(),
            ('{"alg":"es256","kid":"%s"}' % KID).encode(),
            b"null",
            b"[]",
            b"",
            ('{"alg":"ES256","jwk":{"x":"%s"},"kid":"%s"}' % (KID, KID)).encode(),
            ('{"alg":"ES256"}').encode(),                                   # no kid
            ('{"alg":"ES256","kid":"%s"}' % KID[:-1]).encode(),            # 42 characters
            ('{"alg":"ES256","kid":"%sA"}' % KID).encode(),                # 44 characters
            ('{"alg":"ES256","kid":"%s"}' % ("A" * 42 + "B")).encode(),   # spare bits in the kid
            ('{"alg":"ES256","kid":"%s+"}' % KID[:-1]).encode(),           # outside the alphabet
        ]
        for raw in bad_headers:
            self.assertEqual(refused(make(h=raw)), "jws_shape", raw)

    def test_the_kid_comes_from_the_header(self):
        other = KEYS["bob.sign"]["kid"]
        self.assertEqual(jws.parse(make(h=header(other))).kid, other)

    def test_a_header_with_an_escape_is_refused_not_decoded(self):
        raw = ('{"alg":"ES256","kid":"%s"}' % KID).replace("ES256", "ES\\u0032" "56").encode()
        self.assertEqual(refused(make(h=raw)), "jws_shape")


if __name__ == "__main__":
    unittest.main()
