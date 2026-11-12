"""Point validation on P-256 (ACT-11): the checker side of 'the point MUST be on P-256'."""
import json
import unittest
from pathlib import Path

from handsal_check import encoding, p256

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def raw(name):
    key = KEYS[name]
    return encoding.b64u_decode(key["x"]), encoding.b64u_decode(key["y"])


class OnCurve(unittest.TestCase):
    def test_every_fixture_point_is_on_the_curve(self):
        for name, key in KEYS.items():
            if "x" in key:
                x, y = raw(name)
                self.assertTrue(p256.is_on_curve(x, y), name)

    def test_a_moved_coordinate_is_off_the_curve(self):
        x, y = raw("alice.sign")
        bad = y[:-1] + bytes([y[-1] ^ 1])
        self.assertFalse(p256.is_on_curve(x, bad))

    def test_the_origin_is_off_the_curve(self):
        self.assertFalse(p256.is_on_curve(bytes(32), bytes(32)))

    def test_a_coordinate_not_below_the_field_prime_is_refused(self):
        _, y = raw("alice.sign")
        self.assertFalse(p256.is_on_curve(b"\xff" * 32, y))
        self.assertFalse(p256.is_on_curve(P.to_bytes(32, "big"), y))

    def test_only_32_byte_coordinates_are_accepted(self):
        x, y = raw("alice.sign")
        self.assertFalse(p256.is_on_curve(x[1:], y))
        self.assertFalse(p256.is_on_curve(x, y + b"\0"))


if __name__ == "__main__":
    unittest.main()
