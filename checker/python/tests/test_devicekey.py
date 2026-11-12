"""Device key validity (ACT-11, KC-05): one definition for genesis entries and introducing acts."""
import json
import unittest
from pathlib import Path

from handsal_check import devicekey, encoding

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]


def point(name):
    return {"x": KEYS[name]["x"], "y": KEYS[name]["y"]}


KID = KEYS["alice.sign"]["kid"]
SIGN = point("alice.sign")
AGREE = point("alice.agree")


class Valid(unittest.TestCase):
    def test_every_fixture_device_is_valid(self):
        for name in KEYS:
            if name.endswith(".sign") and not name.startswith("relay"):
                person = name[:-5]
                self.assertIsNone(devicekey.defect(KEYS[name]["kid"], point(name), point(person + ".agree")),
                                  name)


class Defects(unittest.TestCase):
    def test_kid_must_be_the_thumbprint_of_sign(self):
        self.assertEqual(devicekey.defect(KEYS["bob.sign"]["kid"], SIGN, AGREE), "kid_not_thumbprint")

    def test_kid_in_the_wrong_form(self):
        self.assertEqual(devicekey.defect(KID[:-1], SIGN, AGREE), "kid_not_thumbprint")

    def test_a_coordinate_of_31_bytes(self):
        short = encoding.b64u_encode(encoding.b64u_decode(SIGN["x"])[1:])
        self.assertEqual(devicekey.defect(KID, {"x": short, "y": SIGN["y"]}, AGREE), "sign_point")

    def test_a_coordinate_that_is_not_base64url(self):
        self.assertEqual(devicekey.defect(KID, {"x": "!" * 43, "y": SIGN["y"]}, AGREE), "sign_point")
        self.assertEqual(devicekey.defect(KID, {"x": 5, "y": SIGN["y"]}, AGREE), "sign_point")

    def test_a_point_off_the_curve(self):
        y = encoding.b64u_decode(SIGN["y"])
        off = {"x": SIGN["x"], "y": encoding.b64u_encode(y[:-1] + bytes([y[-1] ^ 1]))}
        self.assertEqual(devicekey.defect(encoding.thumbprint(off["x"], off["y"]), off, AGREE), "sign_point")

    def test_the_agree_point_is_checked_too(self):
        y = encoding.b64u_decode(AGREE["y"])
        off = {"x": AGREE["x"], "y": encoding.b64u_encode(y[:-1] + bytes([y[-1] ^ 1]))}
        self.assertEqual(devicekey.defect(KID, SIGN, off), "agree_point")

    def test_agree_must_differ_from_sign(self):
        self.assertEqual(devicekey.defect(KID, SIGN, SIGN), "agree_equals_sign")

    def test_a_point_with_an_extra_member_is_a_defect(self):
        self.assertEqual(devicekey.defect(KID, {**SIGN, "alg": "ES256"}, AGREE), "sign_point")
        self.assertEqual(devicekey.defect(KID, SIGN, {"x": AGREE["x"]}), "agree_point")

    def test_a_point_that_is_not_an_object(self):
        self.assertEqual(devicekey.defect(KID, None, AGREE), "sign_point")
        self.assertEqual(devicekey.defect(KID, SIGN, []), "agree_point")


class Point(unittest.TestCase):
    def test_point_ok(self):
        self.assertTrue(devicekey.point_ok(SIGN))
        self.assertFalse(devicekey.point_ok({"x": SIGN["x"], "y": "A" * 43}))

    def test_raw_coordinates(self):
        x, y = devicekey.coordinates(SIGN)
        self.assertEqual((len(x), len(y)), (32, 32))


if __name__ == "__main__":
    unittest.main()
