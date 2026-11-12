"""T3.7 vectors jws/* (ACT-02, ACT-03, KC-05): every row is `jws_shape` at step 1."""
import base64
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

ROWS = {
    "jws/b64-padding", "jws/b64-trailing-bits-header", "jws/b64-trailing-bits-payload",
    "jws/b64-trailing-bits-sig", "jws/empty", "jws/four-segments", "jws/header-alg-eddsa",
    "jws/header-alg-none", "jws/header-extra-member", "jws/header-jwk-present",
    "jws/header-key-order", "jws/header-null", "jws/header-whitespace", "jws/sig-63-bytes",
    "jws/sig-65-bytes", "jws/two-segments",
}


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Jws(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("jws", ["jws"])
        cls.fx = base.Fixtures(base.fixture_profile())

    def jws(self, name):
        return self.v[name]["input"]["jws"]

    def test_rows(self):
        self.assertEqual(set(self.v), ROWS)

    def test_every_row_is_check_act_jws_shape_with_null_id_and_class(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act")
            self.assertEqual(catalog.catalog_code(name), "jws_shape")
            self.assertEqual(json.loads(v["anchor"]), {
                "class": None, "reason": "jws_shape", "receipt_id": None, "valid": False})
            self.assertEqual(v["input"]["expect_method"], inputs.APPROVE)

    def test_segment_defects(self):
        self.assertEqual(self.jws("jws/empty"), "")
        self.assertEqual(len(self.jws("jws/two-segments").split(".")), 2)
        self.assertEqual(len(self.jws("jws/four-segments").split(".")), 4)
        self.assertIn("=", self.jws("jws/b64-padding").split(".")[1])
        self.assertEqual(len(unb64u(self.jws("jws/sig-63-bytes").split(".")[2])), 63)
        self.assertEqual(len(unb64u(self.jws("jws/sig-65-bytes").split(".")[2])), 65)

    def test_spare_bits_rows_decode_to_a_valid_act_but_do_not_re_encode(self):
        for name, index in (("header", 0), ("payload", 1), ("sig", 2)):
            seg = self.jws("jws/b64-trailing-bits-" + name).split(".")[index]
            self.assertNotEqual(b64u(unb64u(seg)), seg, name)
        # decoded, header and payload are those of a real act
        h, p, _ = (unb64u(s) for s in self.jws("jws/b64-trailing-bits-payload").split("."))
        self.assertEqual(json.loads(h)["alg"], "ES256")
        self.assertEqual(json.loads(p)["method"], inputs.APPROVE)

    def test_header_rows(self):
        kid = self.fx.key("alice").kid
        want = {
            "jws/header-alg-eddsa": '{"alg":"EdDSA","kid":"%s"}' % kid,
            "jws/header-alg-none": '{"alg":"none","kid":"%s"}' % kid,
            "jws/header-extra-member": '{"alg":"ES256","kid":"%s","typ":"JWT"}' % kid,
            "jws/header-key-order": '{"kid":"%s","alg":"ES256"}' % kid,
            "jws/header-null": "null",
            "jws/header-whitespace": '{"alg": "ES256","kid":"%s"}' % kid,
        }
        for name, header in want.items():
            self.assertEqual(unb64u(self.jws(name).split(".")[0]), header.encode(), name)
        jwk = json.loads(unb64u(self.jws("jws/header-jwk-present").split(".")[0]))
        self.assertEqual(sorted(jwk), ["alg", "jwk", "kid"])
        self.assertEqual(jwk["jwk"], self.fx.key("alice").jwk())

    def test_header_rows_still_carry_a_valid_payload(self):
        for name in want_header_rows():
            self.assertEqual(json.loads(forge.parts(self.jws(name))[1])["method"], inputs.APPROVE)


def want_header_rows():
    return [n for n in ROWS if n.startswith("jws/header-")]


if __name__ == "__main__":
    unittest.main()
