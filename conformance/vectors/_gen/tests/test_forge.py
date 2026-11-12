"""Forged acts for the negative vectors (ACT-02, ACT-03, ACT-06, ACT-07, ACT-13).

A negative act is a real act with one edit, signed again so that the edit is
the only defect: the earlier steps of VR-02 pass and the step under test is the
first to fail.
"""
import base64
import json
import unittest

from lib import base, es256, forge, jcs

PROFILE = base.fixture_profile()


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Forge(unittest.TestCase):
    def setUp(self):
        self.fx = base.Fixtures(PROFILE)
        self.jws = self.fx.approve()

    def test_parts_round_trip(self):
        h, p, s = forge.parts(self.jws)
        self.assertEqual(h, ('{"alg":"ES256","kid":"%s"}' % self.fx.key("alice").kid).encode())
        self.assertEqual(len(s), 64)
        self.assertEqual(forge.join(h, p, s), self.jws)

    def test_resign_without_an_edit_is_the_same_act(self):
        self.assertEqual(forge.resign(self.fx, self.jws), self.jws)

    def test_resign_edit_changes_only_that_field_and_stays_signed_and_canonical(self):
        out = forge.resign(self.fx, self.jws, lambda p: p.update(status="FAILED"))
        h, p, s = forge.parts(out)
        old = json.loads(forge.parts(self.jws)[1])
        new = json.loads(p)
        self.assertEqual(new.pop("status"), "FAILED")
        old.pop("status")
        self.assertEqual(new, old)
        self.assertEqual(jcs.recognize(p), (True, None))
        k = self.fx.key("alice")
        self.assertTrue(es256.verify((k.x_int, k.y_int), out.rsplit(".", 1)[0].encode(), s))
        self.assertTrue(es256.is_low_s(s))

    def test_resign_can_sign_with_another_device(self):
        out = forge.resign(self.fx, self.jws, signer="bob")
        self.assertEqual(json.loads(forge.parts(out)[0])["kid"], self.fx.key("bob").kid)
        self.assertEqual(json.loads(forge.parts(out)[1]),
                         json.loads(forge.parts(self.jws)[1]))  # the act object still names alice

    def test_resign_with_a_given_header(self):
        header = b'{"alg":"none"}'
        out = forge.resign(self.fx, self.jws, header=header)
        self.assertEqual(forge.parts(out)[0], header)

    def test_act_object_edit_helper(self):
        out = forge.resign(self.fx, self.jws, forge.act_edit(lambda a: a.pop("org")))
        self.assertNotIn("org", json.loads(forge.parts(out)[1])["ext"]["dev.handsal/act"])

    def test_flip_spare_bits_keeps_the_bytes_and_breaks_the_encoding(self):
        for raw in (b"a", b"ab", b"abcd"[:4]):
            seg = b64u(raw)
            if len(raw) % 3 == 0:
                continue
            flipped = forge.flip_spare_bits(seg)
            self.assertNotEqual(flipped, seg)
            self.assertEqual(unb64u(flipped), raw)
            self.assertNotEqual(b64u(unb64u(flipped)), flipped)

    def test_flip_spare_bits_refuses_a_segment_without_spare_bits(self):
        with self.assertRaises(ValueError):
            forge.flip_spare_bits(b64u(b"abc"))

    def test_payload_with_spare_bits_helper(self):
        # a verdict whose payload length is not a multiple of 3, found by varying the request id
        jws = forge.verdict_with_spare_payload_bits(self.fx)
        self.assertNotEqual(len(forge.parts(jws)[1]) % 3, 0)


class RawAndTamper(unittest.TestCase):
    """`raw_edit` changes the emitted bytes before signing; `tamper` keeps the old signature."""

    def setUp(self):
        self.fx = base.Fixtures(PROFILE)
        self.jws = self.fx.approve()

    def test_raw_edit_signs_the_edited_bytes_and_the_signature_verifies(self):
        out = forge.resign(self.fx, self.jws,
                           raw_edit=lambda raw: raw.replace(b'"tokens":"0"', b'"tokens":0'))
        h, p, s = forge.parts(out)
        self.assertIn(b'"tokens":0', p)
        k = self.fx.key("alice")
        self.assertTrue(es256.verify((k.x_int, k.y_int), out.rsplit(".", 1)[0].encode(), s))

    def test_raw_edit_runs_after_the_dict_edit(self):
        out = forge.resign(self.fx, self.jws, lambda p: p.update(seq="1"),
                           raw_edit=lambda raw: raw.replace(b'"seq":"1"', b'"seq":1'))
        self.assertIn(b'"seq":1', forge.parts(out)[1])

    def test_tamper_changes_the_payload_and_keeps_the_signature(self):
        out = forge.tamper(self.jws, lambda p: p.update(status="FAILED"))
        h0, p0, s0 = forge.parts(self.jws)
        h, p, s = forge.parts(out)
        self.assertEqual((h, s), (h0, s0))
        self.assertEqual(json.loads(p)["status"], "FAILED")
        self.assertEqual(p, jcs.emit(json.loads(p)))
        k = self.fx.key("alice")
        self.assertFalse(es256.verify((k.x_int, k.y_int), out.rsplit(".", 1)[0].encode(), s))


if __name__ == "__main__":
    unittest.main()
