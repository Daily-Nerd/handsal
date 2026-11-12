"""T3.43 identity, `inputs_hash` and `outputs_hash` (VR-05, VR-06, VR-07; VR-02 steps 11 and 12)."""
import unittest

from handsal_check import encoding, rules_hash

from .checkact_world import BODY, PROMOTE, RAW, Scenario, b64, check, outputs


class Identity(unittest.TestCase):
    def test_the_performer_must_be_the_recipient(self):
        s = Scenario()
        act = s.verdict(extra={"recipient": "bob"})
        self.assertEqual(check(s.value(act, recipient="bob"))["reason"], "identity_mismatch")

    def test_identity_is_judged_before_the_request_inputs(self):
        s = Scenario()
        act = s.verdict(extra={"recipient": "bob"})
        self.assertEqual(check(s.value(act, recipient="alice"))["reason"], "identity_mismatch")


class Request(unittest.TestCase):
    def test_a_wrong_request_id_or_recipient_input_is_request_mismatch(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(check(s.value(act, request_id="req-99999999"))["reason"], "request_mismatch")
        self.assertEqual(check(s.value(act, recipient="bob"))["reason"], "request_mismatch")

    def test_request_mismatch_comes_before_inputs_mismatch(self):
        s = Scenario()
        act = s.verdict()
        got = check(s.value(act, request_id="req-99999999", request_b64=b64(b"another")))
        self.assertEqual(got["reason"], "request_mismatch")


class Inputs(unittest.TestCase):
    def test_another_requests_bytes_are_inputs_mismatch(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(), request_b64=b64(b"another request")))["reason"], "inputs_mismatch")

    def test_the_bytes_are_hashed_raw_without_recanonicalizing(self):
        s = Scenario()
        raw = b'{"b": 1,   "a": 2}\r\n'
        act = s.verdict(inputs_hash=encoding.hashstr(raw))
        self.assertTrue(check(s.value(act, request_b64=b64(raw)))["valid"])

    def test_a_record_body_that_does_not_hash_to_inputs_hash(self):
        s = Scenario()
        got = check(s.promote_value(record_body_b64=b64(b"another body")))
        self.assertEqual(got["reason"], "inputs_mismatch")

    def test_inputs_are_judged_before_outputs(self):
        s = Scenario()
        act = s.verdict(outputs_hash=encoding.hashstr(b"x"))
        self.assertEqual(check(s.value(act, request_b64=b64(b"another")))["reason"], "inputs_mismatch")


class Outputs(unittest.TestCase):
    def test_a_verdict_swapped_in_outputs_hash_is_outputs_mismatch(self):
        s = Scenario()
        act = s.verdict("approve", outputs_hash=outputs("reject"))
        self.assertEqual(check(s.value(act))["reason"], "outputs_mismatch")

    def test_the_request_id_is_part_of_the_derived_value(self):
        s = Scenario()
        act = s.verdict("approve", outputs_hash=outputs("approve", "req-00000002"))
        self.assertEqual(check(s.value(act))["reason"], "outputs_mismatch")

    def test_each_verdict_derives_its_own_value(self):
        s = Scenario()
        for method in ("reject", "needs-info"):
            act = s.verdict(method)
            value = s.value(act, expect_method="local:handsal.request." + method)
            self.assertTrue(check(value)["valid"], method)

    def test_a_record_promotion_with_the_empty_outputs_hash_is_ok(self):
        # VR-07: for `record.promote` the value is EMPTY_HASH.
        s = Scenario()
        self.assertTrue(check(s.promote_value())["valid"])

    def test_a_record_promotion_with_another_outputs_hash_is_outputs_mismatch(self):
        s = Scenario()
        got = check(s.promote_value(s.promote(outputs_hash=encoding.hashstr(b"x"))))
        self.assertEqual(got["reason"], "outputs_mismatch")

    def test_a_promotion_that_fails_earlier_never_reaches_it(self):
        s = Scenario()
        self.assertEqual(check(s.promote_value(record_body_b64=b64(b"x")))["reason"], "inputs_mismatch")


if __name__ == "__main__":
    unittest.main()
