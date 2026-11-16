"""T3.46 ingestion contract, duplicate receipt and verifier-side limits (VR-14, VR-15, VR-16; step 15)."""
import unittest

from handsal_check import encoding, rules_ingest

from .act_builder import BAD, with_signature
from .checkact_world import Scenario, check


class Duplicate(unittest.TestCase):
    def test_a_receipt_already_seen_is_duplicate_receipt(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(check(s.value(act, seen=[act.id]))["reason"], "duplicate_receipt")

    def test_another_receipt_in_seen_is_no_duplicate_even_for_the_same_request(self):
        s = Scenario()
        act, other = s.verdict(), s.verdict(salt="other")
        self.assertNotEqual(act.id, other.id)
        self.assertTrue(check(s.value(act, seen=[other.id]))["valid"])

    def test_an_invalid_twin_never_in_seen_is_not_a_duplicate(self):
        s = Scenario()
        act = s.verdict()
        twin = with_signature(act, BAD)
        self.assertEqual(twin.id, act.id)
        self.assertTrue(check(s.value(act, seen=[]))["valid"])
        self.assertEqual(check(s.value(twin, seen=[]))["reason"], "bad_signature")

    def test_duplicate_is_judged_last_before_proven(self):
        s = Scenario()
        act = s.verdict(sig=BAD)
        self.assertEqual(check(s.value(act, seen=[act.id]))["reason"], "bad_signature")


class Ingestion(unittest.TestCase):
    def test_a_revocation_after_ingestion_changes_check_act_at_the_new_tip(self):
        s = Scenario()
        act = s.verdict()
        self.assertTrue(check(s.value(act))["valid"])
        removal = s.w.device_remove("alice", ("bob", "carol"))
        later = check(s.value(act, acts=removal.acts))
        self.assertEqual((later["reason"], later["valid"]), ("revoked_key", False))
        self.assertEqual(later["receipt_id"], act.id)   # keyed by the receipt id the consumer stored

    def test_the_result_carries_the_receipt_id_and_class_for_the_consumers_record(self):
        s = Scenario()
        act = s.verdict()
        got = check(s.value(act))
        self.assertEqual((got["receipt_id"], got["class"], got["valid"]), (act.id, "apple-se-bio", True))


class Limits(unittest.TestCase):
    def test_an_oversize_payload_is_rejected_before_any_other_work(self):
        from handsal_check import checkact, profiles
        from .act_builder import FakeVitni
        s = Scenario()
        head = s.verdict().jws.split(".")[0]
        raw = b'{"a":"' + b"x" * 16384 + b'"}'
        text = ".".join((head, encoding.b64u_encode(raw), encoding.b64u_encode(bytes(64))))
        vitni = FakeVitni()
        got = checkact.run(checkact.parse_input(s.value(jws=text)), profiles.load(), True, vitni)
        self.assertEqual((got["reason"], got["receipt_id"]), ("payload_too_large", None))
        self.assertEqual(vitni.calls, [])


if __name__ == "__main__":
    unittest.main()
