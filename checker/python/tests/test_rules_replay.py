"""T3.44 relay, replay across contexts (VR-08, VR-09, VR-10; VR-02 steps 7 and 8)."""
import unittest

from handsal_check import encoding, rules_replay

from .act_builder import BAD, FakeVitni
from .checkact_world import RELAY, Scenario, check


class Relay(unittest.TestCase):
    def test_an_act_for_another_relay_is_relay_mismatch(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(), relay="b.example"))["reason"], "relay_mismatch")
        self.assertEqual(check(s.value(s.verdict(extra={"relay": "a.example"})))["reason"], "relay_mismatch")

    def test_the_same_relay_passes(self):
        s = Scenario()
        self.assertTrue(check(s.value(s.verdict(), relay=RELAY))["valid"])

    def test_relay_is_judged_before_vitni_and_after_the_org(self):
        s = Scenario()
        vitni = FakeVitni()
        got = check(s.value(s.verdict(sig=BAD), relay="b.example"), vitni)
        self.assertEqual(got["reason"], "relay_mismatch")
        self.assertEqual(vitni.calls[-1][2] if vitni.calls else None, "local:handsal.genesis.sign")   # only the fold asked
        act = s.verdict(org=encoding.hashstr(b"other"))
        self.assertEqual(check(s.value(act, relay="b.example"))["reason"], "org_mismatch")

    def test_a_decision_has_no_relay_input_to_compare(self):
        s = Scenario()
        self.assertTrue(check(s.decision_value())["valid"])   # steps 8 to 12 pass over its words


class Replay(unittest.TestCase):
    def test_the_same_receipt_in_another_org_is_org_mismatch_and_another_relay_relay_mismatch(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(org=encoding.hashstr(b"elsewhere"))))["reason"], "org_mismatch")
        self.assertEqual(check(s.value(s.verdict(), relay="other.example"))["reason"], "relay_mismatch")


if __name__ == "__main__":
    unittest.main()
