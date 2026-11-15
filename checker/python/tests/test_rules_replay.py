"""T3.44 relay, replay across contexts (VR-08, VR-09, VR-10; VR-02 steps 7 and 8).

VR-08: a verdict's `relay` must be listed in `relays` of the policy of the state the step reads. The relay is not
an input of either command, in either build.
"""
import unittest

from handsal_check import encoding, errors

from .act_builder import BAD, FakeVitni
from .checkact_world import RELAY, Scenario, check
from .fold_world import World
from .genesis_fixtures import policy


def scenario(*relays):
    return Scenario(World(pol=policy(relays=relays)))


class Relay(unittest.TestCase):
    def test_an_act_for_a_relay_the_policy_does_not_list_is_relay_mismatch(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(extra={"relay": "b.example"})))["reason"], "relay_mismatch")
        self.assertEqual(check(s.value(s.verdict(extra={"relay": "a.example"})))["reason"], "relay_mismatch")

    def test_a_listed_relay_passes(self):
        s = Scenario()
        self.assertTrue(check(s.value(s.verdict()))["valid"])

    def test_two_names_both_pass(self):   # VR-08 S3
        s = scenario("r.example", "s.example")
        for host in ("r.example", "s.example"):
            self.assertTrue(check(s.value(s.verdict(extra={"relay": host})))["valid"], host)
        self.assertEqual(check(s.value(s.verdict(extra={"relay": "t.example"})))["reason"], "relay_mismatch")

    def test_an_empty_relays_makes_every_verdict_relay_mismatch(self):   # VR-08 S4
        s = scenario()
        self.assertEqual(check(s.value(s.verdict()))["reason"], "relay_mismatch")

    def test_a_relay_input_is_malformed_input_and_nothing_reads_it(self):   # VR-01, VR-08 S2
        s = Scenario()
        for relay in (RELAY, "b.example", None, 5):
            with self.assertRaises(errors.Malformed):
                check(s.value(s.verdict(), relay=relay))

    def test_relay_is_judged_before_vitni_and_after_the_org(self):
        s = Scenario()
        vitni = FakeVitni()
        got = check(s.value(s.verdict(sig=BAD, extra={"relay": "b.example"})), vitni)
        self.assertEqual(got["reason"], "relay_mismatch")
        self.assertEqual(vitni.calls[-1][2] if vitni.calls else None, "local:handsal.genesis.sign")   # only the fold asked
        act = s.verdict(org=encoding.hashstr(b"other"), extra={"relay": "b.example"})
        self.assertEqual(check(s.value(act))["reason"], "org_mismatch")

    def test_a_decision_names_no_relay_to_compare(self):
        s = scenario()   # an empty list does not touch a decision
        self.assertTrue(check(s.decision_value())["valid"])   # steps 8 to 12 pass over its words


class Replay(unittest.TestCase):
    def test_the_same_receipt_in_another_org_is_org_mismatch_and_another_relay_relay_mismatch(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(org=encoding.hashstr(b"elsewhere"))))["reason"], "org_mismatch")
        self.assertEqual(check(s.value(s.verdict(extra={"relay": "other.example"})))["reason"], "relay_mismatch")


if __name__ == "__main__":
    unittest.main()
