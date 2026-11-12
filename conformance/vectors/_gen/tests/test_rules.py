"""The generator model refuses an authorial `ok` or `valid` claim that the spec's rules contradict.

`Chain` records the acts a vector author calls valid; nothing else judges them. The rules of
FO-22 and FO-23 that the model can evaluate are checked here, against the state at the act's
parent: quorum, consent on `device.add`, the target of a removal, a new member, key classes.
"""
import unittest

from lib import base, chain, rules

FX = base.Fixtures(base.fixture_profile())
AB, AC, BC = ("alice", "bob"), ("alice", "carol"), ("bob", "carol")


class Consent(unittest.TestCase):
    """FO-22 consent on `device.add`."""

    def setUp(self):
        self.c = chain.Chain(FX)

    def test_an_add_beside_an_active_device_needs_a_key_of_that_person(self):
        with self.assertRaisesRegex(rules.Refused, "consent"):
            self.c.device_add("bob2", AC)

    def test_the_persons_own_key_as_primary_or_endorser_gives_consent(self):
        self.c.device_add("bob2", BC)
        self.c.device_add("alice2", ("bob", "alice"))

    def test_a_removed_key_gives_no_consent(self):
        self.c.device_add("alice2", AB)
        self.c.device_remove("alice", BC)
        with self.assertRaisesRegex(rules.Refused, "consent"):
            self.c.device_add("alice3", ("bob", "carol", "alice"))

    def test_a_person_without_an_active_device_needs_no_consent(self):
        self.c.device_remove("carol", AB)
        self.c.device_add("carol2", AB)

    def test_consent_is_read_at_the_acts_parent_not_at_the_tip(self):
        first = self.c.device_add("alice2", AB)
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "consent"):  # carol is active at `first`
            self.c.device_add("carol2", AB, ok=False, valid=True, parent=first)
        self.c.device_add("carol2", AB)  # and has none at the tip

    def test_an_act_declared_not_ok_is_never_checked(self):
        self.c.device_add("bob2", AC, ok=False)


class StateAt(unittest.TestCase):
    """`Chain.state_at(built)`: the state after any act the author called valid."""

    def test_it_gives_the_state_after_an_applied_and_an_off_tip_act(self):
        c = chain.Chain(FX)
        first = c.device_add("alice2", AB)
        side = c.device_add("bob2", BC, ok=False, valid=True, parent=None)
        self.assertEqual(c.state_at(first).n, 1)
        self.assertIn(FX.key("bob2").kid, c.state_at(side).devices["bob"])
        self.assertNotIn(FX.key("bob2").kid, c.state_at(first).devices["bob"])
        self.assertEqual(c.state_at(None).n, 0)

    def test_an_act_declared_not_ok_has_no_state(self):
        c = chain.Chain(FX)
        gone = c.device_add("alice2", AB, ok=False)
        with self.assertRaises(KeyError):
            c.state_at(gone)


class Quorum(unittest.TestCase):
    def setUp(self):
        self.c = chain.Chain(FX)

    def test_two_devices_of_one_person_are_one_person(self):
        self.c.device_add("alice2", AB)
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            self.c.device_add("alice3", ("alice", "alice2", "dave"))

    def test_a_signer_not_in_the_state_does_not_count(self):
        with self.assertRaisesRegex(rules.Refused, "signer"):
            self.c.device_add("alice2", ("carol2", "alice"))

    def test_a_removed_signer_does_not_count(self):
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "signer"):
            self.c.device_remove("bob", ("carol", "alice"))

    def test_a_person_without_a_listed_role_is_not_counted(self):
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            self.c.device_add("alice2", ("alice", "dave"))

    def test_the_primary_signer_need_not_hold_a_role(self):
        self.c.member_add("dave", AB, role="member")
        self.c.device_add("alice2", ("dave", "alice", "bob"))

    def test_the_rule_is_the_policys_persons(self):
        from lib import epochs
        c = epochs.original_chain(FX, epochs.org4(FX))
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            c.device_add("alice2", AB)
        c.device_add("alice2", ("alice", "bob", "carol"))


class Targets(unittest.TestCase):
    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_removal_needs_an_active_device_of_the_person(self):
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "target"):
            self.c.device_remove("carol", AB)

    def test_a_removal_of_a_key_the_state_does_not_hold_is_refused(self):
        with self.assertRaisesRegex(rules.Refused, "target"):
            self.c.device_remove("alice2", BC)

    def test_a_device_add_needs_a_member(self):
        with self.assertRaisesRegex(rules.Refused, "member"):
            self.c.device_add("dave", AB)

    def test_a_member_add_needs_an_unused_id(self):
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "unused"):
            self.c.member_add("dave2", AB, role="member", member="dave")

    def test_a_member_add_needs_a_listed_role(self):
        with self.assertRaisesRegex(rules.Refused, "role"):
            self.c.member_add("dave", AB, role="admin")

    def test_a_member_id_of_an_earlier_epoch_is_not_unused(self):
        from lib import epochs, inputs
        change = epochs.make_change(FX, FX.org, FX.org_id, carry=("alice", "bob"),
                                    new=("frank",))
        sigs = epochs.sign_change(FX, change)
        lineage = FX.lineage() + [{"doc": change, "sigs": sigs}]
        c = chain.Chain(FX, doc=change, lineage=lineage)
        with self.assertRaisesRegex(rules.Refused, "unused"):
            c.member_add("carol2", ("alice", "bob"), role="maintainer", member="carol")
        self.assertIsNotNone(inputs.doc_id(change))


class Classes(unittest.TestCase):
    """KC-08: a role holder's key must be of a biometric-only class."""

    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_pin_class_key_for_a_role_holder_is_refused(self):
        with self.assertRaisesRegex(rules.Refused, "class"):
            self.c.device_add("alice2", AB, cls="fixture-pin")

    def test_a_pin_class_key_for_a_member_without_a_listed_role_is_allowed(self):
        self.c.member_add("dave", AB, role="member")
        self.c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")


if __name__ == "__main__":
    unittest.main()
