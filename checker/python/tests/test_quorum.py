"""T3.29 quorum: authority by person, consent, counted signatures, surplus (FO-13, FO-22, FO-23, KC-04, KC-08).

An act is valid iff its counted signatures come from at least Q distinct persons whose keys are
active and accepted in the parent state and whose role is listed in the rule, and its body
conditions hold against that state. Two devices of one person are one person. No act is valid with
fewer than Q persons, and a surplus signature never changes what a valid act does.
"""
import unittest

from handsal_check import fold, genesis

from .act_builder import kid_of
from .fold_world import World, device_body, ids, member_body
from .genesis_fixtures import device, policy


def on(w, step, *more, **kw):
    return step.id in ids(w.epoch(step, *more, **kw))


def three_and_dave(persons="2"):
    return World(extra=("dave", "alice2"), members=(("dave", "member"),), persons=persons)


class Persons(unittest.TestCase):
    def test_one_person_is_not_a_quorum(self):
        w = World(extra=("alice2",))
        self.assertFalse(on(w, w.device_remove("alice2", ("alice",))))

    def test_two_devices_of_one_person_are_one_person(self):
        w = World(extra=("alice2",))
        self.assertFalse(on(w, w.device_add("alice3", ("alice", "alice2"))))

    def test_two_persons_are_a_quorum(self):
        w = World(extra=("alice2",))
        self.assertTrue(on(w, w.device_add("alice3", ("alice", "bob"))))

    def test_the_threshold_is_the_policy_not_the_fold(self):
        w = World(persons="3")
        self.assertFalse(on(w, w.device_add("alice2", ("alice", "bob"))))
        self.assertTrue(on(w, w.device_add("alice2", ("alice", "bob", "carol"))))

    def test_the_rule_of_the_method_decides(self):
        pol = policy()
        pol["rules"]["member.add"]["persons"] = "3"
        w = World(pol=pol, members=(("dave", "member"),), extra=("dave",))
        self.assertTrue(on(w, w.device_add("dave2", ("dave", "alice", "bob"))))
        self.assertFalse(on(w, w.member_add("frank", ("alice", "bob"), role="member")))
        self.assertTrue(on(w, w.member_add("frank", ("alice", "bob", "carol"), role="member")))

    def test_the_primary_signer_need_not_hold_a_role_but_counts_only_if_it_does(self):
        w = three_and_dave()
        # dave (role member) signs the primary; alice and bob endorse: two role holders, enough
        self.assertTrue(on(w, w.device_add("alice3", ("dave", "alice", "bob"))))
        # dave and alice: one role holder only
        self.assertFalse(on(w, w.device_add("alice3", ("dave", "alice"))))

    def test_a_signer_who_is_not_in_the_state_signs_nothing(self):
        w = World()
        self.assertFalse(on(w, w.device_add("alice2", ("alice", "grace"))))
        self.assertFalse(on(w, w.device_add("alice2", ("grace", "alice", "bob"))))


class Surplus(unittest.TestCase):
    def test_a_surplus_endorsement_changes_nothing(self):
        w = World()
        base = w.device_add("alice2", ("alice", "bob"))
        extra = w.device_add("alice2", ("alice", "bob", "carol"))
        e1, e2 = w.epoch(base), w.epoch(*extra.acts)
        self.assertEqual(e1.nodes[base.id].state.devices, e2.nodes[base.id].state.devices)

    def test_an_endorsement_by_a_member_without_a_listed_role_is_not_counted(self):
        w = three_and_dave()
        self.assertFalse(on(w, w.member_add("frank", ("alice", "dave"), role="member")))
        self.assertTrue(on(w, w.member_add("frank", ("alice", "bob"), role="member")))

    def test_a_valid_signature_never_makes_an_act_invalid(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob", "carol"))
        self.assertTrue(on(w, step))


class Consent(unittest.TestCase):
    """FO-22: a device.add for a person with a usable key needs a signature by a key of that person."""

    def test_bob_and_carol_cannot_add_a_device_for_alice(self):
        w = World()
        self.assertFalse(on(w, w.device_add("alice2", ("bob", "carol"))))

    def test_bob_signs_and_alices_own_key_endorses(self):
        w = World()
        self.assertTrue(on(w, w.device_add("alice2", ("bob", "alice"))))

    def test_two_devices_of_alice_are_not_two_persons(self):
        w = World(extra=("alice2",))
        self.assertFalse(on(w, w.device_add("alice3", ("alice", "alice2"))))

    def test_consent_by_a_removed_key_is_not_consent(self):
        w = World(extra=("alice2",))
        removal = w.device_remove("alice", ("bob", "carol"))
        add = w.device_add("alice3", ("bob", "alice"), removal)
        self.assertNotIn(add.id, ids(w.epoch(removal, *add.acts)))
        # alice2 is still usable: its consent is needed and given
        ok = w.device_add("alice3", ("bob", "alice2"), removal)
        self.assertTrue(ok.id in ids(w.epoch(removal, ok)))

    def test_a_person_with_no_usable_key_needs_no_consent(self):
        w = World()
        r1 = w.device_remove("alice", ("bob", "carol"))
        add = w.device_add("alice2", ("bob", "carol"), r1)
        e = w.epoch(r1, add)
        self.assertIn(add.id, ids(e))
        self.assertEqual(e.nodes[add.id].state.usable_devices("alice"), [kid_of("alice2")])

    def test_removing_every_key_then_adding_one_both_apply(self):
        w = World()
        r1 = w.device_remove("alice", ("bob", "carol"))
        r2 = w.device_add("alice2", ("bob", "carol"), r1)
        self.assertEqual(ids(w.epoch(r1, r2)), {w.id, r1.id, r2.id})

    def test_consent_is_for_device_add_only(self):
        w = World()
        self.assertTrue(on(w, w.member_add("frank", ("alice", "bob"))))
        self.assertTrue(on(w, w.device_remove("alice", ("bob", "carol"))))


class Removal(unittest.TestCase):
    def test_a_member_may_end_with_zero_devices(self):
        w = World()
        step = w.device_remove("carol", ("alice", "bob"))
        e = w.epoch(step)
        self.assertIn(step.id, ids(e))
        self.assertEqual(e.nodes[step.id].state.usable_devices("carol"), [])

    def test_the_target_counts_like_anyone(self):
        w = World(extra=("bob2",))
        self.assertTrue(on(w, w.device_remove("bob2", ("alice", "bob2"))))

    def test_self_removal_alone_is_not_on_the_chain(self):
        w = World(extra=("alice2",))
        self.assertFalse(on(w, w.device_remove("alice2", ("alice2",))))
        self.assertTrue(on(w, w.device_remove("alice2", ("alice2", "bob"))))

    def test_the_kid_must_belong_to_the_named_person(self):
        w = World()
        self.assertFalse(on(w, w.device_remove("carol", ("alice", "bob"), person="bob")))

    def test_a_removed_key_cannot_be_removed_twice(self):
        w = World()
        r1 = w.device_remove("carol", ("alice", "bob"))
        r2 = w.device_remove("carol", ("alice", "bob"), r1, salt="again")
        self.assertEqual(ids(w.epoch(r1, r2)), {w.id, r1.id})

    def test_an_unknown_kid_is_not_a_removal(self):
        w = World()
        self.assertFalse(on(w, w.device_remove("dave", ("alice", "bob"), person="alice")))


class MemberAdd(unittest.TestCase):
    def test_a_new_member_is_added_with_one_device(self):
        w = World()
        step = w.member_add("frank", ("alice", "bob"))
        e = w.epoch(step)
        self.assertEqual(e.nodes[step.id].state.members["frank"], "maintainer")
        self.assertIn(kid_of("frank"), e.nodes[step.id].state.devices)

    def test_the_id_must_be_unused(self):
        w = World()
        self.assertFalse(on(w, w.member_add("frank", ("alice", "bob"), member="alice")))

    def test_the_id_must_be_unused_in_earlier_epochs(self):
        w = World()
        earlier = fold.Earlier(frozenset(), frozenset(), frozenset({"frank"}))
        self.assertFalse(on(w, w.member_add("frank", ("alice", "bob")), earlier=earlier))

    def test_a_role_the_policy_does_not_list_is_refused(self):
        w = World()
        self.assertFalse(on(w, w.member_add("frank", ("alice", "bob"), role="owner")))

    def test_a_removed_member_id_is_not_reusable(self):
        w = World()
        r = w.device_remove("carol", ("alice", "bob"))
        again = w.member_add("frank", ("alice", "bob"), r, member="carol")
        self.assertEqual(ids(w.epoch(r, again)), {w.id, r.id})


class RoleHolderClass(unittest.TestCase):
    """KC-08 (b): a role holder's new key must be of a biometric-only class."""

    def test_a_pin_capable_key_for_a_role_holder_is_not_on_the_chain(self):
        w = three_and_dave()
        pin = w.device_add("alice-pin", ("alice", "bob"), cls="fixture-pin")
        self.assertFalse(on(w, pin))

    def test_the_same_with_a_class_the_policy_does_not_accept(self):
        w = three_and_dave()
        self.assertFalse(on(w, w.device_add("alice-pin", ("alice", "bob"), cls="fixture-pin")))

    def test_a_member_add_of_a_role_holder_with_a_pin_key_is_not_on_the_chain(self):
        w = three_and_dave()
        self.assertFalse(on(w, w.member_add("frank-pin", ("alice", "bob"), cls="fixture-pin")))
        self.assertTrue(on(w, w.member_add("frank", ("alice", "bob"))))

    def test_a_non_role_member_may_hold_a_pin_key_that_is_not_accepted(self):
        w = three_and_dave()
        step = w.device_add("dave2", ("dave", "alice", "bob"), cls="fixture-pin")
        e = w.epoch(step)
        self.assertIn(step.id, ids(e))
        device_ = e.nodes[step.id].state.devices[kid_of("dave2")]
        self.assertFalse(device_.accepted)
        self.assertNotIn(kid_of("dave2"), e.nodes[step.id].state.keys_map().get("dave", {}))

    def test_a_pin_key_never_counts(self):
        w = three_and_dave()
        pin = w.device_add("dave2", ("dave", "alice", "bob"), cls="fixture-pin")
        # dave2 (not accepted, not a role holder) endorses an act of alice: not counted
        target = w.device_add("alice2", ("alice",), parent=pin)
        extra = w.endorse("dave2", target.primary, pin.id)
        self.assertNotIn(target.id, ids(w.epoch(pin, target.primary, target.pop, extra)))


class Policy(unittest.TestCase):
    def test_the_same_acts_fold_differently_under_another_policy(self):
        step_acts = lambda w: w.device_add("alice2", ("alice", "bob"))
        w2, w3 = World(persons="2"), World(persons="3")
        self.assertTrue(on(w2, step_acts(w2)))
        self.assertFalse(on(w3, step_acts(w3)))


if __name__ == "__main__":
    unittest.main()
