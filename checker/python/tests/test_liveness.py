"""T3.33 liveness: last device, unreachable rules (FO-27).

A rule is reachable at a node iff the role-holding persons with an active accepted key in the state
number at least `Q_r`. The fold invents no authority to leave a deadlock: an unreachable rule just
means no act can reach its quorum, which the quorum rule already enforces.
"""
import unittest

from handsal_check import liveness

from .fold_world import World, ids


def two_lost():
    w = World()
    r1 = w.device_remove("bob", ("alice", "carol"))
    r2 = w.device_remove("carol", ("alice", "carol"), r1)   # bob's key is gone: carol endorses her own removal
    return w, r1, r2


class Reachable(unittest.TestCase):
    def test_every_rule_is_reachable_at_the_start(self):
        w = World()
        e = w.epoch()
        self.assertEqual(liveness.unreachable(e, e.root.state), [])

    def test_one_person_losing_every_device_leaves_every_rule_reachable(self):
        w = World()
        r = w.device_remove("carol", ("alice", "bob"))
        e = w.epoch(r)
        self.assertEqual(liveness.unreachable(e, e.nodes[r.id].state), [])

    def test_two_persons_losing_every_device_leaves_every_rule_unreachable_at_two_of_three(self):
        w, r1, r2 = two_lost()
        e = w.epoch(r1, r2)
        self.assertIn(r2.id, ids(e))
        self.assertEqual(liveness.unreachable(e, e.nodes[r2.id].state),
                         ["chain.resolve", "device.remove", "genesis.change", "member.add"])

    def test_the_person_who_is_alone_cannot_act(self):
        w, r1, r2 = two_lost()
        alone = w.device_add("alice2", ("alice",), r2)
        also = w.device_add("alice2", ("alice", "alice2"), r2)
        e = w.epoch(r1, r2, alone, also)
        self.assertNotIn(alone.id, ids(e))
        self.assertNotIn(also.id, ids(e))

    def test_a_member_with_zero_devices_has_no_signature_until_others_add_one(self):
        w = World()
        r = w.device_remove("carol", ("alice", "bob"))
        mine = w.device_add("carol2", ("carol",), r)
        theirs = w.device_add("carol2", ("alice", "bob"), r, salt="by others")
        e = w.epoch(r, mine, theirs)
        self.assertNotIn(mine.id, ids(e))
        self.assertIn(theirs.id, ids(e))

    def test_a_non_role_member_does_not_make_a_rule_reachable(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        r1 = w.device_remove("bob", ("alice", "carol"))
        r2 = w.device_remove("carol", ("alice", "carol"), r1)
        e = w.epoch(r1, r2)
        self.assertEqual(liveness.unreachable(e, e.nodes[r1.id].state), [])
        self.assertEqual(len(liveness.unreachable(e, e.nodes[r2.id].state)), 4)


if __name__ == "__main__":
    unittest.main()
