"""T3.31 children, fork and refreeze (FO-24).

Two valid children of one parent are a fork. The walk is recomputed from the whole bag, so the result
does not depend on acts' order, and a quorum that signed two conflicting acts freezes the chain.
"""
import random
import unittest
from unittest import mock

from handsal_check import fork, resolve

from .fold_world import World, ids


def two_children(w, parent=None):
    c1 = w.device_add("alice2", ("alice", "bob"), parent)
    c2 = w.device_add("alice3", ("alice", "carol"), parent)
    return c1, c2


class Walk(unittest.TestCase):
    def test_a_chain_without_children_ends_at_the_root(self):
        w = World()
        walked = fork.walk(w.epoch())
        self.assertEqual([n.id for n in walked.chain], [w.id])
        self.assertIsNone(walked.fork)

    def test_one_child_is_the_next_node(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("bob2", ("bob", "alice"), a)
        walked = fork.walk(w.epoch(a, b))
        self.assertEqual([n.id for n in walked.chain], [w.id, a.id, b.id])
        self.assertIsNone(walked.fork)

    def test_two_valid_children_are_a_fork_with_sorted_candidates(self):
        w = World()
        c1, c2 = two_children(w)
        walked = fork.walk(w.epoch(c1, c2))
        self.assertEqual([n.id for n in walked.chain], [w.id])
        self.assertEqual(walked.fork.parent.id, w.id)
        self.assertEqual(walked.fork.candidates, sorted([c1.id, c2.id]))

    def test_the_fork_is_where_the_chain_ends(self):
        w = World()
        a = w.device_add("bob2", ("bob", "alice"))
        c1, c2 = two_children(w, a)
        walked = fork.walk(w.epoch(a, c1, c2))
        self.assertEqual([n.id for n in walked.chain], [w.id, a.id])
        self.assertEqual(walked.fork.parent.id, a.id)

    def test_the_result_does_not_depend_on_the_order_of_acts(self):
        w = World()
        c1, c2 = two_children(w)
        acts = c1.acts + c2.acts
        results = set()
        for seed in range(6):
            random.Random(seed).shuffle(acts)
            walked = fork.walk(w.epoch(*acts))
            results.add((tuple(n.id for n in walked.chain), tuple(walked.fork.candidates)))
        self.assertEqual(len(results), 1)

    def test_one_tricked_signature_cannot_make_a_fork(self):
        w = World()
        honest = w.device_add("alice2", ("alice", "bob"))
        lone = w.device_add("alice3", ("bob",))   # one signer: a tricked touch
        walked = fork.walk(w.epoch(honest, lone))
        self.assertIsNone(walked.fork)
        self.assertEqual([n.id for n in walked.chain], [w.id, honest.id])

    def test_two_valid_removals_of_different_devices_are_a_fork(self):
        w = World(extra=("bob2", "carol2"))
        r1 = w.device_remove("bob2", ("alice", "carol"))
        r2 = w.device_remove("carol2", ("alice", "bob"))
        self.assertEqual(fork.walk(w.epoch(r1, r2)).fork.candidates, sorted([r1.id, r2.id]))

    def test_a_late_endorsement_of_a_stale_proposal_completes_it_and_forks(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        stale = w.device_add("alice3", ("alice",), pop=True)               # alone: not valid
        late = w.endorse("carol", stale.primary, w.id)                     # completes it at the old parent
        walked = fork.walk(w.epoch(a, stale.primary, stale.pop, late))
        self.assertEqual(walked.fork.candidates, sorted([a.id, stale.id]))

    def test_nothing_is_a_fork_when_the_stale_proposal_is_never_completed(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        stale = w.device_add("alice3", ("alice",), pop=True)
        self.assertIsNone(fork.walk(w.epoch(a, stale.primary, stale.pop)).fork)


class ChosenDisagree(unittest.TestCase):
    def test_current_resolves_that_choose_different_children_leave_a_fork_of_those_children(self):
        # FO-24 step 3. Two current resolves that disagree cannot be built from signed bytes (each must
        # name the other with evidence that does not exist until the other is signed), so the rule is
        # exercised by stating what the resolves choose.
        w = World()
        c1, c2 = two_children(w)
        c3 = w.device_add("alice4", ("alice", "bob"))
        e = w.epoch(c1, c2, c3)
        with mock.patch.object(resolve.Resolves, "chosen", return_value={c1.id, c2.id}):
            walked = fork.walk(e)
        self.assertEqual(walked.fork.candidates, sorted([c1.id, c2.id]))
        self.assertEqual([n.id for n in walked.chain], [w.id])


if __name__ == "__main__":
    unittest.main()
