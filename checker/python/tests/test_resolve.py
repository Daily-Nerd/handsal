"""T3.32 chain.resolve: applicable, current, effective overrides, conflicting resolves (FO-25).

A resolve at a fork parent P names the candidates (the children of P), chooses one, and names the
heads up to which it examined the losing branches. A key counts for it only if it is in `S_P` and
removed on no examined path. It is current iff it examined every losing primary and named every
applicable resolve it overturns or discards, with evidence.
"""
import unittest

from handsal_check import encoding, fork, resolve

from .act_builder import kid_of
from .fold_world import World, ids


GHOST = encoding.hashstr(b"ghost")


def chosen_chain(e):
    walked = fork.walk(e)
    return [n.id for n in walked.chain], walked.fork


def fork_world(**kw):
    w = World(**kw)
    c1 = w.device_add("alice2", ("alice", "bob"))
    c2 = w.device_add("alice3", ("alice", "carol"))
    return w, c1, c2


class Lifting(unittest.TestCase):
    def test_a_resolve_by_two_persons_lifts_the_fork(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        chain, forked = chosen_chain(w.epoch(c1, c2, r))
        self.assertEqual(chain, [w.id, c1.id])
        self.assertIsNone(forked)

    def test_one_signer_is_not_enough(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob",), [c1, c2], c1, [c2])
        _, forked = chosen_chain(w.epoch(c1, c2, r))
        self.assertEqual(forked.candidates, sorted([c1.id, c2.id]))

    def test_two_resolves_choosing_the_same_child_are_fine(self):
        w, c1, c2 = fork_world()
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c1, [c2])
        chain, forked = chosen_chain(w.epoch(c1, c2, r1, r2))
        self.assertEqual(chain, [w.id, c1.id])
        self.assertIsNone(forked)

    def test_the_chosen_branch_may_grow_after_the_resolve(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        later = w.device_add("bob2", ("bob", "alice"), c1)
        chain, _ = chosen_chain(w.epoch(c1, c2, r, later))
        self.assertEqual(chain, [w.id, c1.id, later.id])

    def test_a_removal_on_the_chosen_branch_does_not_void_the_resolve(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("alice", "bob"), [c1, c2], c1, [c2])
        removal = w.device_remove("alice", ("bob", "carol"), c1)   # alice's key, removed later on c1
        chain, forked = chosen_chain(w.epoch(c1, c2, r, removal))
        self.assertEqual(chain, [w.id, c1.id, removal.id])
        self.assertIsNone(forked)


class Applicability(unittest.TestCase):
    def test_the_candidates_must_be_the_children(self):
        w, c1, c2 = fork_world()
        c3 = w.device_add("alice4", ("alice", "bob"))
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        _, forked = chosen_chain(w.epoch(c1, c2, c3, r))
        self.assertEqual(forked.candidates, sorted([c1.id, c2.id, c3.id]))

    def test_heads_in_the_chosen_subtree_are_ignored(self):
        w, c1, c2 = fork_world()
        below = w.device_add("bob2", ("bob", "alice"), c1)
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2, below])
        _, forked = chosen_chain(w.epoch(c1, c2, below, r))
        self.assertIsNotNone(forked)

    def test_a_head_that_is_an_ancestor_of_another_is_ignored(self):
        w, c1, c2 = fork_world()
        below = w.device_add("carol2", ("carol", "alice"), c2)
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2, below])
        _, forked = chosen_chain(w.epoch(c1, c2, below, r))
        self.assertIsNotNone(forked)

    def test_every_losing_candidate_needs_a_head(self):
        w = World()
        c1 = w.device_add("alice2", ("alice", "bob"))
        c2 = w.device_add("alice3", ("alice", "carol"))
        c3 = w.device_add("alice4", ("alice", "bob"))
        r = w.resolve(("bob", "carol"), [c1, c2, c3], c1, [c2])
        _, forked = chosen_chain(w.epoch(c1, c2, c3, r))
        self.assertIsNotNone(forked)
        full = w.resolve(("bob", "carol"), [c1, c2, c3], c1, [c2, c3])
        chain, forked = chosen_chain(w.epoch(c1, c2, c3, full))
        self.assertEqual(chain, [w.id, c1.id])

    def test_a_resolve_that_skips_a_losing_candidate_is_not_applicable_so_it_need_not_be_named(self):
        w = World()
        c1 = w.device_add("alice2", ("alice", "bob"))
        c2 = w.device_add("alice3", ("alice", "carol"))
        c3 = w.device_add("alice4", ("alice", "bob"))
        skipping = w.resolve(("alice", "carol"), [c1, c2, c3], c2, [c1])           # no head under c3
        full = w.resolve(("bob", "carol"), [c1, c2, c3], c1, [c2, c3])
        chain, forked = chosen_chain(w.epoch(c1, c2, c3, skipping, full))
        self.assertEqual(chain, [w.id, c1.id])
        self.assertIsNone(forked)

    def test_a_head_must_be_a_node_of_a_losing_subtree(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [GHOST])
        self.assertIsNotNone(chosen_chain(w.epoch(c1, c2, r))[1])

    def test_two_heads_under_one_losing_candidate(self):
        w, c1, c2 = fork_world()
        d1 = w.device_add("bob2", ("bob", "alice"), c2)
        d2 = w.device_add("carol2", ("carol", "alice"), c2)
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [d1, d2])
        chain, forked = chosen_chain(w.epoch(c1, c2, d1, d2, r))
        self.assertEqual(chain, [w.id, c1.id])
        self.assertIsNone(forked)


class Cleanliness(unittest.TestCase):
    """A key removed on an examined path never counts for the resolve (FO-25 applicability 3)."""

    def branch(self):
        w, c1, c2 = fork_world()
        removal = w.device_remove("alice", ("bob", "carol"), c1)   # alice's key removed on c1's branch
        return w, c1, c2, removal

    def test_a_key_removed_on_the_discarded_branch_does_not_count(self):
        w, c1, c2, removal = self.branch()
        r = w.resolve(("alice", "bob"), [c1, c2], c2, [removal])
        _, forked = chosen_chain(w.epoch(c1, c2, removal, r))
        self.assertIsNotNone(forked)

    def test_heads_that_stop_before_the_removal_make_the_resolve_not_current(self):
        w, c1, c2, removal = self.branch()
        r = w.resolve(("alice", "bob"), [c1, c2], c2, [c1])
        _, forked = chosen_chain(w.epoch(c1, c2, removal, r))
        self.assertIsNotNone(forked)

    def test_the_same_resolve_without_the_removed_key_is_current(self):
        w, c1, c2, removal = self.branch()
        r = w.resolve(("bob", "carol"), [c1, c2], c2, [removal])
        chain, forked = chosen_chain(w.epoch(c1, c2, removal, r))
        self.assertEqual(chain, [w.id, c2.id])
        self.assertIsNone(forked)

    def test_a_removal_on_the_losing_branch_has_no_effect_beside_it(self):
        w, c1, c2, removal = self.branch()
        r = w.resolve(("alice", "bob"), [c1, c2], c1, [c2])   # alice counts: the removal is on the chosen branch
        chain, _ = chosen_chain(w.epoch(c1, c2, removal, r))
        self.assertEqual(chain, [w.id, c1.id, removal.id])

    def test_a_key_added_after_the_parent_never_counts(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        c1 = w.device_add("bob2", ("bob", "alice"), a)
        c2 = w.device_add("carol2", ("carol", "alice"), a)
        # alice2 exists below `a` only, but the resolve is at `a`: S_a has alice2. Use a fresh root fork instead
        r = w.resolve(("alice2", "bob"), [c1, c2], c1, [c2], a)
        chain, _ = chosen_chain(w.epoch(a, c1, c2, r))
        self.assertEqual(chain, [w.id, a.id, c1.id])

    def test_a_key_added_on_the_chosen_branch_after_p_is_unknown_at_p(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("alice2", "bob"), [c1, c2], c1, [c2])   # alice2 is introduced by c1, below P
        _, forked = chosen_chain(w.epoch(c1, c2, r))
        self.assertIsNotNone(forked)


class Refreeze(unittest.TestCase):
    def test_a_new_child_of_the_parent_makes_the_resolve_not_current(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        c3 = w.device_add("alice4", ("alice", "bob"))
        _, forked = chosen_chain(w.epoch(c1, c2, r, c3))
        self.assertEqual(forked.candidates, sorted([c1.id, c2.id, c3.id]))

    def test_an_extension_of_a_discarded_branch_makes_it_not_current(self):
        w, c1, c2 = fork_world()
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        grow = w.device_add("carol2", ("carol", "alice"), c2)
        _, forked = chosen_chain(w.epoch(c1, c2, r, grow))
        self.assertEqual(forked.parent.id, w.id)

    def test_a_resolve_whose_heads_examine_the_extension_lifts_it_again(self):
        w, c1, c2 = fork_world()
        grow = w.device_add("carol2", ("carol", "alice"), c2)
        r = w.resolve(("bob", "carol"), [c1, c2], c1, [grow])
        chain, forked = chosen_chain(w.epoch(c1, c2, grow, r))
        self.assertEqual(chain, [w.id, c1.id])
        self.assertIsNone(forked)


class Conflicts(unittest.TestCase):
    def test_two_resolves_choosing_different_children_freeze(self):
        w, c1, c2 = fork_world()
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        _, forked = chosen_chain(w.epoch(c1, c2, r1, r2))
        self.assertEqual(forked.candidates, sorted([c1.id, c2.id]))

    def test_a_resolve_that_names_the_other_with_evidence_lifts_the_freeze(self):
        w, c1, c2 = fork_world()
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        # r4 chooses what r1 chose, so it need not name r1; it must name r2, which chose the other child
        override2 = {"endorsements": sorted(a.id for a in r2.endorsements.values()), "resolve": r2.id}
        r4 = w.resolve(("alice", "bob"), [c1, c2], c1, [c2], overrides=[override2])
        chain, forked = chosen_chain(w.epoch(c1, c2, r1, r2, r4))
        self.assertIsNone(forked)
        self.assertEqual(chain, [w.id, c1.id])

    def test_an_override_with_the_wrong_id_is_not_effective(self):
        w, c1, c2 = fork_world()
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        bad = {"endorsements": sorted(a.id for a in r2.endorsements.values()), "resolve": r1.id}
        r4 = w.resolve(("alice", "bob"), [c1, c2], c1, [c2], overrides=[bad])
        _, forked = chosen_chain(w.epoch(c1, c2, r1, r2, r4))
        self.assertIsNotNone(forked)

    def test_an_override_with_less_evidence_than_a_quorum_is_not_effective(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        c1 = w.device_add("alice2", ("alice", "bob"))
        c2 = w.device_add("alice3", ("alice", "carol"))
        # dave's primary does not count (no listed role): bob and carol complete r2
        r2 = w.resolve(("dave", "bob", "carol"), [c1, c2], c2, [c1])
        ends = {s: a.id for s, a in r2.endorsements.items()}
        thin = {"endorsements": [ends["bob"]], "resolve": r2.id}
        full = {"endorsements": sorted(ends.values()), "resolve": r2.id}
        r_thin = w.resolve(("alice", "bob"), [c1, c2], c1, [c2], overrides=[thin])
        r_full = w.resolve(("alice", "bob"), [c1, c2], c1, [c2], overrides=[full], salt="full")
        self.assertIsNotNone(chosen_chain(w.epoch(c1, c2, r2, r_thin))[1])
        chain, forked = chosen_chain(w.epoch(c1, c2, r2, r_full))
        self.assertIsNone(forked)
        self.assertEqual(chain, [w.id, c1.id])

    def test_evidence_that_does_not_exist_is_not_effective(self):
        w, c1, c2 = fork_world()
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        ghost = {"endorsements": [GHOST], "resolve": r2.id}
        r4 = w.resolve(("alice", "bob"), [c1, c2], c1, [c2], overrides=[ghost])
        self.assertIsNotNone(chosen_chain(w.epoch(c1, c2, r2, r4))[1])


class Reading(unittest.TestCase):
    def test_a_resolve_at_a_node_that_is_not_a_fork_is_never_read(self):
        w, c1, c2 = fork_world()
        a = w.device_add("bob2", ("bob", "alice"))
        r = w.resolve(("bob", "carol"), [a, c1], a, [c1])
        chain, forked = chosen_chain(w.epoch(a, r))
        self.assertEqual(chain, [w.id, a.id])
        self.assertIsNone(forked)


if __name__ == "__main__":
    unittest.main()
