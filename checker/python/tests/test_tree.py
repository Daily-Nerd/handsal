"""T3.30 the act tree: paths, ancestry, subtrees and cleanliness (FO-26).

A node is the root or a valid primary. `clean(k, H)` is: k is active and accepted in the state at H,
nothing after or beside H is read.
"""
import unittest

from handsal_check import tree

from .act_builder import kid_of
from .fold_world import World, ids


def chain_of_three():
    w = World(extra=("bob2",))
    a = w.device_add("alice2", ("alice", "bob"))
    b = w.device_remove("bob2", ("alice", "carol"), a)
    c = w.device_add("carol2", ("carol", "alice"), b)
    d = w.device_add("alice3", ("alice", "bob"), a)   # a side branch under a
    e = w.epoch(a, b, c, d)
    return w, e, a, b, c, d


class Paths(unittest.TestCase):
    def test_path_from_root(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertEqual([n.id for n in tree.path_from_root(e.nodes[c.id])], [w.id, a.id, b.id, c.id])
        self.assertEqual([n.n for n in tree.path_from_root(e.nodes[c.id])], [0, 1, 2, 3])

    def test_ancestry_includes_the_node_itself(self):
        w, e, a, b, c, d = chain_of_three()
        N = e.nodes
        self.assertTrue(tree.is_ancestor(N[a.id], N[c.id]))
        self.assertTrue(tree.is_ancestor(N[c.id], N[c.id]))
        self.assertTrue(tree.is_ancestor(e.root, N[d.id]))
        self.assertFalse(tree.is_ancestor(N[b.id], N[d.id]))
        self.assertFalse(tree.is_ancestor(N[c.id], N[a.id]))

    def test_path_below_excludes_the_top_and_includes_the_node(self):
        w, e, a, b, c, d = chain_of_three()
        N = e.nodes
        self.assertEqual([n.id for n in tree.path_below(N[a.id], N[c.id])], [b.id, c.id])
        self.assertEqual(tree.path_below(N[a.id], N[a.id]), [])
        self.assertIsNone(tree.path_below(N[b.id], N[d.id]))

    def test_subtree_excludes_the_node(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertEqual({n.id for n in tree.subtree(e.nodes[a.id])}, {b.id, c.id, d.id})
        self.assertEqual(tree.subtree(e.nodes[c.id]), [])

    def test_the_removals_on_a_path(self):
        w, e, a, b, c, d = chain_of_three()
        path = tree.path_below(e.root, e.nodes[c.id])
        self.assertEqual(tree.removed_kids(path), {kid_of("bob2")})
        self.assertEqual(tree.removed_kids(tree.path_below(e.root, e.nodes[d.id])), set())


class Clean(unittest.TestCase):
    """clean(k, H): active and accepted in the state at H."""

    def test_active_accepted_key_is_clean(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertTrue(tree.clean(e.nodes[a.id], kid_of("bob2")))

    def test_a_key_removed_on_the_path_is_not_clean_at_the_node_after_it(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertFalse(tree.clean(e.nodes[b.id], kid_of("bob2")))
        self.assertFalse(tree.clean(e.nodes[c.id], kid_of("bob2")))

    def test_a_removal_beside_the_node_is_not_read(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertTrue(tree.clean(e.nodes[d.id], kid_of("bob2")))

    def test_an_unknown_key_is_not_clean(self):
        w, e, a, b, c, d = chain_of_three()
        self.assertFalse(tree.clean(e.root, kid_of("dave")))

    def test_an_unaccepted_key_is_not_clean(self):
        w = World()
        w.doc["devices"][0] = {**w.doc["devices"][0], "class": "fixture-pin"}
        e = w.epoch()
        self.assertFalse(tree.clean(e.root, w.doc["devices"][0]["kid"]))


if __name__ == "__main__":
    unittest.main()
