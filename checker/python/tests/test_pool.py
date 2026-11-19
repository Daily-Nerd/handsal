"""CF-12 `pool`: is a point an `agree` key the organization introduced, at any time, on any branch.

True iff the point is the `agree` point of a device listed in an admitted document, or of any device in the state
of any node of the act tree of any admitted epoch (losing and forked branches too, removed devices too). Sign
points never. Monotone: a `true` for a store is `true` for every larger store (I4).
"""
import unittest

from handsal_check import errors, pool, profiles, registry, render_genesis

from .act_builder import FakeVitni, memo
from .fold_world import World
from .genesis_fixtures import device, point
from .linear_world import acts_of, chain
from .store_world import Counting

REG = registry.load()
PROFILES = profiles.load()
ALL = ("alice", "bob", "carol")
AB = ("alice", "bob")


def original(w):
    return {"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}


def ask(w, agree, acts=(), docs=None, allow_fixture=True, org=None):
    docs = [original(w)] if docs is None else docs
    inp = pool.parse_input({"acts": list(acts), "agree": agree, "docs": docs, "org": org or w.id})
    return pool.run(inp, PROFILES, allow_fixture, memo(), render_genesis.render_size)


def yes(got):
    return got == {"in_pool": True, "reason": "ok"}


def no(got):
    return got == {"in_pool": False, "reason": "not_in_pool"}


class Input(unittest.TestCase):
    def test_the_input_is_the_closed_object_of_acts_agree_docs_and_org(self):
        w = World()
        good = {"acts": [], "agree": point("alice.agree"), "docs": [original(w)], "org": w.id}
        pool.parse_input(good)
        for key in ("item", "pin", "x"):
            with self.assertRaises(errors.Malformed, msg=key):
                pool.parse_input({**good, key: None})
        for name, agree in {"no y": {"x": point("alice.agree")["x"]}, "a string": "x",
                            "bad base64": {"x": "!" * 43, "y": "A" * 43},
                            "not on the curve": {"x": "A" * 43, "y": "A" * 43},
                            "an extra member": {**point("alice.agree"), "z": "A"}}.items():
            with self.subTest(agree=name), self.assertRaises(errors.Malformed):
                pool.parse_input({**good, "agree": agree})


class Membership(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def test_the_agree_point_of_a_genesis_device_is_in_the_pool(self):   # CF-12 S1
        self.assertTrue(yes(ask(self.w, point("alice.agree"))))

    def test_a_sign_point_is_not_in_the_pool(self):   # CF-12 S2
        self.assertTrue(no(ask(self.w, point("alice.sign"))))

    def test_a_point_nothing_introduces_is_not_in_the_pool(self):
        self.assertTrue(no(ask(self.w, point("dave.agree"))))

    def test_a_pending_add_is_not_in_the_pool_and_a_valid_one_is(self):
        pending = self.w.device_add("alice2", ("alice",))
        self.assertTrue(no(ask(self.w, point("alice2.agree"), acts=pending.acts)))
        valid = self.w.device_add("alice2", AB)
        self.assertTrue(yes(ask(self.w, point("alice2.agree"), acts=valid.acts)))
        self.assertTrue(no(ask(self.w, point("alice2.sign"), acts=valid.acts)))

    def test_a_removed_device_stays_in_the_pool(self):
        add = self.w.device_add("alice2", AB)
        remove = self.w.device_remove("alice2", ("bob", "carol"), add)
        self.assertTrue(yes(ask(self.w, point("alice2.agree"), acts=add.acts + remove.acts)))

    def test_a_device_added_on_a_branch_a_resolve_discarded_is_in_the_pool(self):
        c1, c2 = self.w.device_add("alice2", AB), self.w.device_add("alice3", ("alice", "carol"))
        resolve = self.w.resolve(AB, [c1, c2], c1, [c2])
        acts = c1.acts + c2.acts + resolve.acts
        for name in ("alice2", "alice3"):
            self.assertTrue(yes(ask(self.w, point(name + ".agree"), acts=acts)), name)

    def test_a_device_listed_in_a_later_document_is_in_the_pool_once_the_document_is_stored(self):
        w = self.w
        doc = w.change_doc(w.id, devices=[device("alice"), device("bob"), device("carol"), device("grace")],
                           people=("alice", "bob", "carol", "grace"))
        later = {"doc": doc, "sigs": w.sigs(doc, ALL + ("grace",))}
        self.assertTrue(no(ask(w, point("grace.agree"))))
        self.assertTrue(yes(ask(w, point("grace.agree"), docs=[original(w), later])))

    def test_a_snapshot_whose_original_is_not_the_orgs_is_lineage_broken(self):   # CF-12 S3
        other = World(name="OTHER")
        got = ask(self.w, point("alice.agree"), docs=[original(other)])
        self.assertEqual(got, {"in_pool": False, "reason": "lineage_broken"})

    def test_the_fixture_profile_is_refused_in_the_server_build_only(self):
        got = ask(self.w, point("alice.agree"), allow_fixture=False)
        self.assertEqual(got, {"in_pool": False, "reason": "fixture_profile"})

    def test_the_answer_has_no_other_key(self):
        self.assertEqual(set(ask(self.w, point("alice.agree"))), {"in_pool", "reason"})


class Monotone(unittest.TestCase):
    def test_a_key_true_for_a_store_is_true_for_every_larger_store(self):   # CF-12 S4, I4
        w = World()
        first = w.device_add("alice2", AB)
        second = w.device_add("alice3", ("alice", "carol"))        # beside the first: a fork
        resolve = w.resolve(AB, [first, second], first, [second])
        removal = w.device_remove("alice2", ("bob", "carol"), first)
        doc = w.change_doc(w.id, devices=[device("alice"), device("bob"), device("carol"), device("grace")],
                           people=("alice", "bob", "carol", "grace"))
        later = {"doc": doc, "sigs": w.sigs(doc, ALL + ("grace",))}
        stores = [([], [original(w)]),
                  (first.acts, [original(w)]),
                  (first.acts + removal.acts, [original(w)]),
                  (first.acts + removal.acts + second.acts, [original(w)]),
                  (first.acts + removal.acts + second.acts + resolve.acts, [original(w)]),
                  (first.acts + removal.acts + second.acts + resolve.acts + ["junk"], [original(w), later])]
        keys = {name: point(name + ".agree") for name in
                ("alice", "bob", "carol", "alice2", "alice3", "grace", "dave")}
        truth = [{name: ask(w, p, acts=acts, docs=docs)["in_pool"] for name, p in keys.items()}
                 for acts, docs in stores]
        for smaller, larger in zip(truth, truth[1:]):
            for name, was in smaller.items():
                if was:
                    self.assertTrue(larger[name], name)
        self.assertEqual([sorted(n for n, t in row.items() if t) for row in truth][0], ["alice", "bob", "carol"])
        self.assertIn("grace", [n for n, t in truth[-1].items() if t])   # the control: the pool did grow


if __name__ == "__main__":
    unittest.main()


class Cost(unittest.TestCase):
    """What one pool asks the verifier, counted at the verifier under the call's memo (the questions that reach it)."""

    def calls(self, steps):
        w = World()
        counted = Counting()
        inp = pool.parse_input({"acts": acts_of(chain(w, steps)), "agree": point("alice.agree"), "docs": [original(w)],
                                "org": w.id})
        got = pool.run(inp, PROFILES, True, memo(counted), render_genesis.render_size)
        self.assertEqual(got, {"in_pool": True, "reason": "ok"})
        return counted.calls

    def test_the_questions_of_a_pool_grow_linearly_with_the_chain(self):
        base = self.calls(0)
        self.assertEqual(self.calls(10) - base, 2 * (self.calls(5) - base))

    def widest(self, steps):
        """The largest `keys` object, in bytes of JSON, that any question of a pool over `steps` steps carries."""
        w = World()
        vitni = FakeVitni()
        inp = pool.parse_input({"acts": acts_of(chain(w, steps)), "agree": point("alice.agree"), "docs": [original(w)],
                                "org": w.id})
        self.assertEqual(pool.run(inp, PROFILES, True, memo(vitni), render_genesis.render_size)["reason"], "ok")
        return max(len(keys) for _, keys, _ in vitni.calls)

    def test_the_keys_of_a_question_do_not_grow_with_the_chain(self):
        self.assertEqual(self.widest(10), self.widest(5))
