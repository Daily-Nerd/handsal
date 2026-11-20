"""CF-12 `pool`: is a point an `agree` key the organization introduced, at any time, on any branch.

True iff the point is the `agree` point of a device listed in an admitted document, or of any device in the state
of any node of the act tree of any admitted epoch (losing and forked branches too, removed devices too). Sign
points never. Monotone: a `true` for a store is `true` for every larger store (I4).
"""
import unittest

from handsal_check import chain as chain_module, errors, pool, profiles, registry, render_genesis, verifier

from .act_builder import FakeVitni, Unavailable, memo
from .device_reads import DeviceReads
from .fold_world import World
from .genesis_fixtures import device, point
from .linear_world import acts_of, chain
from .profile_sets import production_of
from .store_world import PRODUCTION_ONLY, Counting, opened, random_store, snap_of

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

    def test_the_agree_point_of_a_device_a_member_add_introduces_is_in_the_pool(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        add = w.member_add("frank", AB, role="member")
        docs = [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL + ("dave",))}]
        self.assertTrue(yes(ask(w, point("frank.agree"), acts=add.acts, docs=docs)))
        self.assertTrue(no(ask(w, point("frank.sign"), acts=add.acts, docs=docs)))
        self.assertTrue(no(ask(w, point("frank.agree"), acts=[], docs=docs)))   # the control: the act is what adds it

    def test_a_point_introduced_deep_in_a_chain_is_found_by_its_agree_point_and_not_by_its_sign_point(self):
        steps = chain(self.w, 6)
        acts = acts_of(steps)
        self.assertTrue(yes(ask(self.w, point("bob2.agree"), acts=acts)))
        self.assertTrue(yes(ask(self.w, point("alice2.agree"), acts=acts)))
        self.assertTrue(no(ask(self.w, point("bob2.sign"), acts=acts)))
        self.assertTrue(no(ask(self.w, point("dave2.agree"), acts=acts)))   # the seventh name, not in the chain

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

    def device_reads(self, steps, agree="alice"):
        """The fields of a device that one pool over `steps` steps reads, for the agree point of `agree`'s device."""
        w = World()
        inp = pool.parse_input({"acts": acts_of(chain(w, steps)), "agree": point(agree + ".agree"), "docs": [original(w)],
                                "org": w.id})
        with DeviceReads() as counted:
            got = pool.run(inp, PROFILES, True, memo(), render_genesis.render_size)
        self.assertEqual(got["reason"], "ok" if agree == "alice" else "not_in_pool")
        return counted.reads

    def test_the_devices_a_pool_reads_grow_linearly_with_the_chain(self):
        base = self.device_reads(0)
        self.assertGreater(base, 0)
        self.assertEqual(self.device_reads(10) - base, 2 * (self.device_reads(5) - base))

    def test_the_devices_a_pool_reads_for_a_point_nothing_introduced_grow_linearly_with_the_chain(self):
        base = self.device_reads(0, "dave")
        self.assertGreater(base, 0)
        self.assertEqual(self.device_reads(10, "dave") - base, 2 * (self.device_reads(5, "dave") - base))


def reference_introduced(epochs, agree):
    """The membership walk as it was: the agree point of any device of the state of any node, found by walking them."""
    for found in epochs.values():
        found.build()
        if any(device.agree == agree for node in found.nodes.values() for device in node.state.devices.values()):
            return True
    return False


class IntroducedAsBefore(unittest.TestCase):
    """CF-12: whether a point is in the pool is the answer of the walk over the devices of every node's state, for
    every agree and sign point of every device of generated stores and for points no device has. The points
    `agree_points` yields are that walk."""

    def test_the_answer_is_the_walks_for_every_point_of_generated_stores(self):
        yes_seen = no_seen = 0
        for seed in range(8):
            stored = random_store(seed, production_of(PROFILES))
            epochs = opened(snap_of(stored.acts, stored.docs, stored.org))
            points = {("x11", "y12"), ("x13", "y14")}
            for found in epochs.values():
                found.build()
                points |= {p for n in found.nodes.values() for d in n.state.devices.values() for p in (d.sign, d.agree)}
                points |= {p for d in found.root.state.devices.values() for p in (d.sign, d.agree)}
            for agree in sorted(points):
                want = reference_introduced(epochs, agree)
                self.assertEqual(agree in set(pool.agree_points(epochs)), want, msg=(seed, agree))
                yes_seen, no_seen = yes_seen + want, no_seen + (not want)
        self.assertGreater(yes_seen, 50)
        self.assertGreater(no_seen, 50)   # signing points and absent points: the answer is no


class ActsDown(verifier.Verifier):
    """A verifier that answers for documents and cannot answer for any act of the chain."""

    def __init__(self):
        self.inner = FakeVitni()

    def verify(self, jws, keys, method):
        if method in chain_module.PRIMARIES:
            raise verifier.VerifierUnavailable("down")
        return self.inner.verify(jws, keys, method)


class VerifierDown(unittest.TestCase):
    """CF-12: a verifier that cannot answer is `verifier_unavailable`, wherever in the store check the question is
    asked: at a document, or only when the act tree of the last epoch is built."""

    def go(self, w, acts, vitni):
        inp = pool.parse_input({"acts": list(acts), "agree": point("alice2.agree"), "docs": [original(w)], "org": w.id})
        return pool.run(inp, PROFILES, True, memo(vitni), render_genesis.render_size)

    def test_a_verifier_that_cannot_answer_at_a_document_is_verifier_unavailable(self):
        self.assertEqual(self.go(World(), [], Unavailable()), {"in_pool": False, "reason": "verifier_unavailable"})

    def test_a_verifier_that_cannot_answer_for_an_act_is_verifier_unavailable(self):
        w = World()
        acts = w.device_add("alice2", AB).acts
        self.assertTrue(yes(self.go(w, acts, FakeVitni())))   # the control: the store itself is sound
        self.assertEqual(self.go(w, acts, ActsDown()), {"in_pool": False, "reason": "verifier_unavailable"})


class Asked(verifier.Verifier):
    """A verifier that notes every question that reaches it, under the call's memo: the distinct questions of a call."""

    def __init__(self):
        self.inner, self.questions = FakeVitni(), []

    def verify(self, jws, keys, method):
        self.questions.append(verifier.question(jws, keys, method))
        return self.inner.verify(jws, keys, method)


def first_agree(epochs):
    """The smallest agree point of a device the first epoch's document lists."""
    found = next(iter(epochs.values()))
    found.build()
    return min(device.agree for device in found.root.state.devices.values())


ABSENT = ("x11", "y12")
# (answer, distinct questions) of one pool call per seed, for the first epoch's own point and for a point no
# device has, over `random_store(seed)`: recorded from the lazy walk that stops at the first epoch holding the point
RECORDED = [(("ok", 36), ("not_in_pool", 36)), (("ok", 17), ("not_in_pool", 17)), (("ok", 13), ("not_in_pool", 13)),
            (("ok", 17), ("not_in_pool", 26)), (("ok", 13), ("not_in_pool", 13)), (("ok", 35), ("not_in_pool", 42)),
            (("ok", 13), ("not_in_pool", 13)), (("ok", 32), ("not_in_pool", 32))]


class Agree(unittest.TestCase):
    """CF-12: one pool call asks what it always asked. Epochs are built as the walk reaches them, so a point found
    in an early epoch leaves the later ones unbuilt, and a point nobody introduced builds every epoch."""

    def asked(self, snap, agree):
        noted = Asked()
        got = pool.run(pool.Input(snap, agree), PRODUCTION_ONLY, True, memo(noted), render_genesis.render_size)
        return got["reason"], len(set(noted.questions))

    def test_the_answer_and_the_distinct_questions_of_a_pool_call_stay_what_they_were(self):
        for seed, want in enumerate(RECORDED):
            stored = random_store(seed, production_of(PROFILES))
            snap = snap_of(stored.acts, stored.docs, stored.org)
            got = (self.asked(snap, first_agree(opened(snap))), self.asked(snap, ABSENT))
            self.assertEqual(got, want, msg=seed)

    def test_a_point_found_in_an_early_epoch_asks_less_than_a_point_nobody_introduced(self):
        saved = 0
        for seed, ((_, hit), (_, miss)) in enumerate(RECORDED):
            self.assertLessEqual(hit, miss, msg=seed)
            saved += miss - hit
        self.assertGreater(saved, 0)


class AgreePoints(unittest.TestCase):
    """The one owner of CF-12 membership is `pool.agree_points`: `pool` asks whether a point is among them, and
    stops at the first that is."""

    def stores(self):
        for seed in range(8):
            stored = random_store(seed, production_of(PROFILES))
            yield seed, snap_of(stored.acts, stored.docs, stored.org)

    def test_it_yields_exactly_the_points_the_walk_over_every_state_finds(self):
        total = 0
        for seed, snap in self.stores():
            epochs = opened(snap)
            for found in epochs.values():
                found.build()
            walked = {device.agree for found in epochs.values() for node in [found.root] + list(found.nodes.values())
                      for device in node.state.devices.values()}
            self.assertEqual(set(pool.agree_points(epochs)), walked, msg=seed)
            total += len(walked)
        self.assertGreater(total, 50)

    def test_pool_answers_in_pool_for_exactly_the_points_it_yields(self):
        yes_seen = no_seen = 0
        for seed, snap in self.stores():
            epochs = opened(snap)
            yielded = set(pool.agree_points(epochs))
            signs = {device.sign for found in epochs.values() for device in found.root.state.devices.values()}
            for point_ in sorted(yielded | signs | {ABSENT}):
                got = pool.run(pool.Input(snap, point_), PRODUCTION_ONLY, True, memo(), render_genesis.render_size)
                self.assertEqual(got["in_pool"], point_ in yielded, msg=(seed, point_))
                yes_seen, no_seen = yes_seen + (point_ in yielded), no_seen + (point_ not in yielded)
        self.assertGreater(yes_seen, 50)
        self.assertGreater(no_seen, 8)

    def test_it_builds_an_epoch_only_when_the_walk_reaches_it(self):
        saved = 0
        for seed, snap in self.stores():
            first, everything = Asked(), Asked()
            points = pool.agree_points(opened(snap, first))
            next(points)
            asked_first = len(set(first.questions))
            list(pool.agree_points(opened(snap, everything)))
            self.assertLessEqual(asked_first, len(set(everything.questions)), msg=seed)
            saved += len(set(everything.questions)) - asked_first
        self.assertGreater(saved, 0)
