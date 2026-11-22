"""`agree-points` (CF-13 snapshot in, two lists of `agree` points out): which devices an organization has now (`active`)
and which it ever introduced (`pool`).

`pool` is the membership of CF-12 listed as a set. `active` reads the verdicts the fold already gives: the tip of the
walk of every open epoch (`fork.walk`), or the leaves below the candidates of the fork where it ends, and a device
counts only where `tree.clean` says it is active and accepted, the test `enrolled` makes. Nothing here is a rule of
its own, so the tests pin the shape of the answer on exact stores, and hold `active` to the rules it reads: it is a
subset of `pool`, it is what `enrolled` accepts on a tip, and it asks the verifier no more than `compact` does.
"""
import io
import json
import random
import unittest
from unittest import mock

from handsal_check import agreepoints, commands, compact, conformance, core, emit, enrolled, errors, fork, pool, \
    profiles, render_genesis, server, verifier

from .act_builder import FakeVitni, memo
from .checkact_world import NOW, dave_world, probe_for
from .fold_world import World
from .genesis_fixtures import device, point
from .linear_world import acts_of, chain as linear_chain
from .profile_sets import production_of
from .store_world import ALL, AB, PRODUCTION_ONLY, BatchStub, entry, later_world, opened, random_store, snap_of
from .test_enrolled import production_world
from .test_pool import ActsDown, Asked

PROFILES = profiles.load()
CONFORMANCE = commands.Build(conformance=True, allow_fixture=True)


def original(w):
    return entry(w.doc, w.sigs(w.doc, ALL))


def go(w, acts=(), docs=None, allow_fixture=True, vitni=None, **extra):
    docs = [original(w)] if docs is None else docs
    value = {"acts": list(acts), "docs": docs, "org": w.id, **extra}
    return agreepoints.run(agreepoints.parse_input(value), PROFILES, allow_fixture, memo(vitni),
                           render_genesis.render_size)


def pts(*names):
    """The points `{x, y}` of the agree keys of the fixture devices `names`, in the order the output lists them."""
    found = sorted((point(name + ".agree")["x"], point(name + ".agree")["y"]) for name in names)
    return [{"x": x, "y": y} for x, y in found]


def ok(active, pool_):
    return {"active": pts(*active), "pool": pts(*pool_), "reason": "ok"}


def refused(code):
    return {"active": None, "pool": None, "reason": code}


def sibling(w, name, new, head=None, drop=()):
    """A change document of `w`'s organization, named `name`, that adds the device `new` (or nothing) and drops
    `drop`, with the receipts that make it a valid link."""
    people = tuple(p for p in ALL if p not in drop) + ((new,) if new else ())
    devices = [device(p) for p in people]
    doc = w.change_doc(head or w.id, people=people, devices=devices, name=name)
    return entry(doc, w.sigs(doc, people))


class Contract(unittest.TestCase):
    def test_the_input_is_the_closed_snapshot(self):
        w = World()
        good = {"acts": [], "docs": [original(w)], "org": w.id}
        agreepoints.parse_input(good)
        for key in ("agree", "item", "pin", "now", "x"):
            with self.assertRaises(errors.Malformed, msg=key):
                agreepoints.parse_input({**good, key: None})
        for key in good:
            with self.assertRaises(errors.Malformed, msg=key):
                agreepoints.parse_input({k: v for k, v in good.items() if k != key})
        with self.assertRaises(errors.Malformed):
            agreepoints.parse_input([])

    def test_an_input_error_is_the_error_line_of_every_command_and_never_a_store_refusal(self):
        table = conformance.build_commands(FakeVitni())
        w = World()
        for name, raw in {"extra key": {"acts": [], "agree": point("alice.agree"), "docs": [original(w)], "org": w.id},
                          "acts not a list": {"acts": "x", "docs": [], "org": w.id}}.items():
            out = io.BytesIO()
            core.run(table, ["agree-points"], io.BytesIO(json.dumps(raw).encode()), out)
            self.assertEqual(out.getvalue(), b'{"error":"malformed_input"}\n', name)
        out = io.BytesIO()
        core.run(table, ["agree-points"], io.BytesIO(b"{"), out)
        self.assertEqual(out.getvalue(), b'{"error":"unparseable_input"}\n')

    def test_the_answer_is_one_line_of_exactly_active_pool_and_reason(self):
        w = World()
        table = conformance.build_commands(FakeVitni())
        out = io.BytesIO()
        value = {"acts": [], "docs": [original(w)], "org": w.id}
        core.run(table, ["agree-points"], io.BytesIO(json.dumps(value).encode()), out)
        self.assertEqual(out.getvalue(), emit.emit_result(ok(ALL, ALL)) + b"\n")
        self.assertEqual(list(json.loads(out.getvalue())), ["active", "pool", "reason"])

    def test_the_conformance_table_has_the_command_and_the_server_table_does_not_until_the_spec_names_it(self):
        self.assertLessEqual({"admit", "pool", "compact", "agree-points"}, set(conformance.build_commands(FakeVitni())))
        self.assertNotIn("agree-points", server.build_commands(FakeVitni()))   # CF-10 names admit, pool and compact


class Cases(unittest.TestCase):
    """One exact answer for each shape of store."""

    def setUp(self):
        self.w = World()

    def test_a_device_a_valid_add_introduces_is_in_both(self):
        add = self.w.device_add("alice2", AB)
        self.assertEqual(go(self.w, add.acts), ok(ALL + ("alice2",), ALL + ("alice2",)))

    def test_an_empty_store_holds_the_devices_of_the_document_in_both(self):
        self.assertEqual(go(self.w), ok(ALL, ALL))

    def test_a_removed_device_is_not_active_and_stays_in_the_pool(self):
        add = self.w.device_add("alice2", AB)
        remove = self.w.device_remove("alice2", ("bob", "carol"), add)
        self.assertEqual(go(self.w, add.acts + remove.acts), ok(ALL, ALL + ("alice2",)))

    def test_a_device_removed_on_one_branch_of_an_unresolved_fork_is_active(self):
        w = self.w
        gone, added = w.device_remove("carol", AB), w.device_add("alice2", AB)
        got = go(w, gone.acts + added.acts)
        self.assertEqual(got, ok(ALL + ("alice2",), ALL + ("alice2",)))   # carol: clean on the branch that adds alice2

    def test_a_device_removed_on_every_branch_of_an_unresolved_fork_is_not_active(self):
        w = self.w
        one, other = w.device_remove("carol", AB), w.device_remove("carol", AB, salt="the other branch")
        self.assertEqual(go(w, one.acts + other.acts), ok(("alice", "bob"), ALL))

    def test_a_device_added_only_on_a_losing_branch_is_in_the_pool_and_not_active(self):
        w = self.w
        kept, lost = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [kept, lost], kept, [lost])
        self.assertEqual(go(w, kept.acts + lost.acts + resolve.acts),
                         ok(ALL + ("alice2",), ALL + ("alice2", "alice3")))

    def test_a_device_removed_on_the_chosen_branch_of_a_resolved_fork_is_not_active_and_stays_in_the_pool(self):
        w = self.w
        gone, kept = w.device_remove("carol", AB), w.device_add("alice2", AB)
        resolve = w.resolve(AB, [gone, kept], gone, [kept])
        self.assertEqual(go(w, gone.acts + kept.acts + resolve.acts), ok(("alice", "bob"), ALL + ("alice2",)))

    def test_a_device_removed_only_on_the_losing_branch_of_a_resolved_fork_is_active(self):
        w = self.w
        gone, kept = w.device_remove("carol", AB), w.device_add("alice2", AB)
        resolve = w.resolve(AB, [gone, kept], kept, [gone])
        self.assertEqual(go(w, gone.acts + kept.acts + resolve.acts),
                         ok(ALL + ("alice2",), ALL + ("alice2",)))

    def test_a_device_removed_below_the_chosen_child_of_a_resolved_fork_is_not_active(self):
        w = self.w
        child, other = w.device_add("alice2", AB), w.device_add("bob2", ("bob", "carol"))
        below = w.device_remove("carol", AB, child)
        resolve = w.resolve(AB, [child, other], child, [other])
        self.assertEqual(go(w, child.acts + other.acts + below.acts + resolve.acts),
                         ok(("alice", "bob", "alice2"), ALL + ("alice2", "bob2")))

    def test_a_resolve_signed_by_the_removed_device_still_follows_the_chosen_branch(self):
        w = self.w
        gone, kept = w.device_remove("carol", ("alice", "bob")), w.device_add("alice2", ("alice", "bob"))
        resolve = w.resolve(("alice", "carol"), [gone, kept], gone, [kept])
        self.assertEqual(go(w, gone.acts + kept.acts + resolve.acts), ok(("alice", "bob"), ALL + ("alice2",)))

    def test_an_unresolved_fork_of_three_children_counts_the_leaves_below_every_one(self):
        w = self.w
        a, b, c = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol")), \
            w.device_add("bob2", ("bob", "carol"))
        below = w.device_add("bob3", AB, a, person="bob")
        every = ALL + ("alice2", "alice3", "bob2", "bob3")
        self.assertEqual(go(w, a.acts + b.acts + c.acts + below.acts), ok(every, every))

    def test_a_pending_add_is_in_neither(self):
        pending = self.w.device_add("alice2", ("alice",))
        self.assertEqual(go(self.w, pending.acts), ok(ALL, ALL))

    def test_a_sign_point_is_in_neither(self):
        add = self.w.device_add("alice2", AB)
        got = go(self.w, add.acts)
        for name in ("alice", "alice2"):
            sign = {"x": point(name + ".sign")["x"], "y": point(name + ".sign")["y"]}
            self.assertNotIn(sign, got["active"])
            self.assertNotIn(sign, got["pool"])

    def test_sibling_successor_epochs_both_count_and_the_epoch_they_succeed_does_not(self):
        w = self.w
        docs = [original(w), sibling(w, "A", "grace"), sibling(w, "B", "frank")]
        got = go(w, docs=docs)
        self.assertEqual(got, ok(ALL + ("grace", "frank"), ALL + ("grace", "frank")))

    def test_an_epoch_change_that_drops_a_device_leaves_it_out_of_active_and_in_the_pool(self):
        w = World(extra=("alice2",))
        doc = w.change_doc(w.id, devices=[device(name) for name in ALL], name="NEXT")   # alice2 is not carried over
        docs = [entry(w.doc, w.sigs(w.doc, ALL + ("alice2",))), entry(doc, w.sigs(doc, ALL))]
        self.assertEqual(go(w, docs=docs), ok(ALL, ALL + ("alice2",)))

    def test_a_device_of_a_class_the_policy_does_not_accept_is_in_the_pool_and_not_active(self):
        w, step = dave_world()
        docs = [entry(w.doc, w.sigs(w.doc, ALL + ("dave",)))]
        self.assertEqual(go(w, step.acts, docs), ok(ALL + ("dave",), ALL + ("dave", "dave2")))

    def test_a_point_in_two_sibling_epochs_is_listed_once_and_is_active_if_it_is_in_one(self):
        w = self.w
        a, b = sibling(w, "A", "grace"), sibling(w, "B", "grace")
        below = later_world(w, b["doc"])
        removal = below.device_remove("grace", AB)
        got = go(w, removal.acts, [original(w), a, b])
        self.assertEqual(got, ok(ALL + ("grace",), ALL + ("grace",)))
        both = go(w, [], [original(w), a, b])
        self.assertEqual(both, ok(ALL + ("grace",), ALL + ("grace",)))   # and once when it is active in both

    def test_the_server_build_refuses_a_fixture_profile_with_nulls(self):
        self.assertEqual(go(self.w, allow_fixture=False), refused("fixture_profile"))

    def test_a_store_without_its_original_is_lineage_broken_with_nulls(self):
        self.assertEqual(go(self.w, docs=[]), refused("lineage_broken"))
        self.assertEqual(go(self.w, docs=[original(World(name="OTHER"))]), refused("lineage_broken"))

    def test_a_document_that_is_no_valid_link_answers_its_code(self):
        w = self.w
        bad = w.change_doc(w.id)
        bad["members"] = list(reversed(bad["members"]))
        self.assertEqual(go(w, docs=[original(w), entry(bad, w.sigs(bad, ALL))]), refused("doc_not_sorted"))

    def test_a_verifier_that_cannot_answer_refuses_wherever_the_question_is_asked(self):
        w = self.w
        acts = w.device_add("alice2", AB).acts
        self.assertEqual(go(w, acts, vitni=FakeVitni())["reason"], "ok")   # the control: the store is sound
        self.assertEqual(go(w, acts, vitni=ActsDown()), refused("verifier_unavailable"))      # while the tree is built
        self.assertEqual(go(w, acts, vitni=Unavailable()), refused("verifier_unavailable"))   # at a document

    def test_a_failure_of_the_pool_walk_is_a_refusal_and_not_a_raised_exception(self):
        """`pool.agree_points` is a generator, so what it asks is asked wherever it is consumed, and the one rule here
        is that it is consumed inside the try. A store cannot show it: an epoch with a successor is built when the
        successor is read, and an open epoch is built by the walk or by `active`, whichever comes first, both inside
        the try, so a verifier that fails is refused wherever the questions are asked (the test above). What only this
        test holds is the position of the walk: a generator that fails when consumed must give the refusal of the
        call, not an exception that leaves `run`."""
        for name, err, want in (("verifier", verifier.VerifierUnavailable("down"), refused("verifier_unavailable")),
                                ("store", errors.Refused("lineage_broken"), refused("lineage_broken"))):
            def walk(epochs, err=err):
                raise err
                yield   # makes this a generator: nothing is raised before the first point is asked for

            with self.subTest(name), mock.patch.object(pool, "agree_points", walk):
                self.assertEqual(go(self.w), want)

    def test_the_lists_are_sorted_by_x_then_y_and_unique(self):
        w = self.w
        steps = linear_chain(w, 4)
        got = go(w, acts_of(steps))
        for key in ("active", "pool"):
            keys = [(p["x"], p["y"]) for p in got[key]]
            self.assertEqual(keys, sorted(set(keys)))


class Unavailable(verifier.Verifier):
    def verify(self, *args):
        raise verifier.VerifierUnavailable("down")


def stores(count=24):
    """`(seed, snapshot)` of the generated stores of the first `count` seeds that the command answers `ok` for, under
    the production profile, as the other store tests make them. (The generator also makes stores a document of which
    the lineage refuses; those are refusals, tested as such, and have no points to compare.)"""
    for seed in range(count):
        stored = random_store(seed, production_of(PROFILES))
        snap = snap_of(stored.acts, stored.docs, stored.org)
        if answer(snap)["reason"] == "ok":
            yield seed, snap


def answer(snap, vitni=None, allow_fixture=False):
    return agreepoints.run(snap, PRODUCTION_ONLY, allow_fixture, memo(vitni), render_genesis.render_size)


def listed(points):
    return {(p["x"], p["y"]) for p in points}


class Properties(unittest.TestCase):
    def test_active_is_a_subset_of_pool_and_the_answer_is_pools_over_every_point(self):
        active_seen = inactive_seen = 0
        for seed, snap in stores():
            got = answer(snap)
            self.assertEqual(got["reason"], "ok", msg=seed)
            self.assertLessEqual(listed(got["active"]), listed(got["pool"]), msg=seed)
            epochs = opened(snap)
            known = {d.agree for found in epochs.values() for d in found.root.state.devices.values()}
            for found in epochs.values():
                found.build()
                known |= {d.agree for n in found.nodes.values() for d in n.state.devices.values()}
            signs = {d.sign for found in epochs.values() for d in found.root.state.devices.values()}
            for agree in sorted(known | signs | {("x11", "y12")}):
                want = pool.run(pool.Input(snap, agree), PRODUCTION_ONLY, False, memo(), render_genesis.render_size)
                self.assertEqual(agree in listed(got["pool"]), want["in_pool"], msg=(seed, agree))
            active_seen += len(got["active"])
            inactive_seen += len(got["pool"]) - len(got["active"])
        self.assertGreater(active_seen, 50)
        self.assertGreater(inactive_seen, 10)   # the control: some devices are in the pool only

    def agrees_with_enrolled(self, snap):
        """`(accepted, refused)` over the devices of the tip: for each, `enrolled` accepts it iff its agree point is
        in `active`. None for a store `enrolled` cannot answer a state for (a fork, or no single open epoch)."""
        epochs = opened(snap)
        found = epochs[snap.org]
        found.build()
        walked = fork.walk(found)
        if len(snap.docs) != 1 or walked.fork is not None:
            return None
        got, accepted, refused_ = answer(snap), 0, 0
        for kid, dev in walked.chain[-1].state.devices.items():
            data = {"acts": snap.acts, "device_kid": kid, "lineage": snap.docs, "now": NOW, "org": snap.org,
                    "next": "no", "pin": probe_for(snap.docs[0]["doc"], snap.org), "synced_at": NOW,
                    "tip_statement": None}
            says = enrolled.run(enrolled.parse_input(data, conformance_build=True), PRODUCTION_ONLY, False, memo())
            self.assertIn(says["reason"], ("ok", "local_key_not_active", "local_class_not_accepted"), msg=kid)
            self.assertEqual(says["enrolled"], dev.agree in listed(got["active"]), msg=kid)
            accepted, refused_ = accepted + says["enrolled"], refused_ + (not says["enrolled"])
        return accepted, refused_

    def test_on_a_store_with_one_open_epoch_a_device_of_the_tip_is_active_iff_enrolled_accepts_it(self):
        accepted = refused_ = 0
        for seed, snap in stores(120):
            seen = self.agrees_with_enrolled(snap)
            if seen is not None:
                accepted, refused_ = accepted + seen[0], refused_ + seen[1]
        w = production_world()
        add = w.device_add("alice2", AB)
        remove = w.device_remove("alice2", ("bob", "carol"), add)
        for acts in ([], add.acts, add.acts + remove.acts):   # the control: a removed device is refused by both
            seen = self.agrees_with_enrolled(snap_of(acts, [original(w)], w.id))
            accepted, refused_ = accepted + seen[0], refused_ + seen[1]
        self.assertGreater(accepted, 30)
        self.assertGreater(refused_, 0)

    def test_it_asks_the_verifier_no_more_than_compact_and_as_much_as_a_full_pool_where_no_node_forks(self):
        forkless = 0
        for seed, snap in stores():
            counted = {}
            for name in ("agree-points", "compact", "pool"):
                noted = Asked()
                if name == "agree-points":
                    agreepoints.run(snap, PRODUCTION_ONLY, True, memo(noted), render_genesis.render_size)
                elif name == "compact":
                    compact.run(snap, PRODUCTION_ONLY, True, memo(noted), render_genesis.render_size)
                else:
                    pool.run(pool.Input(snap, ("x11", "y12")), PRODUCTION_ONLY, True, memo(noted),
                             render_genesis.render_size)
                counted[name] = len(set(noted.questions))
            self.assertLessEqual(counted["agree-points"], counted["compact"], msg=seed)
            epochs = opened(snap)
            for found in epochs.values():
                found.build()
            if all(len(node.children) <= 1 for found in epochs.values() for node in found.nodes.values()):
                forkless += 1
                self.assertEqual(counted["agree-points"], counted["pool"], msg=seed)
        self.assertGreater(forkless, 0)

    def test_the_same_snapshot_in_another_order_gives_the_same_bytes(self):
        rng = random.Random(7)
        for seed, snap in stores(12):
            want = emit.emit_result(answer(snap))
            for _ in range(3):
                acts, docs = list(snap.acts), [dict(e, sigs=rng.sample(e["sigs"], len(e["sigs"]))) for e in snap.docs]
                rng.shuffle(acts)
                rng.shuffle(docs)
                value = {"acts": acts, "docs": docs, "org": snap.org}
                shuffled = agreepoints.run(agreepoints.parse_input(value), PRODUCTION_ONLY, False, memo(),
                                           render_genesis.render_size)
                self.assertEqual(emit.emit_result(shuffled), want, msg=seed)

    def test_a_refusal_is_both_lists_null_and_a_success_is_both_lists_and_ok(self):
        w = World()
        outcomes = [go(w), go(w, docs=[]), go(w, allow_fixture=False), go(w, vitni=Unavailable()),
                    go(w, w.device_add("alice2", AB).acts)]
        for seed in range(24, 60):   # whatever a generated store makes the lineage do
            stored = random_store(seed, production_of(PROFILES))
            outcomes.append(answer(snap_of(stored.acts, stored.docs, stored.org)))
        for got in outcomes:
            self.assertEqual(got["reason"] == "ok", got["active"] is not None, msg=got)
            self.assertEqual(got["active"] is None, got["pool"] is None, msg=got)
            self.assertEqual(set(got), {"active", "pool", "reason"})
        self.assertEqual([got["reason"] for got in outcomes[:5]],
                         ["ok", "lineage_broken", "fixture_profile", "verifier_unavailable", "ok"])
        self.assertGreater(len({got["reason"] for got in outcomes}), 4)   # generated stores add codes of their own


class Seam(unittest.TestCase):
    """The command runs under `per_batch` like `admit`, `pool` and `compact`: one round, the bytes of one question
    at a time."""

    def table(self, vitni):
        return {"agree-points": commands.per_batch(vitni, commands.agree_points(CONFORMANCE))}

    def oracle(self, vitni):
        return {"agree-points": commands.per_call(vitni, commands.agree_points(CONFORMANCE))}

    def ask(self, table, value):
        out = io.BytesIO()
        core.run(table, ["agree-points"], io.BytesIO(json.dumps(value).encode()), out)
        return out.getvalue()

    def test_a_linear_store_is_one_round_and_no_single_question(self):
        for n in (1, 5, 10):
            w = World()
            value = {"acts": acts_of(linear_chain(w, n)), "docs": [original(w)], "org": w.id}
            stub = BatchStub()
            self.assertEqual(json.loads(self.ask(self.table(stub), value))["reason"], "ok")
            self.assertEqual((stub.rounds, len(stub.singles)), (1, 0), msg=n)

    def test_the_bytes_are_the_bytes_of_one_question_at_a_time(self):
        for seed, snap in stores(12):
            value = {"acts": snap.acts, "docs": snap.docs, "org": snap.org}
            honest = self.ask(self.table(BatchStub()), value)
            self.assertEqual(honest, self.ask(self.oracle(BatchStub()), value), msg=seed)
            down = self.ask(self.table(BatchStub(down=True)), value)
            self.assertEqual(down, self.ask(self.oracle(BatchStub(down=True)), value), msg=seed)


if __name__ == "__main__":
    unittest.main()
