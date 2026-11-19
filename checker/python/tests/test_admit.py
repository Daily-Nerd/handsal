"""CF-11 `admit`: may one item enter the chain store of an organization (RS5 to RS9, section 20.3).

Every act of the tests carries a stand-in signature (`act_builder`) and `FakeVitni` answers like vitni would. The
rule is "valid now": a pending primary, a lone endorsement and a lone `genesis.sign` are never admitted, and the
answer names the signatures to keep, one per kid, so the caller encodes no rule.
"""
import pathlib
import re
import unittest
from unittest import mock

from handsal_check import admit, chain, encoding, epoch, errors, fold, genesis, quorum, registry, render_genesis, profiles, resolve, retain

from . import old_retain
from .act_builder import BAD, HIGH, FakeVitni, Unavailable, build, memo, with_signature
from .checkact_world import Scenario
from .device_reads import DeviceReads
from .fold_world import World
from .genesis_fixtures import policy
from .profile_sets import fixture_of, production_of
from .linear_world import acts_of, chain as linear_chain, top
from .store_world import Counting, after, later_world, opened, random_store, retained_of, snap_of

REG = registry.load()
PROFILES = profiles.load()
ALL = ("alice", "bob", "carol")
AB = ("alice", "bob")
MAX_INPUT = 16777216
RESERVE = 1048576
LOW = b"\x02" * 64   # another low-S signature over one payload: a twin of one receipt id


def original(w, names=ALL):
    return {"doc": w.doc, "sigs": w.sigs(w.doc, names)}


def go(w, item, acts=(), docs=None, allow_fixture=True, vitni=None, org=None):
    docs = [original(w)] if docs is None else docs
    inp = admit.parse_input({"acts": list(acts), "docs": docs, "item": item, "org": org or w.id})
    return admit.run(inp, PROFILES, allow_fixture, memo(vitni), render_genesis.render_size)


def reason(*args, **kw):
    return go(*args, **kw)["reason"]


def group(step, *extra):
    """The item of the act group of `step` (a fold_world `Step`): the primary and every other act it holds."""
    return {"act": step.primary.jws, "sigs": [a for a in step.acts[1:]] + list(extra)}


class Input(unittest.TestCase):
    def test_the_input_is_the_closed_object_of_acts_docs_item_and_org(self):   # CF-11
        w = World()
        good = {"acts": [], "docs": [original(w)], "item": {"act": "x", "sigs": []}, "org": w.id}
        admit.parse_input(good)
        for key in ("pin", "now", "lineage", "x"):
            with self.assertRaises(errors.Malformed, msg=key):
                admit.parse_input({**good, key: None})
        for name, item in {"both": {"act": "x", "doc": {}, "sigs": []}, "neither": {"sigs": []},
                           "no sigs": {"act": "x"}, "act not a string": {"act": 1, "sigs": []},
                           "doc not an object": {"doc": "x", "sigs": []}, "sigs not strings": {"act": "x", "sigs": [1]},
                           "not an object": []}.items():
            with self.subTest(item=name), self.assertRaises(errors.Malformed):
                admit.parse_input({**good, "item": item})
        for key in ("acts", "docs", "item", "org"):
            with self.assertRaises(errors.Malformed, msg=key):
                admit.parse_input({k: v for k, v in good.items() if k != key})


class StoreChecks(unittest.TestCase):
    """The store is judged before the item: first failure wins."""

    def test_no_original_is_lineage_broken_unless_the_item_is_the_original(self):
        w = World()
        step = w.device_add("alice2", AB)
        self.assertEqual(reason(w, group(step), docs=[]), "lineage_broken")
        other = World(name="OTHER")
        self.assertEqual(reason(w, group(step), docs=[original(other)]), "lineage_broken")
        got = go(w, {"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}, docs=[])   # registration
        self.assertEqual(got["reason"], "ok")

    def test_an_original_that_is_not_the_org_is_lineage_broken(self):
        w, other = World(), World(name="OTHER")
        self.assertEqual(reason(w, {"doc": other.doc, "sigs": other.sigs(other.doc, ALL)}, docs=[]), "lineage_broken")

    def test_a_document_of_the_store_that_is_no_valid_link_answers_its_gp_15_code(self):
        w = World()
        bad = w.change_doc(w.id)
        bad["members"] = list(reversed(bad["members"]))
        docs = [original(w), {"doc": bad, "sigs": w.sigs(bad, ALL)}]
        self.assertEqual(reason(w, group(w.device_add("alice2", AB)), docs=docs), "doc_not_sorted")

    def test_a_document_that_names_no_stored_prev_is_lineage_broken(self):
        w = World()
        orphan = w.change_doc(w.id, prev=World(name="OTHER").doc)
        docs = [original(w), {"doc": orphan, "sigs": w.sigs(orphan, ALL)}]
        self.assertEqual(reason(w, group(w.device_add("alice2", AB)), docs=docs), "lineage_broken")

    def test_the_fixture_profile_is_refused_in_the_server_build_only(self):   # CF-10
        w = World()
        step = w.device_add("alice2", AB)
        self.assertEqual(go(w, group(step), allow_fixture=False), {"reason": "fixture_profile", "store": None})
        self.assertEqual(reason(w, group(step), allow_fixture=True), "ok")

    def test_an_invalid_act_of_the_store_is_ignored_as_the_fold_ignores_it(self):   # FO-06
        w = World()
        pending = w.device_add("bob2", ("bob",))
        self.assertEqual(reason(w, group(w.device_add("alice2", AB)), acts=pending.acts + ["junk"]), "ok")

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable(self):   # 20.10
        w = World()
        self.assertEqual(go(w, group(w.device_add("alice2", AB)), vitni=Unavailable()),
                         {"reason": "verifier_unavailable", "store": None})


class ActGroup(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.step = self.w.device_add("alice2", AB)

    def test_a_good_group_is_ok_and_the_store_is_the_act_with_its_kept_signatures_sorted(self):
        step = self.step
        got = go(self.w, group(step))
        self.assertEqual(got, {"reason": "ok", "store": {"act": step.primary.jws, "sigs": sorted(step.acts[1:])}})

    def test_the_checks_of_vr_02_steps_1_to_5_come_first_in_their_order(self):
        w = self.w
        approve = Scenario(w).verdict()
        for name, jws, code in (
            ("not a jws", "junk", "jws_shape"),
            ("an envelope key more", build("alice", "device.add", org=w.id, body={}, parent=w.id,
                                           edit=lambda p: p.__setitem__("x", "y")).jws, "schema"),
            ("a method no registry knows", build("alice", "bogus", org=w.id, body={}).jws, "method_unknown"),
            ("a verdict", approve.jws, "not_chain_act"),
            ("a lone endorsement", w.endorse("bob", self.step.primary, w.id).jws, "not_chain_act"),
            ("a decision", Scenario(w).decision().jws, "not_chain_act"),
            ("a device.add with another body", w.primary("device.add", {"x": "y"}, AB).primary.jws, "body_schema"),
        ):
            with self.subTest(name):
                self.assertEqual(reason(w, {"act": jws, "sigs": []}), code)

    def test_a_tip_statement_is_method_unknown(self):   # CF-11 S7, WT-02
        w = World()
        statement = build("alice", "relay.tip", org=w.id, body={"epoch": w.id, "next": "no", "tip": w.id})
        self.assertEqual(reason(w, {"act": statement.jws, "sigs": []}), "method_unknown")

    def test_org_mismatch_comes_before_already_stored_and_the_rest(self):
        other = World(name="OTHER")
        foreign = other.device_add("alice2", AB)
        self.assertEqual(reason(self.w, group(foreign), acts=foreign.acts), "org_mismatch")

    def test_an_act_of_another_org_at_a_node_of_ours_is_org_mismatch_not_act_not_valid(self):
        # the fold ignores it without a reason (FO-06), so the boundary names it: admit keeps its own check
        other = World(name="OTHER")
        foreign = self.w.device_add("bob2", AB, self.step, org=other.id)
        self.assertEqual(reason(self.w, group(foreign), acts=self.step.acts), "org_mismatch")

    def test_already_stored_comes_before_parent_unknown(self):
        child = self.w.device_add("bob2", AB, self.step)
        self.assertEqual(reason(self.w, group(child), acts=self.step.acts + child.acts), "already_stored")
        self.assertEqual(reason(self.w, group(child)), "parent_unknown")
        # a copy no node anchors (its parent is not stored) is no stored act: nothing is held pending (CF-11)
        self.assertEqual(reason(self.w, group(child), acts=child.acts), "parent_unknown")

    def test_a_low_s_twin_has_the_receipt_id_of_the_stored_act(self):   # RS7, ACT-12
        twin = with_signature(self.step.primary, LOW)
        self.assertEqual(reason(self.w, {"act": twin.jws, "sigs": self.step.acts[1:]}, acts=self.step.acts),
                         "already_stored")

    def test_a_garbage_twin_does_not_hide_the_valid_act(self):   # CF-11 S14, FO-21, SD6 (c)
        for twin in (with_signature(self.step.primary, BAD), with_signature(self.step.primary, HIGH)):
            with self.subTest(twin=twin.jws[-8:]):
                got = go(self.w, group(self.step), acts=[twin.jws])   # the store holds only the invalid copy
                self.assertEqual(got["reason"], "ok")
                self.assertEqual(got["store"]["act"], self.step.primary.jws)
                # with the valid copy stored beside the garbage one, the act is stored
                self.assertEqual(reason(self.w, group(self.step), acts=self.step.acts + [twin.jws]), "already_stored")

    def test_an_endorsement_of_the_act_alone_does_not_make_it_stored(self):
        self.assertEqual(reason(self.w, group(self.step), acts=[self.step.endorsements["bob"].jws]), "ok")

    def test_a_valid_resolve_stored_is_already_stored(self):   # CF-11: a node or an applicable resolve
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        stored = c1.acts + c2.acts + resolve.acts
        self.assertEqual(reason(w, group(resolve), acts=stored), "already_stored")
        self.assertEqual(reason(w, group(resolve), acts=c1.acts + c2.acts + [resolve.primary.jws]), "ok")   # no quorum yet
        bad = with_signature(resolve.primary, BAD).jws   # a garbage twin of the resolve does not hide it
        self.assertEqual(reason(w, group(resolve), acts=c1.acts + c2.acts + [bad]), "ok")

    def test_parent_unknown_comes_before_high_s_and_high_s_before_act_not_valid(self):
        w = self.w
        orphan = w.device_add("bob2", AB, self.step, sig=HIGH)
        self.assertEqual(reason(w, group(orphan)), "parent_unknown")
        self.assertEqual(reason(w, group(orphan), acts=self.step.acts), "high_s")
        weak = w.device_add("bob3", ("alice",), sig=HIGH)
        self.assertEqual(reason(w, group(weak)), "high_s")

    def test_the_one_touch_device_add_is_act_not_valid(self):   # CF-11 S11, relay design 5.1
        w = World()
        one_touch = w.device_add("alice2", ("alice",))   # alice signs, nobody else: no quorum
        self.assertEqual(go(w, group(one_touch)), {"reason": "act_not_valid", "store": None})

    def test_a_signature_that_does_not_verify_is_not_a_counted_one(self):
        w = World()
        step = w.device_add("alice2", AB, skip=("bob",))   # alice and the proof of possession only
        bad = w.endorse("bob", step.primary, w.id, sig=BAD)
        self.assertEqual(reason(w, {"act": step.primary.jws, "sigs": [bad.jws, step.pop.jws]}), "act_not_valid")

    def test_the_resolve_of_a_fork_is_ok(self):   # CF-11 S2, FO-25
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        self.assertEqual(reason(w, group(resolve), acts=c1.acts + c2.acts), "ok")
        self.assertEqual(reason(w, group(resolve), acts=c1.acts), "act_not_valid")   # the candidates are no nodes

    def test_a_valid_child_at_an_old_parent_that_makes_a_fork_is_ok(self):   # CF-11 S2, FO-24
        w = World()
        first = w.device_add("alice2", AB)
        second = w.device_add("alice3", ("alice", "carol"))   # also at the root: the second child makes the fork
        self.assertEqual(reason(w, group(second), acts=first.acts), "ok")


class ClosedEpoch(unittest.TestCase):
    """CF-11 `epoch_closed` (SD6, I8): an act whose parent is a node of an epoch the store holds a successor of is
    never admitted, because the retained set would drop it at once."""

    def setUp(self):
        self.w = World()
        self.a = self.w.device_add("alice2", AB)
        self.doc = self.w.change_doc(self.a.id)                 # closes epoch 0 at a
        self.docs = [original(self.w), {"doc": self.doc, "sigs": self.w.sigs(self.doc, ALL)}]

    def test_an_act_in_a_closed_epoch_is_epoch_closed(self):   # CF-11 S14
        w = self.w
        child = w.device_add("bob2", AB, self.a)                # a child of the head
        fork = w.device_add("alice3", ("alice", "carol"))       # a sibling of a, at the root
        for name, step in (("below the head", child), ("beside the path", fork)):
            with self.subTest(name):
                self.assertEqual(go(w, group(step), acts=self.a.acts, docs=self.docs),
                                 {"reason": "epoch_closed", "store": None})
                self.assertEqual(reason(w, group(step), acts=self.a.acts), "ok")   # open before the change

    def test_a_resolve_in_a_closed_epoch_is_epoch_closed(self):
        w = self.w
        other = w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [self.a, other], self.a, [other])
        self.assertEqual(reason(w, group(resolve), acts=self.a.acts + other.acts, docs=self.docs), "epoch_closed")

    def test_an_act_of_the_new_epoch_is_admitted(self):
        w1 = later_world(self.w, self.doc)
        step = w1.device_add("alice4", AB)
        self.assertEqual(go(self.w, group(step), acts=self.a.acts, docs=self.docs)["reason"], "ok")

    def test_epoch_closed_comes_after_parent_unknown_and_before_high_s(self):
        w = self.w
        child = w.device_add("bob2", AB, self.a, sig=HIGH)                  # a node's child, with a high S
        grandchild = w.device_add("carol2", AB, child, sig=HIGH)            # its parent is not stored
        self.assertEqual(reason(w, group(grandchild), acts=self.a.acts, docs=self.docs), "parent_unknown")
        self.assertEqual(reason(w, group(child), acts=self.a.acts, docs=self.docs), "epoch_closed")
        self.assertEqual(reason(w, group(child), acts=self.a.acts), "high_s")   # open: the next check answers

    def test_a_stored_act_of_a_closed_epoch_is_already_stored_not_epoch_closed(self):
        self.assertEqual(reason(self.w, group(self.a), acts=self.a.acts, docs=self.docs), "already_stored")

    def test_a_document_is_admitted_while_its_prev_is_closed_a_sibling_change_included(self):   # SD6: documents
        w = self.w
        sibling = w.change_doc(w.id, name="SIBLING")
        self.assertEqual(reason(w, {"doc": sibling, "sigs": w.sigs(sibling, ALL)}, acts=self.a.acts, docs=self.docs),
                         "ok")

    def test_a_change_whose_head_a_compaction_dropped_is_genesis_head_unknown(self):   # CF-11 S15
        w = self.w
        b = w.device_add("bob2", AB, self.a)
        later = w.change_doc(b.id, name="LATER")                 # H = b, an act the compaction dropped
        sigs = w.sigs(later, ALL)
        every = self.a.acts + b.acts
        whole = reason(w, {"doc": later, "sigs": sigs}, acts=every)
        self.assertEqual(whole, "ok")                            # before the compaction b is a usable head
        snap = snap_of(every, self.docs, w.id)                  # the first change closes epoch 0 at a, b is off its path
        dropped, _ = retain.dropped(snap, retained_of(snap))
        self.assertEqual(set(dropped), set(b.acts))
        kept = [text for text in every if text not in dropped]
        self.assertEqual(reason(w, {"doc": later, "sigs": sigs}, acts=kept, docs=self.docs), "genesis_head_unknown")
        retained_head = w.change_doc(self.a.id, name="OTHER")   # a head on the retained path is still publishable
        self.assertEqual(reason(w, {"doc": retained_head, "sigs": w.sigs(retained_head, ALL)}, acts=kept,
                                docs=self.docs), "ok")


class KeptSignatures(unittest.TestCase):
    """RS6: one signature per kid, the smallest JWS string in byte order; junk and high S never stored."""

    def setUp(self):
        self.w = World()
        self.step = self.w.device_add("alice2", AB)
        self.bob = self.step.endorsements["bob"]
        self.pop = self.step.pop

    def kept(self, *extra):
        got = go(self.w, {"act": self.step.primary.jws, "sigs": [self.bob.jws, self.pop.jws, *extra]})
        self.assertEqual(got["reason"], "ok")
        return got["store"]["sigs"]

    def test_junk_a_stranger_and_a_high_s_signature_are_dropped(self):
        stranger = self.w.endorse("dave", self.step.primary, self.w.id)   # a key no state holds
        high = self.w.endorse("carol", self.step.primary, self.w.id, sig=HIGH)
        self.assertEqual(self.kept("junk", "", stranger.jws, high.jws), sorted([self.bob.jws, self.pop.jws]))

    def test_a_second_counting_endorsement_by_another_kid_is_kept(self):
        carol = self.w.endorse("carol", self.step.primary, self.w.id)
        self.assertEqual(self.kept(carol.jws), sorted([self.bob.jws, self.pop.jws, carol.jws]))

    def test_a_second_signature_by_one_kid_is_kid_repeated(self):   # CF-11 S12
        twin = with_signature(self.bob, LOW)
        self.assertNotEqual(twin.jws, self.bob.jws)
        got = go(self.w, {"act": self.step.primary.jws, "sigs": [self.bob.jws, twin.jws, self.pop.jws]})
        self.assertEqual(got, {"reason": "kid_repeated", "store": None})

    def test_the_same_string_twice_is_one_signature(self):
        self.assertEqual(self.kept(self.bob.jws, self.bob.jws), sorted([self.bob.jws, self.pop.jws]))

    def test_two_possession_endorsements_are_kid_repeated(self):   # the new key is a kid like the others
        twin = with_signature(self.pop, LOW)
        got = go(self.w, {"act": self.step.primary.jws, "sigs": [self.bob.jws, self.pop.jws, twin.jws]})
        self.assertEqual(got, {"reason": "kid_repeated", "store": None})

    def test_an_endorsement_of_another_act_is_dropped(self):
        other = self.w.device_add("bob2", AB)
        self.assertEqual(self.kept(other.endorsements["bob"].jws), sorted([self.bob.jws, self.pop.jws]))


class VerificationBound(unittest.TestCase):
    """CF-11: a signature counts only by a key of the state at the parent (or the new key), once per kid. So the
    verifier is called for the signatures of an item at most once per such key, whatever `sigs` holds: the bound is
    measured here by counting calls, never by time."""

    def setUp(self):
        self.w = World()
        self.step = self.w.device_add("alice2", AB)
        self.bob, self.pop = self.step.endorsements["bob"], self.step.pop

    def forged(self, count, kid):
        """`count` distinct well-formed endorsements of the act, all with the header kid `kid`."""
        return [with_signature(self.w.endorse("bob", self.step.primary, self.w.id, kid=kid), bytes([i + 1]) * 64).jws
                for i in range(count)]

    def run_item(self, sigs):
        vitni = FakeVitni()
        got = go(self.w, {"act": self.step.primary.jws, "sigs": sigs}, vitni=vitni)
        own = set(sigs)
        return got, [call for call in vitni.calls if call[0] in own]

    def test_a_kid_repeated_many_times_is_refused_before_any_verification(self):
        sigs = [self.bob.jws, self.pop.jws] + self.forged(200, self.bob.kid)
        got, calls = self.run_item(sigs)
        self.assertEqual(got, {"reason": "kid_repeated", "store": None})
        self.assertEqual(calls, [])

    def test_a_stranger_kid_is_dropped_without_a_verification(self):
        strangers = [self.forged(1, "%042d" % i + "A")[0] for i in range(200)]
        got, calls = self.run_item([self.bob.jws, self.pop.jws] + strangers)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["store"]["sigs"], sorted([self.bob.jws, self.pop.jws]))
        self.assertEqual({call[0] for call in calls} & set(strangers), set())

    def test_the_verifications_of_any_item_are_at_most_the_keys_of_the_parent_state_plus_the_new_key(self):
        state_kids = {device["kid"] for device in self.w.doc["devices"]}
        strangers = [self.forged(1, "%042d" % i + "A")[0] for i in range(100)]
        carol = self.w.endorse("carol", self.step.primary, self.w.id).jws
        got, calls = self.run_item([self.bob.jws, self.pop.jws, carol, "junk"] + strangers)
        self.assertEqual(got["reason"], "ok")
        self.assertLessEqual(len({call[0] for call in calls}), len(state_kids) + 1)

    def test_a_receipt_kid_repeated_many_times_is_refused_before_any_verification(self):
        doc = self.w.change_doc(self.w.id)
        honest = self.w.sigs(doc, ALL)
        twins = [self.w.sigs(doc, ("bob",), sig=bytes([i + 1]) * 64)[0] for i in range(200)]
        vitni = FakeVitni()
        got = go(self.w, {"doc": doc, "sigs": honest + twins}, vitni=vitni)
        self.assertEqual(got, {"reason": "kid_repeated", "store": None})
        self.assertEqual([c for c in vitni.calls if c[0] in set(honest + twins)], [])

    def test_the_order_of_the_answers(self):
        twin = with_signature(self.bob, LOW).jws
        sigs = [self.bob.jws, twin, self.pop.jws]
        one_touch = self.w.device_add("alice3", ("alice",))
        self.assertEqual(reason(self.w, {"act": one_touch.primary.jws,
                                         "sigs": [one_touch.pop.jws, with_signature(one_touch.pop, LOW).jws]}),
                         "kid_repeated")   # before act_not_valid
        weak_high = self.w.device_add("bob3", ("alice",), sig=HIGH)
        self.assertEqual(reason(self.w, {"act": weak_high.primary.jws, "sigs": sigs}), "high_s")   # high_s first
        doc = self.w.change_doc(self.w.id)
        unsigned = self.w.sigs(doc, AB) + self.w.sigs(doc, ("bob",), sig=LOW)
        self.assertEqual(reason(self.w, {"doc": doc, "sigs": unsigned}), "kid_repeated")   # before genesis_unsigned
        orphan = self.w.change_doc(self.w.id, prev=World(name="OTHER").doc)
        self.assertEqual(reason(self.w, {"doc": orphan, "sigs": self.w.sigs(orphan, ("bob", "bob"), sig=LOW)
                                         + self.w.sigs(orphan, ("bob",))}), "parent_unknown")   # after parent_unknown


class DocumentGroup(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def change(self, **kw):
        doc = self.w.change_doc(self.w.id, **kw)
        return doc

    def test_the_original_is_admitted_with_one_receipt_per_kid(self):   # CF-11 S1
        w = self.w
        sigs = w.sigs(w.doc, ALL)
        got = go(w, {"doc": w.doc, "sigs": sigs + ["junk"]}, docs=[])
        self.assertEqual(got, {"reason": "ok", "store": {"doc": w.doc, "sigs": sorted(sigs)}})

    def test_a_valid_change_is_ok_with_one_receipt_per_kid(self):
        doc = self.change()
        sigs = self.w.sigs(doc, ALL)
        got = go(self.w, {"doc": doc, "sigs": sigs + ["junk"]})
        self.assertEqual(got, {"reason": "ok", "store": {"doc": doc, "sigs": sorted(sigs)}})

    def test_a_receipt_by_an_old_role_holder_who_is_not_listed_counts_for_authority(self):
        doc = self.change(people=("alice", "frank", "grace"))
        sigs = self.w.sigs(doc, ("alice", "frank", "grace", "bob"))
        self.assertEqual(go(self.w, {"doc": doc, "sigs": sigs})["store"]["sigs"], sorted(sigs))

    def test_a_receipt_that_counts_for_nothing_is_dropped(self):
        doc = self.change(people=("alice", "frank", "grace"))
        sigs = self.w.sigs(doc, ("alice", "frank", "grace", "bob"))
        dave = self.w.sigs(doc, ("dave",))   # not a device of the document, not in the state at H
        high = self.w.sigs(doc, ("carol",), sig=HIGH)
        wrong = self.w.sigs(doc, ("carol",), head=None)
        got = go(self.w, {"doc": doc, "sigs": sigs + dave + high + wrong})
        self.assertEqual(got["store"]["sigs"], sorted(sigs))

    def test_a_stored_document_is_already_stored(self):   # CF-11 S3
        doc = self.change()
        docs = [original(self.w), {"doc": doc, "sigs": self.w.sigs(doc, ALL)}]
        self.assertEqual(reason(self.w, {"doc": doc, "sigs": []}, docs=docs), "already_stored")
        self.assertEqual(reason(self.w, {"doc": self.w.doc, "sigs": []}), "already_stored")

    def test_lineage_and_parent_codes_come_before_the_genesis_check(self):
        w = self.w
        doc = self.change()
        wrong_org = dict(doc, org=encoding.hashstr(b"another org"))
        self.assertEqual(reason(w, {"doc": wrong_org, "sigs": []}), "lineage_broken")
        orphan = w.change_doc(w.id, prev=World(name="OTHER").doc)
        self.assertEqual(reason(w, {"doc": orphan, "sigs": w.sigs(orphan, ALL)}), "parent_unknown")

    def test_a_change_with_too_few_previous_role_holders_is_not_authorized(self):   # CF-11 S8
        doc = self.change(people=("alice", "frank", "grace"))
        sigs = self.w.sigs(doc, ("alice", "frank", "grace"))
        self.assertEqual(go(self.w, {"doc": doc, "sigs": sigs}), {"reason": "genesis_change_unauthorized", "store": None})

    def test_an_unsigned_device_and_an_unknown_head_come_with_their_codes(self):
        w = self.w
        doc = self.change()
        self.assertEqual(reason(w, {"doc": doc, "sigs": w.sigs(doc, AB)}), "genesis_unsigned")
        far = w.change_doc(encoding.hashstr(b"no such node"))
        self.assertEqual(reason(w, {"doc": far, "sigs": w.sigs(far, ALL)}), "genesis_head_unknown")


class OneAuthorityRule(unittest.TestCase):
    """Admission keeps the receipts and signatures the fold counts, by calling the fold's own public functions:
    there is no copy of the rule in `admit` and no read of a private name of the fold."""

    def test_the_kept_receipts_follow_the_fold_authority_function(self):
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace", "bob"))
        self.assertEqual(go(w, {"doc": doc, "sigs": sigs})["store"]["sigs"], sorted(sigs))
        calls = []

        def never(act, text, node, roles, vitni):
            calls.append(act.kid)
            return None
        real, epoch.authority_person = epoch.authority_person, never
        try:
            got = go(w, {"doc": doc, "sigs": sigs})
        finally:
            epoch.authority_person = real
        self.assertTrue(calls)   # the fold and admit both ask the one function; none counts, so no authority
        self.assertEqual(got, {"reason": "genesis_change_unauthorized", "store": None})

    def test_what_a_store_keeps_has_one_owner_and_admit_holds_no_copy(self):   # SD13
        source = pathlib.Path(admit.__file__).read_text(encoding="utf-8")
        for name in ("def _kept(", "def _kept_receipts(", "authority_person(", "endorse.verified(", "possession("):
            self.assertNotIn(name, source, name)
        for name in ("kept_endorsements", "kept_receipts", "read_endorsements", "read_receipts", "retained"):
            self.assertTrue(callable(getattr(retain, name)), name)

    def test_an_admitted_item_is_kept_by_the_retained_set_of_the_resulting_store(self):   # I8, SD13
        w = World()
        step = w.device_add("alice2", AB)
        stranger = w.endorse("dave", step.primary, w.id).jws
        high = w.endorse("carol", step.primary, w.id, sig=HIGH).jws
        got = go(w, {"act": step.primary.jws, "sigs": step.acts[1:] + ["junk", stranger, high]})
        self.assertEqual(got["reason"], "ok")
        texts = [got["store"]["act"]] + got["store"]["sigs"]
        snap = snap_of(texts, [original(w)], w.id)
        self.assertEqual(set(retained_of(snap).acts), set(texts))   # nothing it admitted is dropped by the rule

    def test_a_receipt_the_document_group_keeps_is_kept_by_the_retained_set(self):   # I8 for documents
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace", "bob")) + w.sigs(doc, ("dave",)) + ["junk"]
        got = go(w, {"doc": doc, "sigs": sigs})
        self.assertEqual(got["reason"], "ok")
        snap = snap_of([], [original(w), {"doc": doc, "sigs": got["store"]["sigs"]}], w.id)
        kept = retained_of(snap).receipts
        self.assertEqual(sorted(kept[genesis.doc_hash(doc)]), got["store"]["sigs"])

    def test_admit_reads_no_private_name_of_the_fold_and_holds_no_copy(self):
        source = pathlib.Path(admit.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\b(?:quorum|epoch|fold|tree|endorse)\._\w+", source))
        self.assertNotIn("_counts_for_authority", source)
        self.assertNotIn("_new_key", source)

    def test_the_fold_exposes_the_two_functions_admit_needs(self):
        self.assertTrue(callable(epoch.authority_person))
        self.assertTrue(callable(quorum.introduced))


class Capacity(unittest.TestCase):
    """RS9: an act group while the canonical size stays within MAX_INPUT minus two reserves (14 MiB), a document
    group within MAX_INPUT minus one reserve (15 MiB). The limits come from the registry: nothing is injected."""

    def test_the_reserve_is_the_registry_constant(self):
        self.assertEqual(REG.number("ADMIT_RESERVE"), RESERVE)
        self.assertEqual(REG.number("MAX_INPUT"), MAX_INPUT)

    def padded(self, count):
        return ["%06d" % i + "x" * 1_000_000 for i in range(count)]

    def test_a_store_past_the_reserve_is_store_full(self):   # CF-11 S10, L15
        w = World()
        step = w.device_add("alice2", AB)
        self.assertEqual(reason(w, group(step), acts=self.padded(13)), "ok")   # 13 MB: under 14 MiB
        self.assertEqual(go(w, group(step), acts=self.padded(15)), {"reason": "store_full", "store": None})
        doc = w.change_doc(w.id)
        sigs = w.sigs(doc, ALL)
        self.assertEqual(reason(w, {"doc": doc, "sigs": sigs}, acts=self.padded(15)), "ok")   # the exit still fits
        self.assertEqual(reason(w, {"doc": doc, "sigs": sigs}, acts=self.padded(16)), "store_full")   # over 15 MiB

    def test_an_invalid_act_is_refused_for_its_own_reason_before_the_store_is_full(self):
        w = World()
        weak = w.device_add("alice2", ("alice",))
        self.assertEqual(reason(w, group(weak), acts=self.padded(15)), "act_not_valid")


if __name__ == "__main__":
    unittest.main()


class Cost(unittest.TestCase):
    """What one admit asks the verifier, counted at the verifier under the call's memo (the questions that reach it)."""

    def calls(self, steps):
        w = World()
        below = linear_chain(w, steps)
        item = top(w, below)
        counted = Counting()
        got = go(w, {"act": item.primary.jws, "sigs": item.acts[1:]}, acts=acts_of(below), vitni=counted)
        self.assertEqual(got["reason"], "ok")
        return counted.calls

    def test_the_questions_of_an_admit_grow_linearly_with_the_chain(self):
        base = self.calls(0)
        self.assertEqual(self.calls(10) - base, 2 * (self.calls(5) - base))

    def widest(self, steps):
        """The largest `keys` object, in bytes of JSON, that any question of an admit over `steps` steps carries."""
        w = World()
        below = linear_chain(w, steps)
        item = top(w, below)
        vitni = FakeVitni()
        got = go(w, {"act": item.primary.jws, "sigs": item.acts[1:]}, acts=acts_of(below), vitni=vitni)
        self.assertEqual(got["reason"], "ok")
        return max(len(keys) for _, keys, _ in vitni.calls)

    def test_the_keys_of_a_question_do_not_grow_with_the_chain(self):
        self.assertEqual(self.widest(10), self.widest(5))

    def device_reads(self, steps):
        """The fields of a device that one admit of the act on top of `steps` steps reads."""
        w = World()
        below = linear_chain(w, steps)
        item = top(w, below)
        with DeviceReads() as counted:
            got = go(w, {"act": item.primary.jws, "sigs": item.acts[1:]}, acts=acts_of(below))
        self.assertEqual(got["reason"], "ok")
        return counted.reads

    def test_the_devices_an_admit_reads_grow_linearly_with_the_chain(self):
        base = self.device_reads(0)
        self.assertGreater(base, 0)
        self.assertEqual(self.device_reads(10) - base, 2 * (self.device_reads(5) - base))

    def orphan_calls(self, steps):
        """The questions of an admit of the act on top of `steps` steps when the store holds the endorsements of
        that act and the item brings none."""
        w = World()
        below = linear_chain(w, steps)
        item = top(w, below)
        counted = Counting()
        got = go(w, {"act": item.primary.jws, "sigs": []}, acts=acts_of(below) + item.acts[1:], vitni=counted)
        self.assertEqual(got["reason"], "ok")
        return counted.calls

    def test_a_stored_orphan_endorsement_costs_the_questions_it_cost_before_the_keys_were_narrowed(self):
        self.assertEqual((self.orphan_calls(0), self.orphan_calls(5), self.orphan_calls(10)), (7, 27, 47))   # 4N + 7


    def real_builds(self, w, item, acts=(), docs=None):
        """`(answer, root ids of the trees a call really built, in order)`: a spy on `Epoch.build` notes each
        epoch that is not built yet when it is asked to build, so a tree built twice is listed twice."""
        built, real = [], fold.Epoch.build

        def spy(epoch):
            if not epoch._built:
                built.append(epoch.root.id)
            return real(epoch)

        with mock.patch.object(fold.Epoch, "build", spy):
            got = go(w, item, acts=acts, docs=docs)
        return got, built

    def test_a_primary_is_judged_without_building_the_tree_again(self):
        w = World()
        step = w.device_add("alice2", AB)
        got, built = self.real_builds(w, group(step))
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(built, [w.id])

    def test_a_resolve_is_judged_without_building_the_tree_again(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        got, built = self.real_builds(w, group(resolve), acts=c1.acts + c2.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(built, [w.id])

    def test_a_second_epoch_adds_the_one_build_that_finds_the_parent_and_nothing_for_the_judgment(self):
        w = World()
        docs = [original(w)] + [{"doc": doc, "sigs": w.sigs(doc, ALL)} for doc in
                                (w.change_doc(w.id, name="LEFT"), w.change_doc(w.id, name="RIGHT"))]
        first = min(genesis.doc_hash(entry["doc"]) for entry in docs[1:])
        at_first = later_world(w, next(e["doc"] for e in docs if genesis.doc_hash(e["doc"]) == first))
        step = at_first.device_add("alice2", AB)
        got, built = self.real_builds(w, group(step), docs=docs)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(built, [w.id, first])   # the original, built to fold its changes, and the one holding the parent

    def view_of_an_admit(self, w, item, acts):
        """`(base, view)` of the one judgment an admit of `item` over `acts` makes."""
        seen, real = [], fold.Epoch.sharing_tree

        def spy(epoch, texts):
            view = real(epoch, texts)
            seen.append((epoch, view))
            return view

        with mock.patch.object(fold.Epoch, "sharing_tree", spy):
            self.assertEqual(go(w, item, acts=acts)["reason"], "ok")
        self.assertEqual(len(seen), 1)
        return seen[0]

    def test_the_view_shares_the_built_tree_and_holds_the_texts_that_bear_on_the_act_only(self):
        w = World()
        step, other = w.device_add("alice2", AB), w.device_add("bob2", AB)
        stored = step.acts[1:]   # bob's endorsement and the proof of the new key
        base, view = self.view_of_an_admit(w, {"act": step.primary.jws, "sigs": []}, other.acts + stored)
        self.assertIs(view.root, base.root)
        self.assertIs(view.nodes, base.nodes)
        self.assertTrue(view._built)
        held = [copy.jws for found in view.bag.groups.values() for copy in found.copies]
        self.assertEqual(sorted(held), sorted([step.primary.jws] + stored))   # not the other act, not its signatures

    def test_the_view_holds_the_stored_copies_of_the_act_then_the_act_then_what_is_kept(self):
        w = World()
        step = w.device_add("alice2", AB)
        twin = with_signature(step.primary, LOW).jws   # a stored pending copy of the act: a text that can change its verdict
        base, view = self.view_of_an_admit(w, {"act": step.primary.jws, "sigs": step.acts[1:]}, [twin])
        self.assertEqual([copy.jws for copy in view.bag.groups[step.id].copies], [twin, step.primary.jws])
        self.assertEqual(sorted(copy.jws for found in view.bag.endorsements_of(view.bag.groups[step.id].act)
                                for copy in found.copies), sorted(step.acts[1:]))

    def test_judging_in_a_view_changes_no_node_of_the_tree_it_shares(self):
        w = World()
        step = w.device_add("alice2", AB)
        base, view = self.view_of_an_admit(w, {"act": step.primary.jws, "sigs": step.acts[1:]}, [])
        self.assertEqual(sorted(base.nodes), [w.id])
        self.assertEqual(base.root.children, [])
        view.build()   # built already: it grows nothing
        self.assertEqual(sorted(base.nodes), [w.id])
        self.assertEqual(base.root.children, [])

    def test_a_view_of_a_tree_that_is_not_built_is_refused(self):
        w = World()
        found = fold.Epoch(w.doc, w.bag(), PROFILES.resolve(fixture_of(PROFILES)), memo())
        with self.assertRaises(RuntimeError):
            found.sharing_tree([])


class StoredTexts(unittest.TestCase):
    """What the store already holds of an act and of the signatures on it bears on the answer for the act: a stored
    endorsement completes a quorum, and the epochs that are not the act's are not built to find its parent."""

    def test_a_stored_endorsement_that_completes_the_quorum_makes_the_primary_ok(self):
        w = World()
        step = w.device_add("alice2", AB)
        got = go(w, {"act": step.primary.jws, "sigs": []}, acts=step.acts[1:])   # bob's endorsement and the proof
        self.assertEqual(got, {"reason": "ok", "store": {"act": step.primary.jws, "sigs": []}})

    def test_a_stored_endorsement_that_completes_the_quorum_makes_the_resolve_ok(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        got = go(w, {"act": resolve.primary.jws, "sigs": []}, acts=c1.acts + c2.acts + resolve.acts[1:])
        self.assertEqual(got, {"reason": "ok", "store": {"act": resolve.primary.jws, "sigs": []}})

    def test_a_stored_endorsement_of_a_resolve_that_is_not_applicable_does_not_make_it_valid(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        got = go(w, {"act": resolve.primary.jws, "sigs": []}, acts=c1.acts + resolve.acts[1:])   # c2 is no node
        self.assertEqual(got, {"reason": "act_not_valid", "store": None})

    def built_roots(self, w, docs, item):
        """`(answer, document hashes of the epochs that a call really built, in order)`: a spy on `Epoch.build`
        notes each epoch that is not built yet when it is asked to build."""
        built, real = [], fold.Epoch.build

        def spy(self):
            if not self._built:
                built.append(self.root.id)
            return real(self)

        with mock.patch.object(fold.Epoch, "build", spy):
            got = go(w, item, docs=docs)
        return got, built

    def siblings(self):
        """An organization with two sibling changes, `(w, docs, first, second)`: the hashes of the two, first by
        lineage order (siblings by hash)."""
        w = World()
        docs = [original(w)] + [{"doc": doc, "sigs": w.sigs(doc, ALL)} for doc in
                                (w.change_doc(w.id, name="LEFT"), w.change_doc(w.id, name="RIGHT"))]
        first, second = sorted(genesis.doc_hash(entry["doc"]) for entry in docs[1:])
        return w, docs, first, second

    def test_the_epoch_after_the_one_that_holds_the_parent_is_not_built(self):
        w, docs, first, second = self.siblings()
        at_first = later_world(w, next(e["doc"] for e in docs if genesis.doc_hash(e["doc"]) == first))
        step = at_first.device_add("alice2", AB)
        got, built = self.built_roots(w, docs, group(step))
        self.assertEqual(got["reason"], "ok")
        self.assertIn(first, built)
        self.assertNotIn(second, built)

    def test_both_epochs_are_built_in_order_when_the_parent_is_in_the_second(self):
        w, docs, first, second = self.siblings()
        at_second = later_world(w, next(e["doc"] for e in docs if genesis.doc_hash(e["doc"]) == second))
        step = at_second.device_add("alice2", AB)
        got, built = self.built_roots(w, docs, group(step))
        self.assertEqual(got["reason"], "ok")
        self.assertLess(built.index(first), built.index(second))

    def test_every_epoch_is_built_when_no_epoch_holds_the_parent(self):
        w, docs, first, second = self.siblings()
        nowhere = World(name="NOWHERE")
        step = w.device_add("alice2", AB, nowhere.device_add("bob2", AB))   # its parent is stored in no epoch
        got, built = self.built_roots(w, docs, group(step))
        self.assertEqual(got["reason"], "parent_unknown")
        self.assertIn(first, built)
        self.assertIn(second, built)


def rebuilt_valid(base, parent, parsed, texts):
    """The judgment of an act before it was made in a view: the whole bag, the store plus the act and what is kept,
    read again into a tree of its own."""
    full = old_retain.over(base, texts)
    full.build()
    if parsed.method in chain.PRIMARIES:
        return parsed.id in full.nodes
    return resolve.Resolves(full).applicable(full.bag.groups[parsed.id], full.nodes[parent.id]) is not None


def located_in(snap, parsed):
    """`(epoch, node)` the act hangs at in the store `snap`, or None when admit answers before it judges: the store
    does not open (dropping an act can leave a change document whose head is gone), or no epoch holds the parent."""
    try:
        return admit._parent(opened(snap), parsed)
    except errors.Refused:
        return None


def both_verdicts(snap, text, sigs, wire=PROFILES.wire):
    """`(over a rebuilt tree, in a view)` of the judgment of the act `text` with the item signatures `sigs` over the
    store `snap`, or None when admit answers before it judges (the act is stored, or its parent is not, or two of
    the signatures are of one kid)."""
    parsed = admit._parse_act(text, wire)
    located = located_in(snap, parsed)
    if located is None or admit._stored(*located, parsed):
        return None
    base, parent = located
    try:
        kept = retain.kept_endorsements(base, parent, parsed, admit._endorsements(base, parsed, sigs))
    except errors.Refused:   # kid_repeated: refused before the judgment
        return None
    return (rebuilt_valid(base, parent, parsed, list(snap.acts) + [parsed.jws] + kept),
            admit._valid(base, parent, parsed, kept))


def endorsements_stored(snap, text, wire=PROFILES.wire):
    """The strings of `snap` that read as endorsements of the act `text`, as admit reads an item's `sigs`."""
    parsed = admit._parse_act(text, wire)
    located = located_in(snap, parsed)
    if located is None:
        return []
    return [s for s in snap.acts if old_retain.read_endorsements(located[0], parsed, [s])]


class SameVerdict(unittest.TestCase):
    """The act is judged in a view of the store's tree, not over a tree built again: the verdict is the one of the
    rebuilt tree for every store shape, with the texts the store already holds for the act and its endorsements."""

    SEEDS = range(8)

    def same(self, snap, text, sigs):
        got = both_verdicts(snap, text, sigs)
        if got is not None:
            self.assertEqual(got[0], got[1])
        return got

    def test_every_stored_primary_and_resolve_is_judged_as_over_a_rebuilt_tree(self):
        seen, methods = [], set()
        for seed in self.SEEDS:
            stored = random_store(seed, production_of(PROFILES))
            snap = snap_of(stored.acts, stored.docs, stored.org)
            for text in snap.acts:
                try:
                    admit._parse_act(text, PROFILES.wire)
                except errors.Refused:
                    continue
                without = after(snap, acts_gone=[text])
                moved = endorsements_stored(without, text)
                for reading, store, sigs in (("stored", without, []), ("all as item", without, list(without.acts)),
                                             ("moved", after(without, acts_gone=moved), moved)):
                    with self.subTest(seed=seed, text=text[-12:], reading=reading):
                        got = self.same(store, text, sigs)
                        if got is not None:
                            seen.append(got[0])
                            methods.add(admit._parse_act(text, PROFILES.wire).method)
        self.assertIn(True, seen)    # the generator makes acts that are valid with their signatures
        self.assertIn(False, seen)   # and ones that are not (pending, no quorum)
        self.assertGreater(len(seen), 100)
        self.assertIn(chain.RESOLVE, methods)
        self.assertTrue(methods & chain.PRIMARIES)

    def test_a_stored_orphan_endorsement_that_completes_the_quorum_counts_in_the_view(self):
        w = World()
        step = w.device_add("alice2", AB)
        snap = snap_of(step.acts[1:], [original(w)], w.id)
        self.assertEqual(self.same(snap, step.primary.jws, []), (True, True))

    def test_a_resolve_is_judged_as_over_a_rebuilt_tree_applicable_or_not_with_stored_endorsements(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        resolve_ = w.resolve(AB, [c1, c2], c1, [c2])
        both = snap_of(c1.acts + c2.acts + resolve_.acts[1:], [original(w)], w.id)
        self.assertEqual(self.same(both, resolve_.primary.jws, []), (True, True))
        only = snap_of(c1.acts + resolve_.acts[1:], [original(w)], w.id)   # c2 is no node: not applicable
        self.assertEqual(self.same(only, resolve_.primary.jws, []), (False, False))

    def test_a_resolve_that_overrides_another_is_judged_as_over_a_rebuilt_tree(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        names = {"endorsements": sorted(a.id for a in r2.endorsements.values()), "resolve": r2.id}
        r4 = w.resolve(AB, [c1, c2], c1, [c2], overrides=[names])   # it names r2, which chose the other child
        snap = snap_of(c1.acts + c2.acts + r1.acts + r2.acts + r4.acts[1:], [original(w)], w.id)
        self.assertIsNotNone(self.same(snap, r4.primary.jws, []))

    def test_stored_garbage_twins_of_the_act_are_judged_as_over_a_rebuilt_tree(self):
        w = World()
        step = w.device_add("alice2", AB)
        for sig in (BAD, HIGH, LOW):
            snap = snap_of([with_signature(step.primary, sig).jws], [original(w)], w.id)
            got = self.same(snap, step.primary.jws, step.acts[1:])
            self.assertIsNotNone(got, sig)

    def test_a_stored_pending_twin_with_a_valid_signature_and_an_item_with_a_bad_one_are_judged_as_before(self):
        w = World()
        step = w.device_add("alice2", AB)
        item = with_signature(step.primary, BAD).jws
        snap = snap_of([step.primary.jws], [original(w)], w.id)   # pending: one person signed it
        self.assertIsNotNone(self.same(snap, item, step.acts[1:]))   # the verdict is not pinned: both ways agree
