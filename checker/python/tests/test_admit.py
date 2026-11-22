"""CF-11 `admit`: may one item enter the chain store of an organization (RS5 to RS9, section 20.3).

Every act of the tests carries a stand-in signature (`act_builder`) and `FakeVitni` answers like vitni would. The
rule is "valid now": a pending primary, a lone endorsement and a lone `genesis.sign` are never admitted, and the
answer names the signatures to keep, one per kid, so the caller encodes no rule.
"""
import pathlib
import re
import unittest
from unittest import mock

from handsal_check import admit, chain, encoding, epoch, errors, fold, genesis, quorum, registry, render_genesis, profiles, resolve, retain, snapshot

from . import old_retain
from .adm_world import Adm, item_of, written_by
from .act_builder import BAD, HIGH, Act, FakeVitni, Unavailable, build, memo, with_signature
from .checkact_world import Scenario
from .device_reads import DeviceReads
from .fold_world import World
from .genesis_fixtures import policy
from .profile_sets import fixture_of, production_of
from .linear_world import acts_of, chain as linear_chain, top
from .store_world import PRODUCTION_ONLY, Counting, after, later_world, opened, random_store, retained_of, snap_of

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
        for name in ("def _kept(", "def _kept_receipts(", "authority_person(", "endorse.verified(", "possession(",
                     "_smallest_valid", '{"act": parsed.jws'):
            self.assertNotIn(name, source, name)
        for name in ("kept_act", "kept_endorsements", "kept_receipts", "read_endorsements", "read_receipts", "retained"):
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
        self.assertIsNone(re.search(r"\b(?:quorum|epoch|fold|tree|endorse|retain)\._\w+", source))
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

    def test_the_capacity_is_that_of_the_texts_admit_answers_not_of_the_texts_the_item_carries(self):   # RS9
        w = World()
        step = w.device_add("alice2", AB)
        bob = step.endorsements["bob"]
        twin = with_signature(bob, LOW).jws   # the larger twin of a stored endorsement: the answer leaves it out
        item = {"act": step.primary.jws, "sigs": [twin, step.pop.jws]}
        limit = MAX_INPUT - 2 * RESERVE

        def sizes(pad):
            stored = snap_of([bob.jws, pad], [original(w)], w.id)
            out = [step.primary.jws, step.pop.jws]   # what admit answers: the item's texts the retained set keeps
            return stored, snapshot.canonical_size(stored, extra_acts=out), snapshot.canonical_size(stored, extra_acts=out + [twin])

        fill = limit - sizes("x")[1] + 1   # the answer's size lands exactly on the limit
        stored, answered, carried = sizes("x" * fill)
        self.assertEqual(answered, limit)
        self.assertGreater(carried, limit)   # the item's own texts would not fit
        got = go(w, item, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertNotIn(twin, got["store"]["sigs"])
        self.assertEqual(snapshot.canonical_size(stored, extra_acts=[got["store"]["act"]] + got["store"]["sigs"]), limit)


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

    def test_an_admit_never_asks_a_question_whose_keys_are_empty(self):
        """vitni answers `unknown_key` to empty keys (CONTRACT section 7 step 3, or an earlier refusal), never `ok`, so
        the answer is known without asking: the new key's proof of possession is asked once, with the new key."""
        w = World()
        below = linear_chain(w, 5)
        item = top(w, below)
        vitni = FakeVitni()
        got = go(w, {"act": item.primary.jws, "sigs": item.acts[1:]}, acts=acts_of(below), vitni=vitni)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual([keys for _, keys, _ in vitni.calls if keys == "{}"], [])

    def test_the_questions_of_an_admit_are_three_per_step_and_six_more(self):
        self.assertEqual((self.calls(0), self.calls(5), self.calls(10)), (6, 21, 36))   # 3N + 6

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

    def test_a_stored_orphan_endorsement_costs_the_questions_the_item_would_bring(self):
        self.assertEqual((self.orphan_calls(0), self.orphan_calls(5), self.orphan_calls(10)), (6, 21, 36))   # 3N + 6


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

    def test_a_document_admit_folds_its_path_once(self):
        """A change reads the tree of the document it follows, and opening the store folded the stored path already, so
        admitting a change over a stored change builds the trees of the path once each (v0.4.2 folded the path a second
        time: the original and the first change built twice)."""
        w = World()
        first = w.change_doc(w.id, name="ONE")
        second = w.change_doc(genesis.doc_hash(first), name="TWO", prev=first)
        docs = [original(w), {"doc": first, "sigs": w.sigs(first, ALL)}]
        got, built = self.real_builds(w, {"doc": second, "sigs": w.sigs(second, ALL)}, docs=docs)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(built, [w.id, genesis.doc_hash(first)])

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


    def test_a_stored_twin_costs_at_most_one_question_per_stored_copy_of_the_receipt_id(self):
        w = World()
        step = w.device_add("alice2", AB)
        item = {"act": with_signature(step.primary, BAD).jws, "sigs": step.acts[1:]}

        def questions(acts):
            counted = Counting()
            go(w, item, acts=acts, vitni=counted)
            return counted.calls
        self.assertLessEqual(questions([step.primary.jws]) - questions([]), 1)   # the one stored copy of the act


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
    read again into a tree of its own. A resolve is valid when it is applicable there and every one of its entries
    is effective there."""
    full = old_retain.over(base, texts)
    full.build()
    if parsed.method in chain.PRIMARIES:
        return parsed.id in full.nodes
    judge = resolve.Resolves(full)
    found = judge.applicable(full.bag.groups[parsed.id], full.nodes[parent.id])
    return found is not None and judge._effective(found) == {entry["resolve"] for entry in admit._entries(parsed)}


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
    the signatures are of one kid, or a named text is missing from the item or does not count)."""
    parsed = admit._parse_act(text, wire)
    located = located_in(snap, parsed)
    if located is None or admit._stored(*located, parsed):
        return None
    base, parent = located
    try:
        kept = retain.kept_endorsements(base, parent, parsed, admit._endorsements(base, parsed, sigs))
        named, evidence = admit._counted(base, parsed, admit._evidence(base, parsed, sigs))
    except errors.Refused:   # refused before the judgment
        return None
    return (rebuilt_valid(base, parent, parsed, list(snap.acts) + [parsed.jws] + kept + evidence),
            admit._judged(base, parent, parsed, kept, named, evidence) is not None)


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

    def test_a_resolve_that_overrides_another_is_judged_as_over_a_rebuilt_tree_when_every_entry_is_effective(self):
        w = World()
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        r1 = w.resolve(("bob", "carol"), [c1, c2], c1, [c2])
        r2 = w.resolve(("alice", "carol"), [c1, c2], c2, [c1])
        names = {"endorsements": sorted(a.id for a in r2.endorsements.values()), "resolve": r2.id}
        r4 = w.resolve(AB, [c1, c2], c1, [c2], overrides=[names])   # it names r2, which chose the other child
        snap = snap_of(c1.acts + c2.acts + r1.acts + r2.acts + r4.acts[1:], [original(w)], w.id)
        evidence = [a.jws for a in r2.endorsements.values()]
        self.assertEqual(self.same(snap, r4.primary.jws, evidence), (True, True))
        self.assertIsNone(self.same(snap, r4.primary.jws, []))   # the text must come from the item

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


class InvalidTwinOfAStoredAct(unittest.TestCase):
    def test_an_item_whose_own_signature_is_invalid_is_not_stored_beside_a_valid_pending_twin(self):
        w = World()
        step = w.device_add("alice2", AB)
        stored = snap_of([step.primary.jws], [original(w)], w.id)   # pending: one person signed it, valid signature
        item = with_signature(step.primary, BAD).jws   # same receipt id, its own signature does not verify
        got = go(w, {"act": item, "sigs": step.acts[1:]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        texts = [got["store"]["act"]] + got["store"]["sigs"]
        grown = snap_of(list(stored.acts) + texts, [original(w)], w.id)
        self.assertEqual(set(texts) - set(retained_of(grown).acts), set())

    def test_the_bad_twin_answer_is_the_stored_copy(self):
        w = World()
        step = w.device_add("alice2", AB)
        stored = snap_of([step.primary.jws], [original(w)], w.id)
        got = go(w, {"act": with_signature(step.primary, BAD).jws, "sigs": step.acts[1:]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["store"]["act"], step.primary.jws)

    def test_the_stored_valid_copy_stays_retained_after_an_invalid_twin_is_admitted(self):
        w = World()
        step = w.device_add("alice2", AB)
        stored = snap_of([step.primary.jws], [original(w)], w.id)
        got = go(w, {"act": with_signature(step.primary, BAD).jws, "sigs": step.acts[1:]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        grown = snap_of(list(stored.acts) + [got["store"]["act"]] + got["store"]["sigs"], [original(w)], w.id)
        self.assertIn(step.primary.jws, retained_of(grown).acts)   # the act never loses its only valid copy

    def test_a_valid_twin_larger_than_the_stored_valid_copy_is_answered_with_the_stored_copy(self):
        w = World()
        step = w.device_add("alice2", AB)
        stored = snap_of([step.primary.jws], [original(w)], w.id)
        twin = with_signature(step.primary, LOW).jws   # valid, and larger in byte order than the stored copy
        got = go(w, {"act": twin, "sigs": step.acts[1:]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["store"]["act"], step.primary.jws)
        texts = [got["store"]["act"]] + got["store"]["sigs"]
        grown = snap_of(list(stored.acts) + texts, [original(w)], w.id)
        self.assertEqual(set(texts) - set(retained_of(grown).acts), set())

    def test_a_valid_twin_smaller_than_the_stored_copy_is_answered_with_its_own_text(self):
        w = World()
        step = w.device_add("alice2", AB)
        low = with_signature(step.primary, LOW).jws
        stored = snap_of([low], [original(w)], w.id)   # pending, and larger than the item's copy
        got = go(w, {"act": step.primary.jws, "sigs": step.acts[1:]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["store"]["act"], step.primary.jws)

    def test_an_endorsement_twin_of_a_stored_smaller_endorsement_is_not_in_the_output(self):
        w = World()
        step = w.device_add("alice2", AB)
        bob = step.endorsements["bob"]
        stored = snap_of([bob.jws], [original(w)], w.id)   # an orphan endorsement, the smaller twin of one receipt id
        twin = with_signature(bob, LOW).jws
        got = go(w, {"act": step.primary.jws, "sigs": [twin, step.pop.jws]}, acts=stored.acts)
        self.assertEqual(got["reason"], "ok")
        self.assertNotIn(twin, got["store"]["sigs"])
        texts = [got["store"]["act"]] + got["store"]["sigs"]
        grown = snap_of(list(stored.acts) + texts, [original(w)], w.id)
        self.assertEqual(set(texts) - set(retained_of(grown).acts), set())


def run_admit(snap, item):
    """The answer of `admit` for `item` over the store `snap`, production documents only (the stores of the generator)."""
    inp = admit.parse_input({"acts": list(snap.acts), "docs": list(snap.docs), "item": item, "org": snap.org})
    return admit.run(inp, PRODUCTION_ONLY, True, memo(), render_genesis.render_size)


def twin_of(text, sig):
    """`text` with another signature: a twin of one receipt id."""
    return with_signature(Act(text, None, None, None), sig).jws


class AdmittedTextsAreRetained(unittest.TestCase):
    """I8 over every store shape: each text admit answers `ok` for is in the retained set of the store grown by the
    answer, and where the store was already consistent with that set the answer is the item and its kept signatures."""

    SEEDS = range(8)

    def legacy(self, snap, text, sigs):
        """`(act, kept signatures)` as admit answered before the retained set owned the choice, or None."""
        parsed = admit._parse_act(text, PROFILES.wire)
        located = located_in(snap, parsed)
        if located is None:
            return None
        try:
            return text, retain.kept_endorsements(*located, parsed, admit._endorsements(located[0], parsed, sigs))
        except errors.Refused:
            return None

    def check(self, snap, text, sigs, tally):
        """Admit `text` with `sigs` over `snap`; assert the invariant when it answers ok; count what it met."""
        got = run_admit(snap, {"act": text, "sigs": list(sigs)})
        if got["reason"] != "ok":
            return
        out = got["store"]
        texts = {out["act"], *out["sigs"]}
        grown = snap_of(list(snap.acts) + sorted(texts), snap.docs, snap.org)
        old = self.legacy(snap, text, sigs)
        wide = snap_of(list(snap.acts) + [old[0]] + old[1], snap.docs, snap.org)
        consistent = {old[0], *old[1]} <= set(retained_of(wide).acts)
        tally.append(consistent)
        self.assertEqual(texts - set(retained_of(grown).acts), set())          # (a) nothing it admits is dropped
        self.assertTrue(texts - set(snap.acts))                                # (b) it adds something
        if consistent:                                                         # (c) no byte change where consistent
            self.assertEqual(out, {"act": old[0], "sigs": old[1]})

    def variants(self, snap, text):
        """`(store, act text, sigs)` readings of one act of the store with twins injected: the act's endorsements
        moved to the item, the act itself stored beside an item twin, and an endorsement stored beside its twin."""
        without = after(snap, acts_gone=[text])
        moved = endorsements_stored(without, text)
        yield without, text, []
        yield without, text, list(without.acts)
        yield after(without, acts_gone=moved), text, moved
        for sig in (BAD, LOW):
            yield snap_of(list(without.acts) + [twin_of(text, sig)], without.docs, snap.org), text, moved
            yield after(snap, acts_gone=moved), twin_of(text, sig), moved   # the pending act stored, its twin offered
        for one in moved:
            rest = [other for other in moved if other != one]
            yield after(without, acts_gone=rest), text, rest + [twin_of(one, LOW)]   # `one` stored, its twin offered
            yield without, text, rest + [twin_of(one, LOW)]

    def test_every_text_admit_stores_is_kept_by_the_retained_set_of_the_grown_store(self):
        tally = []
        for seed in self.SEEDS:
            stored = random_store(seed, production_of(PROFILES))
            snap = snap_of(stored.acts, stored.docs, stored.org)
            for text in snap.acts:
                try:
                    admit._parse_act(text, PROFILES.wire)
                except errors.Refused:
                    continue
                for number, (store, item, sigs) in enumerate(self.variants(snap, text)):
                    with self.subTest(seed=seed, text=text[-12:], variant=number):
                        self.check(store, item, sigs, tally)
        self.assertIn(True, tally)    # the generator makes answers where the store was consistent
        self.assertIn(False, tally)   # and ones where the old answer is dropped by the retained set

    def test_the_view_keeps_the_texts_of_a_tree_built_again(self):
        kept = 0
        for seed in self.SEEDS:
            stored = random_store(seed, production_of(PROFILES))
            snap = snap_of(stored.acts, stored.docs, stored.org)
            for text in snap.acts:
                try:
                    parsed = admit._parse_act(text, PROFILES.wire)
                except errors.Refused:
                    continue
                without = after(snap, acts_gone=[text])
                moved = endorsements_stored(without, text)
                for store, sigs in ((without, []), (after(without, acts_gone=moved), moved)):
                    located = located_in(store, parsed)
                    if located is None or admit._stored(*located, parsed):
                        continue
                    base, parent = located
                    try:
                        offered = retain.kept_endorsements(base, parent, parsed, admit._endorsements(base, parsed, sigs))
                    except errors.Refused:
                        continue
                    if not rebuilt_valid(base, parent, parsed, list(store.acts) + [parsed.jws] + offered):
                        continue
                    with self.subTest(seed=seed, text=text[-12:]):
                        view = base.sharing_tree(self.texts_of(base, parsed) + [parsed.jws] + offered)
                        full = old_retain.over(base, list(store.acts) + [parsed.jws] + offered)
                        full.build()
                        self.assertEqual(retain.kept_act(view, view.bag.groups[parsed.id], parent),
                                         retain.kept_act(full, full.bag.groups[parsed.id], full.nodes[parent.id]))
                        kept += 1
        self.assertGreater(kept, 20)

    def texts_of(self, base, parsed):
        stored = [base.bag.groups.get(parsed.id)] + base.bag.endorsements_of(parsed)
        return [copy.jws for group in stored if group is not None for copy in group.copies]


class ResolveWorld(unittest.TestCase):
    """What the fold answers over the resolve world, with and without the evidence an `overrides` entry names. These
    answers are the premise of the admission rules below: they hold on the last release and must keep holding."""

    def test_a_resolve_that_names_its_evidence_is_effective_and_its_choice_wins(self):
        a = Adm()
        acts = a.c1.acts + a.c2.acts + a.r1.acts + a.s.acts + [a.e_alice.jws]
        self.assertEqual(a.answer(acts), ("chain", ["c2"]))

    def test_the_first_resolve_alone_chooses_its_child(self):
        a = Adm()
        self.assertEqual(a.answer(a.c1.acts + a.c2.acts + a.r1.acts), ("chain", ["c1"]))

    def test_the_same_resolve_without_the_evidence_text_has_no_effect_and_overrules_nothing(self):
        a = Adm()
        acts = a.c1.acts + a.c2.acts + a.r1.acts + a.s.acts
        self.assertEqual(a.answer(acts), ("fork", ["c1", "c2"]))   # neither resolve is current: the fork stays

    def test_an_entry_whose_evidence_cannot_complete_the_resolve_never_takes_effect(self):
        a = Adm()
        weak = a.over([(a.r1, [a.e_bob])], "weak")
        acts = a.c1.acts + a.c2.acts + a.r1.acts + weak.acts + [a.e_bob.jws]
        self.assertEqual(a.answer(acts), ("fork", ["c1", "c2"]))


class NamedResolvesAreStored(unittest.TestCase):
    """CF-11, the `parent_unknown` slot: a resolve is admitted only after every resolve its `overrides` name is in the
    store, so no order of offers leaves a resolve whose meaning needs a text the store never got."""

    def test_a_resolve_naming_a_resolve_the_store_lacks_is_parent_unknown(self):
        a = Adm()
        store, _ = a.stored(*a.base())
        self.assertEqual(a.reason(store, item_of(a.s, a.e_alice.jws)), "parent_unknown")

    def test_the_resolve_offered_before_the_one_it_names_is_refused_then_admitted_after_it(self):
        a = Adm()
        offers = a.base() + [item_of(a.s, a.e_alice.jws), a.minimal(a.r1), item_of(a.s, a.e_alice.jws)]
        _, reasons = a.stored(*offers)
        self.assertEqual(reasons, ["ok", "ok", "parent_unknown", "ok", "ok"])

    def test_two_entries_the_first_of_which_is_not_stored_are_parent_unknown_whatever_the_second_is(self):
        a = Adm()
        r2 = a.resolve_at_root("r2")
        e2_bob = a.w.endorse("bob", r2.primary, r2.parent_id, salt="bob-self")   # a text that cannot complete r2
        store, _ = a.stored(*a.base(), a.minimal(r2))
        both = a.over([(a.r1, [a.e_alice]), (r2, [e2_bob])], "two")
        self.assertEqual(a.reason(store, item_of(both, a.e_alice.jws, e2_bob.jws)), "parent_unknown")
        self.assertEqual(a.reason(store, item_of(both)), "parent_unknown")   # before any evidence is looked at

    def test_a_named_resolve_that_is_only_a_string_of_the_store_is_parent_unknown(self):
        a = Adm()
        pending = a.w.resolve(("bob",), [a.c1, a.c2], a.c1, [a.c2], salt="pending")   # one person: not applicable
        e_pending = a.w.endorse("alice", pending.primary, pending.parent_id)
        store, _ = a.stored(*a.base())
        named = a.over([(pending, [e_pending])], "named-pending")
        self.assertEqual(a.reason(store + pending.acts, item_of(named, e_pending.jws)), "parent_unknown")


class Evidence(unittest.TestCase):
    """CF-11, carriage: the texts an `overrides` entry names come from the item, one text per named receipt id, and a
    text no entry names and no endorsement of the act asks nothing of the verifier and is never stored."""

    def twins(self, act, count):
        """`count` more low-S texts of the receipt id of `act`: twins, the same unit under another signature."""
        return [with_signature(act, bytes([i + 1]) * 64).jws for i in range(count)]

    def asked(self, a, store, item):
        """`(answer, texts of the item that reached the verifier)`."""
        vitni = FakeVitni()
        got = a.admit(store, item, vitni)
        sent = {call[0] for call in vitni.calls}
        return got, sent & set(item["sigs"])

    def stored_world(self, a, *with_text):
        store, reasons = a.stored(*a.base(), item_of(a.r1, *with_text))
        self.assertEqual(reasons, ["ok"] * 3)
        return store

    def test_forty_eight_texts_of_one_named_id_are_kid_repeated_before_any_is_verified(self):
        a = Adm()
        store = self.stored_world(a)
        crowd = self.twins(a.e_alice, 48)
        got, sent = self.asked(a, store, item_of(a.s, a.e_alice.jws, *crowd))
        self.assertEqual(got, {"reason": "kid_repeated", "store": None})
        self.assertEqual(sent, set())

    def test_two_texts_of_one_kid_with_distinct_named_ids_are_both_kept(self):
        a = Adm()
        second = a.w.endorse("alice", a.r1.primary, a.r1.parent_id, salt="second")
        both = a.over([(a.r1, [a.e_alice, second])], "both")
        store = self.stored_world(a)
        got = a.admit(store, item_of(both, a.e_alice.jws, second.jws))
        self.assertEqual(got["reason"], "ok")
        self.assertTrue({a.e_alice.jws, second.jws} <= set(got["store"]["sigs"]))

    def test_unnamed_texts_are_neither_verified_nor_stored(self):
        a = Adm()
        store = self.stored_world(a)
        unnamed = [a.w.endorse("alice", a.r1.primary, a.r1.parent_id, salt="u%d" % i).jws for i in range(300)]
        got, sent = self.asked(a, store, item_of(a.s, a.e_alice.jws, *unnamed))
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(sent & set(unnamed), set())
        self.assertEqual(set(got["store"]["sigs"]) & set(unnamed), set())

    def test_a_named_text_missing_from_the_item_is_evidence_missing_though_the_store_holds_it(self):
        a = Adm()
        store = self.stored_world(a, a.e_alice.jws)
        self.assertIn(a.e_alice.jws, store)
        self.assertEqual(a.reason(store, item_of(a.s)), "evidence_missing")

    def test_a_named_text_held_by_neither_the_item_nor_the_store_is_evidence_missing(self):
        a = Adm()
        self.assertEqual(a.reason(self.stored_world(a), item_of(a.s)), "evidence_missing")

    def test_two_entries_one_without_its_text_and_one_that_cannot_complete_are_evidence_missing_in_either_order(self):
        a = Adm()
        r2 = a.resolve_at_root("r2")
        e2_alice = a.w.endorse("alice", r2.primary, r2.parent_id)
        e2_bob = a.w.endorse("bob", r2.primary, r2.parent_id, salt="bob-self")
        store, _ = a.stored(*a.base(), a.minimal(a.r1), a.minimal(r2))
        absent_first = a.over([(a.r1, [a.e_alice]), (r2, [e2_bob])], "t1")
        absent_second = a.over([(a.r1, [a.e_bob]), (r2, [e2_alice])], "t2")
        self.assertEqual(a.reason(store, item_of(absent_first, e2_bob.jws)), "evidence_missing")
        self.assertEqual(a.reason(store, item_of(absent_second, a.e_bob.jws)), "evidence_missing")

    def test_a_garbage_text_of_the_named_id_alone_is_act_not_valid_and_with_the_valid_text_kid_repeated(self):
        a = Adm()
        store = self.stored_world(a)
        garbage = with_signature(a.e_alice, BAD).jws
        self.assertEqual(a.reason(store, item_of(a.s, garbage)), "act_not_valid")
        self.assertEqual(a.reason(store, item_of(a.s, garbage, a.e_alice.jws)), "kid_repeated")


class StrictClosure(unittest.TestCase):
    """CF-11: a resolve is admitted only when every `overrides` entry is effective over the store plus the item, with
    the evidence from the item. So the store of any order of offers is the same store, and the fold answers the same."""

    def five(self, a):
        """The offers of the world: both children, the first resolve bare and with its text, the second with its."""
        return [item_of(a.c1), item_of(a.c2), a.minimal(a.r1), item_of(a.r1, a.e_alice.jws), item_of(a.s, a.e_alice.jws)]

    def test_every_order_of_the_offers_gives_one_store_and_the_second_resolve_wins(self):
        a = Adm()
        found = a.every_order(self.five(a))
        self.assertEqual(sum(found.values()), 120)
        self.assertEqual(len(found), 1)   # one store and one answer, in all 120 orders
        (answer, _), = found
        self.assertEqual(answer, ("chain", ("c2",)))

    def test_with_the_evidence_left_bare_the_stores_differ_by_order_which_is_what_the_closure_removes(self):
        a = Adm()   # the control: the same orders, the second resolve never carries the text, R1 may or may not
        found = a.every_order(self.five(a)[:4] + [item_of(a.s)])
        self.assertEqual(sum(found.values()), 120)
        self.assertEqual({(a.e_alice.jws in store) for _, store in found}, {True, False})   # two stores
    def test_a_zero_key_attack_at_two_relays_in_different_orders_gives_one_answer(self):
        a = Adm()
        x, _ = a.stored(*a.base(), a.minimal(a.r1), item_of(a.r1, a.e_alice.jws), item_of(a.s, a.e_alice.jws))
        y, _ = a.stored(*a.base(), item_of(a.r1, a.e_alice.jws), item_of(a.s, a.e_alice.jws))
        self.assertEqual(a.answer(x), ("chain", ["c2"]))
        self.assertEqual(a.answer(y), ("chain", ["c2"]))
        self.assertEqual(x, y)

    def test_a_resolve_carrying_its_evidence_over_the_stored_resolve_is_ok_and_the_store_holds_the_text(self):
        a = Adm()
        store, _ = a.stored(*a.base(), a.minimal(a.r1))
        got = a.admit(store, item_of(a.s, a.e_alice.jws))
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["store"]["act"], a.s.primary.jws)
        self.assertIn(a.e_alice.jws, got["store"]["sigs"])
        self.assertEqual(sorted(got["store"]["sigs"]), sorted(a.s.acts[1:] + [a.e_alice.jws]))

    def stored_r1(self, a):
        store, _ = a.stored(*a.base(), a.minimal(a.r1))
        return store

    def test_a_resolve_naming_a_primary_is_act_not_valid(self):
        a = Adm()
        names_c1 = a.over([(a.c1, [a.e_alice])], "names-c1")   # c1 is a node: publishing cannot fix it
        self.assertEqual(a.reason(self.stored_r1(a), item_of(names_c1, a.e_alice.jws)), "act_not_valid")

    def test_a_resolve_naming_a_resolve_of_another_parent_is_act_not_valid(self):
        a = Adm()
        d1 = a.w.device_add("bob2", AB, a.c2)
        d2 = a.w.device_add("carol2", ("alice", "carol"), a.c2)
        below = a.w.resolve(("bob", "carol"), [d1, d2], d1, [d2], parent=a.c2)
        e_below = a.w.endorse("alice", below.primary, a.c2.id)
        store, reasons = a.stored(*a.base(), a.minimal(a.r1), item_of(d1), item_of(d2), item_of(below))
        self.assertEqual(reasons, ["ok"] * 6)
        named = a.over([(below, [e_below])], "names-below")
        self.assertEqual(a.reason(store, item_of(named, e_below.jws)), "act_not_valid")

    def test_a_resolve_naming_a_resolve_of_another_epoch_is_act_not_valid(self):
        a = Adm()
        w = a.w
        change = w.change_doc(a.c1.id)                          # closes the first epoch at c1
        docs = a.docs + [{"doc": change, "sigs": w.sigs(change, ALL)}]
        later = later_world(w, change)
        d1 = later.device_add("bob2", AB)
        d2 = later.device_add("carol2", ("alice", "carol"))
        far = later.resolve(AB, [d1, d2], d1, [d2], overrides=[{"endorsements": [a.e_alice.id], "resolve": a.r1.id}],
                            salt="far")
        acts = a.c1.acts + a.c2.acts + a.r1.acts + d1.acts + d2.acts
        item = item_of(far, a.e_alice.jws)
        inp = admit.parse_input({"acts": acts, "docs": docs, "item": item, "org": w.id})
        got = admit.run(inp, PROFILES, True, memo(), render_genesis.render_size)
        self.assertEqual(got["reason"], "act_not_valid")   # r1 is no node of the epoch of the resolve: not effective

    def test_a_named_text_by_a_key_that_is_not_in_the_state_at_the_named_resolves_parent_is_act_not_valid(self):
        a = Adm()
        outside = a.w.endorse("alice2", a.r1.primary, a.r1.parent_id)   # alice2 is added at c1, below the parent
        named = a.over([(a.r1, [outside])], "outside")
        self.assertEqual(a.reason(self.stored_r1(a), item_of(named, outside.jws)), "act_not_valid")

    def test_a_text_with_the_named_id_that_endorses_nothing_of_the_resolve_is_act_not_valid(self):
        a = Adm()
        wrong = a.w.endorse("alice", a.r1.primary, a.r1.parent_id, head={"id": a.c1.id, "kind": "chain"}, salt="wrong")
        named = a.over([(a.r1, [wrong])], "wrong-head")
        self.assertEqual(a.reason(self.stored_r1(a), item_of(named, wrong.jws)), "act_not_valid")

    def test_every_named_text_present_and_too_few_persons_is_act_not_valid_and_the_same_without_the_entry_ok(self):
        a = Adm()
        weak = a.over([(a.r1, [a.e_bob])], "weak")   # bob signed r1: the entry cannot reach two persons
        store = self.stored_r1(a)
        self.assertEqual(a.reason(store, item_of(weak, a.e_bob.jws)), "act_not_valid")
        plain = a.w.resolve(AB, [a.c1, a.c2], a.c2, [a.c1], salt="weak")   # the same freeze, no entry
        self.assertEqual(a.reason(store, item_of(plain)), "ok")


class EvidenceBound(unittest.TestCase):
    """CF-11, the bound with `overrides`: the verifier is asked, for the item's texts, once per key of the state at the
    parent and the new key, and once per named receipt id (at most 16 entries of 15 ids); and, to judge each named
    resolve over the store, the questions of that resolve's own group: its primary and every endorsement the store
    holds for it. Questions are counted at the verifier, one for each distinct (text, keys, method)."""

    NAMED, EACH = 16, 15

    def world(self, extra_stored=0, unnamed=0):
        """`(adm, store, item, kinds)`: the resolves named by one resolve, each with its evidence, and the labels of
        the texts: evidence of the item, the stored texts of the named resolves, the item's own two texts."""
        a = Adm()
        named = [a.resolve_at_root("r%02d" % i) for i in range(self.NAMED)]
        evidence = {r.id: [a.w.endorse("alice", r.primary, r.parent_id, salt="e%02d-%02d" % (i, j))
                           for j in range(self.EACH)] for i, r in enumerate(named)}
        more = [a.w.endorse("alice", r.primary, r.parent_id, salt="m%02d-%02d" % (i, j))
                for i, r in enumerate(named) for j in range(extra_stored)]
        crowd = [a.w.endorse("alice", r.primary, r.parent_id, salt="u%02d-%02d" % (i, j)).jws
                 for i, r in enumerate(named) for j in range(unnamed)]
        big = a.over([(r, evidence[r.id]) for r in named], "worst")
        store = a.c1.acts + a.c2.acts + [text for r in named for text in r.acts] + [e.jws for e in more]
        texts = [e.jws for r in named for e in evidence[r.id]]
        item = item_of(big, *texts, *crowd)
        kinds = {"evidence": set(texts), "judging": {text for r in named for text in r.acts} | {e.jws for e in more},
                 "own": set(big.acts)}
        return a, store, item, kinds

    def asked(self, a, store, item, kinds):
        vitni = FakeVitni()
        got = a.admit(store, item, vitni)
        found = {call for call in vitni.calls}
        by_kind = {kind: len({call for call in found if call[0] in texts}) for kind, texts in kinds.items()}
        by_kind["store"] = len(found) - sum(by_kind.values())
        return got, len(found), by_kind

    def test_the_worst_evidence_resolve_asks_283_questions(self):
        a, store, item, kinds = self.world()
        got, total, by_kind = self.asked(a, store, item, kinds)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(by_kind, {"store": 9, "own": 2, "evidence": 240, "judging": 32})
        self.assertEqual(total, 283)

    def test_an_ordinary_call_over_the_same_store_asks_eleven(self):
        a, store, _, _ = self.world()
        plain = a.w.resolve(AB, [a.c1, a.c2], a.c2, [a.c1], salt="plain")
        vitni = FakeVitni()
        self.assertEqual(a.admit(store, item_of(plain), vitni)["reason"], "ok")
        self.assertEqual(len(set(vitni.calls)), 11)

    def test_texts_no_entry_names_add_no_question(self):
        a, store, item, kinds = self.world(unnamed=20)
        self.assertEqual(self.asked(a, store, item, kinds)[1], 283)

    def test_judging_a_named_resolve_asks_for_every_endorsement_the_store_holds_for_it(self):
        """The third term is bounded by the store, as the store checks are, not by two questions for each named
        resolve: 15 more stored endorsements on each of the 16 add 240 questions, and nothing else changes."""
        a, store, item, kinds = self.world(extra_stored=15)
        got, total, by_kind = self.asked(a, store, item, kinds)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(by_kind, {"store": 9, "own": 2, "evidence": 240, "judging": 16 * (1 + 1 + 15)})
        self.assertEqual(total, 283 + 16 * 15)


class LegacyStores(unittest.TestCase):
    """CF-11, stores written before the closure: a stored act is never judged again, so a resolve stored with no
    evidence stays as stored; its text comes in only with a new resolve that names it and carries it. The same
    answers hold on a store the last two releases wrote."""

    TAGS = ("v0.4.1", "v0.4.2")

    def legacy(self, a):
        """The store of the world as an older admit wrote it: both children, R1 bare, S bare, S naming e_alice."""
        store, reasons = a.stored(*a.base(), a.minimal(a.r1))
        return sorted(set(store) | set(a.s.acts))

    def check(self, a, store):
        self.assertEqual(a.answer(store), ("fork", ["c1", "c2"]))   # S is stored and not effective: nothing is chosen
        for label, item in (("S bare", item_of(a.s)), ("S with its text", item_of(a.s, a.e_alice.jws)),
                            ("R1 with the text", item_of(a.r1, a.e_alice.jws))):
            with self.subTest(label):
                self.assertEqual(a.reason(store, item), "already_stored")
        again = a.over([(a.r1, [a.e_alice])], "again")
        got = a.admit(store, item_of(again, a.e_alice.jws))
        self.assertEqual(got["reason"], "ok")
        grown = sorted(set(store) | {got["store"]["act"], *got["store"]["sigs"]})
        self.assertEqual(a.answer(grown), ("chain", ["c2"]))   # the text now in the bag makes the stored S effective too
        self.assertEqual(a.reason(store, item_of(again)), "evidence_missing")   # carried with it, or not at all

    def test_a_store_with_a_resolve_that_has_no_evidence_keeps_it_and_a_new_resolve_brings_the_text(self):
        a = Adm()
        self.check(a, self.legacy(a))

    def test_the_same_answers_hold_on_a_store_each_of_the_last_two_releases_wrote(self):
        a = Adm()
        for tag in self.TAGS:
            with self.subTest(tag):
                store, reasons = written_by(tag, a, *a.base(), a.minimal(a.r1), a.minimal(a.s))
                self.assertEqual(reasons, ["ok"] * 4)   # the release admits the resolve bare: that is the legacy store
                self.check(a, store)


class ConcurrentAdmits(unittest.TestCase):
    """CF-11, calls judged against one snapshot and written together: the store is the union of answers judged
    alone, and validity is monotone, so each admitted act is valid in the union and the retained set of the union
    keeps it. What only a serialized caller holds is one text for a receipt id."""

    def alone(self, a, store, *items):
        """The strings each of `items` adds when it is judged alone over `store`, all of them ok."""
        found = []
        for item in items:
            got = a.admit(store, item)
            self.assertEqual(got["reason"], "ok")
            found.append({got["store"]["act"], *got["store"]["sigs"]})
        return found

    def test_two_items_judged_alone_are_valid_together(self):
        a = Adm()
        store, _ = a.stored(*a.base(), a.minimal(a.r1))
        second = a.resolve_at_root("second")
        first_item, second_item = item_of(a.s, a.e_alice.jws), a.minimal(second)
        first, other = self.alone(a, store, first_item, second_item)
        union = sorted(set(store) | first | other)
        sequential, reasons = a.stored(*a.base(), a.minimal(a.r1), first_item, second_item)
        self.assertEqual(reasons, ["ok"] * 5)
        self.assertEqual(union, sequential)   # for acts that do not share a receipt id the order is not in the store
        for item in (first_item, second_item):
            self.assertEqual(a.reason(union, item), "already_stored")   # each is a valid act of the union
        kept = retained_of(snap_of(union, a.docs, a.w.id)).acts
        self.assertEqual((first | other) - kept, set())   # and the retained set of the union keeps every text
        self.assertEqual(a.answer(union), a.answer(sequential))

    def test_two_twins_judged_alone_are_both_valid_and_the_retained_set_keeps_one_text(self):
        a = Adm()
        store, _ = a.stored(*a.base(), a.minimal(a.r1))
        twin = {"act": twin_of(a.s.primary.jws, LOW), "sigs": a.s.acts[1:] + [a.e_alice.jws]}
        first, other = self.alone(a, store, item_of(a.s, a.e_alice.jws), twin)
        union = sorted(set(store) | first | other)
        self.assertEqual(a.answer(union), ("chain", ["c2"]))
        kept = retained_of(snap_of(union, a.docs, a.w.id)).acts
        self.assertEqual(len((first | other) & kept & {a.s.primary.jws, twin["act"]}), 1)   # one JWS per receipt id
        for item in (item_of(a.s, a.e_alice.jws), twin):
            self.assertEqual(a.reason(union, item), "already_stored")
