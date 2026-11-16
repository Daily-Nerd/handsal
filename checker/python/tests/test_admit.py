"""CF-11 `admit`: may one item enter the chain store of an organization (RS5 to RS9, section 20.3).

Every act of the tests carries a stand-in signature (`act_builder`) and `FakeVitni` answers like vitni would. The
rule is "valid now": a pending primary, a lone endorsement and a lone `genesis.sign` are never admitted, and the
answer names the signatures to keep, one per kid, so the caller encodes no rule.
"""
import pathlib
import re
import unittest

from handsal_check import admit, encoding, epoch, errors, genesis, quorum, registry, render_genesis, profiles, retain

from .act_builder import BAD, HIGH, FakeVitni, Unavailable, build, with_signature
from .checkact_world import Scenario
from .fold_world import World
from .genesis_fixtures import policy
from .store_world import later_world, retained_of, snap_of

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
    return admit.run(inp, PROFILES, allow_fixture, vitni or FakeVitni(), render_genesis.render_size)


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
