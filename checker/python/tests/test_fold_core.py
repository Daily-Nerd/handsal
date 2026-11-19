"""T3.27 fold core: chain recovery, link rules, prefix-state evaluation, ignored acts (FO-04 to FO-06,
FO-15, FO-21).

The act tree of an epoch is the root plus every chain primary that is valid against the state at its
parent. A failing act is ignored, never an error. Order comes from parent links, never from array
position.
"""
import json
import random
import unittest

from handsal_check import encoding, errors, jws, verifier

from .act_builder import BAD, HIGH, GOOD, FakeVitni, Unavailable, build, kid_of, with_signature
from .fold_world import World, device_body, ids
from .genesis_fixtures import point


def first(world, name="alice2", signers=("alice", "bob"), **kw):
    return world.device_add(name, signers, **kw)


class Recovery(unittest.TestCase):
    def test_a_valid_primary_becomes_a_child_of_the_root(self):
        w = World()
        step = first(w)
        e = w.epoch(step)
        self.assertEqual(ids(e), {w.id, step.id})
        node = e.nodes[step.id]
        self.assertIs(node.parent, e.root)
        self.assertEqual(node.n, 1)
        self.assertEqual(e.root.n, 0)
        self.assertEqual(e.root.id, w.id)
        self.assertEqual(e.root.children, [node])

    def test_the_root_state_is_the_document(self):
        w = World()
        state = w.epoch().root.state
        self.assertEqual(set(state.members), {"alice", "bob", "carol"})
        self.assertEqual(len(state.devices), 3)
        self.assertTrue(all(d.status == "active" and d.accepted for d in state.devices.values()))

    def test_the_applied_primary_changes_the_state_and_the_parent_keeps_its_own(self):
        w = World()
        step = first(w)
        e = w.epoch(step)
        self.assertIn(kid_of("alice2"), e.nodes[step.id].state.devices)
        self.assertNotIn(kid_of("alice2"), e.root.state.devices)

    def test_order_comes_from_parent_links_not_array_position(self):
        w = World()
        a = first(w)
        b = w.device_add("bob2", ("bob", "alice"), a)
        c = w.device_add("carol2", ("carol", "alice"), b)
        acts = a.acts + b.acts + c.acts
        for seed in range(5):
            random.Random(seed).shuffle(acts)
            e = w.epoch(*acts)
            self.assertEqual(ids(e), {w.id, a.id, b.id, c.id})
            self.assertEqual([e.nodes[i].n for i in (a.id, b.id, c.id)], [1, 2, 3])

    def test_a_dangling_parent_is_not_on_the_chain(self):
        w = World()
        a = first(w)
        b = w.device_add("bob2", ("bob", "alice"), a)
        self.assertEqual(ids(w.epoch(b)), {w.id})

    def test_a_chain_primary_never_reaches_the_tree_through_an_invalid_parent(self):
        w = World()
        a = w.device_add("alice2", ("alice",), None)   # one signer: invalid
        b = w.device_add("bob2", ("bob", "alice"), a)
        self.assertEqual(ids(w.epoch(a, b)), {w.id})


class LinkRules(unittest.TestCase):
    """FO-04: parent_performer_id is null at the root and the parent's performer elsewhere."""

    def test_a_root_child_with_a_parent_performer_is_off_the_chain(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"), parent_performer="carol")
        self.assertEqual(ids(w.epoch(step)), {w.id})

    def test_a_null_parent_performer_at_a_non_root_parent_is_off_the_chain(self):
        w = World()
        a = first(w)
        step = w.device_add("bob2", ("bob", "alice"), a, parent_performer=None)
        self.assertEqual(ids(w.epoch(a, step)), {w.id, a.id})

    def test_a_wrong_parent_performer_is_off_the_chain(self):
        w = World()
        a = first(w)
        step = w.device_add("bob2", ("bob", "alice"), a, parent_performer="carol")
        self.assertEqual(ids(w.epoch(a, step)), {w.id, a.id})

    def test_the_right_parent_performer_links(self):
        w = World()
        a = first(w)
        step = w.device_add("bob2", ("bob", "alice"), a)
        self.assertIn(step.id, ids(w.epoch(a, step)))


class PrefixState(unittest.TestCase):
    """FO-05: each act is verified against the state at its parent, so a removal only affects later positions."""

    def world(self):
        w = World(extra=("bob2",))
        removal = w.device_remove("bob2", ("bob", "alice"))
        return w, removal

    def test_a_removed_key_cannot_authorize_a_later_primary(self):
        w, removal = self.world()
        late = w.device_add("alice2", ("bob2", "alice"), removal)
        self.assertNotIn(late.id, ids(w.epoch(removal, late)))

    def test_the_same_key_still_signs_at_an_older_parent(self):
        w, removal = self.world()
        early = w.device_add("alice2", ("bob2", "alice"))
        e = w.epoch(removal, early)
        self.assertEqual(ids(e), {w.id, removal.id, early.id})

    def test_a_removed_device_keeps_its_entry(self):
        w, removal = self.world()
        e = w.epoch(removal)
        self.assertEqual(e.nodes[removal.id].state.devices[kid_of("bob2")].status, "removed")


class IgnoredNotErrors(unittest.TestCase):
    def test_junk_appended_changes_nothing(self):
        w = World()
        step = first(w)
        clean = w.epoch(step)
        junk = [build("alice", "device.add", org=w.id, body=device_body("X1"), parent=w.id, salt=str(i), sig=BAD).jws
                for i in range(100)] + ["junk", "a.b.c", ""]
        dirty = w.epoch(*step.acts, *junk)
        self.assertEqual(ids(dirty), ids(clean))

    def test_a_forged_signature_is_ignored(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"), sig=BAD)
        self.assertEqual(ids(w.epoch(step)), {w.id})

    def test_non_lifecycle_acts_are_never_on_the_chain(self):
        w = World()
        verdict = build("alice", "request.approve", org=w.id, body={}, head={"id": w.id, "kind": "chain"},
                        extra={"expires": "2026-01-01T01:00:00Z", "recipient": "alice", "relay": "relay.example",
                               "request_id": "request-0001"})
        decision = build("alice", "decision", org=w.id,
                         body={"action": "ratify ruling", "consumer": "notes", "subject": "ruling-0001"},
                         head={"id": w.id, "kind": "chain"}, extra={"expires": "2026-01-01T01:00:00Z"})
        sign = build("alice", "genesis.sign", org=w.id, body={})
        vitni = FakeVitni()
        e = w.epoch(verdict, decision, sign, vitni=vitni)
        self.assertEqual(ids(e), {w.id})
        self.assertEqual(vitni.calls, [])

    def test_a_body_that_breaks_its_schema_is_ignored(self):
        w = World()
        body = device_body("alice2")
        del body["link_code_hash"]
        self.assertEqual(ids(w.epoch(w.device_add("alice2", ("alice", "bob"), body=body))), {w.id})

    def test_a_non_empty_inputs_hash_is_ignored(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"), inputs_hash=w.id)
        self.assertEqual(ids(w.epoch(step)), {w.id})


class OneOrganization(unittest.TestCase):
    """A chain act counts in the fold of an organization only if its signed `org` is that organization: the
    fold, the one owner, ignores the others (FO-06), anchored or not."""

    def test_a_primary_of_another_org_at_a_node_of_ours_is_ignored(self):
        w = World()
        other = World(name="OTHER")
        foreign = w.device_add("alice2", ("alice", "bob"), org=other.id)
        self.assertEqual(ids(w.epoch(foreign)), {w.id})

    def test_the_same_primary_of_our_org_is_a_node(self):   # control: only `org` differs
        w = World()
        step = w.device_add("alice2", ("alice", "bob"))
        self.assertIn(step.id, ids(w.epoch(step)))

    def test_an_endorsement_of_another_org_does_not_count(self):
        w = World()
        other = World(name="OTHER")
        step = w.device_add("alice2", ("alice",))
        foreign = w.endorse("bob", step.primary, w.id, org=other.id)
        self.assertEqual(ids(w.epoch(step, foreign.jws)), {w.id})
        own = w.endorse("bob", step.primary, w.id)
        self.assertIn(step.id, ids(w.epoch(step, own.jws)))

    def test_a_resolve_of_another_org_is_not_applicable(self):
        w = World()
        other = World(name="OTHER")
        a, f = w.device_add("alice2", ("alice", "bob")), w.device_add("alice3", ("alice", "carol"))
        resolve = w.resolve(("alice", "bob"), [a, f], a, [f], org=other.id)
        e = w.epoch(a, f, resolve)
        self.assertEqual([g.act.id for g in e.bag.acts_at(w.id)], sorted((a.id, f.id)))


class VerifyBeforeDedup(unittest.TestCase):
    """FO-21: among texts of one receipt id only valid ones count, whatever their place."""

    def test_a_garbage_twin_listed_first_does_not_shadow(self):
        w = World()
        step = first(w)
        twin = with_signature(step.primary, BAD)
        e = w.epoch(twin.jws, *step.acts)
        self.assertIn(step.id, ids(e))
        e2 = w.epoch(*step.acts, twin.jws)
        self.assertEqual(ids(e), ids(e2))

    def test_a_garbage_twin_alone_is_nothing(self):
        w = World()
        step = first(w)
        twin = with_signature(step.primary, BAD)
        self.assertNotIn(step.id, ids(w.epoch(twin.jws, *[a for a in step.acts[1:]])))

    def test_a_valid_act_listed_twice_is_one_node(self):
        w = World()
        step = first(w)
        e = w.epoch(*step.acts, *step.acts)
        self.assertEqual(len(e.nodes), 2)

    def test_a_high_s_twin_does_not_count_but_a_low_s_one_does(self):
        w = World()
        step = first(w)
        high = with_signature(step.primary, HIGH)
        self.assertNotIn(step.id, ids(w.epoch(high.jws, *step.acts[1:])))
        self.assertIn(step.id, ids(w.epoch(high.jws, *step.acts)))


class WhatVitniIsAsked(unittest.TestCase):
    def asked(self, w, *items):
        """`(vitni, [(jws, keys object, method)])`: every question of the fold of `items`."""
        vitni = FakeVitni()
        e = w.epoch(*items, vitni=vitni)
        return e, [(jws_text, json.loads(keys), method) for jws_text, keys, method in vitni.calls]

    def test_the_method_is_pinned_and_each_question_carries_the_signers_entry_of_the_parent(self):
        w = World()
        a = first(w)
        b = w.device_add("bob2", ("bob", "alice"), a)
        e, asked = self.asked(w, a, b)
        want = e.nodes[a.id].state.keys_for(b.primary.performer, b.primary.kid)
        self.assertEqual(len(want[b.primary.performer]), 1)
        self.assertIn((b.primary.jws, want, "local:handsal.device.add"), asked)
        self.assertTrue(all(m.startswith("local:handsal.") for _, _, m in asked))

    def test_every_question_carries_at_most_one_entry_and_it_is_the_one_of_its_own_signer(self):
        w = World()
        a = first(w)
        b = w.device_add("bob2", ("bob", "alice"), a)
        _, asked = self.asked(w, a, b)
        self.assertGreater(len(asked), 4)
        for text, keys, _ in asked:
            _, payload, _ = text.split(".")
            kid = jws.parse(text).kid
            performer = json.loads(encoding.b64u_decode(payload))["performer_id"]
            self.assertLessEqual(sum(len(entries) for entries in keys.values()), 1)
            self.assertTrue(set(keys) <= {performer} and all(set(entries) <= {kid} for entries in keys.values()))

    def test_the_possession_question_carries_the_new_key_and_nothing_else(self):
        w = World()
        a = first(w)
        b = w.device_add("bob2", ("bob", "alice"), a)
        _, asked = self.asked(w, a, b)
        new = {"bob": {kid_of("bob2"): verifier.key_entry(point("bob2.sign"), "active")}}
        self.assertIn((b.pop.jws, new, "local:handsal.act.endorse"), asked)
        self.assertIn((b.pop.jws, {}, "local:handsal.act.endorse"), asked)   # counting: the new key is no key of the state

    def test_each_question_is_asked_once(self):
        w = World()
        step = first(w)
        vitni = FakeVitni()
        w.epoch(*step.acts, *step.acts, vitni=vitni)
        self.assertEqual(len(vitni.calls), len(set(vitni.calls)))

    def test_a_verifier_that_cannot_answer_is_an_error_not_an_ignored_act(self):
        w = World()
        with self.assertRaises(verifier.VerifierUnavailable):
            w.epoch(first(w), vitni=Unavailable())


if __name__ == "__main__":
    unittest.main()
