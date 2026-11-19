"""T3.28 endorsements, possession proofs, key uniqueness, link-code reuse (FO-07, FO-08, SG-09, GP-18).

An `act.endorse` links to the act it endorses and names that act's parent as its head. A `device.add`
or `member.add` is valid only with a proof-of-possession endorsement by the new key. A new key may
equal no existing key of any epoch, and a link code is used once on a path.
"""
import random
import types
import unittest

from handsal_check import chain, encoding, endorse, envelope, errors, fold, genesis, jws, quorum, verifier
from handsal_check import state as state_module

from .act_builder import BAD, FakeVitni, build, head_of, kid_of, with_signature
from .fold_world import World, device_body, ids, link_code
from .genesis_fixtures import device, point
from .profile_sets import production_of
from .store_world import PROFILES, opened, random_store, snap_of


def quorum_of(w, step, **kw):
    return step.id in ids(w.epoch(step, **kw))


class Possession(unittest.TestCase):
    def test_a_device_add_with_the_new_keys_proof_is_valid(self):
        w = World()
        self.assertTrue(quorum_of(w, w.device_add("alice2", ("alice", "bob"))))

    def test_without_the_new_keys_endorsement_it_is_not_on_the_chain(self):
        w = World()
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob"), pop=False)))

    def test_the_proof_must_name_the_new_keys_person_as_performer(self):
        w = World()
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob"), pop_performer="bob")))

    def test_the_proof_must_verify(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"))
        bad = w.endorse("alice2", step.primary, w.id, sig=BAD)
        self.assertNotIn(step.id, ids(w.epoch(step.primary, *step.endorsements.values(), bad)))

    def test_a_proof_by_another_key_is_not_a_proof(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"), pop=False)
        other = w.endorse("carol", step.primary, w.id, performer="alice")   # carol's key, alice as performer
        self.assertNotIn(step.id, ids(w.epoch(step.primary, *step.endorsements.values(), other)))

    def test_the_proof_is_never_a_counted_signature(self):
        w = World()
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice",))))

    def test_a_member_add_needs_the_proof_too(self):
        w = World(members=(("dave", "member"),))
        self.assertTrue(quorum_of(w, w.member_add("frank", ("alice", "bob"), role="member")))
        self.assertFalse(quorum_of(w, w.member_add("frank", ("alice", "bob"), role="member", pop=False)))
        self.assertFalse(quorum_of(w, w.member_add("frank", ("alice", "bob"), role="member", pop_performer="grace")))

    def test_a_proof_signed_before_the_key_is_bound_is_still_a_signature_over_this_act(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"))
        other = w.device_add("alice2", ("alice", "bob"), label="other")   # another primary, another id
        self.assertNotEqual(step.id, other.id)
        self.assertFalse(other.id in ids(w.epoch(other.primary, *other.endorsements.values(), step.pop)))


class EndorsementRules(unittest.TestCase):
    """FO-08: parent, performer, body.act and head must all name the endorsed act and its parent."""

    def two_person_primary(self, w, **over):
        step = w.device_add("alice2", ("alice",), pop=True)
        endorsement = w.endorse("bob", step.primary, over.pop("head_parent", w.id), **over)
        return step, endorsement

    def valid(self, w, step, endorsement):
        return step.id in ids(w.epoch(step.primary, step.pop, endorsement))

    def test_a_well_formed_endorsement_counts(self):
        w = World()
        step, e = self.two_person_primary(w)
        self.assertTrue(self.valid(w, step, e))

    def test_an_endorsement_with_another_head_is_ignored(self):
        w = World()
        step, e = self.two_person_primary(w, head_parent=genesis.doc_hash(World(name="OTHER").doc))
        self.assertFalse(self.valid(w, step, e))

    def test_an_endorsement_head_of_a_later_position_does_not_count(self):
        w = World()
        other = w.device_add("bob2", ("bob", "alice"))
        step = w.device_add("alice2", ("alice",), pop=True)
        late = w.endorse("bob", step.primary, other.id)
        self.assertFalse(step.id in ids(w.epoch(other, step.primary, step.pop, late)))

    def test_a_wrong_parent_performer_is_ignored(self):
        w = World()
        step, e = self.two_person_primary(w, parent_performer="carol")
        self.assertFalse(self.valid(w, step, e))

    def test_a_body_act_that_differs_from_the_parent_is_ignored(self):
        w = World()
        step, e = self.two_person_primary(w, body={"act": w.id})
        self.assertFalse(self.valid(w, step, e))

    def test_the_head_must_be_a_chain_head(self):
        w = World()
        step, e = self.two_person_primary(w, head={"id": w.id, "kind": "merkle"})
        self.assertFalse(self.valid(w, step, e))

    def test_an_endorsement_of_an_endorsement_is_ignored(self):
        w = World()
        step = w.device_add("alice2", ("alice",), pop=True)
        e1 = w.endorse("bob", step.primary, w.id)
        e2 = w.endorse("carol", e1, step.primary.id)   # endorses the endorsement
        self.assertFalse(step.id in ids(w.epoch(step.primary, step.pop, e2)))

    def test_an_endorsement_of_an_unknown_id_is_ignored(self):
        w = World()
        step = w.device_add("alice2", ("alice",), pop=True)
        stray = build("bob", "act.endorse", org=w.id, body={"act": w.id}, parent=w.id, parent_performer=None,
                      head=head_of(w.id))
        self.assertFalse(step.id in ids(w.epoch(step.primary, step.pop, stray)))

    def test_a_valid_endorsement_is_found_among_invalid_twins(self):
        w = World()
        step, e = self.two_person_primary(w)
        from .act_builder import with_signature
        twin = with_signature(e, BAD)
        self.assertTrue(step.id in ids(w.epoch(twin.jws, step.primary, step.pop, e)))
        self.assertFalse(step.id in ids(w.epoch(twin.jws, step.primary, step.pop)))


class Uniqueness(unittest.TestCase):
    """FO-07: a new kid, sign point or agree point equals no existing key, removed included, or the relay key."""

    def test_a_kid_removed_never_returns(self):
        w = World(extra=("bob2",))
        removal = w.device_remove("bob2", ("alice", "carol"))
        again = w.device_add("bob2", ("bob", "alice"), removal)
        self.assertFalse(again.id in ids(w.epoch(removal, again)))

    def test_a_new_kid_equal_to_an_active_one_is_refused(self):
        w = World(extra=("bob2",))
        self.assertFalse(quorum_of(w, w.device_add("bob2", ("bob", "alice"))))

    def test_a_new_agree_equal_to_another_devices_agree_is_refused(self):
        w = World()
        body = device_body("alice2")
        body["agree"] = point("bob.agree")
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob"), body=body)))

    def test_a_new_agree_equal_to_another_devices_sign_is_refused(self):
        w = World()
        body = device_body("alice2")
        body["agree"] = point("bob.sign")
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob"), body=body)))

    def test_a_new_sign_equal_to_another_devices_agree_is_refused(self):
        w = World()
        body = device_body("alice2")
        body["sign"], body["kid"] = point("bob.agree"), encoding.thumbprint(*point("bob.agree").values())
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob"), body=body, pop=False)))

    def test_the_relay_key_cannot_be_introduced(self):
        from .genesis_fixtures import policy, relay_witness, KEYS
        w = World(pol=policy(witness=relay_witness()))
        key = KEYS["relay-fixture"]
        body = device_body("alice2")
        body["sign"] = {"x": key["x"], "y": key["y"]}
        body["kid"] = key["kid"]
        step = w.device_add("alice2", ("alice", "bob"), body=body, pop=False)
        self.assertFalse(quorum_of(w, step))

    def test_a_kid_of_an_earlier_epoch_cannot_return(self):
        w = World()
        earlier = fold.Earlier(frozenset({kid_of("alice2")}), frozenset(), frozenset())
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob")), earlier=earlier))
        pts = frozenset({(point("alice2.agree")["x"], point("alice2.agree")["y"])})
        earlier = fold.Earlier(frozenset(), pts, frozenset())
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob")), earlier=earlier))
        self.assertTrue(quorum_of(w, w.device_add("alice2", ("alice", "bob")), earlier=fold.NO_EARLIER))

    def test_a_kid_and_points_added_on_one_branch_are_fresh_on_a_sibling_branch(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("alice2", ("alice", "carol"), salt="sibling")   # the same keys, beside the first, not under it
        self.assertNotEqual(a.id, b.id)
        self.assertEqual(ids(w.epoch(a, b)), {w.id, a.id, b.id})
        after = w.device_add("alice2", ("alice", "bob"), a, salt="below")   # under the first: the keys are used there
        self.assertNotIn(after.id, ids(w.epoch(a, after)))

    def test_a_removed_devices_sign_point_cannot_return_as_a_new_agree_point(self):
        w = World(extra=("bob2",))
        removal = w.device_remove("bob2", ("alice", "carol"))
        body = device_body("alice2")
        body["agree"] = point("bob2.sign")
        reused = w.device_add("alice2", ("alice", "bob"), removal, body=body)
        self.assertNotIn(reused.id, ids(w.epoch(removal, reused)))
        fresh = w.device_add("alice2", ("alice", "bob"), removal)
        self.assertIn(fresh.id, ids(w.epoch(removal, fresh)))

    def test_a_sign_point_of_an_earlier_epoch_cannot_return(self):
        w = World()
        pts = frozenset({(point("alice2.sign")["x"], point("alice2.sign")["y"])})
        earlier = fold.Earlier(frozenset(), pts, frozenset())
        self.assertFalse(quorum_of(w, w.device_add("alice2", ("alice", "bob")), earlier=earlier))
        self.assertTrue(quorum_of(w, w.device_add("alice2", ("alice", "bob")), earlier=fold.NO_EARLIER))


def reference_fresh_key(epoch, state, kid, sign, agree):
    """`endorse.fresh_key` as it was: a set of every kid and point in use, built by walking the state's devices."""
    used_kids = set(state.devices) | epoch.earlier.kids
    used_points = set(epoch.earlier.points)
    for device in state.devices.values():
        used_points.update((device.sign, device.agree))
    if epoch.relay is not None:
        used_kids.add(epoch.relay[0])
        used_points.add(epoch.relay[1])
    new_points = {state_module.point(sign), state_module.point(agree)}
    return kid not in used_kids and not new_points & used_points


class FreshKeyAsBefore(unittest.TestCase):
    """FO-07: the uniqueness answer is the one of the walk over the state's devices, for every candidate at every node
    of generated stores: a candidate drawn from the node's own kids and points, from the earlier epochs and the relay
    key, from new values, and crossed (a new agree that is an old sign, a new sign that is an old agree)."""

    @staticmethod
    def candidates(node, earlier, relay, rng):
        kids = list(node.devices) + sorted(earlier.kids) + ([relay[0]] if relay else []) + ["fresh-kid"]
        points = ([p for d in node.devices.values() for p in (d.sign, d.agree)] + sorted(earlier.points)
                  + ([relay[1]] if relay else []) + [(11, 12), (13, 14)])
        obj = state_module.point_obj
        out = [(rng.choice(kids), obj(rng.choice(points)), obj(rng.choice(points))) for _ in range(40)]
        for device in node.devices.values():
            out += [("fresh-kid", obj(device.agree), obj((15, 16))), ("fresh-kid", obj((15, 16)), obj(device.sign)),
                    ("fresh-kid", obj(device.agree), obj(device.sign)), ("fresh-kid", obj((15, 16)), obj((17, 18)))]
        return out

    def test_the_answer_is_the_walks_at_every_node_of_generated_stores(self):
        asked = fresh = 0
        for seed in range(8):
            rng = random.Random(seed)
            stored = random_store(seed, production_of(PROFILES))
            for found in opened(snap_of(stored.acts, stored.docs, stored.org)).values():
                found.build()
                for node in [found.root] + list(found.nodes.values()):
                    eras = [(found.earlier, found.relay),
                            (fold.Earlier(frozenset({kid_of("alice2"), "ek"}), frozenset({(1, 2), (3, 4)}), frozenset()), None),
                            (found.earlier, ("relay-kid", (5, 6)))]
                    for earlier, relay in eras:
                        epoch = types.SimpleNamespace(earlier=earlier, relay=relay)
                        for kid, sign, agree in self.candidates(node.state, earlier, relay, rng):
                            want = reference_fresh_key(epoch, node.state, kid, sign, agree)
                            self.assertEqual(endorse.fresh_key(epoch, node.state, kid, sign, agree), want,
                                             msg=(seed, kid[:6]))
                            asked += 1
                            fresh += want
        self.assertGreater(asked, 1000)
        self.assertGreater(fresh, 100)            # the controls: some candidates are fresh,
        self.assertGreater(asked - fresh, 100)    # and some are not


class LinkCodes(unittest.TestCase):
    """SG-09: a link code hash is used once on a path; the first applies and the second is ignored."""

    def test_a_reused_code_on_a_path_is_ignored(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"), code=link_code("shared"))
        b = w.device_add("bob2", ("bob", "alice"), a, code=link_code("shared"))
        self.assertEqual(ids(w.epoch(a, b)), {w.id, a.id})

    def test_a_fresh_code_applies(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"))
        b = w.device_add("bob2", ("bob", "alice"), a)
        self.assertEqual(ids(w.epoch(a, b)), {w.id, a.id, b.id})

    def test_the_code_of_another_branch_is_not_used_here(self):
        w = World()
        a = w.device_add("alice2", ("alice", "bob"), code=link_code("shared"))
        b = w.device_add("bob2", ("bob", "alice"), code=link_code("shared"))
        self.assertEqual(ids(w.epoch(a, b)), {w.id, a.id, b.id})


class ProductionProfile(unittest.TestCase):
    """GP-18: under a production profile a fixture kid is never introduced."""

    def introduced(self, new, body_keys):
        """True iff alice's `device.add` of the device `new` is on the chain of a production epoch."""
        from handsal_check import chain, profiles, registry
        from .act_builder import memo
        from .genesis_fixtures import org as make_org
        from .p256_helper import production_device
        people = ("alice", "bob", "carol")
        devices = {p: production_device(p, p) for p in people}
        doc = make_org(production_of(profiles.load()), people=people, devices=list(devices.values()))
        root = genesis.doc_hash(doc)
        body = {"agree": new["agree"], "class": "apple-se-bio", "kid": new["kid"], "label": "phone",
                "link_code_hash": link_code("x"), "person": "alice", "sign": new["sign"]}
        primary = build("alice", "device.add", kid=devices["alice"]["kid"], org=root, body=body, parent=root)
        counted = build("bob", "act.endorse", kid=devices["bob"]["kid"], org=root, body={"act": primary.id},
                        parent=primary.id, parent_performer="alice", head=head_of(root))
        pop = build("alice", "act.endorse", kid=new["kid"], org=root, body={"act": primary.id},
                    parent=primary.id, parent_performer="alice", head=head_of(root))
        reg = registry.load()
        epoch = fold.Epoch(doc, chain.Bag([primary.jws, counted.jws, pop.jws], reg.wire, root),
                           profiles.load().resolve(production_of(profiles.load())), memo())
        epoch.build()
        return primary.id in epoch.nodes

    def test_a_production_kid_is_introduced(self):
        from .p256_helper import production_device
        self.assertTrue(self.introduced(production_device("alice2", "alice"), None))

    def test_a_fixture_kid_is_not(self):
        self.assertFalse(self.introduced(device("alice2"), None))


class Narrowed(unittest.TestCase):
    """The question about one text carries the entry of its own signer and nothing else, and vitni answers it as it
    answers the question with every key of the state: it reads `keys[performer_id][kid]` and nothing more (CONTRACT
    section 7). The checker reads that pair exactly as vitni does, so one entry is the whole question."""

    def setUp(self):
        self.w = World(extra=("bob2",))
        w = self.w
        removal = w.device_remove("bob2", ("alice", "carol"))
        step = w.device_add("alice2", ("alice", "bob"), removal)
        extra = [w.endorse("bob2", step.primary, removal.id),                                  # a revoked key
                 w.endorse("carol", step.primary, removal.id, performer="alice"),            # carol's kid, alice as performer
                 w.endorse("dave", step.primary, removal.id),                                 # a key no state holds
                 with_signature(step.endorsements["bob"], BAD),                              # a twin that does not verify
                 w.endorse("alice2", step.primary, removal.id, performer="bob")]             # the new key, another person
        self.epoch = w.epoch(removal, step, *extra)
        self.step, self.removal = step, removal

    def questions(self):
        """`(copy, method, parent node)` for every text of every primary and of every endorsement of it."""
        out = []
        for group in self.epoch.bag.groups.values():
            node = self.epoch.nodes.get(group.act.parent)
            if group.act.method not in chain.PRIMARIES or node is None:
                continue
            for item in [group] + self.epoch.bag.endorsements_of(group.act):
                out.extend((copy, item.act.method, node) for copy in item.copies)
        return out

    def test_counting_answers_the_same_for_the_whole_state_and_for_the_signers_entry(self):
        seen = set()
        for copy, method, node in self.questions():
            full = node.state.keys_map()
            narrowed = node.state.keys_for(copy.performer, copy.kid)
            got = FakeVitni().verify(copy.jws, full, method)
            self.assertEqual(FakeVitni().verify(copy.jws, narrowed, method), got)
            seen.add(got)
        self.assertEqual(seen, {"ok", "unknown_key", "revoked_key", "bad_signature"})

    def test_possession_answers_the_same_for_the_state_plus_the_new_key_and_for_the_new_entry(self):
        group = self.epoch.bag.groups[self.step.id]
        person, kid, sign = quorum.introduced(group.act)
        state = self.epoch.nodes[self.removal.id].state
        full = {owner: dict(entries) for owner, entries in state.keys_map().items()}
        full.setdefault(person, {})[kid] = verifier.key_entry(sign, "active")
        own = {person: {kid: verifier.key_entry(sign, "active")}}
        seen = set()
        for item in self.epoch.bag.endorsements_of(group.act):
            for copy in item.copies:
                narrowed = own if (copy.performer, copy.kid) == (person, kid) else state.keys_for(copy.performer, copy.kid)
                got = FakeVitni().verify(copy.jws, full, item.act.method)
                self.assertEqual(FakeVitni().verify(copy.jws, narrowed, item.act.method), got)
                seen.add(got)
        self.assertEqual(seen, {"ok", "unknown_key", "revoked_key", "bad_signature"})

    def test_the_new_key_alone_is_a_proof_and_no_counted_signature(self):
        group = self.epoch.bag.groups[self.step.id]
        person, kid, sign = quorum.introduced(group.act)
        pop, method = self.step.pop, self.epoch.bag.endorsements_of(group.act)[0].act.method
        state = self.epoch.nodes[self.removal.id].state
        self.assertEqual(FakeVitni().verify(pop.jws, {person: {kid: verifier.key_entry(sign, "active")}}, method), "ok")
        self.assertEqual(FakeVitni().verify(pop.jws, state.keys_for(pop.performer, pop.kid), method), "unknown_key")

    def header_text(self, header):
        """The act of the step with `header` (bytes) as its header: the text the checker is asked to read."""
        _, payload, signature = self.step.primary.jws.split(".")
        return ".".join((encoding.b64u_encode(header), payload, signature))

    def test_the_header_is_read_byte_exact_so_the_kid_is_the_one_vitni_reads(self):
        kid = self.step.primary.kid
        for name, header in {"whitespace": '{"alg": "ES256","kid":"%s"}' % kid,
                             "members swapped": '{"kid":"%s","alg":"ES256"}' % kid,
                             "an extra member": '{"alg":"ES256","kid":"%s","typ":"JWT"}' % kid,
                             "a 42 character kid": '{"alg":"ES256","kid":"%s"}' % kid[:42],
                             "a 44 character kid": '{"alg":"ES256","kid":"%sA"}' % kid}.items():
            with self.subTest(name), self.assertRaises(errors.Refused) as caught:
                jws.parse(self.header_text(header.encode()))
            self.assertEqual(caught.exception.code, "jws_shape")
        self.assertEqual(jws.parse(self.step.primary.jws).kid, kid)

    def test_a_payload_with_the_performer_twice_is_refused_so_the_performer_is_the_one_vitni_reads(self):
        _, payload, _ = self.step.primary.jws.split(".")
        raw = encoding.b64u_decode(payload)
        once = b'"performer_id":"alice"'
        self.assertEqual(raw.count(once), 1)
        with self.assertRaises(errors.Refused):
            envelope.parse_payload(raw.replace(once, once + b"," + once))
        envelope.parse_payload(raw)


if __name__ == "__main__":
    unittest.main()
