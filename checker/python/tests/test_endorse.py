"""T3.28 endorsements, possession proofs, key uniqueness, link-code reuse (FO-07, FO-08, SG-09, GP-18).

An `act.endorse` links to the act it endorses and names that act's parent as its head. A `device.add`
or `member.add` is valid only with a proof-of-possession endorsement by the new key. A new key may
equal no existing key of any epoch, and a link code is used once on a path.
"""
import unittest

from handsal_check import encoding, fold, genesis

from .act_builder import BAD, build, head_of, kid_of
from .fold_world import World, device_body, ids, link_code
from .genesis_fixtures import device, point
from .profile_sets import production_of


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
        from .act_builder import FakeVitni
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
                           profiles.load().resolve(production_of(profiles.load())), FakeVitni())
        epoch.build()
        return primary.id in epoch.nodes

    def test_a_production_kid_is_introduced(self):
        from .p256_helper import production_device
        self.assertTrue(self.introduced(production_device("alice2", "alice"), None))

    def test_a_fixture_kid_is_not(self):
        self.assertFalse(self.introduced(device("alice2"), None))


if __name__ == "__main__":
    unittest.main()
