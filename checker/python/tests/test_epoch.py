"""T3.34 lineage and genesis changes (GP-15, GP-19, GP-20, GP-07, GP-09, FO-07).

Per document from the original, the first failure of the first failing document wins. A change is
read against the path to its head H in the epoch before it (never a full fold, so a fork there never
fails a later epoch): H must be a node, enough previous role holders whose keys are clean at H must
have signed, and carried devices must be active and unchanged.
"""
import unittest

from handsal_check import encoding, epoch, errors, genesis, verifier

from .act_builder import FakeVitni, Unavailable, genesis_sign, head_of, kid_of
from .fold_world import REG, PROFILES, World
from .genesis_fixtures import device, policy

ALL = ("alice", "bob", "carol")
BIG_PEOPLE = ("alice", "bob", "carol", "dave", "grace")
BIG_EXTRA = ("alice2", "alice3", "alice4", "bob2", "bob3", "carol2", "dave2")


def no_render(doc, previous):
    return None


def run(w, docs_and_sigs, acts=(), vitni=None, render=no_render):
    lineage = [{"doc": d, "sigs": s} for d, s in docs_and_sigs]
    texts = [t for item in acts for t in (item.acts if hasattr(item, "acts") else [item.jws])]
    return epoch.fold_lineage(lineage, texts, REG, PROFILES, True, vitni or FakeVitni(), render)


def code(w, docs_and_sigs, **kw):
    try:
        run(w, docs_and_sigs, **kw)
    except errors.Refused as err:
        return err.code
    return None


def original(w):
    return w.doc, w.sigs(w.doc, ALL)


class Original(unittest.TestCase):
    def test_a_signed_original_folds(self):
        w = World()
        epochs = run(w, [original(w)])
        self.assertEqual(len(epochs), 1)
        self.assertEqual(epochs[0].root.id, w.id)

    def test_an_unsigned_device_is_genesis_unsigned(self):
        w = World()
        self.assertEqual(code(w, [(w.doc, w.sigs(w.doc, ("alice", "bob")))]), "genesis_unsigned")

    def test_junk_and_unlisted_signatures_are_ignored(self):
        w = World()
        self.assertIsNone(code(w, [(w.doc, w.sigs(w.doc, ALL + ("dave",)) + ["junk"])]))

    def test_the_verifier_being_down_is_not_a_fold_of_nothing(self):
        w = World()
        with self.assertRaises(verifier.VerifierUnavailable):
            run(w, [original(w)], vitni=Unavailable())

    def test_the_render_size_step_is_asked_for_every_document_before_possession(self):
        w = World()
        seen = []
        run(w, [original(w)], render=lambda doc, previous: seen.append((doc, previous)))
        self.assertEqual(seen, [(w.doc, None)])
        # an unsigned original that is also too large reports the size first (GP-15 steps 5 then 6)

        def too_large(doc, previous):
            raise errors.Refused("genesis_render_too_large")
        self.assertEqual(code(w, [(w.doc, [])], render=too_large), "genesis_render_too_large")

    def test_the_default_render_size_step_is_the_genesis_render(self):
        w = World()
        epoch.fold_lineage([{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}], [], REG, PROFILES, True, FakeVitni())
        big = World(people=BIG_PEOPLE, extra=BIG_EXTRA)   # 12 devices: the signed render is 74 lines
        with self.assertRaises(errors.Refused) as ctx:
            epoch.fold_lineage([{"doc": big.doc, "sigs": []}], [], REG, PROFILES, True, FakeVitni())
        self.assertEqual(ctx.exception.code, "genesis_render_too_large")


class Order(unittest.TestCase):
    """GP-15: structure, profile, policy, links, size, possession, then the change steps, per document."""

    def test_structure_before_possession(self):
        w = World()
        broken = dict(w.doc, name="x" * 25)
        self.assertEqual(code(w, [(broken, [])]), "genesis_schema")

    def test_the_first_failing_document_wins_even_if_a_later_one_fails_earlier_in_the_order(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        bad_later = w.change_doc(tip.id)
        bad_later["name"] = "x" * 25   # genesis_schema in document 1; document 0 is merely unsigned
        self.assertEqual(code(w, [(w.doc, []), (bad_later, [])]), "genesis_unsigned")

    def test_lineage_broken_before_unsigned(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        doc["prev"] = encoding.hashstr(b"not the previous document")
        self.assertEqual(code(w, [original(w), (doc, [])], acts=[tip]), "lineage_broken")

    def test_unsigned_before_head_unknown(self):
        w = World()
        doc = w.change_doc(genesis.doc_hash(World(name="OTHER").doc))
        self.assertEqual(code(w, [original(w), (doc, [])]), "genesis_unsigned")

    def test_head_unknown_before_unauthorized(self):
        w = World()
        other = genesis.doc_hash(World(name="OTHER").doc)
        doc = w.change_doc(other, people=("alice", "frank", "grace"))
        self.assertEqual(code(w, [original(w), (doc, w.sigs(doc, ("alice", "frank", "grace")))]),
                         "genesis_head_unknown")


class ChangeAuthority(unittest.TestCase):
    def two_epochs(self, doc, names=ALL, **kw):
        w = kw.pop("w")
        return [original(w), (doc, w.sigs(doc, names))]

    def test_two_of_three_at_the_tip_is_authorized(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        epochs = run(w, self.two_epochs(doc, w=w), acts=[tip])
        self.assertEqual([e.root.id for e in epochs], [w.id, genesis.doc_hash(doc)])

    def test_the_head_may_be_the_root(self):
        w = World()
        doc = w.change_doc(w.id)
        self.assertIsNone(code(w, self.two_epochs(doc, w=w)))

    def test_one_counted_person_is_not_enough(self):
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace"))
        self.assertEqual(code(w, [original(w), (doc, sigs)]), "genesis_change_unauthorized")

    def test_an_unlisted_clean_role_holder_counts(self):
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace", "bob"))
        self.assertIsNone(code(w, [original(w), (doc, sigs)]))

    def test_a_full_key_rotation_is_authorized_by_old_keys(self):
        w = World()
        new = [device("alice2", label="phone"), device("bob2", label="phone"), device("carol2", label="phone")]
        doc = w.change_doc(w.id, devices=new)
        sigs = w.sigs(doc, ("alice2", "bob2", "carol2", "alice", "bob"))
        self.assertIsNone(code(w, [original(w), (doc, sigs)]))

    def test_a_full_rotation_with_no_old_key_signing_is_unauthorized(self):
        w = World()
        new = [device("alice2", label="phone"), device("bob2", label="phone"), device("carol2", label="phone")]
        doc = w.change_doc(w.id, devices=new)
        self.assertEqual(code(w, [original(w), (doc, w.sigs(doc, ("alice2", "bob2", "carol2")))]),
                         "genesis_change_unauthorized")

    def test_a_signature_naming_another_head_does_not_count_for_possession_or_authority(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        wrong = [genesis_sign(n, doc, w.id, head=head_of(w.id)).jws for n in ALL]
        self.assertEqual(code(w, [original(w), (doc, wrong)], acts=[tip]), "genesis_unsigned")

    def test_an_unlisted_signature_naming_another_head_does_not_count(self):
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace"))
        sigs.append(genesis_sign("bob", doc, w.id, head=head_of(genesis.doc_hash(World(name="O").doc))).jws)
        self.assertEqual(code(w, [original(w), (doc, sigs)]), "genesis_change_unauthorized")

    def test_the_performer_must_be_the_persons_in_the_state_at_h(self):
        w = World()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace")) + [genesis_sign("bob", doc, w.id, performer="carol").jws]
        self.assertEqual(code(w, [original(w), (doc, sigs)]), "genesis_change_unauthorized")

    def test_a_signer_who_holds_no_listed_role_in_the_old_policy_does_not_count(self):
        w = World(extra=("dave",), members=(("dave", "member"),))
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        sigs = w.sigs(doc, ("alice", "frank", "grace", "dave"))
        self.assertEqual(code(w, [(w.doc, w.sigs(w.doc, ALL + ("dave",))), (doc, sigs)]), "genesis_change_unauthorized")

    def test_a_role_holder_whose_class_the_policy_does_not_accept_does_not_count(self):
        """GP-19 and KC-04: acceptance is half of clean(k, H). Registry version 1 has one `biometric_only`
        class, so no vector can build a role holder of an unaccepted class (CF-07); the epoch is built
        directly, with alice's device in the fixture-only class that the policy does not list."""
        w = World()
        w.doc["devices"] = [dict(d, **{"class": "fixture-pin"}) if d["person"] == "alice" else d for d in w.doc["devices"]]
        w.id = w.org = genesis.doc_hash(w.doc)
        previous = w.epoch()
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))
        node = previous.nodes[w.id]

        def counted(names):
            return epoch._authorized(doc, w.sigs(doc, names), node, previous, w.id, REG, FakeVitni())
        # control: the unaccepted holder's signature is a good one, and bob's counts: two persons would be enough
        self.assertTrue(counted(("bob", "carol")))
        self.assertFalse(counted(("alice", "bob")))
        self.assertFalse(counted(("alice",)))


class Cleanliness(unittest.TestCase):
    """GP-19: the signing key must be active and accepted in the state at H, nothing after or beside H is read."""

    def world(self):
        w = World()
        r1 = w.device_remove("alice", ("bob", "carol"))                 # alice's key is removed at position 1
        r2 = w.device_add("bob2", ("bob", "carol"), r1)                  # position 2
        return w, r1, r2

    def test_a_key_removed_before_h_does_not_count(self):
        w, r1, r2 = self.world()
        doc = w.change_doc(r2.id, people=("bob", "frank", "grace"))
        sigs = w.sigs(doc, ("bob", "frank", "grace", "alice"))
        self.assertEqual(code(w, [original(w), (doc, sigs)], acts=[r1, r2]), "genesis_change_unauthorized")

    def test_a_key_removed_after_h_still_counts(self):
        w, r1, r2 = self.world()
        doc = w.change_doc(w.id)
        self.assertIsNone(code(w, [original(w), (doc, w.sigs(doc, ALL))], acts=[r1, r2]))

    def test_h_on_a_side_branch_reads_that_branch_only(self):
        w, r1, r2 = self.world()
        side = w.device_add("carol2", ("carol", "bob"))                  # a sibling of r1 at the root
        doc = w.change_doc(side.id)
        self.assertIsNone(code(w, [original(w), (doc, w.sigs(doc, ALL))], acts=[r1, r2, side]))

    def test_a_fork_in_the_previous_epoch_does_not_fail_the_change(self):
        w, r1, r2 = self.world()
        side = w.device_add("carol2", ("carol", "bob"))
        doc = w.change_doc(r1.id, people=("bob", "carol", "frank"), devices=[device("bob"), device("carol"), device("frank")])
        sigs = w.sigs(doc, ("bob", "carol", "frank"))
        self.assertIsNone(code(w, [original(w), (doc, sigs)], acts=[r1, side]))


class Carried(unittest.TestCase):
    """GP-20: a carried device is active at H, never removed in an earlier closing state, and unchanged."""

    def test_a_carried_device_must_be_active_at_h(self):
        w = World(extra=("bob2",))
        r = w.device_remove("bob2", ("alice", "carol"))
        doc = w.change_doc(r.id, people=("alice", "bob", "carol"),
                           devices=[device("alice"), device("bob"), device("bob2"), device("carol")])
        sigs = w.sigs(doc, ("alice", "bob", "bob2", "carol"))
        base = w.doc, w.sigs(w.doc, ALL + ("bob2",))
        self.assertEqual(code(w, [base, (doc, sigs)], acts=[r]), "genesis_device_revoked")

    def test_a_device_removed_after_h_is_carried(self):
        w = World(extra=("bob2",))
        r = w.device_remove("bob2", ("alice", "carol"))
        doc = w.change_doc(w.id, devices=[device("alice"), device("bob"), device("bob2"), device("carol")])
        sigs = w.sigs(doc, ("alice", "bob", "bob2", "carol"))
        self.assertIsNone(code(w, [(w.doc, w.sigs(w.doc, ALL + ("bob2",))), (doc, sigs)], acts=[r]))

    def test_a_carried_entry_must_be_byte_identical(self):
        w = World()
        doc = w.change_doc(w.id, devices=[device("alice", label="renamed"), device("bob"), device("carol")])
        self.assertEqual(code(w, [original(w), (doc, w.sigs(doc, ALL))]), "genesis_device_changed")

    def test_a_carried_kid_under_another_person_is_changed(self):
        w = World()
        doc = w.change_doc(w.id, devices=[device("alice2", label="phone"), device("alice", person="bob"),
                                          device("bob"), device("carol")])
        sigs = w.sigs(doc, ("alice2", "bob", "carol")) + [genesis_sign("alice", doc, w.id, performer="bob").jws]
        self.assertEqual(code(w, [original(w), (doc, sigs)]), "genesis_device_changed")

    def test_revoked_is_reported_before_changed(self):
        w = World(extra=("bob2",))
        r = w.device_remove("bob2", ("alice", "carol"))
        doc = w.change_doc(r.id, devices=[device("alice", label="renamed"), device("bob"), device("bob2"), device("carol")])
        sigs = w.sigs(doc, ("alice", "bob", "bob2", "carol"))
        self.assertEqual(code(w, [(w.doc, w.sigs(w.doc, ALL + ("bob2",))), (doc, sigs)], acts=[r]),
                         "genesis_device_revoked")

    def test_a_kid_removed_in_an_earlier_epoch_cannot_return_two_changes_later(self):
        w = World(extra=("bob2",))
        r = w.device_remove("bob2", ("alice", "carol"))
        doc1 = w.change_doc(r.id, name="ONE")
        doc2 = w.change_doc(w.id, name="TWO", devices=[device("alice"), device("bob"), device("bob2"), device("carol")],
                            prev=doc1)
        doc2["head"] = genesis.doc_hash(doc1)
        sigs1 = w.sigs(doc1, ALL)
        sigs2 = [genesis_sign(n, doc2, w.id).jws for n in ("alice", "bob", "bob2", "carol")]
        self.assertEqual(code(w, [(w.doc, w.sigs(w.doc, ALL + ("bob2",))), (doc1, sigs1), (doc2, sigs2)], acts=[r]),
                         "genesis_device_revoked")


class Epochs(unittest.TestCase):
    def test_the_last_epoch_is_the_fold_and_each_epoch_roots_at_its_document(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        epochs = run(w, [original(w), (doc, w.sigs(doc, ALL))], acts=[tip])
        self.assertEqual(len(epochs), 2)
        epochs[0].build()
        self.assertIn(tip.id, epochs[0].nodes)
        epochs[1].build()
        self.assertEqual(set(epochs[1].nodes), {genesis.doc_hash(doc)})

    def test_acts_of_the_old_epoch_are_not_read_by_the_new_one(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        epochs = run(w, [original(w), (doc, w.sigs(doc, ALL))], acts=[tip])
        epochs[1].build()
        self.assertNotIn(tip.id, epochs[1].nodes)

    def test_a_key_of_an_earlier_epoch_cannot_be_introduced_again(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        epochs = run(w, [original(w), (doc, w.sigs(doc, ALL))], acts=[tip])
        self.assertIn(kid_of("alice2"), epochs[1].earlier.kids)
        self.assertEqual({"alice", "bob", "carol"}, set(epochs[1].earlier.members))


if __name__ == "__main__":
    unittest.main()
