"""ORG4 and the lineage helpers (catalog-part3 ORG4: a fourth maintainer `erin`)."""
import json
import unittest

from lib import base, chain, epochs, inputs

FX = base.Fixtures(base.fixture_profile())


class Org4(unittest.TestCase):
    def setUp(self):
        self.doc = epochs.org4(FX)

    def test_it_is_org_plus_a_fourth_maintainer_and_is_a_valid_document(self):
        self.assertEqual(base.check_genesis_shape(self.doc), [])
        self.assertEqual([m["id"] for m in self.doc["members"]], ["alice", "bob", "carol", "erin"])
        self.assertTrue(all(m["role"] == "maintainer" for m in self.doc["members"]))
        erin = [d for d in self.doc["devices"] if d["person"] == "erin"]
        self.assertEqual(len(erin), 1)
        self.assertEqual(erin[0]["class"], "apple-se-bio")
        self.assertEqual(erin[0]["kid"], FX.key("erin").kid)

    def test_the_rest_of_the_document_is_orgs(self):
        a, b = dict(self.doc), dict(FX.org)
        for k in ("devices", "members"):
            a.pop(k), b.pop(k)
        a["policy"] = {k: v for k, v in a["policy"].items() if k != "rules"}
        b["policy"] = {k: v for k, v in b["policy"].items() if k != "rules"}
        self.assertEqual(a, b)

    def test_persons_defaults_to_three_for_every_rule_with_a_spare(self):
        rules = self.doc["policy"]["rules"]
        self.assertEqual({r["persons"] for r in rules.values()}, {"3"})
        self.assertEqual(epochs.org4(FX, persons="2")["policy"]["rules"]["chain.resolve"]["persons"],
                         "2")

    def test_an_edit_applies_to_the_document(self):
        doc = epochs.org4(FX, edit=lambda d: d["policy"]["rules"]["device.remove"].update(
            persons="2"))
        self.assertEqual(doc["policy"]["rules"]["device.remove"]["persons"], "2")
        self.assertEqual(doc["policy"]["rules"]["member.add"]["persons"], "3")

    def test_erin_is_the_same_key_each_time_it_is_asked_for(self):
        self.assertEqual(epochs.org4(FX), epochs.org4(FX))
        self.assertEqual(FX.person_of_kid(FX.key("erin").kid), "erin")


class OriginalChain(unittest.TestCase):
    def test_a_chain_over_org4_roots_at_its_document_hash(self):
        doc = epochs.org4(FX)
        c = epochs.original_chain(FX, doc)
        self.assertIsInstance(c, chain.Chain)
        self.assertEqual(c.root, inputs.doc_id(doc))
        self.assertEqual(c.fold_input()["org"], inputs.doc_id(doc))
        self.assertEqual(len(c.lineage), 1)
        self.assertEqual(len(c.lineage[0]["sigs"]), 4)  # one genesis.sign per listed device


class Changes(unittest.TestCase):
    """CHG-NEW and CHG-VALID documents and their genesis.sign sets (catalog-part3 section 0)."""

    def setUp(self):
        self.original = FX.org

    def test_a_change_carries_the_named_persons_devices_byte_identical_plus_new_maintainers(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice",))
        self.assertEqual(base.check_genesis_shape(doc), [])
        self.assertEqual((doc["org"], doc["prev"], doc["head"]),
                         (FX.org_id, FX.org_id, FX.org_id))
        self.assertEqual([m["id"] for m in doc["members"]], ["alice", "frank", "grace"])
        by_kid = {d["kid"]: d for d in doc["devices"]}
        alice = FX.device_entry("alice")
        self.assertEqual(by_kid[alice["kid"]], [d for d in self.original["devices"]
                                                if d["kid"] == alice["kid"]][0])
        self.assertEqual({d["person"] for d in doc["devices"]}, {"alice", "frank", "grace"})
        self.assertEqual(doc["policy"], self.original["policy"])

    def test_carry_two_persons_and_one_new_maintainer(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice", "bob"),
                                 new=("grace",))
        self.assertEqual([m["id"] for m in doc["members"]], ["alice", "bob", "grace"])
        self.assertEqual(base.check_genesis_shape(doc), [])

    def test_the_carried_devices_come_from_the_state_at_h(self):
        c = chain.Chain(FX)
        c.device_add("alice2", ("alice", "bob"))
        doc = epochs.make_change(FX, self.original, c.tip.id, carry=("alice",), st=c.state,
                                 new=("frank", "grace"))
        kids = {d["kid"] for d in doc["devices"] if d["person"] == "alice"}
        self.assertEqual(kids, {FX.key("alice").kid, FX.key("alice2").kid})

    def test_a_removed_device_is_not_carried_by_default_and_can_be_forced(self):
        c = chain.Chain(FX)
        c.device_add("bob2", ("alice", "bob"))
        c.device_remove("bob2", ("alice", "carol"))
        doc = epochs.make_change(FX, self.original, c.tip.id, carry=("bob",), st=c.state)
        self.assertNotIn(FX.key("bob2").kid, {d["kid"] for d in doc["devices"]})
        forced = epochs.make_change(FX, self.original, c.tip.id, carry=("bob",), st=c.state,
                                    include_removed=True)
        self.assertIn(FX.key("bob2").kid, {d["kid"] for d in forced["devices"]})

    def test_edit_runs_last_and_heidi_is_a_registered_new_maintainer(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice",),
                                 new=("grace", "heidi"), edit=lambda d: d.update(name="renamed"))
        self.assertEqual(doc["name"], "renamed")
        self.assertIn("heidi", [m["id"] for m in doc["members"]])

    def test_every_listed_device_signs_with_the_head_and_extras_sign_unlisted(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice",))
        sigs = epochs.sign_change(FX, doc, also=["carol"])
        who = [json.loads(base._unb64u(s.split(".")[0]))["kid"] for s in sigs]
        listed = [d["kid"] for d in doc["devices"]]
        self.assertEqual(sorted(who[:-1]), sorted(listed))
        self.assertEqual(who[-1], FX.key("carol").kid)
        for s in sigs:
            act = json.loads(base._unb64u(s.split(".")[1]))["ext"]["dev.handsal/act"]
            self.assertEqual(act["head"], {"id": doc["head"], "kind": "chain"})

    def test_skip_drops_a_listed_signer_and_also_takes_overrides(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice",))
        sigs = epochs.sign_change(FX, doc, skip=["grace"],
                                  also=[("carol", {"performer": "alice"})])
        pers = [json.loads(base._unb64u(s.split(".")[1]))["performer_id"] for s in sigs]
        self.assertEqual(sorted(pers), ["alice", "alice", "frank"])

    def test_the_lineage_appends_the_document_with_its_signatures(self):
        doc = epochs.make_change(FX, self.original, FX.org_id, carry=("alice",))
        sigs = epochs.sign_change(FX, doc)
        lineage = epochs.lineage_with(FX.lineage(), doc, sigs)
        self.assertEqual(len(lineage), 2)
        self.assertEqual(lineage[1], {"doc": doc, "sigs": sigs})
        self.assertEqual(lineage[0], FX.lineage()[0])


if __name__ == "__main__":
    unittest.main()
