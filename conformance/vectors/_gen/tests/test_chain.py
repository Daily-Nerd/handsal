"""Chain builder: a bag of acts and the state its valid acts give (FO-01, FO-22)."""
import json
import unittest

from lib import base, chain, forge, inputs, state
from lib.forks import AB

FX = base.Fixtures(base.fixture_profile())


class Applied(unittest.TestCase):
    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_valid_device_add_adds_acts_state_and_advances_the_tip(self):
        built = self.c.device_add("alice2", ("alice", "bob"))
        self.assertEqual(self.c.acts, built.acts)
        self.assertEqual(len(built.acts), 3)  # primary, bob's endorsement, the new key's proof
        out = json.loads(self.c.expect())
        self.assertEqual(out["tip"], {"genesis": FX.org_id, "id": built.id, "n": "1"})
        self.assertIn(FX.key("alice2").kid, out["devices"]["alice"])
        self.assertEqual(built.parent, FX.org_id)

    def test_the_next_act_links_to_the_previous_primary(self):
        first = self.c.device_add("alice2", ("alice", "bob"))
        second = self.c.device_remove("carol", ("alice", "bob"))
        self.assertEqual(second.parent, first.id)
        self.assertEqual(json.loads(self.c.expect())["tip"]["n"], "2")

    def test_a_remove_marks_the_device_removed(self):
        self.c.device_remove("carol", ("alice", "bob"))
        out = json.loads(self.c.expect())
        self.assertEqual(out["devices"]["carol"][FX.key("carol").kid]["status"], "removed")
        self.assertEqual(out["keys"]["carol"][FX.key("carol").kid]["status"], "revoked")

    def test_member_add_creates_the_member_with_the_given_role_device(self):
        self.c.member_add("dave", ("alice", "bob"), role="member")
        self.assertIn("dave", json.loads(self.c.expect())["devices"])

    def test_not_ok_adds_the_acts_but_leaves_state_and_tip(self):
        before = self.c.expect()
        built = self.c.device_add("alice2", ("alice", "bob"), ok=False)
        self.assertEqual(self.c.acts, built.acts)
        self.assertEqual(self.c.expect(), before)

    def test_a_class_outside_the_policy_is_added_not_accepted(self):
        self.c.member_add("dave", ("alice", "bob"), role="member")
        built = self.c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")
        out = json.loads(self.c.expect())
        entry = out["devices"]["dave"][FX.key("dave2").kid]
        self.assertEqual((entry["class"], entry["accepted"]), ("fixture-pin", False))
        self.assertNotIn(FX.key("dave2").kid, out["keys"]["dave"])
        body = json.loads(base._unb64u(built.acts[0].split(".")[1]))["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["class"], "fixture-pin")

    def test_edit_act_replaces_one_act_in_the_built_list_and_the_bag(self):
        built = self.c.device_add("alice2", ("alice", "bob"), ok=False)
        old = built.acts[1]
        self.c.edit_act(built, 1, "x.y.z")
        self.assertEqual(self.c.acts[1], "x.y.z")
        self.assertEqual(built.acts[1], "x.y.z")
        self.assertNotIn(old, self.c.acts)

    def test_fold_input_uses_the_lineage_org_pin_and_the_bag(self):
        self.c.device_add("alice2", ("alice", "bob"))
        got = self.c.fold_input()
        self.assertEqual(got, inputs.fold_input(FX.lineage(), acts=self.c.acts))

    def test_at_selects_the_prefix_state(self):
        a = self.c.device_add("alice2", ("alice", "bob"))
        self.c.device_remove("carol", ("alice", "bob"))
        got = self.c.fold_input(at=1)
        self.assertEqual(got["at"], "1")
        out = json.loads(self.c.expect(at=1))
        self.assertEqual(out["tip"]["id"], a.id)
        self.assertEqual(out["devices"]["carol"][FX.key("carol").kid]["status"], "active")
        self.assertEqual(json.loads(self.c.expect(at=0))["tip"]["n"], "0")

    def test_at_beyond_the_tip_has_no_prefix_state(self):
        with self.assertRaises(IndexError):
            self.c.expect(at=1)

    def test_a_parent_override_builds_at_an_older_position(self):
        first = self.c.device_add("alice2", ("alice", "bob"))
        side = self.c.device_remove("carol", ("alice", "bob"), parent=None, ok=False)
        self.assertEqual(side.parent, FX.org_id)
        self.assertNotEqual(side.parent, first.id)

    def test_witness_org_variant(self):
        c = chain.Chain(FX, wit=True)
        self.assertEqual(json.loads(c.expect())["org"], FX.wit_org_id)
        self.assertEqual(c.fold_input()["org"], FX.wit_org_id)


class OtherOrg(unittest.TestCase):
    def test_a_chain_can_name_another_organization_in_every_act_and_still_hang_at_its_own_root(self):
        c = chain.Chain(FX, org_id=FX.wit_org_id)
        built = c.device_add("alice2", AB, ok=False)
        self.assertEqual(c.root, FX.org_id)
        self.assertEqual(built.parent, FX.org_id)
        orgs = {json.loads(forge.parts(a)[1])["ext"]["dev.handsal/act"]["org"] for a in built.acts}
        self.assertEqual(orgs, {FX.wit_org_id})
        self.assertEqual(c.expect(), chain.Chain(FX).expect())   # nothing applied


class Positives(unittest.TestCase):
    """Every act the author calls valid is handed to the vitni cross-check (CF-06)."""

    class Ctx:
        def __init__(self):
            self.calls = []

        def positive(self, jws, method, signers):
            self.calls.append((jws, method, tuple(signers)))

    def test_the_lineage_signatures_are_recorded_once_with_genesis_sign(self):
        ctx = self.Ctx()
        chain.Chain(FX, ctx=ctx)
        self.assertEqual(sorted((m, s) for _j, m, s in ctx.calls),
                         [("local:handsal.genesis.sign", (n,)) for n in ("alice", "bob", "carol")])
        self.assertEqual(sorted(j for j, _m, _s in ctx.calls), sorted(FX.lineage()[0]["sigs"]))
        chain.Chain(FX, ctx=ctx)  # the same acts again: the driver judges each act once

    def test_a_valid_device_add_records_primary_endorsement_and_proof(self):
        ctx = self.Ctx()
        c = chain.Chain(FX, ctx=ctx)
        del ctx.calls[:]
        built = c.device_add("alice2", ("alice", "bob"))
        self.assertEqual([jws for jws, _m, _s in ctx.calls], built.acts)
        self.assertEqual([(m, s) for _j, m, s in ctx.calls], [
            ("local:handsal.device.add", ("alice",)),
            ("local:handsal.act.endorse", ("bob",)),
            ("local:handsal.act.endorse", ("alice2",))])

    def test_an_act_declared_not_ok_is_not_recorded(self):
        ctx = self.Ctx()
        c = chain.Chain(FX, ctx=ctx)
        del ctx.calls[:]
        c.device_add("alice2", ("alice", "bob"), ok=False)
        self.assertEqual(ctx.calls, [])

    def test_a_valid_act_off_the_tip_is_recorded_but_not_applied(self):
        ctx = self.Ctx()
        c = chain.Chain(FX, ctx=ctx)
        del ctx.calls[:]
        before = c.expect()
        c.device_add("alice2", ("alice", "bob"), ok=False, valid=True, parent=None)
        self.assertEqual(len(ctx.calls), 3)
        self.assertEqual(c.expect(), before)

    def test_a_remove_has_no_proof_of_possession(self):
        ctx = self.Ctx()
        c = chain.Chain(FX, ctx=ctx)
        del ctx.calls[:]
        c.device_remove("carol", ("alice", "bob"))
        self.assertEqual([(m, s) for _j, m, s in ctx.calls], [
            ("local:handsal.device.remove", ("alice",)),
            ("local:handsal.act.endorse", ("bob",))])


class OverADocument(unittest.TestCase):
    """A chain whose root is any lineage document, not only ORG (GP-07, GP-09, FO-04)."""

    def setUp(self):
        self.change = inputs.change_doc(FX)
        sigs = [FX.genesis_sign(n, self.change) for n in ("alice", "bob", "carol")]
        self.lineage = FX.lineage() + [{"doc": self.change, "sigs": sigs}]
        self.c = chain.Chain(FX, doc=self.change, lineage=self.lineage)
        self.change_id = inputs.doc_id(self.change)

    def payload(self, jws):
        return json.loads(base._unb64u(jws.split(".")[1]))

    def test_the_state_at_the_root_is_the_document_and_the_org_is_the_original(self):
        out = json.loads(self.c.expect())
        self.assertEqual(out["tip"], {"genesis": self.change_id, "id": self.change_id, "n": "0"})
        self.assertEqual((out["org"], out["org_name"]), (FX.org_id, "example"))
        self.assertNotEqual(self.change_id, FX.org_id)

    def test_acts_root_at_the_document_hash_and_name_the_original_org(self):
        built = self.c.device_add("alice2", ("alice", "bob"))
        primary, endorse = self.payload(built.acts[0]), self.payload(built.acts[1])
        self.assertEqual(primary["parent_receipt_hash"], self.change_id)
        self.assertEqual(built.parent, self.change_id)
        self.assertEqual(primary["ext"]["dev.handsal/act"]["org"], FX.org_id)
        self.assertEqual(endorse["ext"]["dev.handsal/act"]["head"],
                         {"id": self.change_id, "kind": "chain"})
        out = json.loads(self.c.expect())
        self.assertEqual(out["tip"], {"genesis": self.change_id, "id": built.id, "n": "1"})

    def test_a_second_act_links_to_the_first_not_to_the_root(self):
        first = self.c.device_add("alice2", ("alice", "bob"))
        second = self.c.device_remove("carol", ("alice", "bob"))
        self.assertEqual(second.parent, first.id)

    def test_the_fold_input_carries_the_given_lineage_and_the_original_org(self):
        data = self.c.fold_input()
        self.assertEqual(data["lineage"], self.lineage)
        self.assertEqual(data["org"], FX.org_id)
        self.assertEqual(data["pin"], inputs.probe_for(self.lineage))

    def test_the_given_lineage_is_recorded_for_the_vitni_cross_check(self):
        seen = []

        class Ctx:
            def positive(self, jws, method, signers):
                seen.append((jws, method, tuple(signers)))
        chain.Chain(FX, doc=self.change, lineage=self.lineage, ctx=Ctx())
        self.assertEqual([s[0] for s in seen], FX.lineage()[0]["sigs"] + self.lineage[1]["sigs"])
        self.assertEqual({s[1] for s in seen}, {chain.GENESIS_SIGN})
        self.assertEqual([s[2] for s in seen][-3:], [("alice",), ("bob",), ("carol",)])


class Resolves(unittest.TestCase):
    """`Chain.resolve`: a resolve is a bag member that takes no position (FO-24, FO-25)."""

    def setUp(self):
        self.seen = []
        seen = self.seen

        class Ctx:
            def positive(self, jws, method, signers):
                seen.append((method, tuple(signers)))
        self.c = chain.Chain(FX, ctx=Ctx())
        self.kept = self.c.device_add("alice2", ("alice", "bob"))
        self.lost = self.c.device_add("alice3", ("alice", "bob"), ok=False, valid=True, parent=None)

    def test_it_joins_the_bag_without_moving_state_or_tip(self):
        before = self.c.expect()
        built = self.c.resolve(("bob", "carol"), candidates=[self.kept.id, self.lost.id],
                               choose=self.kept.id, heads=[self.lost.id], parent=None)
        self.assertEqual(self.c.expect(), before)
        for jws in built.acts:
            self.assertIn(jws, self.c.acts)
        self.assertEqual(self.c.tip.id, self.kept.id)

    def test_the_body_and_parent_are_the_ones_given(self):
        built = self.c.resolve(("bob", "carol"), candidates=[self.kept.id, self.lost.id],
                               choose=self.lost.id, heads=[self.kept.id], parent=None)
        p = json.loads(base._unb64u(built.acts[0].split(".")[1]))
        act = p["ext"]["dev.handsal/act"]
        self.assertEqual(p["parent_receipt_hash"], FX.org_id)
        self.assertEqual(act["body"]["choose"], self.lost.id)
        self.assertEqual(act["body"]["heads"], [self.kept.id])
        self.assertEqual(act["body"]["overrides"], [])

    def test_a_resolve_at_a_node_links_to_it(self):
        built = self.c.resolve(("bob", "carol"), candidates=[self.kept.id, self.lost.id],
                               choose=self.kept.id, heads=[self.lost.id], parent=None)
        self.assertEqual(built.parent, FX.org_id)
        deeper = self.c.device_add("alice4", ("alice", "bob"))
        other = self.c.device_add("bob2", ("alice", "bob"), ok=False, valid=True, parent=self.kept)
        res = self.c.resolve(("bob", "carol"), candidates=[deeper.id, other.id], choose=deeper.id,
                             heads=[other.id], parent=self.kept)
        self.assertEqual(res.parent, self.kept.id)

    def test_the_acts_are_recorded_for_the_vitni_cross_check_primary_then_endorsements(self):
        before = len(self.seen)
        self.c.resolve(("bob", "carol"), candidates=[self.kept.id, self.lost.id],
                       choose=self.kept.id, heads=[self.lost.id], parent=None)
        self.assertEqual(self.seen[before:], [(chain.RESOLVE, ("bob",)), (chain.ENDORSE, ("carol",))])

    def test_over_a_change_document_it_roots_at_the_document(self):
        change = inputs.change_doc(FX)
        sigs = [FX.genesis_sign(n, change) for n in ("alice", "bob", "carol")]
        c = chain.Chain(FX, doc=change, lineage=FX.lineage() + [{"doc": change, "sigs": sigs}])
        a = c.device_add("alice2", ("alice", "bob"))
        b = c.device_add("alice3", ("alice", "bob"), ok=False, valid=True, parent=None)
        res = c.resolve(("bob", "carol"), candidates=[a.id, b.id], choose=a.id, heads=[b.id],
                        parent=None)
        self.assertEqual(res.parent, inputs.doc_id(change))


if __name__ == "__main__":
    unittest.main()
