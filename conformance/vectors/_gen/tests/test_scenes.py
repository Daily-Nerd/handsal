"""Shared vector scenes: one owner of each multi-act setup a group reuses."""
import json
import unittest

from lib import base, forge, scenes

FX = base.Fixtures(base.fixture_profile())


class LosingBranch(unittest.TestCase):
    """A fork at T1 (kept and lost), lifted by a current resolve choosing `kept` (FO-24, FO-25)."""

    def setUp(self):
        self.s = scenes.losing_branch(FX)

    def test_the_two_candidates_share_the_parent_and_the_resolve_names_them(self):
        s = self.s
        body = json.loads(forge.parts(s.resolve.acts[0])[1])["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["candidates"], sorted([s.kept.id, s.lost.id]))
        self.assertEqual((body["choose"], body["heads"]), (s.kept.id, [s.lost.id]))
        for built in (s.kept, s.lost):
            self.assertEqual(built.parent, s.first.id)

    def test_the_bag_holds_every_act_and_the_anchor_is_the_chain_through_kept(self):
        s = self.s
        for built in (s.first, s.kept, s.lost, s.resolve):
            for jws in built.acts:
                self.assertIn(jws, s.bag)
        self.assertEqual(len(s.bag), len(set(s.bag)))
        out = json.loads(s.chain.expect())
        self.assertEqual((out["tip"]["id"], out["tip"]["n"]), (s.kept.id, "2"))

    def test_the_wit_variant_is_built_on_the_witness_org(self):
        s = scenes.losing_branch(FX, wit=True)
        self.assertEqual(json.loads(s.chain.expect())["org"], FX.wit_org_id)


if __name__ == "__main__":
    unittest.main()
