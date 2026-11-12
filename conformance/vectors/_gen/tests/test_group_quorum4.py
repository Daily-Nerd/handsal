"""The three rows on ORG4: a rule at `persons "3"` is not met by two persons (FO-11, FO-22, GP-02).

Each row is a two-person act on a four-maintainer organization whose rule asks for three:
the act is not on the chain, so the expected output is ORG4's own state. The second half of
`quo/raised-floor-3-two-rejected` (carol's endorsement added, applied) is a different input
under the same id and is not written.
"""
import json
import unittest

from lib import base, forge, inputs, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
ROWS = {"rem/second-person-quorum-unmet", "quo/policy-swap-2-vs-3",
        "quo/raised-floor-3-two-rejected", "quo/raised-floor-3-three-applied"}


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(["quorum4"], ["rem", "quo"])

    def test_rows(self):
        self.assertEqual(set(self.v), ROWS)

    def test_the_three_person_row_applies_the_removal(self):
        v = self.v["quo/raised-floor-3-three-applied"]
        out = json.loads(v["anchor"])
        self.assertEqual(out["tip"]["n"], "1")
        self.assertEqual(out["devices"]["carol"][FX.key("carol").kid]["status"], "removed")
        self.assertEqual(v["input"]["lineage"][0]["doc"]["policy"]["rules"]["device.remove"][
            "persons"], "3")

    def test_every_row_is_orgs_four_state_unchanged(self):
        for name, v in self.v.items():
            if name.endswith("-applied"):
                continue
            doc = v["input"]["lineage"][0]["doc"]
            self.assertEqual(v["command"], "fold", name)
            self.assertEqual(v["anchor"], state.anchor(state.State(doc)), name)
            self.assertEqual(v["input"]["org"], inputs.doc_id(doc), name)
            self.assertEqual(len(doc["members"]), 4, name)

    def test_the_rule_under_test_asks_for_three_and_the_act_has_two_persons(self):
        for name, rule in (("rem/second-person-quorum-unmet", "device.remove"),
                           ("quo/policy-swap-2-vs-3", "device.remove"),
                           ("quo/raised-floor-3-two-rejected", "device.remove")):
            v = self.v[name]
            doc = v["input"]["lineage"][0]["doc"]
            self.assertEqual(doc["policy"]["rules"][rule]["persons"], "3", name)
            signers = set()
            for jws in v["input"]["acts"]:
                p = json.loads(forge.parts(jws)[1])
                if p["method"] != "local:handsal.device.add" or "add" in name:
                    signers.add(p["performer_id"])
            self.assertEqual(len(signers - {"alice2"}), 2, name)

    def test_the_raised_floor_row_raises_only_the_removal_rule(self):
        rules = self.v["quo/raised-floor-3-two-rejected"]["input"]["lineage"][0]["doc"][
            "policy"]["rules"]
        self.assertEqual({k: r["persons"] for k, r in rules.items()},
                         {"chain.resolve": "2", "device.remove": "3", "genesis.change": "2",
                          "member.add": "2"})

    def test_the_removal_rows_remove_carols_device_and_the_swap_row_adds(self):
        body = lambda n: [json.loads(forge.parts(j)[1])["ext"]["dev.handsal/act"]
                          for j in self.v[n]["input"]["acts"]][0]
        for name in ("rem/second-person-quorum-unmet", "quo/raised-floor-3-two-rejected"):
            self.assertEqual(body(name)["body"], {"kid": FX.key("carol").kid, "person": "carol"})
        self.assertEqual(body("quo/policy-swap-2-vs-3")["body"]["kid"], FX.key("alice2").kid)


if __name__ == "__main__":
    unittest.main()
