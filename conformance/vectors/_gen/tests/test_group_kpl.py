"""Vectors kpl/*: `pool` (CF-12, RS10). Each row is stated from the spec, not from a checker."""
import json
import unittest

from lib import base, foldmodel, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
COMPACTED = "kpl/dropped-branch-key-not-in-pool"
EARLIER = "kpl/earlier-head-key-in-pool"
TRUE = ("kpl/genesis-device", "kpl/added-on-losing-branch", "kpl/removed-device", "kpl/earlier-head-key-in-pool")
POINT = {"kpl/genesis-device": ("alice", "agree"), "kpl/sign-point-not-in-pool": ("alice", "sign"),
         "kpl/removed-device": ("alice2", "agree"), "kpl/added-on-losing-branch": ("alice3", "agree"),
         "kpl/pending-add-not-in-pool": ("alice2", "agree"), "kpl/unknown": ("dave", "agree"),
         "kpl/store-original-wrong-org": ("alice", "agree"),
         "kpl/dropped-branch-key-not-in-pool": ("X1", "agree"), "kpl/earlier-head-key-in-pool": ("alice2", "agree")}


def methods(acts):
    return [json.loads(forge.parts(a)[1])["method"].split("local:handsal.")[-1] for a in acts]


class KplRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        both = catalog.generate_modules(("kpl", "cmp"), ("kpl", "cmp"))
        cls.v = {k: x for k, x in both.items() if k.startswith("kpl/")}
        cls.cmp = both["cmp/closed-resolve-dropped"]

    def test_rows_are_the_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("kpl/")})
        self.assertEqual(set(self.v), set(POINT))

    def test_every_row_is_a_pool_of_the_four_keys_with_the_catalog_answer(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "pool", name)
            self.assertEqual(sorted(v["input"]), ["acts", "agree", "docs", "org"], name)
            got = json.loads(v["anchor"])
            self.assertEqual(sorted(got), ["in_pool", "reason"], name)
            self.assertEqual(got["reason"], catalog.catalog_code(name), name)
            self.assertEqual(got["in_pool"], name in TRUE, name)
            self.assertEqual(v["input"]["org"], FX.org_id, name)

    def test_the_point_is_the_one_the_row_names(self):
        for name, (device, use) in POINT.items():
            self.assertEqual(self.v[name]["input"]["agree"], FX.key(device, use).point(), name)

    def test_the_store_of_every_row_but_the_wrong_org_one_is_the_original_with_its_receipts(self):
        for name, v in self.v.items():
            if name in (COMPACTED, EARLIER):
                continue
            want = FX.wit_org if name == "kpl/store-original-wrong-org" else FX.org
            sigs = FX.lineage(wit=name == "kpl/store-original-wrong-org")[0]["sigs"]
            self.assertEqual(v["input"]["docs"], [{"doc": want, "sigs": sigs}], name)

    def test_the_acts_of_each_row(self):
        acts = lambda n: methods(self.v[n]["input"]["acts"])
        self.assertEqual(self.v["kpl/genesis-device"]["input"]["acts"], [])
        self.assertEqual(acts("kpl/pending-add-not-in-pool").count("device.add"), 1)
        self.assertEqual(acts("kpl/pending-add-not-in-pool").count("act.endorse"), 1)   # the possession proof only
        self.assertIn("device.remove", acts("kpl/removed-device"))
        resolve = self.v["kpl/added-on-losing-branch"]["input"]["acts"]
        self.assertEqual(methods(resolve).count("chain.resolve"), 1)
        self.assertEqual(methods(resolve).count("device.add"), 2)

    def test_the_unknown_point_is_on_the_curve_and_in_no_document(self):
        point = self.v["kpl/unknown"]["input"]["agree"]
        for entry in FX.org["devices"]:
            self.assertNotIn(point, (entry["sign"], entry["agree"]))

    def test_a_key_added_only_on_a_dropped_branch_is_not_in_the_pool(self):   # CF-12, CF-14, SD8
        v = self.v[COMPACTED]
        self.assertEqual(json.loads(v["anchor"]), {"in_pool": False, "reason": "not_in_pool"})
        drop = json.loads(self.cmp["anchor"])["drop"]
        want = foldmodel.without(self.cmp["input"], drop)   # the store of a cmp row, compacted
        self.assertEqual((v["input"]["acts"], v["input"]["docs"]), (want["acts"], want["docs"]))
        x1 = FX.key("X1")
        adds = [a for a in self.cmp["input"]["acts"] if a.count(".") == 2 and json.loads(forge.parts(a)[1])[
            "method"].endswith("device.add") and json.loads(forge.parts(a)[1])["ext"]["dev.handsal/act"][
            "body"]["kid"] == x1.kid]
        self.assertEqual(len(adds), 1)
        self.assertIn(adds[0], drop["acts"])   # the only act that introduced it was dropped
        self.assertNotIn(adds[0], v["input"]["acts"])
        for entry in v["input"]["docs"]:
            self.assertNotIn(x1.point(), [d["agree"] for d in entry["doc"]["devices"]])
            self.assertNotIn(FX.key("X1", "agree").point(), [d["agree"] for d in entry["doc"]["devices"]])


    def test_the_earlier_head_row_has_a_change_at_an_earlier_node_that_lists_no_device_of_the_key(self):   # CF-12 S6
        v = self.v[EARLIER]
        acts = [a for a in v["input"]["acts"] if methods([a]) != ["act.endorse"]]
        self.assertEqual(methods(acts), ["device.add", "device.remove", "device.add"])   # n1 adds, n2 removes, n3 adds
        ids = [inputs.receipt_id(a) for a in acts]
        change = v["input"]["docs"][1]["doc"]
        self.assertEqual(change["head"], ids[0])   # H is n1, earlier than the tip n3
        alice2 = FX.key("alice2").kid
        self.assertNotIn(alice2, {d["kid"] for d in change["devices"]})   # the key reaches `pool` through n1 alone
        self.assertEqual({d["person"] for d in change["devices"]}, {"alice", "bob", "carol"})
        self.assertEqual(len(v["input"]["docs"][1]["sigs"]), len(change["devices"]))   # signed by every listed device

if __name__ == "__main__":
    unittest.main()
