"""Vectors kpl/*: `pool` (CF-12, RS10). Each row is stated from the spec, not from a checker."""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
TRUE = ("kpl/genesis-device", "kpl/added-on-losing-branch", "kpl/removed-device")
POINT = {"kpl/genesis-device": ("alice", "agree"), "kpl/sign-point-not-in-pool": ("alice", "sign"),
         "kpl/removed-device": ("alice2", "agree"), "kpl/added-on-losing-branch": ("alice3", "agree"),
         "kpl/pending-add-not-in-pool": ("alice2", "agree"), "kpl/unknown": ("dave", "agree"),
         "kpl/store-original-wrong-org": ("alice", "agree")}


def methods(acts):
    return [json.loads(forge.parts(a)[1])["method"].split("local:handsal.")[-1] for a in acts]


class KplRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("kpl", ["kpl"])

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


if __name__ == "__main__":
    unittest.main()
