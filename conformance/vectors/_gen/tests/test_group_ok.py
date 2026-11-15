"""T3.7 vectors ok/* and vrd/*: valid acts and the outputs check (ACT-09, VR-07)."""
import json
import unittest

import generate
from lib import base, es256, forge, inputs
from tests import catalog

OK_ROWS = {"ok/approve", "ok/reject", "ok/needs-info", "ok/decision",
           "ok/decision-action-24", "ok/decision-other-consumer"}
FX = base.Fixtures(base.fixture_profile())


class Ok(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("ok", ["ok"])

    def test_rows(self):
        self.assertEqual(set(self.v), OK_ROWS)

    def test_every_row_is_valid_check_act(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act", name)
            self.assertEqual(catalog.catalog_code(name), "ok")
            obj = json.loads(v["anchor"])
            self.assertEqual((obj["valid"], obj["reason"], obj["class"]),
                             (True, "ok", "apple-se-bio"), name)
            self.assertEqual(obj["receipt_id"], inputs.receipt_id(v["input"]["jws"]), name)

    def test_methods_and_inputs(self):
        want = {"ok/approve": inputs.APPROVE, "ok/reject": inputs.REJECT,
                "ok/needs-info": inputs.NEEDS_INFO,
                "ok/decision": inputs.DECISION, "ok/decision-action-24": inputs.DECISION,
                "ok/decision-other-consumer": inputs.DECISION}
        for name, method in want.items():
            inp = self.v[name]["input"]
            self.assertEqual(inp["expect_method"], method)
            self.assertEqual(json.loads(forge.parts(inp["jws"])[1])["method"], method)

    def test_the_signatures_are_real_and_low_s(self):
        k = FX.key("alice")
        for v in self.v.values():
            jws = v["input"]["jws"]
            sig = forge.parts(jws)[2]
            self.assertTrue(es256.verify((k.x_int, k.y_int), jws.rsplit(".", 1)[0].encode(), sig))
            self.assertTrue(es256.is_low_s(sig))

    def test_every_positive_is_recorded_for_the_vitni_cross_check(self):
        import groups.ok as module
        import tempfile
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[module], known_ids=generate.shipping_ids(), stats=stats)
        self.assertEqual(stats["positives"], len(OK_ROWS))


class Vrd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("vrd", ["vrd"])

    def test_the_row_has_one_defect_expect_method_names_the_acts_own_method(self):
        """VR-02: step 9 (`context_mismatch`) outranks step 12 (`outputs_mismatch`), so a row of
        step 12 passes `expect_method` equal to the method of the act."""
        for name, v in self.v.items():
            method = json.loads(forge.parts(v["input"]["jws"])[1])["method"]
            self.assertEqual(v["input"]["expect_method"], method, name)

    def test_outputs_verdict_swapped(self):
        self.assertEqual(set(self.v), {"vrd/outputs-verdict-swapped"})
        v = self.v["vrd/outputs-verdict-swapped"]
        self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(v["name"]))
        p = json.loads(forge.parts(v["input"]["jws"])[1])
        self.assertEqual(p["method"], inputs.APPROVE)
        self.assertEqual(p["outputs_hash"], base.hashstr(
            b'{"request_id":"req-00000001","verdict":"reject"}'))
        self.assertEqual(json.loads(v["anchor"])["class"], "apple-se-bio")


if __name__ == "__main__":
    unittest.main()
