"""T3.7 vectors mth/* and bod/* (ACT-09, VR-02 steps 4 and 5)."""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
MTH = {"mth/case-variant", "mth/chain-method-to-check-act", "mth/endorse-to-check-act",
       "mth/genesis-sign-to-check-act", "mth/mcp-prefix", "mth/request-send",
       "mth/resolve-to-check-act", "mth/unknown-verb"}
BOD = {"bod/approve-body-nonempty", "bod/record-anchor-empty", "bod/record-anchors-17"}


def payload(v):
    return json.loads(forge.parts(v["input"]["jws"])[1])


class Mth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("mth", ["mth"])

    def test_rows(self):
        self.assertEqual(set(self.v), MTH)

    def test_codes_match_the_catalog_and_the_anchor_shape(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act")
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)
            obj = json.loads(v["anchor"])
            self.assertEqual(obj["receipt_id"], inputs.receipt_id(v["input"]["jws"]), name)
            self.assertIsNone(obj["class"])

    def test_unknown_method_strings(self):
        want = {"mth/case-variant": "Local:Handsal.request.approve",
                "mth/mcp-prefix": "mcp:handsal.request.approve",
                "mth/request-send": "local:handsal.request.send",
                "mth/unknown-verb": "local:handsal.request.cancel"}
        for name, method in want.items():
            self.assertEqual(payload(self.v[name])["method"], method)
            self.assertEqual(self.v[name]["input"]["expect_method"], inputs.APPROVE)

    def test_chain_methods_are_valid_acts_of_the_named_method(self):
        want = {"mth/chain-method-to-check-act": "local:handsal.device.add",
                "mth/endorse-to-check-act": "local:handsal.act.endorse",
                "mth/genesis-sign-to-check-act": "local:handsal.genesis.sign",
                "mth/resolve-to-check-act": "local:handsal.chain.resolve"}
        for name, method in want.items():
            self.assertEqual(payload(self.v[name])["method"], method)


class Bod(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("bod", ["bod"])

    def test_rows(self):
        self.assertEqual({n for n in self.v if self.v[n]["command"] == "check-act"}, BOD)

    def test_codes_match_the_catalog(self):
        # the fold-state rows of bod are covered by tests/test_group_state_rows.py
        for name, v in ((n, v) for n, v in self.v.items() if n in BOD):
            self.assertEqual(v["command"], "check-act")
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)
            self.assertEqual(json.loads(v["anchor"])["reason"], "body_schema")

    def test_the_single_edit_is_in_the_body(self):
        act = lambda v: payload(v)["ext"]["dev.handsal/act"]
        self.assertEqual(act(self.v["bod/approve-body-nonempty"])["body"], {"x": "y"})
        self.assertEqual(act(self.v["bod/record-anchor-empty"])["body"]["anchors"], [""])
        anchors = act(self.v["bod/record-anchors-17"])["body"]["anchors"]
        self.assertEqual(len(anchors), 17)
        self.assertEqual(len(set(anchors)), 17)
        for name in ("bod/record-anchor-empty", "bod/record-anchors-17"):
            self.assertEqual(self.v[name]["input"]["expect_method"], inputs.RECORD_PROMOTE)
            self.assertEqual(payload(self.v[name])["method"], inputs.RECORD_PROMOTE)


if __name__ == "__main__":
    unittest.main()
