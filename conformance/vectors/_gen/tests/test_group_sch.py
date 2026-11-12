"""T3.7 vectors sch/* (ACT-01, ACT-06 to ACT-08, ACT-13, ACT-14, GP-02 decimals).

Each check-act row is a real act with ONE edit, signed again. The test states
the edit independently as the payload paths that may differ from the valid act.
"""
import json
import unittest

from lib import base, es256, forge, inputs
from tests import catalog

ACT = ("ext", "dev.handsal/act")
# row -> payload path prefixes that the row's single edit may touch
CHECK_ACT = {
    "sch/act-extra-key": [ACT + ("x",)],
    "sch/act-kid-differs-from-header": [ACT + ("kid",)],
    "sch/act-kid-missing": [ACT + ("kid",)],
    "sch/act-missing-body": [ACT + ("body",)],
    "sch/act-missing-head": [ACT + ("head",)],
    "sch/act-missing-org": [ACT + ("org",)],
    "sch/act-object-extra-key-after-method": [ACT + ("seq",)],
    "sch/binding-mcp": [("binding",)],
    "sch/cost-nonzero": [("cost", "usd_micros")],
    "sch/ext-extra-key": [("ext", "x.other")],
    "sch/ext-missing": [("ext",)],
    "sch/extra-top-key": [("seq",)],
    "sch/hashstr-bad-char": [("inputs_hash",)],
    "sch/hashstr-no-u": [("inputs_hash",)],
    "sch/hashstr-short": [("inputs_hash",)],
    "sch/hashstr-trailing-bits": [("inputs_hash",)],
    "sch/hashstr-wrong-code": [("inputs_hash",)],
    "sch/head-has-n": [ACT + ("head", "n")],
    "sch/head-kind-unknown": [ACT + ("head", "kind")],
    "sch/missing-top-key": [("log_policy",)],
    "sch/nonce-not-hashstr": [("nonce",)],
    "sch/parent-performer-absent": [("parent_performer_id",)],
    "sch/performer-empty": [("performer_id",)],
    "sch/performer-too-long": [("performer_id",)],
    "sch/performer-uppercase": [("performer_id",)],
    "sch/record-parent-nonnull": [("parent_receipt_hash",)],
    "sch/status-not-ok": [("status",)],
    "sch/ts-feb30": [("ts",)],
    "sch/ts-fraction": [("ts",)],
    "sch/ts-leap-second": [("ts",)],
    "sch/ts-lowercase-t": [("ts",)],
    "sch/ts-no-z": [("ts",)],
    "sch/ts-offset": [("ts",)],
    "sch/verdict-parent-nonnull": [("parent_receipt_hash",)],
    "sch/verdict-parent-performer-nonnull": [("parent_performer_id",)],
}
DECIMALS = {"sch/decimal-11-digits": "12345678901", "sch/decimal-empty": "",
            "sch/decimal-exponent": "1e3", "sch/decimal-leading-zero": "02",
            "sch/decimal-negative": "-1"}
GENESIS = {"sch/genesis-sign-change-without-head", "sch/genesis-sign-original-with-head"}
FX = base.Fixtures(base.fixture_profile())


def flatten(value, path=()):
    if isinstance(value, dict) and value:
        out = {}
        for k, v in value.items():
            out.update(flatten(v, path + (k,)))
        return out
    return {path: value}


def changed(a, b):
    fa, fb = flatten(a), flatten(b)
    return {p for p in set(fa) | set(fb) if fa.get(p, "<absent>") != fb.get(p, "<absent>")}


# fold-state rows, covered by tests/test_group_state_rows.py
STATE_ROWS = {"sch/chain-primary-with-head", "sch/endorse-missing-head"}


class Sch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("sch", ["sch"])

    def test_rows(self):
        self.assertEqual(set(self.v), set(CHECK_ACT) | set(DECIMALS) | GENESIS | STATE_ROWS)

    def test_codes_match_the_catalog(self):
        for name, v in self.v.items():
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)

    def test_check_act_rows_have_one_edit_and_a_valid_signature(self):
        for name, prefixes in CHECK_ACT.items():
            v = self.v[name]
            self.assertEqual(v["command"], "check-act", name)
            method = inputs.RECORD_PROMOTE if name == "sch/record-parent-nonnull" else inputs.APPROVE
            self.assertEqual(v["input"]["expect_method"], method, name)
            valid = FX.record_promote() if method == inputs.RECORD_PROMOTE else FX.approve()
            diff = changed(json.loads(forge.parts(valid)[1]),
                           json.loads(forge.parts(v["input"]["jws"])[1]))
            self.assertTrue(diff, name)
            for path in diff:
                self.assertTrue(any(path[:len(p)] == p for p in prefixes), (name, path))
            for p in prefixes:
                self.assertTrue(any(path[:len(p)] == p for path in diff), (name, p))
            h, _p, s = forge.parts(v["input"]["jws"])
            signer = FX.name_of_kid(json.loads(h)["kid"])
            k = FX.key(signer)
            self.assertTrue(es256.verify((k.x_int, k.y_int),
                                         v["input"]["jws"].rsplit(".", 1)[0].encode(), s), name)

    def test_check_act_anchors_carry_the_payload_id_and_no_class(self):
        for name in CHECK_ACT:
            obj = json.loads(self.v[name]["anchor"])
            self.assertEqual(obj["reason"], "schema")
            self.assertEqual(obj["receipt_id"], inputs.receipt_id(self.v[name]["input"]["jws"]))
            self.assertIsNone(obj["class"])
            self.assertFalse(obj["valid"])

    def test_hashstr_rows_are_each_non_canonical_in_their_own_way(self):
        def value(name):
            return json.loads(forge.parts(self.v[name]["input"]["jws"])[1])["inputs_hash"]
        self.assertIn("+", value("sch/hashstr-bad-char"))
        self.assertEqual(len(value("sch/hashstr-short")), 46)
        self.assertNotEqual(value("sch/hashstr-no-u")[0], "u")
        self.assertEqual(len(value("sch/hashstr-no-u")), 47)
        self.assertFalse(base.is_hashstr(value("sch/hashstr-trailing-bits")))
        self.assertEqual(len(value("sch/hashstr-trailing-bits")), 47)
        self.assertFalse(base.is_hashstr(value("sch/hashstr-wrong-code")))
        self.assertEqual(len(value("sch/hashstr-wrong-code")), 47)

    def test_ts_rows(self):
        ts = {n: json.loads(forge.parts(self.v[n]["input"]["jws"])[1])["ts"] for n in CHECK_ACT
              if n.startswith("sch/ts-")}
        self.assertEqual(ts["sch/ts-feb30"], "2026-02-30T12:00:00Z")
        self.assertEqual(ts["sch/ts-fraction"], "2026-11-08T11:59:00.5Z")
        self.assertEqual(ts["sch/ts-leap-second"], "2026-11-08T11:59:60Z")
        self.assertEqual(ts["sch/ts-lowercase-t"], "2026-11-08t11:59:00Z")
        self.assertEqual(ts["sch/ts-no-z"], "2026-11-08T11:59:00")
        self.assertEqual(ts["sch/ts-offset"], "2026-11-08T11:59:00+00:00")

    def test_performer_rows(self):
        p = {n: json.loads(forge.parts(self.v[n]["input"]["jws"])[1])["performer_id"]
             for n in CHECK_ACT if n.startswith("sch/performer-")}
        self.assertEqual(p, {"sch/performer-empty": "", "sch/performer-uppercase": "Alice",
                             "sch/performer-too-long": "a" * 33})

    def test_decimal_rows_are_fold_policy_invalid_with_one_bad_decimal(self):
        for name, text in DECIMALS.items():
            v = self.v[name]
            self.assertEqual((v["command"], v["anchor"]), ("fold", '{"error":"policy_invalid"}'))
            rules = v["input"]["lineage"][0]["doc"]["policy"]["rules"]
            self.assertEqual(rules["device.remove"]["persons"], text, name)
            for other in ("chain.resolve", "genesis.change", "member.add"):
                self.assertEqual(rules[other]["persons"], "2")

    def test_genesis_sign_rows(self):
        change = self.v["sch/genesis-sign-change-without-head"]
        self.assertEqual((change["command"], change["anchor"]),
                         ("fold", '{"error":"genesis_unsigned"}'))
        lineage = change["input"]["lineage"]
        self.assertEqual(len(lineage), 2)
        heads = []
        for jws in lineage[1]["sigs"]:
            act = json.loads(forge.parts(jws)[1])["ext"]["dev.handsal/act"]
            heads.append("head" in act)
        self.assertEqual(sorted(heads), [False, True, True])  # one signature lacks it
        orig = self.v["sch/genesis-sign-original-with-head"]
        self.assertEqual(orig["anchor"], '{"error":"genesis_unsigned"}')
        heads = ["head" in json.loads(forge.parts(j)[1])["ext"]["dev.handsal/act"]
                 for j in orig["input"]["lineage"][0]["sigs"]]
        self.assertEqual(sorted(heads), [False, False, True])

    def test_fold_inputs_have_a_consistent_org_and_pin(self):
        for name in list(DECIMALS) + list(GENESIS):
            inp = self.v[name]["input"]
            self.assertEqual(sorted(inp), ["acts", "lineage", "org", "pin"])
            self.assertEqual(inp["org"], inputs.doc_id(inp["lineage"][0]["doc"]))
            self.assertEqual(inp["pin"], inputs.probe_for(inp["lineage"]))


if __name__ == "__main__":
    unittest.main()
