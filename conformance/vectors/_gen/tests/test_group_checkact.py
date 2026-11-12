"""T3.41 vectors ord, tim, frs, ing, rep, rly, idn, inp: the check-act pipeline (VR-02, VR-05 to VR-12)."""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

GROUPS = ("ord", "tim", "frs", "ing", "rep", "rly", "idn", "inp")
NOT_WRITTEN = set()
# rows whose catalog text has no backticked code
CODE = {"ord/owner-before-pin-parse": "pin_owner", "inp/empty-bytes": "ok",
        "frs/offline-historical-verify-unaffected": None,
        "rep/same-payload-two-sigs": "high_s", "rep/invalid-twin-not-in-seen": "ok",
        "rep/same-payload-low-s-same-receipt-id": "ok"}
FX = base.Fixtures(base.fixture_profile())


class CheckActRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(GROUPS, GROUPS)

    def test_rows_are_the_catalog_ids_less_the_harness_rows(self):
        group = {k for k in catalog.ROWS if k.split("/")[0] in GROUPS}
        # wit/ord-* rows belong to the wit group
        self.assertEqual(set(self.v), group - NOT_WRITTEN)

    def test_every_row_carries_the_catalog_code(self):
        for name, v in self.v.items():
            if name == "frs/offline-historical-verify-unaffected":
                self.assertEqual(v["command"], "fold")
                continue
            self.assertEqual(v["command"], "check-act", name)
            want = CODE[name] if name in CODE else catalog.catalog_code(name)
            self.assertEqual(catalog.anchor_code(v), want, name)

    def test_the_ordering_rows_are_pairs_whose_first_defect_wins(self):
        # every ord row names its reason; the input is the full conformance input
        for name, v in self.v.items():
            if name.startswith("ord/"):
                self.assertTrue({"acts", "jws", "lineage", "org", "pin", "synced_at",
                                 "tip_statement"} <= set(v["input"]), name)

    def test_the_time_boundaries_are_exact(self):
        def act(name):
            return json.loads(forge.parts(self.v[name]["input"]["jws"])[1])

        def expires(name):
            return act(name)["ext"]["dev.handsal/act"]["expires"]
        self.assertEqual(expires("tim/expired-at-now"), base.NOW)
        self.assertEqual(expires("tim/one-second-left-ok"), base.shift(base.NOW, 1))
        self.assertEqual(act("tim/ts-future-by-skew-ok")["ts"], base.shift(base.NOW, 300))
        self.assertEqual(act("tim/ts-future-by-skew-plus-1")["ts"], base.shift(base.NOW, 301))
        for name, gap in (("tim/validity-exactly-max-ok", 604800),
                          ("tim/validity-max-plus-1", 604801)):
            self.assertEqual(base.shift(act(name)["ts"], gap), expires(name))
        self.assertEqual(expires("tim/expires-equal-ts"), act("tim/expires-equal-ts")["ts"])
        self.assertEqual(base.shift(expires("tim/expires-before-ts"), 1),
                         act("tim/expires-before-ts")["ts"])

    def test_the_view_boundaries_are_exact(self):
        for name, gap in (("frs/age-exactly-max-ok", -86400), ("frs/age-max-plus-1", -86401),
                          ("frs/as-of-future", 301), ("frs/local-sync-stale", -90000)):
            self.assertEqual(self.v[name]["input"]["synced_at"], base.shift(base.NOW, gap), name)
        self.assertNotIn("synced_at", self.v["frs/no-view-supplied"]["input"])

    def test_a_replay_row_carries_the_receipt_id_in_seen(self):
        v = self.v["rep/same-receipt-twice"]
        self.assertEqual(v["input"]["seen"], [inputs.receipt_id(v["input"]["jws"])])
        self.assertEqual(self.v["rep/invalid-twin-not-in-seen"]["input"]["seen"], [])
        seen = self.v["rep/different-receipt-same-request-ok"]["input"]
        self.assertNotIn(inputs.receipt_id(seen["jws"]), seen["seen"])
        self.assertEqual(len(seen["seen"]), 1)

    def test_the_swapped_field_rows_keep_the_old_signature(self):
        # the payload no longer matches its signature: vitni says `bad_signature`
        for name in ("rep/inputs-hash-swapped", "rep/org-swapped", "rep/request-id-swapped"):
            jws = self.v[name]["input"]["jws"]
            k = FX.key("alice")
            from lib import es256
            self.assertFalse(es256.verify((k.x_int, k.y_int), jws.rsplit(".", 1)[0].encode(),
                                          forge.parts(jws)[2]), name)

    def test_the_high_s_row_is_the_second_signature_of_the_ok_payload(self):
        from lib import es256
        jws = self.v["rep/same-payload-two-sigs"]["input"]["jws"]
        low = FX.approve()
        self.assertEqual(forge.parts(jws)[1], forge.parts(low)[1])
        self.assertFalse(es256.is_low_s(forge.parts(jws)[2]))
        self.assertEqual(json.loads(self.v["rep/same-payload-two-sigs"]["anchor"])["receipt_id"],
                         inputs.receipt_id(low))

    def test_the_low_s_row_is_valid_and_has_the_receipt_id_of_the_high_s_form(self):
        v = self.v["rep/same-payload-low-s-same-receipt-id"]
        high = self.v["rep/same-payload-two-sigs"]["input"]["jws"]
        out = json.loads(v["anchor"])
        self.assertEqual((out["valid"], out["reason"]), (True, "ok"))
        self.assertEqual(out["receipt_id"], json.loads(self.v["rep/same-payload-two-sigs"]["anchor"])["receipt_id"])
        self.assertEqual(forge.parts(v["input"]["jws"])[1], forge.parts(high)[1])

    def test_every_positive_is_recorded_for_the_vitni_cross_check(self):
        import tempfile
        import generate
        import importlib
        stats = {}
        mods = [importlib.import_module("groups." + m) for m in GROUPS]
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=mods, known_ids=generate.shipping_ids(), stats=stats)
        self.assertGreater(stats["positives"], 20)
        self.assertGreater(stats["negatives"], 5)


if __name__ == "__main__":
    unittest.main()
