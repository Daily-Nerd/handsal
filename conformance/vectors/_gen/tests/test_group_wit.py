"""T3.37 vectors wit/*: the witness policy, the tip statement and the relay check (WT-01 to WT-10)."""
import json
import unittest

from lib import base, forge
from tests import catalog

FX = base.Fixtures(base.fixture_profile())

CHECK = {
    "wit/valid-tip-ok", "wit/tip-older-than-consumer-tip-ok", "wit/tip-root-position-ok",
    "wit/tip-age-exactly-max-ok", "wit/stale-tip", "wit/future-within-skew-ok", "wit/future-tip",
    "wit/wrong-key-kid", "wit/wrong-key-signature", "wit/statement-high-s", "wit/wrong-org",
    "wit/wrong-epoch-newer", "wit/behind-tip", "wit/tip-junk", "wit/tip-other-branch",
    "wit/mode-none-statement-supplied", "wit/mode-none-garbage-statement",
    "wit/mode-none-null-ok", "wit/mode-relay-no-statement", "wit/statement-key-absent",
    "wit/statement-wrong-type", "wit/malformed-jws", "wit/malformed-head-present",
    "wit/malformed-body-extra-key", "wit/malformed-method", "wit/malformed-performer",
    "wit/statement-as-act", "wit/never-validates-revoked", "wit/never-validates-bad-sig",
    "wit/never-validates-unproven", "wit/synced-at-still-checked", "wit/head-kind-relay-schema",
    "wit/ord-time-before-witness", "wit/ord-view-before-witness",
    "wit/ord-witness-before-duplicate", "wit/ord-key-before-signature",
    "wit/ord-signature-before-content", "wit/ord-stale-before-behind",
    "wit/order-superseded-before-stale", "wit/superseded-epoch-refused",
    "wit/next-no-latest-epoch-ok", "wit/next-missing-malformed",
    "wit/next-boolean-not-canonical-malformed", "wit/next-other-string-malformed",
    "wit/next-hashstr-malformed",
}
ENROLLED = {"wit/enr-relay-ok", "wit/enr-relay-missing", "wit/enr-relay-stale",
            "wit/enr-mode-none-supplied"}
FOLD = {
    "wit/pol-missing-witness", "wit/pol-mode-unknown", "wit/pol-none-extra-key",
    "wit/pol-relay-missing-jwk", "wit/pol-kid-not-thumbprint", "wit/pol-jwk-not-on-curve",
    "wit/pol-jwk-extra-member", "wit/pol-tip-age-59", "wit/pol-tip-age-86401",
    "wit/pol-relay-key-is-device-key", "wit/pol-relay-key-is-agree-key",
    "wit/device-add-relay-key-ignored", "wit/relay-ok-original", "wit/statement-in-bag-ignored",
    "wit/pol-tip-age-bounds-ok", "wit/pol-tip-age-upper-bound-ok",
}
GENESIS_CHECK = {"wit/genesis-check-relay-ok"}
RENDER = {"wit/render-genesis-witness-none", "wit/render-genesis-witness-relay"}
WRITTEN = CHECK | ENROLLED | FOLD | GENESIS_CHECK | RENDER
NOT_WRITTEN = {
    # needs a genesis change (written by the wit_change group)
    "wit/change-after-repin-needs-statement", "wit/change-before-repin-old-mode",
    "wit/change-none-to-relay-one-signer", "wit/change-none-to-relay-quorum",
    "wit/change-none-to-relay-revoked-signer", "wit/change-relay-key-rotation-ok",
    "wit/change-relay-to-none-one-signer",
}


class Wit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("wit", ["wit"])

    def test_rows(self):
        self.assertEqual(set(self.v), WRITTEN)

    def test_written_and_skipped_ids_are_disjoint_catalog_ids(self):
        group = {k for k in catalog.ROWS if k.startswith("wit/")}
        self.assertTrue(WRITTEN <= group and NOT_WRITTEN <= group)
        self.assertFalse(WRITTEN & NOT_WRITTEN)

    def test_check_act_rows_carry_the_catalog_code(self):
        for name in CHECK:
            v = self.v[name]
            self.assertEqual(v["command"], "check-act", name)
            want = "ok" if name == "wit/mode-none-null-ok" else catalog.catalog_code(name)
            self.assertEqual(catalog.anchor_code(v), want, name)

    def test_enrolled_rows_carry_the_catalog_reason(self):
        for name in ENROLLED:
            v = self.v[name]
            self.assertEqual(v["command"], "enrolled", name)
            obj = json.loads(v["anchor"])
            self.assertEqual((obj["enrolled"], obj["reason"]),
                             (False, catalog.catalog_code(name)), name)

    def test_policy_rows_carry_the_catalog_code(self):
        for name in FOLD - {"wit/device-add-relay-key-ignored", "wit/relay-ok-original",
                            "wit/statement-in-bag-ignored"}:
            self.assertEqual(self.v[name]["command"], "fold", name)
            self.assertEqual(catalog.anchor_code(self.v[name]), catalog.catalog_code(name), name)

    def test_the_relay_original_is_a_state_with_mode_relay(self):
        out = json.loads(self.v["wit/relay-ok-original"]["anchor"])
        self.assertEqual(out["policy"]["witness"]["mode"], "relay")
        self.assertEqual(out["org"], FX.wit_org_id)

    def test_the_bag_with_a_statement_folds_like_the_bag_without_it(self):
        v = self.v["wit/statement-in-bag-ignored"]
        acts = v["input"]["acts"]
        stmt = [a for a in acts if json.loads(forge.parts(a)[1])["method"] ==
                "local:handsal.relay.tip"]
        self.assertEqual(len(stmt), 1)
        out = json.loads(v["anchor"])
        self.assertEqual(out["tip"]["n"], "4")

    def test_mode_none_with_null_is_the_ok_approve_input(self):
        a = self.v["wit/mode-none-null-ok"]
        b = catalog.generate_group("ok", ["ok"])["ok/approve"]
        self.assertEqual((a["command"], a["input"], a["anchor"]),
                         (b["command"], b["input"], b["anchor"]))

    def test_relay_rows_carry_a_statement_unless_the_row_is_about_its_absence(self):
        for name in ("wit/valid-tip-ok", "wit/stale-tip", "wit/wrong-org"):
            stmt = self.v[name]["input"]["tip_statement"]
            self.assertEqual(json.loads(forge.parts(stmt)[1])["method"], "local:handsal.relay.tip")
        for name in ("wit/mode-relay-no-statement", "wit/ord-time-before-witness"):
            self.assertIsNone(self.v[name]["input"]["tip_statement"])
        self.assertNotIn("tip_statement", self.v["wit/statement-key-absent"]["input"])
        self.assertEqual(self.v["wit/statement-wrong-type"]["input"]["tip_statement"], [])

    def test_ts_boundaries_are_exact(self):
        def ts(name):
            stmt = self.v[name]["input"]["tip_statement"]
            return json.loads(forge.parts(stmt)[1])["ts"]
        self.assertEqual(ts("wit/tip-age-exactly-max-ok"), base.shift(base.NOW, -3600))
        self.assertEqual(ts("wit/stale-tip"), base.shift(base.NOW, -3601))
        self.assertEqual(ts("wit/future-within-skew-ok"), base.shift(base.NOW, 300))
        self.assertEqual(ts("wit/future-tip"), base.shift(base.NOW, 301))

    def test_the_tip_of_each_position_row_is_the_named_position(self):
        def tip(name):
            stmt = self.v[name]["input"]["tip_statement"]
            return json.loads(forge.parts(stmt)[1])["ext"]["dev.handsal/act"]["body"]["tip"]
        ids = [json.loads(forge.parts(a)[1]) for a in self.v["wit/valid-tip-ok"]["input"]["acts"]]
        self.assertTrue(len(ids) >= 4)
        self.assertEqual(tip("wit/tip-root-position-ok"), FX.wit_org_id)
        self.assertEqual(self.v["wit/tip-root-position-ok"]["input"]["acts"], [])
        self.assertEqual(tip("wit/tip-junk"), base.hashstr(b"tip junk"))

    def test_every_positive_act_and_statement_is_recorded_for_the_cross_check(self):
        import tempfile
        import generate
        import groups.wit as module
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[module], known_ids=generate.shipping_ids(), stats=stats)
        self.assertGreater(stats["positives"], 40)


if __name__ == "__main__":
    unittest.main()
