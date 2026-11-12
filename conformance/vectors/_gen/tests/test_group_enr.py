"""T3.52 vectors enr/*: the `enrolled` predicate in order, first failure wins (GP-13, GP-14, GP-17).

Every row runs under the fixture profile except `enr/fixture-kid`, which folds under the
production profile (GP-18). A row that passes steps 1 to 6 ends at `fixture_profile` (step 7),
because the conformance fixtures are fixture keys. Not written: `enr/prodk-fixture-kid-unknown`
(it needs the production keys, PRODK, not yet generated). The retired ids `pin/probe-symlink-ancestor`
and `cli/prod-*` are platform and production-build tests (CF-07, see groups/enr.py).
"""
import base64
import json
import unittest

from lib import base, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
REASONS = {
    "enr/ok": "fixture_profile", "enr/device-kid-not-presence": "fixture_profile",
    "enr/fixture-kid": "fixture_key", "enr/fork": "fork",
    "enr/genesis-pin-mismatch": "genesis_pin_mismatch",
    "enr/local-class-not-accepted": "local_class_not_accepted",
    "enr/local-key-revoked": "local_key_not_active", "enr/local-key-unknown": "local_key_unknown",
    "enr/no-secure-enclave-machine": "local_key_unknown", "enr/pin-malformed": "pin_malformed",
    "enr/pin-missing": "pin_missing", "enr/pin-owner": "pin_owner",
    "enr/pin-probe-unavailable": "pin_probe_unavailable", "enr/stale-view": "stale_view",
    "enr/state-error": "genesis_unsigned", "enr/view-in-future": "view_in_future",
    "enr/wsl-unprotected": "pin_probe_unprotected",
}
SKIPPED = {"enr/prodk-fixture-kid-unknown"}


class Enr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("enr", ["enr"])

    def test_rows(self):
        self.assertEqual(set(self.v), set(REASONS))

    def test_written_and_skipped_ids_are_the_catalog_group(self):
        group = {k for k in catalog.ROWS if k.startswith("enr/")}
        self.assertEqual(set(REASONS) | SKIPPED, group)

    def test_every_row_is_not_enrolled_with_the_catalog_reason(self):
        for name, reason in REASONS.items():
            v = self.v[name]
            self.assertEqual(v["command"], "enrolled", name)
            self.assertEqual(json.loads(v["anchor"]), {"enrolled": False, "reason": reason}, name)
            self.assertEqual(catalog.catalog_code(name), reason, name)

    def test_the_inputs_are_the_gp13_keys(self):
        for name, v in self.v.items():
            self.assertEqual(sorted(v["input"]), ["acts", "device_kid", "lineage", "now", "org",
                                                  "pin", "synced_at", "tip_statement"], name)

    def test_the_probe_rows_carry_the_probe_that_names_their_reason(self):
        for name, reason in (("enr/pin-missing", "pin_missing"), ("enr/pin-owner", "pin_owner"),
                             ("enr/pin-probe-unavailable", "pin_probe_unavailable"),
                             ("enr/wsl-unprotected", "pin_probe_unprotected")):
            pin = self.v[name]["input"]["pin"]
            self.assertEqual((pin["owner_ok"], pin["reason"]), (False, reason), name)

    def test_the_view_rows_sit_one_second_past_the_bounds(self):
        stale = self.v["enr/stale-view"]["input"]
        self.assertEqual(stale["synced_at"], base.shift(base.NOW, -86401))
        future = self.v["enr/view-in-future"]["input"]
        self.assertEqual(future["synced_at"], base.shift(base.NOW, 301))

    def test_the_key_rows_name_the_device_the_state_decides_on(self):
        self.assertEqual(self.v["enr/device-kid-not-presence"]["input"]["device_kid"],
                         FX.key("bob").kid)
        self.assertEqual(self.v["enr/local-key-revoked"]["input"]["device_kid"], FX.key("carol").kid)
        self.assertEqual(self.v["enr/local-class-not-accepted"]["input"]["device_kid"],
                         FX.key("dave2").kid)
        unknown = self.v["enr/local-key-unknown"]["input"]["device_kid"]
        none = self.v["enr/no-secure-enclave-machine"]["input"]["device_kid"]
        self.assertNotEqual(unknown, none)
        for kid in (unknown, none):
            self.assertNotIn(kid, [d["kid"] for d in self.v["enr/ok"]["input"]["lineage"][0][
                "doc"]["devices"]])

    def test_the_fixture_kid_row_is_under_the_production_profile(self):
        v = self.v["enr/fixture-kid"]
        self.assertEqual(v["input"]["lineage"][0]["doc"]["profile"], base.production_profile())

    def test_the_malformed_pin_bytes_are_not_a_pin(self):
        raw = base64.b64decode(self.v["enr/pin-malformed"]["input"]["pin"]["bytes_b64"])
        self.assertFalse(raw.endswith(b"}\n"))

    def test_the_state_error_row_has_an_unsigned_original(self):
        self.assertEqual(self.v["enr/state-error"]["input"]["lineage"][0]["sigs"], [])

    def test_the_pin_mismatch_row_pins_another_genesis(self):
        pin = self.v["enr/genesis-pin-mismatch"]["input"]["pin"]
        line = json.loads(base64.b64decode(pin["bytes_b64"]))
        last = inputs.doc_id(self.v["enr/genesis-pin-mismatch"]["input"]["lineage"][-1]["doc"])
        self.assertNotEqual(line["genesis"], last)


if __name__ == "__main__":
    unittest.main()
