"""T3.15 vectors org/*, fix/* and pin/* (GP-04, GP-05, GP-13, GP-14, GP-18)."""
import base64
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
FXP = base.Fixtures(base.production_profile())

ORG = {"org/check-act-org-input-missing", "org/enrolled-org-mismatch", "org/fold-org-mismatch",
       "org/other-org", "org/probe-filename-mismatch", "org/probe-other-org",
       "org/sig-valid-wrong-org"}
FIX = {"fix/fix-profile-check-act-ok", "fix/fix-profile-enrolled", "fix/mixed-profile-lineage",
       "fix/prod-check-act-fixture-pin-refused", "fix/prod-genesis-fixture-kid"}
PIN = {"pin/513-bytes", "pin/crlf", "pin/duplicate-key", "pin/duplicate-key-differing-values",
       "pin/empty", "pin/extra-line", "pin/filename-mismatch", "pin/genesis-mismatch",
       "pin/lineage-original-not-org", "pin/missing", "pin/no-trailing-lf",
       "pin/non-ascii", "pin/ok", "pin/org-not-original", "pin/reordered", "pin/spec-mismatch",
       "pin/spec-not-last-profile", "pin/unknown-key", "pin/v-wrong"}


def pin_bytes(v):
    return base64.b64decode(v["input"]["pin"]["bytes_b64"])


class Org(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("org", ["org"])

    def test_rows(self):
        self.assertEqual(set(self.v), ORG)

    def test_codes_match_the_catalog(self):
        for name, v in self.v.items():
            want = catalog.catalog_code(name)
            if name == "org/enrolled-org-mismatch":
                self.assertEqual(v["command"], "enrolled")
                self.assertEqual(v["anchor"], '{"enrolled":false,"reason":"pin_org_mismatch"}')
            else:
                self.assertEqual(catalog.anchor_code(v), want, name)

    def test_missing_org_is_malformed_input(self):
        v = self.v["org/check-act-org-input-missing"]
        self.assertEqual((v["command"], v["anchor"]), ("check-act", '{"error":"malformed_input"}'))
        self.assertNotIn("org", v["input"])

    def test_enrolled_and_fold_use_another_orgs_probe_or_input(self):
        e = self.v["org/enrolled-org-mismatch"]["input"]
        self.assertEqual(e["org"], FX.org_id)
        self.assertEqual(e["pin"], FX.pin_ok(wit=True))
        f = self.v["org/fold-org-mismatch"]
        self.assertEqual(f["command"], "fold")
        self.assertEqual(f["input"]["org"], FX.wit_org_id)
        self.assertEqual(f["input"]["pin"], FX.pin_ok())

    def test_probe_filename_mismatch_only_changes_the_file_name(self):
        pin = self.v["org/probe-filename-mismatch"]["input"]["pin"]
        good = FX.pin_ok()
        self.assertEqual({k: v for k, v in pin.items() if k != "filename"},
                         {k: v for k, v in good.items() if k != "filename"})
        self.assertEqual(pin["filename"], inputs.filename_of(FX.wit_org_id))

    def test_probe_other_org_is_a_valid_probe_of_org_b_against_input_a(self):
        v = self.v["org/probe-other-org"]
        self.assertEqual(v["command"], "check-act")
        self.assertEqual(v["input"]["pin"], FX.pin_ok(wit=True))
        self.assertEqual(v["input"]["org"], FX.org_id)
        self.assertEqual(json.loads(v["anchor"])["reason"], "pin_org_mismatch")

    def test_act_org_rows(self):
        for name in ("org/other-org", "org/sig-valid-wrong-org"):
            v = self.v[name]
            act = json.loads(forge.parts(v["input"]["jws"])[1])["ext"]["dev.handsal/act"]
            self.assertEqual(act["org"], FX.wit_org_id, name)
            self.assertEqual(v["input"]["org"], FX.org_id)
            obj = json.loads(v["anchor"])
            self.assertEqual((obj["reason"], obj["class"]), ("org_mismatch", "apple-se-bio"))


class Fix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("fix", ["fix"])

    def test_rows(self):
        self.assertEqual(set(self.v), FIX)

    def test_commands_and_codes(self):
        self.assertEqual(self.v["fix/fix-profile-check-act-ok"]["command"], "check-act")
        self.assertEqual(json.loads(self.v["fix/fix-profile-check-act-ok"]["anchor"])["reason"], "ok")
        self.assertEqual(self.v["fix/fix-profile-enrolled"]["anchor"],
                         '{"enrolled":false,"reason":"fixture_profile"}')
        self.assertEqual(self.v["fix/fix-profile-enrolled"]["command"], "enrolled")
        for name in ("fix/mixed-profile-lineage", "fix/prod-genesis-fixture-kid"):
            self.assertEqual(self.v[name]["command"], "fold")
            self.assertEqual(catalog.anchor_code(self.v[name]), catalog.catalog_code(name))
        self.assertEqual(catalog.catalog_code("fix/prod-check-act-fixture-pin-refused"), "fixture_key")
        self.assertEqual(json.loads(self.v["fix/prod-check-act-fixture-pin-refused"]["anchor"])["reason"],
                         "fixture_key")

    def test_profiles(self):
        docs = lambda v: [e["doc"]["profile"] for e in v["input"]["lineage"]]
        self.assertEqual(docs(self.v["fix/mixed-profile-lineage"]),
                         [base.fixture_profile(), base.production_profile()])
        self.assertEqual(docs(self.v["fix/prod-genesis-fixture-kid"]), [base.production_profile()])
        pin = json.loads(base64.b64decode(
            self.v["fix/prod-check-act-fixture-pin-refused"]["input"]["pin"]["bytes_b64"]))
        self.assertEqual(pin["spec"], base.production_profile())
        self.assertEqual(self.v["fix/prod-check-act-fixture-pin-refused"]["input"]["org"], FXP.org_id)

    def test_fixture_profile_acts_are_the_same_as_ok_approve(self):
        v = self.v["fix/fix-profile-check-act-ok"]
        self.assertEqual(v["input"]["jws"], FX.approve())


class Pin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("pin", ["pin"])
        cls.good = inputs.pin_line(FX.org_id, FX.org_id, base.fixture_profile())

    def test_rows(self):
        self.assertEqual(set(self.v), PIN)

    def test_codes_match_the_catalog(self):
        for name, v in self.v.items():
            if name == "pin/ok":
                self.assertEqual(json.loads(v["anchor"])["reason"], "ok")
                self.assertEqual(v["command"], "check-act")
            else:
                self.assertEqual(v["command"], "fold", name)
                self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)

    def test_byte_level_defects(self):
        good = self.good
        want = {
            "pin/crlf": good[:-1] + b"\r\n",
            "pin/no-trailing-lf": good[:-1],
            "pin/empty": b"",
            "pin/extra-line": good + good,
        }
        for name, raw in want.items():
            self.assertEqual(pin_bytes(self.v[name]), raw, name)
        big = pin_bytes(self.v["pin/513-bytes"])
        self.assertEqual(len(big), 513)
        self.assertTrue(big.startswith(good[:-1]) and big.endswith(b"\n"))
        self.assertGreater(len(good), 100)

    def test_member_level_defects(self):
        def members(name):
            pairs = []
            json.loads(pin_bytes(self.v[name]).decode("utf-8"),
                       object_pairs_hook=lambda p: pairs.append([k for k, _ in p]) or dict(p))
            return pairs[-1]
        self.assertEqual(members("pin/duplicate-key").count("org"), 2)
        self.assertEqual(members("pin/duplicate-key-differing-values").count("org"), 2)
        self.assertEqual(members("pin/reordered"), ["org", "genesis", "spec", "v"])
        self.assertEqual(sorted(members("pin/unknown-key")), ["foo", "genesis", "org", "spec", "v"])
        self.assertEqual(json.loads(pin_bytes(self.v["pin/v-wrong"]))["v"], "handsal-pin/2")
        raw = pin_bytes(self.v["pin/non-ascii"])
        self.assertTrue(any(b > 0x7e for b in raw))
        raw.decode("utf-8")

    def test_pin_content_rows_change_exactly_one_value(self):
        want = {"pin/genesis-mismatch": ("genesis", FX.wit_org_id),
                "pin/org-not-original": ("org", FX.wit_org_id),
                "pin/spec-not-last-profile": ("spec", base.production_profile())}
        for name, (key, value) in want.items():
            pin = json.loads(pin_bytes(self.v[name]))
            self.assertEqual(pin[key], value, name)
            for other, expect in {"genesis": FX.org_id, "org": FX.org_id,
                                  "spec": base.fixture_profile()}.items():
                if other != key:
                    self.assertEqual(pin[other], expect, (name, other))
        spec = json.loads(pin_bytes(self.v["pin/spec-mismatch"]))["spec"]
        self.assertTrue(base.is_hashstr(spec))
        self.assertNotIn(spec, (base.fixture_profile(), base.production_profile()))

    def test_duplicate_key_rows_differ_only_in_the_second_value(self):
        def org_values(name):
            pairs = []
            json.loads(pin_bytes(self.v[name]).decode("utf-8"),
                       object_pairs_hook=lambda p: pairs.append(p) or dict(p))
            return [value for key, value in pairs[-1] if key == "org"]
        self.assertEqual(org_values("pin/duplicate-key"), [FX.org_id, FX.org_id])
        self.assertEqual(org_values("pin/duplicate-key-differing-values"),
                         [FX.org_id, FX.wit_org_id])

    def test_lineage_original_not_org_changes_only_the_org_the_three_inputs_name(self):
        v = self.v["pin/lineage-original-not-org"]
        self.assertEqual((v["command"], v["anchor"]), ("fold", '{"error":"lineage_broken"}'))
        data = v["input"]
        other = FX.wit_org_id
        self.assertEqual(data["org"], other)
        self.assertEqual(data["lineage"], FX.lineage())   # the lineage is the original ORG's
        self.assertEqual(inputs.doc_id(data["lineage"][0]["doc"]), FX.org_id)
        self.assertNotEqual(inputs.doc_id(data["lineage"][0]["doc"]), other)
        probe = data["pin"]
        self.assertEqual((probe["org"], probe["filename"], probe["owner_ok"], probe["reason"]),
                         (other, inputs.filename_of(other), True, "ok"))
        pin = json.loads(pin_bytes(v))
        # steps (a) to (f) and the last-document comparison pass: only the first document is wrong
        self.assertEqual(pin, {"genesis": inputs.doc_id(data["lineage"][-1]["doc"]),
                               "org": other, "spec": base.fixture_profile(), "v": "handsal-pin/1"})
        self.assertEqual(catalog.anchor_code(v), catalog.catalog_code("pin/lineage-original-not-org"))

    def test_probe_rows(self):
        probe = self.v["pin/filename-mismatch"]["input"]["pin"]
        self.assertEqual(probe["filename"], inputs.filename_of(FX.wit_org_id))
        missing = self.v["pin/missing"]["input"]["pin"]
        self.assertEqual((missing["owner_ok"], missing["reason"]), (False, "pin_missing"))
        org_not_original = self.v["pin/org-not-original"]["input"]
        self.assertEqual(org_not_original["pin"]["org"], FX.org_id)
        self.assertEqual(org_not_original["pin"]["filename"], inputs.filename_of(FX.org_id))


if __name__ == "__main__":
    unittest.main()
