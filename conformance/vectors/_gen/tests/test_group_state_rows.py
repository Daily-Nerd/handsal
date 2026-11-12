"""Rows of key, sch, bod, gen and pol whose anchor is a fold state (FO-01, ACT-09 to ACT-11).

Each expectation is stated here from the spec: an invalid act leaves the genesis
state as it was (FO-06), a valid one adds its device and moves the tip (FO-22).
"""
import json
import unittest

from lib import base, forge, inputs, jcs, keys, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
GENESIS = state.anchor(state.State(FX.org))

KEY_ROWS = {"key/infinity-or-zero", "key/kid-not-thumbprint", "key/not-on-curve", "key/x-31-bytes",
            "key/x-leading-zero-ok", "key/y-33-bytes", "key/y-not-canonical-b64"}
SCH_ROWS = {"sch/chain-primary-with-head", "sch/endorse-missing-head"}
BOD_ROWS = {"bod/device-add-extra-key", "bod/device-add-missing-link-code",
            "bod/device-remove-extra-key", "bod/label-65", "bod/label-backslash",
            "bod/label-del", "bod/label-e-acute", "bod/label-empty", "bod/label-quote",
            "bod/member-add-role-unlisted"}
BOD_FORK_ROWS = {"bod/resolve-choose-not-hashstr", "bod/resolve-extra-key"}
GEN_ROWS = {"gen/ok-3-maintainers", "gen/junk-sig-ignored", "gen/duplicate-sig-same-kid-ok",
            "gen/sig-by-unlisted-key"}


def _bag(v):
    return [forge.parts(j)[1] for j in v["input"]["acts"]]


class Key(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("key", ["key"])

    def test_rows(self):
        self.assertEqual(set(self.v), KEY_ROWS)

    def test_every_row_folds_and_a_defective_key_leaves_the_genesis_state(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "fold", name)
            if name != "key/x-leading-zero-ok":
                self.assertEqual(v["anchor"], GENESIS, name)
                self.assertEqual(len(v["input"]["acts"]), 3, name)

    def test_the_leading_zero_key_is_added_and_the_tip_moves(self):
        v = self.v["key/x-leading-zero-ok"]
        out = json.loads(v["anchor"])
        key = FX.key("alice")
        crafted = [k for k in out["devices"]["alice"] if k != key.kid]
        self.assertEqual(len(crafted), 1)
        entry = out["devices"]["alice"][crafted[0]]
        self.assertEqual(base._unb64u(entry["sign"]["x"])[0], 0)
        self.assertEqual(len(base._unb64u(entry["sign"]["x"])), 32)
        self.assertEqual(out["tip"]["n"], "1")
        self.assertEqual(out["keys"]["alice"][crafted[0]]["status"], "active")

    def test_each_defect_is_in_the_body_of_the_primary(self):
        def body(name):
            return json.loads(_bag(self.v[name])[0])["ext"]["dev.handsal/act"]["body"]
        zero = "A" * 43
        self.assertEqual(body("key/infinity-or-zero")["sign"], {"x": zero, "y": zero})
        self.assertEqual(len(base._unb64u(body("key/x-31-bytes")["sign"]["x"])), 31)
        self.assertEqual(len(base._unb64u(body("key/y-33-bytes")["sign"]["y"])), 33)
        y = body("key/y-not-canonical-b64")["sign"]["y"]
        self.assertNotEqual(base._b64u(base._unb64u(y)), y)
        b = body("key/kid-not-thumbprint")
        self.assertNotEqual(b["kid"], keys.thumbprint(b["sign"]["x"], b["sign"]["y"]))
        b = body("key/not-on-curve")
        from lib import p256
        self.assertFalse(p256.on_curve((int.from_bytes(base._unb64u(b["sign"]["x"]), "big"),
                                        int.from_bytes(base._unb64u(b["sign"]["y"]), "big"))))
        # the kid names the strings as given, so the encoding or the curve is the only defect
        for name in ("key/infinity-or-zero", "key/x-31-bytes", "key/y-33-bytes",
                     "key/y-not-canonical-b64", "key/not-on-curve"):
            b = body(name)
            self.assertEqual(b["kid"], keys.thumbprint(b["sign"]["x"], b["sign"]["y"]), name)


class Sch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("sch", ["sch"])

    def test_rows_are_present_and_leave_the_genesis_state(self):
        for name in SCH_ROWS:
            self.assertEqual(self.v[name]["command"], "fold", name)
            self.assertEqual(self.v[name]["anchor"], GENESIS, name)

    def test_primary_with_head_has_a_head_in_its_act_object(self):
        act = json.loads(_bag(self.v["sch/chain-primary-with-head"])[0])["ext"]["dev.handsal/act"]
        self.assertEqual(act["head"], {"id": FX.org_id, "kind": "chain"})

    def test_endorsement_without_head_is_the_counted_one(self):
        bag = [json.loads(p) for p in _bag(self.v["sch/endorse-missing-head"])]
        acts = [p["ext"]["dev.handsal/act"] for p in bag]
        self.assertNotIn("head", acts[1])
        self.assertIn("head", acts[2])  # the proof of possession keeps its head


class Bod(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("bod", ["bod"])

    def test_rows(self):
        self.assertTrue((BOD_ROWS | BOD_FORK_ROWS) <= set(self.v))

    def test_a_defective_body_leaves_the_genesis_state(self):
        for name in BOD_ROWS:
            self.assertEqual(self.v[name]["command"], "fold", name)
            self.assertEqual(self.v[name]["anchor"], GENESIS, name)

    def test_label_rows_hold_the_bytes_the_alphabet_forbids(self):
        want = {"bod/label-quote": b'\\"', "bod/label-backslash": b"\\\\",
                "bod/label-e-acute": "é".encode("utf-8"), "bod/label-del": b"\x7f"}
        for name, needle in want.items():
            raw = _bag(self.v[name])[0]
            self.assertIn(needle, raw, name)
            self.assertEqual(jcs.recognize(raw)[0], False, name)  # the recognizer refuses it
        for name in ("bod/label-65", "bod/label-empty"):
            raw = _bag(self.v[name])[0]
            self.assertTrue(jcs.recognize(raw)[0], name)  # in the subset: a body_schema defect
        body = json.loads(_bag(self.v["bod/label-65"])[0])["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(len(body["label"]), 65)
        body = json.loads(_bag(self.v["bod/label-empty"])[0])["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["label"], "")

    def test_resolve_rows_fork_because_the_defective_resolve_is_ignored(self):
        for name in BOD_FORK_ROWS:
            obj = json.loads(self.v[name]["anchor"])
            self.assertEqual(sorted(obj), ["error", "fork"], name)
            self.assertEqual(obj["error"], "fork")
            self.assertEqual(obj["fork"]["parent"], FX.org_id)
            self.assertEqual(obj["fork"]["candidates"], sorted(obj["fork"]["candidates"]))
            self.assertEqual(len(obj["fork"]["candidates"]), 2)


class Gen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("gen", ["gen"])

    def test_rows_are_present(self):
        self.assertTrue(GEN_ROWS <= set(self.v))

    def test_every_row_is_the_org_state_at_position_zero(self):
        for name in GEN_ROWS:
            self.assertEqual(self.v[name]["command"], "fold", name)
            self.assertEqual(self.v[name]["anchor"], GENESIS, name)

    def test_signature_sets(self):
        def sigs(name):
            return self.v[name]["input"]["lineage"][0]["sigs"]
        self.assertEqual(len(sigs("gen/ok-3-maintainers")), 3)
        self.assertEqual(len(sigs("gen/duplicate-sig-same-kid-ok")), 4)
        kids = [json.loads(forge.parts(j)[0])["kid"] for j in sigs("gen/duplicate-sig-same-kid-ok")]
        self.assertEqual(kids.count(FX.key("alice").kid), 2)
        self.assertEqual(len(set(sigs("gen/duplicate-sig-same-kid-ok"))), 4)  # two receipt ids
        kids = [json.loads(forge.parts(j)[0])["kid"] for j in sigs("gen/sig-by-unlisted-key")]
        self.assertIn(FX.key("dave").kid, kids)
        self.assertEqual(len(sigs("gen/junk-sig-ignored")), 4)


class Pol(unittest.TestCase):
    def test_org3_2_of_3_ok_is_the_org_state(self):
        v = catalog.generate_group("pol", ["pol"])["pol/org3-2-of-3-ok"]
        self.assertEqual(v["command"], "fold")
        self.assertEqual(v["anchor"], GENESIS)
        rules = FX.org["policy"]["rules"]
        self.assertTrue(all(r["persons"] == "2" for r in rules.values()))


if __name__ == "__main__":
    unittest.main()
