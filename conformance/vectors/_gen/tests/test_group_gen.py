"""T3.15 vectors gen/* (GP-01, GP-03, GP-15 order) through `fold` errors.

Rows whose expectation is a fold state are not written here (they wait for the
FO-01 state anchor builder). Every written row is one genesis defect: the test
states, independently of the module, which document paths each row may touch.
"""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
CHANGE = inputs.change_doc(FX)

# original-document rows: row -> document paths the single defect may touch
ORIGINAL = {
    "gen/agree-equals-sign": [("devices",)],
    "gen/device-not-accepted-class": [("devices",)],
    "gen/device-person-unlisted": [("devices",)],
    "gen/duplicate-agree-key": [("devices",)],
    "gen/duplicate-kid-across-persons": [("devices",)],
    "gen/duplicate-member-id": [("members",)],
    "gen/extra-key": [("extra",)],
    "gen/key-not-on-curve": [("devices",)],
    "gen/kid-not-thumbprint": [("devices",)],
    "gen/member-no-device": [("devices",)],
    "gen/member-role-unlisted": [("members",)],
    "gen/missing-key": [("name",)],
    "gen/name-25": [("name",)],
    "gen/org-nonnull-original": [("org",)],
    "gen/order-policy-before-device-class": [("policy", "classes")],
    "gen/order-profile-before-class": [("profile",), ("policy", "classes")],
    "gen/order-profile-before-fixture-key": [("profile",)],
    "gen/profile-mismatch": [("profile",)],
    "gen/render-too-large": [("devices",), ("members",)],
    "gen/unsorted-devices": [("devices",)],
    "gen/unsorted-members": [("members",)],
    "gen/unsorted-roles": [("policy", "roles")],
    "gen/v-wrong": [("v",)],
    "gen/zero-members": [("members",)],
    "gen/prev-nonnull-no-lineage": [("org",), ("prev",), ("head",)],
}
# signature rows: the document is ORG, the defect is in alice's signature
SIGS = {"gen/missing-maintainer-sig", "gen/sig-over-other-doc", "gen/sig-parent-nonnull-ignored",
        "gen/sig-performer-mismatch-ignored", "gen/sign-act-kid-differs-unsigned",
        "gen/sign-body-not-empty-unsigned"}
# two-document rows: the second document is a change of ORG
CHANGES = {
    "gen/order-schema-before-lineage": [("members",), ("prev",)],
    "gen/order-lineage-before-unsigned": [("prev",)],
    "gen/order-unsigned-before-head": [("head",)],
    "gen/order-lineage-before-render": [("prev",), ("devices",), ("members",)],
}
SKIPPED = {
    "gen/order-revoked-before-changed", "gen/order-unauthorized-before-carry",  # need removal chains
}


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


def covered(diff, prefixes):
    return (all(any(p[:len(x)] == x for x in prefixes) for p in diff)
            and all(any(p[:len(x)] == x for p in diff) for x in prefixes))


def alice_sig_act(v):
    """The act object and payload of the signature whose person is alice."""
    for jws in v["input"]["lineage"][-1]["sigs"]:
        payload = json.loads(forge.parts(jws)[1])
        if payload["performer_id"] == "alice" or payload["ext"]["dev.handsal/act"]["kid"] == FX.key("alice").kid:
            return payload
    return None


# fold-state rows, covered by tests/test_group_state_rows.py
STATE_ROWS = {"gen/ok-3-maintainers", "gen/junk-sig-ignored", "gen/duplicate-sig-same-kid-ok",
              "gen/sig-by-unlisted-key"}


class Gen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("gen", ["gen"])

    def test_rows(self):
        self.assertEqual(set(self.v), set(ORIGINAL) | SIGS | set(CHANGES) | STATE_ROWS)
        self.assertFalse(SKIPPED & set(self.v))

    def test_every_row_is_fold_with_the_catalog_error(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "fold", name)
            self.assertEqual(sorted(v["input"]), ["acts", "lineage", "org", "pin"], name)
            if name not in STATE_ROWS:
                self.assertEqual(v["anchor"], '{"error":"%s"}' % catalog.catalog_code(name), name)

    def test_org_and_pin_follow_the_documents(self):
        for name, v in self.v.items():
            inp = v["input"]
            self.assertEqual(inp["org"], inputs.doc_id(inp["lineage"][0]["doc"]), name)
            self.assertEqual(inp["pin"], inputs.probe_for(inp["lineage"]), name)

    def test_original_rows_have_one_document_defect(self):
        for name, prefixes in ORIGINAL.items():
            lin = self.v[name]["input"]["lineage"]
            self.assertEqual(len(lin), 1, name)
            if name == "gen/prev-nonnull-no-lineage":
                continue
            self.assertTrue(covered(changed(FX.org, lin[0]["doc"]), prefixes), name)

    def test_prev_nonnull_row_is_a_change_shaped_document_alone(self):
        doc = self.v["gen/prev-nonnull-no-lineage"]["input"]["lineage"][0]["doc"]
        self.assertTrue(covered(changed(FX.org, doc), ORIGINAL["gen/prev-nonnull-no-lineage"]))
        self.assertEqual(base.check_genesis_shape(doc), [])

    def test_unsorted_rows_are_sorted_lists_reversed(self):
        for name, path in (("gen/unsorted-devices", ("devices",)), ("gen/unsorted-members", ("members",))):
            doc = self.v[name]["input"]["lineage"][0]["doc"]
            self.assertEqual(doc[path[0]], list(reversed(FX.org[path[0]])), name)
        roles = self.v["gen/unsorted-roles"]["input"]["lineage"][0]["doc"]["policy"]["roles"]
        self.assertEqual(roles, ["member", "maintainer"])

    def test_device_defect_rows_keep_the_lists_sorted_by_kid(self):
        for name in ("gen/key-not-on-curve", "gen/kid-not-thumbprint", "gen/agree-equals-sign",
                     "gen/duplicate-agree-key", "gen/duplicate-kid-across-persons"):
            kids = [d["kid"] for d in self.v[name]["input"]["lineage"][0]["doc"]["devices"]]
            self.assertEqual(kids, sorted(kids), name)

    def test_the_curve_and_thumbprint_rows(self):
        from lib import keys, p256
        doc = self.v["gen/key-not-on-curve"]["input"]["lineage"][0]["doc"]
        bad = [d for d in doc["devices"] if d["kid"] not in {e["kid"] for e in FX.org["devices"]}]
        self.assertEqual(len(bad), 1)
        x, y = (int.from_bytes(base._unb64u(bad[0]["sign"][c]), "big") for c in "xy")
        self.assertFalse(p256.on_curve((x, y)))
        self.assertEqual(bad[0]["kid"], keys.thumbprint(bad[0]["sign"]["x"], bad[0]["sign"]["y"]))
        doc = self.v["gen/kid-not-thumbprint"]["input"]["lineage"][0]["doc"]
        wrong = [d for d in doc["devices"] if d["kid"] != keys.thumbprint(d["sign"]["x"], d["sign"]["y"])]
        self.assertEqual(len(wrong), 1)

    def test_render_too_large_has_13_members_and_13_devices(self):
        doc = self.v["gen/render-too-large"]["input"]["lineage"][0]["doc"]
        self.assertEqual((len(doc["members"]), len(doc["devices"])), (13, 13))
        self.assertEqual(base.check_genesis_shape(doc), [])

    def test_signature_rows_keep_the_document_and_damage_alices_signature(self):
        for name in SIGS:
            lin = self.v[name]["input"]["lineage"]
            self.assertEqual(len(lin), 1)
            self.assertEqual(lin[0]["doc"], FX.org, name)
        sigs = lambda n: self.v[n]["input"]["lineage"][0]["sigs"]
        self.assertEqual(len(sigs("gen/missing-maintainer-sig")), 2)
        alice = FX.key("alice").kid
        self.assertNotIn(alice, [json.loads(forge.parts(j)[0])["kid"] for j in sigs("gen/missing-maintainer-sig")])
        for name in SIGS - {"gen/missing-maintainer-sig"}:
            self.assertEqual(len(sigs(name)), 3, name)
        p = alice_sig_act(self.v["gen/sig-parent-nonnull-ignored"])
        self.assertEqual(p["parent_receipt_hash"], FX.org_id)
        self.assertEqual(alice_sig_act(self.v["gen/sig-performer-mismatch-ignored"])["performer_id"], "bob")
        a = alice_sig_act(self.v["gen/sign-act-kid-differs-unsigned"])["ext"]["dev.handsal/act"]
        self.assertEqual(a["kid"], FX.key("bob").kid)
        b = alice_sig_act(self.v["gen/sign-body-not-empty-unsigned"])["ext"]["dev.handsal/act"]
        self.assertEqual(b["body"], {"x": "y"})
        other = alice_sig_act(self.v["gen/sig-over-other-doc"])
        self.assertEqual(other["inputs_hash"], FX.wit_org_id)

    def test_change_rows_are_an_original_then_a_change(self):
        for name, prefixes in CHANGES.items():
            lin = self.v[name]["input"]["lineage"]
            self.assertEqual(len(lin), 2, name)
            self.assertEqual(lin[0]["doc"], FX.org, name)
            self.assertEqual(len(lin[0]["sigs"]), 3, name)
            self.assertTrue(covered(changed(CHANGE, lin[1]["doc"]), prefixes), name)
        self.assertEqual(len(self.v["gen/order-lineage-before-render"]["input"]["lineage"][1]["doc"]["devices"]), 16)
        self.assertEqual(self.v["gen/order-unsigned-before-head"]["input"]["lineage"][1]["sigs"] != [], True)

    def test_wrong_prev_rows(self):
        for name in ("gen/order-schema-before-lineage", "gen/order-lineage-before-unsigned",
                     "gen/order-lineage-before-render"):
            doc = self.v[name]["input"]["lineage"][1]["doc"]
            self.assertNotEqual(doc["prev"], FX.org_id, name)
            self.assertTrue(base.is_hashstr(doc["prev"]))
        self.assertEqual(self.v["gen/order-lineage-before-unsigned"]["input"]["lineage"][1]["sigs"], [])


if __name__ == "__main__":
    unittest.main()
