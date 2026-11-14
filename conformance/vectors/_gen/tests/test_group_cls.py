"""Vectors cls/*: key classes, accepted and unproven keys (KC-01 to KC-08, FO-02).

Written: 20 ids (three duplicates of other rows are retired: the catalog says why). Not written, with the reason (the catalog lists them, the spec cannot back a
vector):
- `cls/tagged-registry-no-pending` is retired: a property of the registry file at the tag (KC-02),
  not the output of a command; `check_catalog.py --final` proves it.
- `cls/pending-class-accepted`, `cls/win-hello-biometric-only-maintainer-ok` and
  `cls/win-hello-pin-capable-maintainer-refused` are retired for the macOS-only first tag: the
  registry has no Windows class, and a tagged registry holds no `pending-spike` class (KC-02), so
  `class_pending` is proven by implementation tests on a registry built for them.
"""
import base64
import json
import tempfile
import unittest

import generate
from groups import cls as groups_cls
from lib import base, forge, inputs, rules, state
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
ORG_STATE = state.anchor(state.State(FX.org))

GENESIS_ERRORS = {
    "cls/unknown-class-genesis": "class_unknown",
    "cls/test-class-listed": "class_test_only",
    "cls/uv-mismatch": "class_policy_mismatch",
    "cls/role-holder-pin-genesis-refused": "role_key_class",
    "cls/ed25519-device": "genesis_schema",
}
STATE_ROWS = {"cls/nonrole-pin-device-ok"}
NOT_ON_CHAIN = {
    "cls/unknown-class-device-add", "cls/role-holder-unaccepted-pin-class-not-on-chain",
    "cls/unproven-endorsement-ignored", "cls/unproven-self-remove-ignored",
    "cls/unproven-vote-not-counted", "cls/pin-key-never-counts",
    "cls/role-holder-pin-device-add-not-on-chain", "cls/role-holder-pin-member-add-not-on-chain",
}
CHAIN_OK = {"cls/role-holder-biometric-member-add-ok"}
CHECK_ACT = {
    "cls/verdict-unproven": ("unproven_class", "fixture-pin"),
    "cls/test-class-key-unproven": ("unproven_class", "test-sw-p256"),
    "cls/policy-swap-human": ("ok", "fixture-pin"),
    "cls/vitni-ok-not-approval": ("stale_view", "apple-se-bio"),
}
WRITTEN = set(GENESIS_ERRORS) | STATE_ROWS | NOT_ON_CHAIN | CHAIN_OK | set(CHECK_ACT)
NOT_WRITTEN = set()    # the catalog group is exactly the written ids


def _payload(jws):
    return json.loads(forge.parts(jws)[1])


def _act(jws):
    return _payload(jws)["ext"]["dev.handsal/act"]


def _diff(a, b, path=()):
    """The paths where JSON values `a` and `b` differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += _diff(a.get(key), b.get(key), path + (key,))
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += _diff(x, y, path + (i,))
        return out
    return [] if a == b else [path]


class Cls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("cls", ["cls"])

    def test_rows(self):
        self.assertEqual(set(self.v), WRITTEN)

    def test_written_and_unwritten_ids_are_the_catalog_group(self):
        group = {k for k in catalog.ROWS if k.startswith("cls/")}
        self.assertEqual(WRITTEN | NOT_WRITTEN, group)
        self.assertFalse(WRITTEN & NOT_WRITTEN)

    def test_commands(self):
        for name in WRITTEN:
            want = "check-act" if name in CHECK_ACT else "fold"
            self.assertEqual(self.v[name]["command"], want, name)

    # genesis documents -------------------------------------------------------------------
    def doc(self, name):
        return self.v[name]["input"]["lineage"][-1]["doc"]

    def test_a_genesis_row_gives_the_error_the_catalog_and_the_class_model_give(self):
        for name, code in GENESIS_ERRORS.items():
            self.assertEqual(json.loads(self.v[name]["anchor"]), {"error": code}, name)
            self.assertEqual(catalog.catalog_code(name), code, name)
            if code != "genesis_schema":
                self.assertEqual(rules.genesis_classes(self.doc(name), fixture=True), code, name)

    def test_every_listed_device_signs_every_document_of_a_row(self):
        # GP-15 step 6: a device without a counting signature is `genesis_unsigned`
        for name in set(GENESIS_ERRORS) | STATE_ROWS | NOT_ON_CHAIN | CHAIN_OK:
            for entry in self.v[name]["input"]["lineage"]:
                signers = {json.loads(forge.parts(j)[0])["kid"] for j in entry["sigs"]}
                self.assertEqual(signers, {d["kid"] for d in entry["doc"]["devices"]}, name)

    def test_a_class_row_differs_from_org_in_the_policy_classes_and_nothing_else(self):
        for name in ("cls/unknown-class-genesis", "cls/test-class-listed", "cls/uv-mismatch"):
            changed = {p[:2] for p in _diff(self.doc(name), FX.org)}
            self.assertEqual(changed, {("policy", "classes")}, name)

    def test_the_policy_pairs_are_the_ones_the_row_names(self):
        pairs = {n: self.doc(n)["policy"]["classes"] for n in GENESIS_ERRORS}
        self.assertIn({"class": "yubikey-piv", "user_verification": "biometric_only"},
                      pairs["cls/unknown-class-genesis"])
        self.assertIn({"class": "test-sw-p256", "user_verification": "none"},
                      pairs["cls/test-class-listed"])
        self.assertEqual(pairs["cls/uv-mismatch"],
                         [{"class": "apple-se-bio", "user_verification": "biometric_or_pin"}])
        for name, classes in pairs.items():
            self.assertEqual([c["class"] for c in classes], sorted({c["class"] for c in classes}), name)

    def test_the_ed25519_row_adds_an_alg_member_to_one_device_entry(self):
        doc = self.doc("cls/ed25519-device")
        changed = _diff(doc, FX.org)
        self.assertEqual(len(changed), 1)
        path = changed[0]
        self.assertEqual((path[0], path[2]), ("devices", "alg"))
        self.assertIn("alg", doc["devices"][path[1]])
        self.assertEqual({k for k in doc["devices"][path[1]]} - {"alg"},
                         {"agree", "class", "kid", "label", "person", "sign"})

    def test_the_role_holder_pin_genesis_gives_alice_a_second_device_of_a_pin_class(self):
        doc = self.doc("cls/role-holder-pin-genesis-refused")
        mine = [d for d in doc["devices"] if d["person"] == "alice"]
        self.assertEqual(sorted(d["class"] for d in mine), ["apple-se-bio", "fixture-pin"])
        dave = [d for d in doc["devices"] if d["person"] == "dave"]
        self.assertEqual([d["class"] for d in dave], ["fixture-pin"])

    # PINORG ------------------------------------------------------------------------------
    def test_the_two_state_rows_are_pinorg_with_only_dave_holding_the_pin_device(self):
        for name in STATE_ROWS:
            v = self.v[name]
            doc = v["input"]["lineage"][-1]["doc"]
            self.assertEqual(rules.genesis_classes(doc, fixture=True), None, name)
            self.assertEqual(doc["members"][-1], {"id": "dave", "role": "member"}, name)
            pins = [d for d in doc["devices"] if d["class"] == "fixture-pin"]
            self.assertEqual([d["person"] for d in pins], ["dave"], name)
            self.assertIn({"class": "fixture-pin", "user_verification": "biometric_or_pin"},
                          doc["policy"]["classes"], name)
            out = json.loads(v["anchor"])
            self.assertTrue(out["devices"]["dave"][pins[0]["kid"]]["accepted"], name)
            self.assertIn(pins[0]["kid"], out["keys"]["dave"], name)

    def test_pinorg_differs_from_org_only_where_the_catalog_says(self):
        doc = self.doc("cls/nonrole-pin-device-ok")
        top = {p[0] for p in _diff(doc, FX.org)}
        self.assertEqual(top, {"devices", "members", "policy"})
        self.assertEqual(doc["org"], None)
        self.assertEqual(doc["prev"], None)
        self.assertEqual(json.loads(self.v["cls/nonrole-pin-device-ok"]["anchor"])["tip"]["n"], "0")

    # acts --------------------------------------------------------------------------------
    def bag(self, name):
        return [json.loads(forge.parts(j)[1])["ext"]["dev.handsal/act"] | {
            "method": _payload(j)["method"]} for j in self.v[name]["input"]["acts"]]

    def test_every_not_on_chain_row_leaves_the_state_of_its_valid_acts(self):
        for name in NOT_ON_CHAIN:
            v = self.v[name]
            out = json.loads(v["anchor"])
            self.assertNotIn("error", out, name)
            self.assertIn(out["tip"]["n"], ("0", "2"), name)  # 0, or after dave's two valid acts

    def test_the_rows_that_start_from_org_or_pinorg_have_those_documents(self):
        pinorg = self.doc("cls/nonrole-pin-device-ok")
        for name, doc in (("cls/unknown-class-device-add", FX.org),
                          ("cls/role-holder-unaccepted-pin-class-not-on-chain", FX.org),
                          ("cls/unproven-endorsement-ignored", FX.org),
                          ("cls/unproven-self-remove-ignored", FX.org),
                          ("cls/unproven-vote-not-counted", FX.org),
                          ("cls/pin-key-never-counts", pinorg),
                          ("cls/role-holder-pin-device-add-not-on-chain", pinorg),
                          ("cls/role-holder-pin-member-add-not-on-chain", pinorg),
                          ("cls/role-holder-biometric-member-add-ok", pinorg)):
            self.assertEqual(self.v[name]["input"]["lineage"][-1]["doc"], doc, name)

    def test_the_defect_act_of_each_row(self):
        def last_primary(name):
            return [a for a in self.bag(name) if a["method"] != "local:handsal.act.endorse"][-1]

        body = last_primary("cls/unknown-class-device-add")["body"]
        self.assertEqual(body["class"], "yubikey-piv")
        self.assertEqual(body["person"], "alice")
        for name in ("cls/role-holder-unaccepted-pin-class-not-on-chain",
                     "cls/role-holder-pin-device-add-not-on-chain"):
            body = last_primary(name)["body"]
            self.assertEqual((body["class"], body["person"]), ("fixture-pin", "alice"), name)
        body = last_primary("cls/role-holder-pin-member-add-not-on-chain")["body"]
        self.assertEqual((body["device"]["class"], body["role"], body["member"]),
                         ("fixture-pin", "maintainer", "frank"))
        body = last_primary("cls/role-holder-biometric-member-add-ok")["body"]
        self.assertEqual((body["device"]["class"], body["role"], body["member"]),
                         ("apple-se-bio", "maintainer", "frank"))
        self.assertEqual(last_primary("cls/unproven-vote-not-counted")["method"],
                         "local:handsal.member.add")
        self.assertEqual(last_primary("cls/unproven-self-remove-ignored")["method"],
                         "local:handsal.device.remove")

    def test_the_endorser_or_primary_that_does_not_count_is_the_key_the_row_names(self):
        dave2 = FX.key("dave2").kid
        for name in ("cls/unproven-endorsement-ignored", "cls/unproven-vote-not-counted"):
            kids = [json.loads(forge.parts(j)[0])["kid"] for j in self.v[name]["input"]["acts"]]
            self.assertIn(dave2, kids[-3:], name)
        removal = [j for j in self.v["cls/unproven-self-remove-ignored"]["input"]["acts"]
                   if _payload(j)["method"] == "local:handsal.device.remove"][0]
        self.assertEqual(json.loads(forge.parts(removal)[0])["kid"], dave2)
        self.assertEqual(_act(removal)["body"]["kid"], dave2)
        pin = self.v["cls/pin-key-never-counts"]["input"]["acts"]
        self.assertEqual([json.loads(forge.parts(j)[0])["kid"] for j in pin][:2],
                         [FX.key("alice").kid, FX.key("dave").kid])

    def test_the_applied_row_adds_frank_as_a_maintainer_with_an_accepted_device(self):
        out = json.loads(self.v["cls/role-holder-biometric-member-add-ok"]["anchor"])
        self.assertEqual(out["tip"]["n"], "1")
        (device,) = out["devices"]["frank"].values()
        self.assertEqual((device["class"], device["accepted"]), ("apple-se-bio", True))

    # check-act ---------------------------------------------------------------------------
    def test_check_act_rows(self):
        for name, (reason, cls) in CHECK_ACT.items():
            out = json.loads(self.v[name]["anchor"])
            self.assertEqual((out["reason"], out["class"], out["valid"]),
                             (reason, cls, reason == "ok"), name)
            inp = self.v[name]["input"]
            self.assertEqual(out["receipt_id"], inputs.receipt_id(inp["jws"]), name)

    def test_the_unproven_rows_are_verdicts_by_dave2_of_the_listed_class(self):
        for name, method, cls in (
                ("cls/verdict-unproven", inputs.APPROVE, "fixture-pin"),
                ("cls/test-class-key-unproven", inputs.APPROVE, "test-sw-p256")):
            inp = self.v[name]["input"]
            self.assertEqual(inp["expect_method"], method, name)
            self.assertEqual(_payload(inp["jws"])["method"], method, name)
            self.assertEqual(json.loads(forge.parts(inp["jws"])[0])["kid"], FX.key("dave2").kid, name)
            self.assertEqual(inp["recipient"], "dave", name)
            added = [_act(j)["body"] for j in inp["acts"]
                     if _payload(j)["method"] == "local:handsal.device.add"]
            self.assertEqual([b["class"] for b in added], [cls], name)
            self.assertNotIn(cls, [c["class"] for c in inp["lineage"][-1]["doc"]["policy"]["classes"]], name)

    def test_the_policy_swap_row_has_the_same_acts_and_a_policy_that_lists_the_class(self):
        swap, plain = self.v["cls/policy-swap-human"]["input"], self.v["cls/verdict-unproven"]["input"]
        self.assertEqual({p[:2] for p in _diff(swap["lineage"][-1]["doc"], FX.org)}, {("policy", "classes")})
        self.assertIn({"class": "fixture-pin", "user_verification": "biometric_or_pin"},
                      swap["lineage"][-1]["doc"]["policy"]["classes"])
        self.assertEqual(swap["org"], inputs.doc_id(swap["lineage"][-1]["doc"]))
        self.assertEqual(_act(swap["jws"])["org"], swap["org"])
        self.assertEqual(len(swap["acts"]), len(plain["acts"]))
        self.assertEqual(rules.genesis_classes(swap["lineage"][-1]["doc"], fixture=True), None)

    def test_the_vitni_rows(self):
        stale = self.v["cls/vitni-ok-not-approval"]["input"]
        self.assertEqual(stale["synced_at"], base.shift(base.NOW, -86401))
        self.assertEqual(_act(stale["jws"])["kid"], FX.key("alice").kid)

    def test_the_vitni_direct_check_is_a_negative_act_and_no_vector(self):
        """FO-02: no vector of its own (its bytes are those of `fld/unaccepted-not-in-keys`), but
        both vitni binaries still answer `unknown_key` for dave2's verdict at generation time."""
        for retired in ("cls/vitni-direct-unknown-key", "cls/biometric-or-pin-listed-ok",
                        "cls/biometric-or-pin-not-listed-unproven"):
            self.assertNotIn(retired, self.v)
            self.assertNotIn(retired, generate.shipping_ids())
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[groups_cls], known_ids=generate.shipping_ids(), stats=stats)
        self.assertEqual(stats["negatives"], 1)


if __name__ == "__main__":
    unittest.main()
