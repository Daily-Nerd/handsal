"""T3.15 vectors pol/* (GP-02, GP-15 step 3) through `fold` errors.

`pol/org3-2-of-3-ok` expects a state and waits for the FO-01 state anchor
builder. `pol/missing-policy` is `policy_invalid`: GP-01 leaves the presence
of `policy` to GP-02.
"""
import unittest

from lib import base, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
CHANGE = inputs.change_doc(FX)
POL = ("policy",)

# row -> document paths the single defect may touch (the document is ORG or ORG's change)
ROWS = {
    "pol/device-remove-keys-form": [POL + ("rules", "device.remove")],
    "pol/duplicate-class-entry": [POL + ("classes",)],
    "pol/empty-accepted-classes": [POL + ("classes",)],
    "pol/empty-from": [POL + ("rules", "member.add", "roles")],
    "pol/extra-policy-key": [POL + ("x",)],
    "pol/max-validity-over-30d": [POL + ("freshness", "max_validity_s")],
    "pol/max-view-age-too-large": [POL + ("freshness", "max_view_age_s")],
    "pol/max-view-age-too-small": [POL + ("freshness", "max_view_age_s")],
    "pol/missing-freshness": [POL + ("freshness",)],
    "pol/missing-policy": [POL],
    "pol/missing-quorum-rule-device-remove-other": [POL + ("rules", "device.remove")],
    "pol/missing-quorum-rule-genesis-change": [POL + ("rules", "genesis.change")],
    "pol/missing-quorum-rule-member-add": [POL + ("rules", "member.add")],
    "pol/missing-rule-chain-resolve": [POL + ("rules", "chain.resolve")],
    "pol/persons-16-out-of-bounds": [POL + ("rules", "chain.resolve", "persons")],
    "pol/persons-equals-role-holders-refused": [POL + ("rules", "device.remove", "persons")],
    "pol/persons-one-refused": [POL + ("rules", "device.remove", "persons")],
    "pol/rule-role-unlisted": [POL + ("rules", "chain.resolve", "roles")],
    "pol/skew-3601": [POL + ("freshness", "clock_skew_s")],
    "pol/threshold-unreachable": [POL + ("rules", "device.remove", "persons")],
    "pol/threshold-zero": [POL + ("rules", "device.remove", "persons")],
    "pol/v-wrong": [POL + ("v",)],
}
# rows that also change who is in the organization
MEMBERS = {
    "pol/single-person-org-unreachable": [("devices",), ("members",)],
    "pol/two-person-org-refused": [("devices",), ("members",)],
    "pol/spare-counted-per-rule-roles": [("members",), POL + ("roles",), POL + ("rules",)],
}
# change rows: a change of ORG
CHANGES = {
    "pol/change-removing-spare-refused": [("devices",), ("members",)],
    "pol/persons-one-in-change-refused": [POL + ("rules", "member.add", "persons")],
}
SKIPPED = set()  # pol/org3-2-of-3-ok is a state row now


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


class Pol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("pol", ["pol"])

    def doc(self, name, index=0):
        return self.v[name]["input"]["lineage"][index]["doc"]

    def test_rows(self):
        self.assertEqual(set(self.v), set(ROWS) | set(MEMBERS) | set(CHANGES) | {"pol/org3-2-of-3-ok"})
        self.assertFalse(SKIPPED & set(self.v))

    def test_every_row_is_fold_with_the_catalog_error(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "fold", name)
            self.assertEqual(sorted(v["input"]), ["acts", "lineage", "org", "pin"], name)
            if name != "pol/org3-2-of-3-ok":  # a state row, see test_group_state_rows.py
                self.assertEqual(v["anchor"], '{"error":"%s"}' % catalog.catalog_code(name), name)
            self.assertEqual(v["input"]["org"], inputs.doc_id(v["input"]["lineage"][0]["doc"]))
            self.assertEqual(v["input"]["pin"], inputs.probe_for(v["input"]["lineage"]))

    def test_each_row_has_one_policy_defect(self):
        for name, prefixes in ROWS.items():
            self.assertEqual(len(self.v[name]["input"]["lineage"]), 1, name)
            self.assertTrue(covered(changed(FX.org, self.doc(name)), prefixes), name)
        for name, prefixes in MEMBERS.items():
            self.assertEqual(len(self.v[name]["input"]["lineage"]), 1, name)
            self.assertTrue(covered(changed(FX.org, self.doc(name)), prefixes), name)
        for name, prefixes in CHANGES.items():
            lin = self.v[name]["input"]["lineage"]
            self.assertEqual(len(lin), 2, name)
            self.assertEqual(lin[0]["doc"], FX.org)
            self.assertTrue(covered(changed(CHANGE, lin[1]["doc"]), prefixes), name)

    def test_values(self):
        rules = lambda n, r: self.doc(n)["policy"]["rules"][r]["persons"]
        self.assertEqual(rules("pol/persons-16-out-of-bounds", "chain.resolve"), "16")
        self.assertEqual(rules("pol/persons-equals-role-holders-refused", "device.remove"), "3")
        self.assertEqual(rules("pol/persons-one-refused", "device.remove"), "1")
        self.assertEqual(rules("pol/threshold-unreachable", "device.remove"), "4")
        self.assertEqual(rules("pol/threshold-zero", "device.remove"), "0")
        fr = lambda n, k: self.doc(n)["policy"]["freshness"][k]
        self.assertEqual(fr("pol/max-validity-over-30d", "max_validity_s"), "2592001")
        self.assertEqual(fr("pol/max-view-age-too-large", "max_view_age_s"), "2592001")
        self.assertEqual(fr("pol/max-view-age-too-small", "max_view_age_s"), "59")
        self.assertEqual(fr("pol/skew-3601", "clock_skew_s"), "3601")
        self.assertEqual(self.doc("pol/v-wrong")["policy"]["v"], "handsal-policy/2")
        self.assertEqual(self.doc("pol/empty-accepted-classes")["policy"]["classes"], [])
        classes = self.doc("pol/duplicate-class-entry")["policy"]["classes"]
        self.assertEqual(len(classes), 2)
        self.assertEqual(classes[0], classes[1])

    def test_organizations_of_one_and_two(self):
        self.assertEqual([m["id"] for m in self.doc("pol/single-person-org-unreachable")["members"]],
                         ["alice"])
        self.assertEqual([m["id"] for m in self.doc("pol/two-person-org-refused")["members"]],
                         ["alice", "bob"])
        for name in ("pol/single-person-org-unreachable", "pol/two-person-org-refused"):
            doc = self.doc(name)
            self.assertEqual({d["person"] for d in doc["devices"]}, {m["id"] for m in doc["members"]})
            self.assertEqual(doc["policy"]["rules"]["device.remove"]["persons"], "2")

    def test_spare_is_counted_per_rule_roles(self):
        doc = self.doc("pol/spare-counted-per-rule-roles")
        lead = [m["id"] for m in doc["members"] if m["role"] == "lead"]
        self.assertEqual(len(lead), 2)
        self.assertEqual(doc["policy"]["rules"]["chain.resolve"], {"persons": "2", "roles": ["lead"]})
        holders = {m["id"] for m in doc["members"]}
        for rule in ("device.remove", "genesis.change", "member.add"):
            r = doc["policy"]["rules"][rule]
            self.assertLess(int(r["persons"]),
                            sum(1 for m in doc["members"] if m["role"] in r["roles"]))
        self.assertEqual(len(holders), 3)

    def test_change_rows(self):
        drop = self.doc("pol/change-removing-spare-refused", 1)
        self.assertEqual([m["id"] for m in drop["members"]], ["alice", "bob"])
        self.assertEqual(self.doc("pol/persons-one-in-change-refused", 1)
                         ["policy"]["rules"]["member.add"]["persons"], "1")
        for name in CHANGES:
            doc = self.doc(name, 1)
            self.assertEqual((doc["org"], doc["prev"], doc["head"]), (FX.org_id,) * 3)


if __name__ == "__main__":
    unittest.main()
