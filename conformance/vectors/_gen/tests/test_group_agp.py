"""Vectors agp/*: `agree-points` (CF-16). Each row is stated from the spec, not from a checker.

The input is the snapshot of CF-13, `{acts, docs, org}`. The anchor is `{active, pool, reason}`: the `agree` points of
the devices that count now, and of every device the organization ever introduced, each list unique and sorted by `x`
then `y`; a refusal carries `null` for both. The expected devices of every row are written here by name, from the
sentences of CF-16 (S1 to S9), and read back through the fixture keys.
"""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
GEN = ("alice", "bob", "carol")

# name: (devices in `active`, devices in `pool`), by device name; `agree` points only
LISTS = {
    "agp/active-genesis-device": (GEN + ("alice2",), GEN + ("alice2",)),
    "agp/removed-device": (GEN, GEN + ("alice2",)),
    "agp/empty-acts-genesis-devices": (GEN, GEN),
    "agp/removed-on-one-fork-branch": (GEN + ("alice2", "bob2"), GEN + ("alice2", "bob2")),   # S6: in `active`
    "agp/removed-on-all-branches": (GEN, GEN + ("alice2",)),   # S6: not in `active`
    "agp/added-on-losing-branch-only": (GEN + ("alice2",), GEN + ("alice2", "alice3")),   # S7
    "agp/pending-add-in-neither": (GEN, GEN),   # S8
    "agp/sign-point-in-neither": (GEN + ("alice2", "bob2"), GEN + ("alice2", "bob2")),   # S8
    "agp/sibling-epochs-both-active": (("alice", "bob", "grace", "frank"), GEN + ("grace", "frank")),   # S9
    "agp/change-drops-device": (("alice", "bob", "grace"), GEN + ("grace",)),   # S9
    "agp/unaccepted-device-pool-only": (GEN + ("dave",), GEN + ("dave", "dave2")),   # S8
    "agp/same-point-two-epochs-once": (GEN + ("grace", "frank"), GEN + ("grace", "frank")),   # S9
}
REFUSED = {"agp/lineage-broken-refused": "lineage_broken", "agp/fixture-profile-refused": "fixture_profile"}


def points(names):
    found = {(p["x"], p["y"]): p for p in (FX.key(n, "agree").point() for n in names)}
    return [found[k] for k in sorted(found)]


def payload(jws):
    return json.loads(forge.parts(jws)[1])


def methods(acts):
    return [payload(a)["method"].split("local:handsal.")[-1] for a in acts]


class AgpRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(("agp",), ("agp",))

    def answer(self, name):
        return json.loads(self.v[name]["anchor"])

    def test_rows_are_the_fourteen_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("agp/")})
        self.assertEqual(set(self.v), set(LISTS) | set(REFUSED))
        self.assertEqual(len(self.v), 14)

    def test_every_row_is_an_agree_points_of_the_closed_snapshot_with_the_catalog_code(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "agree-points", name)
            self.assertEqual(sorted(v["input"]), ["acts", "docs", "org"], name)
            self.assertEqual(v["input"]["org"], FX.org_id, name)
            self.assertEqual(sorted(self.answer(name)), ["active", "pool", "reason"], name)
            self.assertEqual(self.answer(name)["reason"], catalog.catalog_code(name), name)

    def test_the_lists_of_each_row_are_the_devices_the_sentence_names(self):
        for name, (active, pool) in LISTS.items():
            self.assertEqual(self.answer(name), {"active": points(active), "pool": points(pool), "reason": "ok"}, name)

    def test_a_refusal_is_both_lists_null_and_a_store_code(self):
        for name, code in REFUSED.items():
            self.assertEqual(self.answer(name), {"active": None, "pool": None, "reason": code}, name)

    def test_the_output_line_is_the_jcs_of_the_answer_with_sorted_unique_points(self):
        for name, v in self.v.items():
            got = self.answer(name)
            self.assertEqual(v["anchor"], json.dumps(got, sort_keys=True, separators=(",", ":")), name)
            for key in ("active", "pool"):
                listed = got[key]
                if listed is None:
                    continue
                keys = [(p["x"], p["y"]) for p in listed]
                self.assertEqual(keys, sorted(set(keys)), name)

    def test_active_is_a_subset_of_pool_and_no_sign_point_is_listed(self):   # S10, S8
        sign = {(FX.key(n, "sign").point()["x"], FX.key(n, "sign").point()["y"])
                for n in GEN + ("alice2", "bob2", "alice3", "dave", "dave2", "grace", "frank")}
        for name in LISTS:
            got = self.answer(name)
            as_keys = lambda items: {(p["x"], p["y"]) for p in items}
            self.assertLessEqual(as_keys(got["active"]), as_keys(got["pool"]), name)
            self.assertFalse(as_keys(got["pool"]) & sign, name)

    def test_the_refused_rows_have_the_snapshot_the_sentence_names(self):
        wrong = self.v["agp/lineage-broken-refused"]["input"]
        self.assertEqual(wrong["docs"], FX.lineage(wit=True))   # an original that is not the organization's
        mixed = self.v["agp/fixture-profile-refused"]["input"]["docs"]
        self.assertEqual([e["doc"]["profile"] for e in mixed], [base.fixture_profile(), base.production_profile()])

    def test_the_fork_rows_have_two_children_of_one_node_and_no_resolve(self):   # S6
        for name, removes in (("agp/removed-on-one-fork-branch", 1), ("agp/removed-on-all-branches", 2)):
            acts = [a for a in self.v[name]["input"]["acts"] if payload(a)["method"] != "local:handsal.act.endorse"]
            parents = [payload(a)["parent_receipt_hash"] for a in acts]
            self.assertEqual(max(parents.count(p) for p in parents), 2, name)
            self.assertNotIn("chain.resolve", methods(acts), name)
            self.assertEqual(methods(acts).count("device.remove"), removes, name)

    def test_the_losing_branch_row_has_a_resolve_that_chooses_the_other_branch(self):   # S7
        acts = self.v["agp/added-on-losing-branch-only"]["input"]["acts"]
        self.assertIn("chain.resolve", methods(acts))
        adds = [a for a in acts if payload(a)["method"] == "local:handsal.device.add"]
        self.assertEqual(len(adds), 2)

    def test_the_pending_row_has_one_primary_signer_and_the_new_key_endorsement_only(self):   # S8
        acts = self.v["agp/pending-add-in-neither"]["input"]["acts"]
        self.assertEqual(methods(acts), ["device.add", "act.endorse"])

    def test_the_sibling_rows_have_two_successors_of_the_original(self):   # S9
        for name in ("agp/sibling-epochs-both-active", "agp/same-point-two-epochs-once"):
            docs = [e["doc"] for e in self.v[name]["input"]["docs"]]
            self.assertEqual(len(docs), 3, name)
            self.assertEqual([d["prev"] for d in docs[1:]], [FX.org_id, FX.org_id], name)
            self.assertNotEqual(inputs.doc_id(docs[1]), inputs.doc_id(docs[2]), name)
        drops = [e["doc"] for e in self.v["agp/change-drops-device"]["input"]["docs"]]
        self.assertEqual(len(drops), 2)
        self.assertNotIn("carol", {m["id"] for m in drops[1]["members"]})

    def test_the_unaccepted_row_adds_a_device_of_a_class_the_policy_does_not_list(self):   # S8
        v = self.v["agp/unaccepted-device-pool-only"]
        listed = {c["class"] for c in v["input"]["docs"][0]["doc"]["policy"]["classes"]}
        added = [payload(a)["ext"]["dev.handsal/act"]["body"] for a in v["input"]["acts"]
                 if payload(a)["method"] == "local:handsal.device.add"]
        self.assertEqual([b["class"] for b in added], ["test-sw-p256"])
        self.assertNotIn("test-sw-p256", listed)

    def test_the_catalog_rows_name_the_same_codes(self):
        for name, code in REFUSED.items():
            self.assertIn("`%s`" % code, catalog.ROWS[name]["expected"], name)


if __name__ == "__main__":
    unittest.main()
