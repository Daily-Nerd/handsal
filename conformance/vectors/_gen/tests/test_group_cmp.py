"""Vectors cmp/*: `compact`, what a store may drop (CF-14, design 21.2, catalog part 4 section 30).

Each row is stated from the spec: the store is built with the generator's own chain helpers and the drop list is
the author's statement of the retained set's complement. Nothing here, and nothing in the group, calls the
checker. The whole-set guard is proved twice: the group runs it before it writes a row, and this module runs it
again over the written rows and shows it has teeth (a drop that names a retained path node, a possession
receipt, or a string the store does not hold is refused).
"""
import json
import unittest

from lib import base, es256, foldmodel, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
REFUSED = ("cmp/store-doc-invalid", "cmp/store-original-wrong-org")   # no drop: the answer is a store code
OK = tuple(sorted(k for k in catalog.ROWS if k.startswith("cmp/") and k not in REFUSED))
EMPTY = {"acts": [], "sigs": []}


def payload(jws):
    return json.loads(forge.parts(jws)[1])


def method(jws):
    return payload(jws)["method"].split("local:handsal.")[-1]


def parent(jws):
    return payload(jws)["parent_receipt_hash"]


def body(jws):
    return payload(jws)["ext"]["dev.handsal/act"]["body"]


def kid(jws):
    return json.loads(forge.parts(jws)[0])["kid"]


def rid(jws):
    return inputs.receipt_id(jws)


def is_act(text):
    try:
        forge.parts(text)
        return True
    except ValueError:
        return False


def verifies(jws):
    k = FX.key(FX.name_of_kid(kid(jws)))
    return es256.verify((k.x_int, k.y_int), jws.rsplit(".", 1)[0].encode(), forge.parts(jws)[2])


class CmpRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("cmp", ["cmp"])

    def drop(self, name):
        return json.loads(self.v[name]["anchor"])["drop"]

    def acts(self, name):
        return self.v[name]["input"]["acts"]

    def docs(self, name):
        return self.v[name]["input"]["docs"]

    def primaries(self, name):
        return [a for a in self.acts(name) if is_act(a) and method(a) in ("device.add", "device.remove", "member.add")]

    def test_rows_are_the_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("cmp/")})
        self.assertEqual(len(self.v), 17)

    def test_every_row_is_a_compact_of_the_three_snapshot_keys_with_the_catalog_code(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "compact", name)
            self.assertEqual(sorted(v["input"]), ["acts", "docs", "org"], name)
            self.assertEqual(v["input"]["org"], FX.org_id, name)
            out = json.loads(v["anchor"])
            self.assertEqual(sorted(out), ["drop", "reason"], name)
            self.assertEqual(out["reason"], catalog.catalog_code(name), name)

    def test_a_drop_is_two_sorted_unique_lists_of_strings_the_store_holds(self):   # CF-14: A and G
        for name in OK:
            drop = self.drop(name)
            self.assertEqual(sorted(drop), ["acts", "sigs"], name)
            for key in ("acts", "sigs"):
                self.assertEqual(drop[key], sorted(set(drop[key])), (name, key))
            self.assertTrue(set(drop["acts"]) <= set(self.acts(name)), name)
            held = {s for e in self.docs(name) for s in e["sigs"]}
            self.assertTrue(set(drop["sigs"]) <= held, name)

    def test_the_whole_set_guard_holds_for_every_row_and_every_leaf_document(self):   # design 21.11 step 3
        for name in OK:
            snapshot = self.v[name]["input"]
            drop = self.drop(name)
            whole = foldmodel.Model(FX, snapshot["acts"], snapshot["docs"]).answers()
            self.assertGreaterEqual(len(whole), 1, name)
            rest = foldmodel.without(snapshot, drop)
            self.assertEqual(foldmodel.Model(FX, rest["acts"], rest["docs"]).answers(), whole, name)
            self.assertEqual(foldmodel.guard(FX, snapshot, drop), whole, name)

    def test_the_guard_has_teeth(self):
        v = self.v["cmp/closed-off-path-dropped"]["input"]
        drop = self.drop("cmp/closed-off-path-dropped")
        change = self.docs("cmp/closed-off-path-dropped")[1]["doc"]
        path_node = next(a for a in self.primaries("cmp/closed-off-path-dropped") if rid(a) == change["head"])
        with self.assertRaises(foldmodel.GuardError):   # H is no node once its primary is gone
            foldmodel.guard(FX, v, {"acts": sorted(drop["acts"] + [path_node]), "sigs": []})
        sigs = self.docs("cmp/closed-off-path-dropped")[1]["sigs"]
        with self.assertRaises(foldmodel.GuardError):   # a device is unsigned once its possession receipt is gone
            foldmodel.guard(FX, v, {"acts": drop["acts"], "sigs": [sigs[0]]})
        with self.assertRaises(foldmodel.GuardError):   # a name that matches nothing is the author's mistake
            foldmodel.guard(FX, v, {"acts": drop["acts"] + ["not held"], "sigs": []})
        self.assertEqual(foldmodel.guard(FX, v, EMPTY), foldmodel.guard(FX, v, drop))

    def test_an_open_epoch_is_kept_whole_with_its_fork_and_its_losing_branch(self):
        name = "cmp/open-epoch-kept-whole"
        self.assertEqual(self.drop(name), EMPTY)
        self.assertEqual(self.docs(name), [{"doc": FX.org, "sigs": FX.lineage()[0]["sigs"]}])
        nodes = self.primaries(name)
        by_parent = {}
        for a in nodes:
            by_parent.setdefault(parent(a), []).append(rid(a))
        self.assertTrue(any(len(c) >= 2 for c in by_parent.values()))   # a fork
        self.assertTrue(any(p in {r for c in by_parent.values() for r in c} for p in by_parent))   # a branch below it
        leaf = inputs.doc_id(FX.org)
        self.assertEqual(json.loads(foldmodel.guard(FX, self.v[name]["input"], EMPTY)[leaf])["error"], "fork")

    def chain_above(self, name, head):
        """The primaries of the store that are below `head`, by the parent pointers of the acts."""
        below, grew, ids = set(), True, {rid(a) for a in self.primaries(name)}
        while grew:
            grew = False
            for a in self.primaries(name):
                if rid(a) not in below and (parent(a) == head or parent(a) in below):
                    below.add(rid(a))
                    grew = True
        return below & ids

    def group_of(self, name, ids):
        """The strings of the store that are a primary in `ids` or an endorsement of one."""
        return {a for a in self.acts(name) if is_act(a) and (rid(a) in ids or (
            method(a) == "act.endorse" and body(a)["act"] in ids))}

    def test_a_closed_epoch_keeps_the_path_to_h_and_drops_what_is_above_it(self):   # GP-19 Close
        name = "cmp/closed-off-path-dropped"
        self.assertEqual(len(self.docs(name)), 2)
        change = self.docs(name)[1]["doc"]
        self.assertEqual((change["prev"], change["org"]), (FX.org_id, FX.org_id))
        above = self.chain_above(name, change["head"])
        self.assertEqual(len(above), 2)   # positions 3 and 4, H being position 2
        self.assertEqual(set(self.drop(name)["acts"]), self.group_of(name, above))
        self.assertEqual(self.drop(name)["sigs"], [])
        self.assertEqual(len(self.primaries(name)), 4)
        self.assertIn(change["head"], {rid(a) for a in self.primaries(name)})

    def test_a_resolve_at_a_path_node_is_dropped_with_the_losing_branch(self):   # GP-19 Path, FO-25 Effect
        name = "cmp/closed-resolve-dropped"
        base_name = "cmp/closed-off-path-dropped"
        change = self.docs(name)[1]["doc"]
        resolves = [a for a in self.acts(name) if is_act(a) and method(a) == "chain.resolve"]
        self.assertEqual(len(resolves), 1)
        path = {rid(a) for a in self.primaries(name)} - self.chain_above(name, change["head"])
        self.assertIn(parent(resolves[0]), path)   # at the fork parent, a node on the path to H
        siblings = [a for a in self.primaries(name) if parent(a) == parent(resolves[0])]
        self.assertEqual(len(siblings), 2)   # the fork the resolve lifts
        dropped = set(self.drop(name)["acts"])
        self.assertTrue(set(resolves) <= dropped)
        self.assertTrue(set(self.drop(base_name)["acts"]) <= dropped)
        self.assertTrue(dropped - set(self.drop(base_name)["acts"]) >= set(resolves))

    def test_two_sibling_changes_keep_the_paths_to_both_heads(self):   # GP-12
        name = "cmp/sibling-successor-paths-kept"
        docs = self.docs(name)
        self.assertEqual(len(docs), 3)
        a, b = docs[1]["doc"], docs[2]["doc"]
        self.assertEqual((a["prev"], b["prev"]), (FX.org_id, FX.org_id))
        self.assertNotEqual(a["head"], b["head"])
        ids = {rid(x): x for x in self.primaries(name)}
        self.assertTrue({a["head"], b["head"]} <= set(ids))
        paths = []
        for head in (a["head"], b["head"]):
            chain, at = [], head
            while at in ids:
                chain.append(at)
                at = parent(ids[at])
            paths.append(set(chain))
        self.assertFalse(paths[0] & paths[1])   # two branches, nothing shared but the root
        kept = paths[0] | paths[1]
        self.assertEqual(set(self.drop(name)["acts"]), self.group_of(name, set(ids) - kept))
        self.assertTrue(set(ids) - kept)
        self.assertEqual(len(foldmodel.guard(FX, self.v[name]["input"], self.drop(name))), 2)   # two leaves

    def test_a_change_at_the_root_keeps_nothing_of_its_epoch(self):
        name = "cmp/change-at-root-keeps-nothing-of-epoch"
        self.assertEqual(self.docs(name)[1]["doc"]["head"], FX.org_id)
        self.assertEqual(len(self.primaries(name)), 3)
        self.assertEqual(set(self.drop(name)["acts"]), set(self.acts(name)))

    def test_junk_a_verdict_and_a_receipt_are_dropped_and_the_chain_stays(self):   # FO-15
        name = "cmp/junk-and-non-chain-dropped"
        dropped = self.drop(name)["acts"]
        self.assertEqual(len(dropped), 3)
        self.assertEqual(sum(not is_act(a) for a in dropped), 1)
        self.assertEqual(sorted(method(a) for a in dropped if is_act(a)), ["genesis.sign", "request.approve"])
        self.assertTrue(self.primaries(name))
        self.assertFalse(set(self.primaries(name)) & set(dropped))

    def test_an_act_of_another_organization_is_dropped(self):
        name = "cmp/other-org-act-dropped"
        (dropped,) = self.drop(name)["acts"]
        self.assertEqual(payload(dropped)["ext"]["dev.handsal/act"]["org"], FX.wit_org_id)
        self.assertEqual(method(dropped), "device.add")

    def test_an_act_of_another_organization_at_a_node_of_ours_is_dropped(self):   # CF-14 D3, FO-06, GP-04
        name = "cmp/other-org-anchored-act-dropped"
        dropped = self.drop(name)["acts"]
        self.assertEqual(sorted(method(a) for a in dropped), ["act.endorse", "act.endorse", "device.add"])
        for a in dropped:
            self.assertEqual(payload(a)["ext"]["dev.handsal/act"]["org"], FX.wit_org_id)
        (primary,) = [a for a in dropped if method(a) == "device.add"]
        nodes = {rid(a) for a in self.primaries(name)} | {FX.org_id}
        self.assertIn(parent(primary), nodes)               # anchored: the parent is a node of ORG
        self.assertTrue(all(verifies(a) for a in dropped))  # every signature is valid
        self.assertTrue(set(self.primaries(name)) - set(dropped))   # a kept group of ORG stays

    def test_an_invalid_twin_is_dropped_and_the_valid_copy_stays(self):   # FO-21
        name = "cmp/invalid-twin-dropped"
        (twin,) = self.drop(name)["acts"]
        self.assertFalse(verifies(twin))
        (kept,) = [a for a in self.acts(name) if is_act(a) and rid(a) == rid(twin) and a != twin]
        self.assertTrue(verifies(kept))
        self.assertEqual(forge.parts(kept)[1], forge.parts(twin)[1])

    def test_the_larger_of_two_valid_copies_is_dropped(self):   # ACT-12, FO-21
        name = "cmp/second-valid-copy-dropped"
        (gone,) = self.drop(name)["acts"]
        (other,) = [a for a in self.acts(name) if is_act(a) and rid(a) == rid(gone) and a != gone]
        self.assertTrue(verifies(gone) and verifies(other))
        self.assertTrue(es256.is_low_s(forge.parts(gone)[2]) and es256.is_low_s(forge.parts(other)[2]))
        self.assertGreater(gone.encode("ascii"), other.encode("ascii"))

    def test_a_stranger_endorsement_is_dropped(self):   # FO-08
        name = "cmp/stranger-endorsement-dropped"
        (dropped,) = self.drop(name)["acts"]
        self.assertEqual(method(dropped), "act.endorse")
        self.assertNotIn(kid(dropped), {d["kid"] for d in FX.org["devices"]})
        self.assertIn(body(dropped)["act"], {rid(a) for a in self.primaries(name)})

    def test_a_pending_primary_is_dropped(self):   # FO-24
        name = "cmp/pending-primary-dropped"
        (dropped,) = self.drop(name)["acts"]
        self.assertEqual(method(dropped), "device.add")
        self.assertFalse([a for a in self.acts(name) if is_act(a) and method(a) == "act.endorse"
                          and body(a)["act"] == rid(dropped)])   # no quorum: nobody endorsed it
        self.assertIn(parent(dropped), {FX.org_id} | {rid(a) for a in self.primaries(name)})   # its parent is a node

    def test_an_act_whose_parent_is_no_node_is_dropped(self):   # FO-06
        name = "cmp/unanchored-act-dropped"
        (dropped,) = self.drop(name)["acts"]
        self.assertNotIn(parent(dropped), {FX.org_id} | {rid(a) for a in self.acts(name) if is_act(a)})
        self.assertTrue(verifies(dropped))

    def test_override_evidence_is_kept(self):   # FO-25
        name = "cmp/override-evidence-kept"
        self.assertEqual(self.drop(name), EMPTY)
        resolves = [a for a in self.acts(name) if is_act(a) and method(a) == "chain.resolve"]
        entries = [e for r in resolves for e in body(r)["overrides"]]
        self.assertEqual(len(entries), 1)
        self.assertEqual(len(entries[0]["endorsements"]), 2)
        held = {rid(a) for a in self.acts(name) if is_act(a)}
        self.assertTrue(set(entries[0]["endorsements"]) | {entries[0]["resolve"]} <= held)
        leaf = inputs.doc_id(FX.org)
        self.assertNotIn("error", json.loads(foldmodel.guard(FX, self.v[name]["input"], EMPTY)[leaf]))   # the override lifts the fork

    def test_a_receipt_that_counts_for_nothing_is_dropped(self):   # GP-15
        name = "cmp/non-counting-receipt-dropped"
        drop = self.drop(name)
        self.assertEqual((drop["acts"], len(drop["sigs"])), ([], 1))
        (receipt,) = drop["sigs"]
        doc = self.docs(name)[0]
        self.assertIn(receipt, doc["sigs"])
        self.assertNotIn(kid(receipt), {d["kid"] for d in doc["doc"]["devices"]})
        self.assertEqual(method(receipt), "genesis.sign")

    def test_a_store_with_an_invalid_document_is_refused_with_its_code(self):
        name = "cmp/store-doc-invalid"
        self.assertEqual(self.v[name]["anchor"], '{"drop":null,"reason":"doc_not_sorted"}')
        bad = self.docs(name)[1]["doc"]
        ids = [m["id"] for m in bad["members"]]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_a_store_whose_original_is_not_the_organizations_is_refused_with_lineage_broken(self):   # CF-14, CF-11
        name = "cmp/store-original-wrong-org"
        self.assertEqual(self.v[name]["anchor"], '{"drop":null,"reason":"lineage_broken"}')
        self.assertEqual(self.docs(name), FX.lineage(wit=True))   # the original of another organization
        self.assertEqual(self.v[name]["input"]["org"], FX.org_id)
        self.assertNotEqual(inputs.doc_id(self.docs(name)[0]["doc"]), FX.org_id)


if __name__ == "__main__":
    unittest.main()
