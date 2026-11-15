"""Vectors adm/*: `admit` (CF-11, RS5 to RS9). Each row is stated from the spec, not from a checker.

The input is `{acts, docs, item, org}`; the anchor is `{reason, store}` where `store` is the item with the kept
signatures (one per kid, `sigs` sorted) when `reason` is `ok`, else null. A kid named twice in `sigs` is `kid_repeated`.
"""
import json
import unittest

from lib import base, es256, foldmodel, forge, inputs
from tests import catalog

FX = base.Fixtures(base.fixture_profile())
OK_ROWS = ("adm/ok-original", "adm/ok-change-doc", "adm/ok-device-add-group", "adm/drops-junk-sig",
           "adm/ok-resolve",
           "adm/ok-valid-child-at-old-parent", "adm/ok-change-at-retained-head", "adm/garbage-twin-not-stored")
COMPACTED = ("adm/ok-change-at-retained-head", "adm/change-head-dropped")   # the store of a cmp row without its drop
KEYS = ["acts", "docs", "item", "org"]


def method(jws):
    return json.loads(forge.parts(jws)[1])["method"].split("local:handsal.")[-1]


def kid(jws):
    return json.loads(forge.parts(jws)[0])["kid"]


def receipt(jws):
    return inputs.receipt_id(jws)


class AdmRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        both = catalog.generate_modules(("adm", "cmp"), ("adm", "cmp"))
        cls.v = {k: x for k, x in both.items() if k.startswith("adm/")}
        cls.cmp = {k: x for k, x in both.items() if k.startswith("cmp/")}

    def reason(self, name):
        return json.loads(self.v[name]["anchor"])["reason"]

    def store(self, name):
        return json.loads(self.v[name]["anchor"])["store"]

    def item(self, name):
        return self.v[name]["input"]["item"]

    def test_rows_are_the_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("adm/")})
        self.assertEqual(len(self.v), 28)

    def test_every_row_is_an_admit_of_the_four_keys_and_carries_the_catalog_code(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "admit", name)
            self.assertEqual(sorted(v["input"]), KEYS, name)
            self.assertEqual(sorted(json.loads(v["anchor"])), ["reason", "store"], name)
            self.assertEqual(self.reason(name), catalog.catalog_code(name), name)
            self.assertEqual(self.store(name) is not None, name in OK_ROWS, name)
            self.assertEqual(v["input"]["org"], FX.org_id, name)

    def test_the_store_of_most_rows_is_the_original_document_with_its_receipts(self):
        for name, v in self.v.items():
            if name in ("adm/ok-original", "adm/original-wrong-org"):
                self.assertEqual((v["input"]["docs"], v["input"]["acts"]), ([], []), name)
            elif name not in ("adm/already-stored-doc", "adm/ok-change-doc", "adm/store-doc-invalid",
                              "adm/parent-unknown-doc", "adm/change-unauthorized", "adm/epoch-closed-act") + COMPACTED:
                self.assertEqual(v["input"]["docs"], [{"doc": FX.org, "sigs": FX.lineage()[0]["sigs"]}], name)

    def test_an_ok_row_stores_the_item_with_sorted_kept_signatures(self):
        for name in OK_ROWS:
            kept = self.store(name)
            given = self.item(name)
            key = "doc" if "doc" in given else "act"
            self.assertEqual(kept[key], given[key], name)
            self.assertEqual(kept["sigs"], sorted(kept["sigs"]), name)
            self.assertTrue(set(kept["sigs"]) <= set(given["sigs"]), name)
            kids = [kid(s) for s in kept["sigs"]]
            self.assertEqual(len(kids), len(set(kids)), name)   # one per kid

    def test_the_device_add_group_keeps_the_endorsement_and_the_possession_endorsement(self):
        got = self.store("adm/ok-device-add-group")
        self.assertEqual(got["sigs"], sorted(self.item("adm/ok-device-add-group")["sigs"]))
        self.assertEqual(sorted(kid(s) for s in got["sigs"]), sorted([FX.key("bob").kid, FX.key("alice2").kid]))
        self.assertEqual(kid(got["act"]), FX.key("alice").kid)

    def test_junk_and_a_stranger_are_dropped_and_the_rest_is_the_plain_group(self):
        plain = self.store("adm/ok-device-add-group")
        junk = self.item("adm/drops-junk-sig")["sigs"]
        self.assertEqual(self.store("adm/drops-junk-sig"), plain)
        self.assertEqual(len(junk), len(plain["sigs"]) + 2)
        self.assertIn(True, [not s.count(".") == 2 for s in junk])   # a string that is no JWS
        strangers = [s for s in junk if s.count(".") == 2 and kid(s) not in {kid(x) for x in plain["sigs"]}]
        self.assertEqual(len(strangers), 1)   # an endorsement by a kid no state holds
        self.assertNotIn(kid(strangers[0]), {d["kid"] for d in FX.org["devices"]})

    def test_a_second_signature_by_one_kid_is_refused(self):   # CF-11: bounds the verifications by the key set
        for name, signer in (("adm/kid-repeated-endorsement", "bob"), ("adm/kid-repeated-pop", "alice2")):
            sigs = self.item(name)["sigs"]
            same = [s for s in sigs if kid(s) == FX.key(signer).kid]
            self.assertEqual(len(same), 2, name)
            self.assertEqual(len({forge.parts(s)[1] for s in same}), 1, name)   # one payload, two signatures
            self.assertNotEqual(forge.parts(same[0])[2], forge.parts(same[1])[2], name)
            self.assertTrue(all(es256.is_low_s(forge.parts(s)[2]) for s in same), name)
            self.assertEqual((self.reason(name), self.store(name)), ("kid_repeated", None), name)
            plain = self.item("adm/ok-device-add-group")
            self.assertEqual(self.item(name)["act"], plain["act"], name)
            self.assertEqual(set(sigs) - set(same), set(plain["sigs"]) - {s for s in plain["sigs"]
                                                                          if kid(s) == FX.key(signer).kid}, name)

    def test_a_second_receipt_by_one_kid_is_refused(self):
        item = self.item("adm/kid-repeated-receipt")
        change = self.item("adm/ok-change-doc")
        self.assertEqual(item["doc"], change["doc"])
        same = [s for s in item["sigs"] if kid(s) == FX.key("bob").kid]
        self.assertEqual(len(same), 2)
        self.assertEqual(len({forge.parts(s)[1] for s in same}), 1)
        self.assertTrue(all(es256.is_low_s(forge.parts(s)[2]) for s in same))
        self.assertTrue(set(change["sigs"]) < set(item["sigs"]))
        self.assertEqual((self.reason("adm/kid-repeated-receipt"), self.store("adm/kid-repeated-receipt")),
                         ("kid_repeated", None))

    def test_the_resolve_and_the_old_parent_rows_have_their_stores(self):
        resolve = json.loads(forge.parts(self.item("adm/ok-resolve")["act"])[1])
        self.assertEqual(method(self.item("adm/ok-resolve")["act"]), "chain.resolve")
        self.assertEqual(len(self.v["adm/ok-resolve"]["input"]["acts"]), 6)   # two children, each with its group
        self.assertIsNotNone(resolve)
        old = self.item("adm/ok-valid-child-at-old-parent")["act"]
        self.assertEqual(method(old), "device.remove")
        parent = json.loads(forge.parts(old)[1])["parent_receipt_hash"]
        self.assertEqual(parent, FX.org_id)   # the old parent is the root, which already has a child in the store

    def test_the_twin_has_the_receipt_id_of_a_stored_act_and_another_signature(self):
        v = self.v["adm/already-stored-low-s-twin"]
        stored = {receipt(a): a for a in v["input"]["acts"]}
        twin = v["input"]["item"]["act"]
        self.assertIn(receipt(twin), stored)
        self.assertNotEqual(twin, stored[receipt(twin)])
        self.assertTrue(es256.is_low_s(forge.parts(twin)[2]))
        self.assertIn(receipt(self.item("adm/already-stored-act")["act"]),
                      [receipt(a) for a in self.v["adm/already-stored-act"]["input"]["acts"]])
        self.assertEqual(self.item("adm/already-stored-doc")["doc"], FX.org)

    def test_the_high_s_row_is_a_valid_act_whose_s_is_above_half_n(self):
        act = self.item("adm/high-s")["act"]
        self.assertFalse(es256.is_low_s(forge.parts(act)[2]))
        self.assertEqual(method(act), "device.add")

    def test_the_wrong_kind_of_act_rows(self):
        self.assertEqual(method(self.item("adm/lone-endorsement-not-chain")["act"]), "act.endorse")
        self.assertEqual(method(self.item("adm/verdict-not-chain")["act"]), "request.approve")
        self.assertEqual(method(self.item("adm/statement-method-unknown")["act"]), "relay.tip")
        other = json.loads(forge.parts(self.item("adm/other-org-act")["act"])[1])["ext"]["dev.handsal/act"]["org"]
        self.assertEqual(other, FX.wit_org_id)

    def test_an_act_of_another_org_at_a_node_of_ours_names_that_org_and_hangs_in_the_store(self):   # CF-11, GP-04
        v = self.v["adm/other-org-act-at-our-node"]
        act = self.item("adm/other-org-act-at-our-node")["act"]
        self.assertEqual(json.loads(forge.parts(act)[1])["ext"]["dev.handsal/act"]["org"], FX.wit_org_id)
        stored = {receipt(a) for a in v["input"]["acts"]}
        self.assertIn(json.loads(forge.parts(act)[1])["parent_receipt_hash"], stored | {FX.org_id})
        self.assertEqual(v["input"]["org"], FX.org_id)

    def test_the_one_touch_device_add_has_no_quorum(self):   # the 5.1 attack
        item = self.item("adm/pending-device-add-not-valid")
        self.assertEqual(method(item["act"]), "device.add")
        self.assertEqual(len(item["sigs"]), 1)
        self.assertEqual(kid(item["sigs"][0]), FX.key("alice2").kid)   # the possession endorsement of the new key
        self.assertEqual(kid(item["act"]), FX.key("alice").kid)

    def test_the_document_rows(self):
        change = self.item("adm/ok-change-doc")["doc"]
        self.assertEqual((change["prev"], change["org"]), (FX.org_id, FX.org_id))
        self.assertEqual(self.v["adm/ok-change-doc"]["input"]["docs"], [{"doc": FX.org, "sigs": FX.lineage()[0]["sigs"]}])
        wrong = self.item("adm/original-wrong-org")["doc"]
        self.assertEqual(wrong, FX.wit_org)
        late = self.item("adm/parent-unknown-doc")["doc"]
        stored = {inputs.doc_id(e["doc"]) for e in self.v["adm/parent-unknown-doc"]["input"]["docs"]}
        self.assertNotIn(late["prev"], stored)
        bad = self.v["adm/store-doc-invalid"]["input"]["docs"][1]["doc"]
        ids = [m["id"] for m in bad["members"]]
        self.assertEqual(ids, sorted(ids, reverse=True))   # listed out of order
        self.assertEqual(self.item("adm/store-doc-invalid")["act"].count("."), 2)
        weak = self.item("adm/change-unauthorized")["doc"]
        self.assertEqual([m["id"] for m in weak["members"]][0], "alice")
        self.assertEqual({m["id"] for m in weak["members"]} & {"bob", "carol"}, set())   # one previous role holder

    # ---- Phase 14 (CF-11 epoch_closed, CF-14, SD6)
    def test_an_act_whose_parent_is_a_node_of_a_closed_epoch_is_epoch_closed(self):
        v = self.v["adm/epoch-closed-act"]
        docs = v["input"]["docs"]
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[1]["doc"]["prev"], FX.org_id)   # the store holds a successor of epoch 0
        stored = {receipt(a) for a in v["input"]["acts"]}
        item = v["input"]["item"]["act"]
        self.assertNotIn(receipt(item), stored)   # a new act, not a copy
        self.assertIn(json.loads(forge.parts(item)[1])["parent_receipt_hash"], stored | {FX.org_id})   # a node of epoch 0
        self.assertEqual(method(item), "device.add")
        self.assertEqual((self.reason("adm/epoch-closed-act"), self.store("adm/epoch-closed-act")), ("epoch_closed", None))

    def test_the_compacted_stores_are_the_store_of_a_cmp_row_without_its_drop(self):
        source = self.cmp["cmp/closed-off-path-dropped"]
        want = foldmodel.without(source["input"], json.loads(source["anchor"])["drop"])
        for name in COMPACTED:
            got = self.v[name]["input"]
            self.assertEqual((got["acts"], got["docs"], got["org"]), (want["acts"], want["docs"], want["org"]), name)

    def test_a_second_change_at_a_retained_head_is_ok(self):
        v = self.v["adm/ok-change-at-retained-head"]
        item = self.item("adm/ok-change-at-retained-head")["doc"]
        first = v["input"]["docs"][1]["doc"]
        stored = {receipt(a) for a in v["input"]["acts"]}
        self.assertIn(item["head"], stored)   # H is on the retained path
        self.assertNotEqual(item["head"], first["head"])
        self.assertEqual((item["prev"], item["org"]), (FX.org_id, FX.org_id))
        self.assertNotEqual(inputs.doc_id(item), inputs.doc_id(first))
        self.assertEqual((self.reason("adm/ok-change-at-retained-head"),
                          self.store("adm/ok-change-at-retained-head")["doc"]), ("ok", item))

    def test_a_change_at_a_head_the_compaction_dropped_is_genesis_head_unknown(self):
        v = self.v["adm/change-head-dropped"]
        item = self.item("adm/change-head-dropped")["doc"]
        stored = {receipt(a) for a in v["input"]["acts"]}
        dropped = {receipt(a) for a in json.loads(self.cmp["cmp/closed-off-path-dropped"]["anchor"])["drop"]["acts"]}
        self.assertIn(item["head"], dropped)   # a node of epoch 0, off the path of the stored change
        self.assertNotIn(item["head"], stored)
        self.assertEqual((self.reason("adm/change-head-dropped"), self.store("adm/change-head-dropped")),
                         ("genesis_head_unknown", None))

    def test_a_store_that_holds_only_a_garbage_twin_admits_the_valid_act(self):   # FO-21
        v = self.v["adm/garbage-twin-not-stored"]
        (twin,) = v["input"]["acts"]
        act = self.item("adm/garbage-twin-not-stored")["act"]
        self.assertEqual(forge.parts(twin)[1], forge.parts(act)[1])   # one receipt id
        self.assertNotEqual(twin, act)
        k = FX.key("alice")
        message = twin.rsplit(".", 1)[0].encode()
        self.assertFalse(es256.verify((k.x_int, k.y_int), message, forge.parts(twin)[2]))
        self.assertTrue(es256.verify((k.x_int, k.y_int), act.rsplit(".", 1)[0].encode(), forge.parts(act)[2]))
        kept = self.store("adm/garbage-twin-not-stored")
        self.assertEqual(kept, {"act": act, "sigs": sorted(self.item("adm/garbage-twin-not-stored")["sigs"])})
        self.assertEqual(self.reason("adm/garbage-twin-not-stored"), "ok")


if __name__ == "__main__":
    unittest.main()
