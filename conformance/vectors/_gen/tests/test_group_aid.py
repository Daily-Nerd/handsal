"""Vectors aid/*: `genesis-aids` (CF-03, SG-12 steps 6 and 7).

The anchors are the author's statement of the facts, so these tests read them against the lineage each row builds:
the document the change names as H, the receipts of the bag, and the kids the change lists or whose key signed it.
"""
import json
import unittest

from lib import forge, inputs
from tests import catalog

IDS = (
    "aid/original-has-no-aids", "aid/head-is-tip", "aid/head-not-tip", "aid/fork-head-is-parent",
    "aid/fork-head-below-candidate", "aid/fork-head-is-candidate", "aid/fork-head-not-below",
    "aid/removed-key-carried", "aid/removed-key-signed", "aid/removed-key-on-discarded-branch",
    "aid/nested-fork-shown", "aid/refused-lineage-has-no-aids",
)


def answer(vector):
    return json.loads(vector["anchor"])


def act_parent(jws):
    return json.loads(forge.parts(jws)[1])["parent_receipt_hash"]


class AidRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(("aid",), ("aid",))

    def test_rows_are_the_ids_of_the_catalog(self):
        self.assertEqual(sorted(self.v), sorted(IDS))

    def test_every_row_is_a_genesis_aids_row_over_acts_and_a_lineage(self):
        for name, vector in self.v.items():
            self.assertEqual(vector["command"], "genesis-aids", name)
            self.assertEqual(sorted(vector["input"]), ["acts", "lineage"], name)

    def test_the_anchor_is_one_jcs_line(self):
        for name, vector in self.v.items():
            self.assertEqual(vector["anchor"], json.dumps(answer(vector), sort_keys=True, separators=(",", ":")), name)

    def test_no_aids_for_one_document_and_for_a_refused_lineage(self):
        self.assertEqual(answer(self.v["aid/original-has-no-aids"]), {"aids": None, "reason": "ok"})
        self.assertEqual(len(self.v["aid/original-has-no-aids"]["input"]["lineage"]), 1)
        self.assertEqual(answer(self.v["aid/refused-lineage-has-no-aids"]),
                         {"aids": None, "reason": "genesis_change_unauthorized"})

    def test_every_other_row_is_a_change_that_is_ok(self):
        for name, vector in self.v.items():
            if name in ("aid/original-has-no-aids", "aid/refused-lineage-has-no-aids"):
                continue
            self.assertEqual(len(vector["input"]["lineage"]), 2, name)
            self.assertEqual(answer(vector)["reason"], "ok", name)
            self.assertEqual(sorted(answer(vector)["aids"]), ["head", "removed"], name)

    def test_the_head_object_is_the_tip_or_the_fork_and_names_ids_of_the_bag(self):
        for name, vector in self.v.items():
            aids = answer(vector)["aids"]
            if aids is None:
                continue
            head, root = aids["head"], inputs.doc_id(vector["input"]["lineage"][0]["doc"])
            known = {root} | {act_parent(jws) for jws in vector["input"]["acts"]}
            if head["at"] == "tip":
                self.assertEqual(sorted(head), ["at", "place", "tip"], name)
                self.assertIn(head["place"], ("tip", "not_tip"), name)
            else:
                self.assertEqual(sorted(head), ["at", "candidate", "candidates", "parent", "place"], name)
                self.assertEqual(head["candidates"], sorted(head["candidates"]), name)
                self.assertIn(head["parent"], known, name)
                self.assertIn(head["place"], ("parent", "below", "not_below"), name)
                self.assertEqual(head["candidate"] is not None, head["place"] == "below", name)

    def test_h_is_the_tip_when_the_change_names_the_tip(self):
        vector = self.v["aid/head-is-tip"]
        change = vector["input"]["lineage"][1]["doc"]
        self.assertEqual(answer(vector)["aids"]["head"], {"at": "tip", "place": "tip", "tip": change["head"]})
        other = self.v["aid/head-not-tip"]
        self.assertNotEqual(answer(other)["aids"]["head"]["tip"], other["input"]["lineage"][1]["doc"]["head"])

    def test_the_fork_places_follow_the_head_the_change_names(self):
        def place(name):
            vector = self.v[name]
            head = answer(vector)["aids"]["head"]
            return vector["input"]["lineage"][1]["doc"]["head"], head
        h, head = place("aid/fork-head-is-parent")
        self.assertEqual((h, head["place"]), (head["parent"], "parent"))
        h, head = place("aid/fork-head-is-candidate")
        self.assertEqual((h, head["place"], head["candidate"]), (head["candidate"], "below", head["candidate"]))
        h, head = place("aid/fork-head-below-candidate")
        self.assertEqual((head["place"], h in head["candidates"]), ("below", False))
        self.assertIn(head["candidate"], head["candidates"])
        h, head = place("aid/fork-head-not-below")
        self.assertEqual((head["place"], head["candidate"], h == head["parent"]), ("not_below", None, False))

    def test_a_removed_kid_is_one_the_change_lists_or_whose_key_signed_it(self):
        for name in ("aid/removed-key-carried", "aid/removed-key-signed", "aid/removed-key-on-discarded-branch",
                     "aid/nested-fork-shown"):
            vector = self.v[name]
            entry = vector["input"]["lineage"][1]
            listed = {device["kid"] for device in entry["doc"]["devices"]}
            signers = {json.loads(forge.parts(jws)[0])["kid"] for jws in entry["sigs"]}
            removed = answer(vector)["aids"]["removed"]
            self.assertTrue(removed, name)
            self.assertEqual(removed, sorted(removed), name)
            self.assertTrue(set(removed) <= listed | signers, name)
        signed = self.v["aid/removed-key-signed"]
        removed = answer(signed)["aids"]["removed"]
        self.assertFalse(set(removed) & {d["kid"] for d in signed["input"]["lineage"][1]["doc"]["devices"]},
                         "the kid is listed by signing alone")

    def test_a_row_with_nothing_removed_lists_nothing(self):
        for name in ("aid/head-is-tip", "aid/head-not-tip", "aid/fork-head-is-parent"):
            self.assertEqual(answer(self.v[name])["aids"]["removed"], [], name)


if __name__ == "__main__":
    unittest.main()
