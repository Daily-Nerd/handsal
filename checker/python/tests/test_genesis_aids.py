"""`genesis-aids` (CF-03, SG-12 steps 6 and 7): what the ceremony shows about the previous epoch of a change.

Input `{acts, lineage}`, the `genesis-check` input, and nothing else. Output `{aids, reason}`. `aids` is null for a
lineage of one document and for a refused lineage (`reason` is then the first failing code, as `genesis-check`
gives it). For a change it is `{head, removed}`: where H lies in the previous epoch's accepted chain, and the kids
that the candidate carries or whose key signed it and that some valid `device.remove` of the previous epoch removes.
"""
import io
import json
import unittest

from handsal_check import conformance, core, errors, genesis_aids, genesis_check

from .act_builder import FakeVitni, Unavailable, kid_of, memo
from .fold_world import PROFILES, World

AB = ("alice", "bob")
ALL = ("alice", "bob", "carol")


def no_render(doc, previous):
    return None


def lineage_value(w, *links, acts=()):
    return {"acts": list(acts), "lineage": [{"doc": d, "sigs": s} for d, s in links]}


def aids(value, vitni=None):
    return genesis_aids.run(genesis_aids.parse_input(value), PROFILES, True, memo(vitni), no_render)


def change_of(w, head, *, acts=(), people=ALL, signers=None, name="NEXT"):
    """The aids of `w`'s original followed by a change at `head`."""
    doc = w.change_doc(head, people=people, name=name)
    return aids(lineage_value(w, (w.doc, w.sigs(w.doc, ALL)), (doc, w.sigs(doc, signers or people)), acts=acts))


def head_of(answer):
    return answer["aids"]["head"]


class Input(unittest.TestCase):
    def test_the_input_is_the_genesis_check_input(self):
        w = World()
        good = lineage_value(w, (w.doc, w.sigs(w.doc, ALL)))
        self.assertEqual(genesis_aids.parse_input(good), genesis_check.parse_input(good))
        for bad in ({"acts": []}, {"lineage": []}, dict(good, extra=1), dict(good, org=w.id), dict(good, acts={}), [], None):
            with self.assertRaises(errors.Malformed):
                genesis_aids.parse_input(bad)


class Shape(unittest.TestCase):
    def test_a_lineage_of_one_document_has_no_aids(self):
        w = World()
        self.assertEqual(aids(lineage_value(w, (w.doc, w.sigs(w.doc, ALL)))), {"aids": None, "reason": "ok"})

    def test_a_refused_lineage_gives_the_code_genesis_check_gives(self):
        w = World()
        value = lineage_value(w, (w.doc, w.sigs(w.doc, ("alice", "bob"))))
        self.assertEqual(aids(value), {"aids": None, "reason": "genesis_unsigned"})
        self.assertEqual(genesis_check.run(genesis_check.parse_input(value), PROFILES, True, memo(), no_render)["reason"],
                         "genesis_unsigned")
        self.assertEqual(aids({"acts": [], "lineage": []}), {"aids": None, "reason": "lineage_broken"})

    def test_a_forged_middle_link_refuses_the_whole_lineage(self):
        w = World()
        tip = w.device_add("alice2", AB)
        mid = w.change_doc(tip.id, people=("alice", "frank", "grace"), name="MID")
        last = w.change_doc(w.id, name="LAST", prev=mid)
        value = lineage_value(w, (w.doc, w.sigs(w.doc, ALL)), (mid, w.sigs(mid, ("alice", "frank", "grace"))),
                              (last, w.sigs(last, ALL)), acts=tip.acts)
        self.assertEqual(aids(value), {"aids": None, "reason": "genesis_change_unauthorized"})

    def test_an_unavailable_verifier_is_its_own_reason(self):
        w = World()
        value = lineage_value(w, (w.doc, w.sigs(w.doc, ALL)))
        self.assertEqual(aids(value, Unavailable()), {"aids": None, "reason": "verifier_unavailable"})

    def test_the_aids_are_those_of_the_last_link_of_a_longer_lineage(self):
        w = World()
        tip = w.device_add("alice2", AB)
        second = w.change_doc(w.id, name="SECOND")
        third = w.change_doc(genesis_head(second), name="THIRD", prev=second)
        value = lineage_value(w, (w.doc, w.sigs(w.doc, ALL)), (second, w.sigs(second, ALL)), (third, w.sigs(third, ALL)),
                              acts=tip.acts)
        self.assertEqual(aids(value), {"aids": {"head": {"at": "tip", "place": "tip", "tip": genesis_head(second)}, "removed": []},
                                       "reason": "ok"})


def genesis_head(doc):
    from handsal_check import genesis
    return genesis.doc_hash(doc)


class HeadAtATip(unittest.TestCase):
    def test_h_is_the_tip(self):
        w = World()
        tip = w.device_add("alice2", AB)
        self.assertEqual(change_of(w, tip.id, acts=tip.acts),
                         {"aids": {"head": {"at": "tip", "place": "tip", "tip": tip.id}, "removed": []}, "reason": "ok"})

    def test_h_is_not_the_tip_and_the_tip_is_named(self):
        w = World()
        a = w.device_add("alice2", AB)
        b = w.device_add("bob2", AB, a)
        self.assertEqual(head_of(change_of(w, a.id, acts=a.acts + b.acts)), {"at": "tip", "place": "not_tip", "tip": b.id})
        self.assertEqual(head_of(change_of(w, w.id, acts=a.acts + b.acts)), {"at": "tip", "place": "not_tip", "tip": b.id})

    def test_an_epoch_with_no_act_ends_at_its_root(self):
        w = World()
        self.assertEqual(head_of(change_of(w, w.id)), {"at": "tip", "place": "tip", "tip": w.id})


class HeadAtAFork(unittest.TestCase):
    def setUp(self):
        self.w = w = World()
        self.c1 = w.device_add("alice2", AB)
        self.c2 = w.device_add("alice3", ("alice", "carol"))
        self.below = w.device_add("bob2", AB, self.c2)
        self.acts = self.c1.acts + self.c2.acts + self.below.acts
        self.candidates = sorted([self.c1.id, self.c2.id])

    def head(self, head):
        out = head_of(change_of(self.w, head, acts=self.acts))
        self.assertEqual((out["at"], out["parent"], out["candidates"]), ("fork", self.w.id, self.candidates))
        return out["place"], out["candidate"]

    def test_h_is_the_fork_parent(self):
        self.assertEqual(self.head(self.w.id), ("parent", None))

    def test_h_below_a_candidate_names_it(self):
        self.assertEqual(self.head(self.below.id), ("below", self.c2.id))

    def test_h_that_is_a_candidate_counts_as_below_itself(self):
        self.assertEqual(self.head(self.c1.id), ("below", self.c1.id))
        self.assertEqual(self.head(self.c2.id), ("below", self.c2.id))

    def test_h_above_the_fork_is_not_below_it(self):
        w = World()
        a = w.device_add("bob2", AB)
        c1, c2 = w.device_add("alice2", AB, a), w.device_add("alice3", ("alice", "carol"), a)
        out = head_of(change_of(w, a.id, acts=a.acts + c1.acts + c2.acts))
        self.assertEqual((out["at"], out["parent"], out["place"]), ("fork", a.id, "parent"))
        out = head_of(change_of(w, w.id, acts=a.acts + c1.acts + c2.acts))
        self.assertEqual((out["at"], out["parent"], out["place"], out["candidate"]), ("fork", a.id, "not_below", None))

    def test_a_resolve_that_chose_one_branch_makes_it_a_tip(self):
        resolve = self.w.resolve(AB, [self.c1, self.c2], self.c1, [self.below])   # it examined the head of the other branch
        out = head_of(change_of(self.w, self.c1.id, acts=self.acts + resolve.acts))
        self.assertEqual(out, {"at": "tip", "place": "tip", "tip": self.c1.id})


class Removed(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.carol = kid_of("carol")

    def removal(self, parent=None):
        return self.w.device_remove("carol", AB, parent)

    def test_a_carried_kid_that_a_removal_removes_is_listed(self):
        removal = self.removal()
        out = change_of(self.w, self.w.id, acts=removal.acts)   # H is before the removal, and the document carries carol
        self.assertEqual(out["aids"]["removed"], [self.carol])

    def test_a_kid_the_document_does_not_carry_is_not_listed(self):
        removal = self.removal()
        out = change_of(self.w, self.w.id, acts=removal.acts, people=("alice", "bob", "frank"))
        self.assertEqual(out["aids"]["removed"], [])

    def test_a_kid_whose_key_signed_the_change_is_listed_though_the_document_omits_it(self):
        removal = self.removal()
        out = change_of(self.w, self.w.id, acts=removal.acts, people=("alice", "bob", "frank"),
                        signers=("alice", "bob", "frank", "carol"))
        self.assertEqual(out["aids"]["removed"], [self.carol])

    def test_a_signature_that_is_not_a_receipt_of_the_document_names_nobody(self):
        removal = self.removal()
        w = self.w
        doc = w.change_doc(w.id, people=("alice", "bob", "frank"))
        elsewhere = w.change_doc(w.id, people=("alice", "bob", "frank"), name="ELSEWHERE")
        sigs = w.sigs(doc, ("alice", "bob", "frank")) + w.sigs(elsewhere, ("carol",)) + ["junk"]
        out = aids(lineage_value(w, (w.doc, w.sigs(w.doc, ALL)), (doc, sigs), acts=removal.acts))
        self.assertEqual(out["aids"]["removed"], [])

    def test_nothing_removed_lists_nothing(self):
        self.assertEqual(change_of(self.w, self.w.id)["aids"]["removed"], [])

    def test_a_removal_that_is_not_a_valid_act_lists_nothing(self):
        bad = self.w.device_remove("carol", ("alice",))   # one person where two are needed
        self.assertEqual(change_of(self.w, self.w.id, acts=bad.acts)["aids"]["removed"], [])

    def test_a_removal_on_either_branch_of_a_fork_counts_once(self):
        w = self.w
        c1 = w.device_add("alice2", AB)
        c2 = self.removal()
        out = change_of(w, w.id, acts=c1.acts + c2.acts)
        self.assertEqual((head_of(out)["at"], out["aids"]["removed"]), ("fork", [self.carol]))

    def test_a_removal_on_a_branch_a_resolve_discarded_counts_too(self):   # SG-12 step 7: anywhere in the previous epoch
        w = self.w
        c1 = w.device_add("alice2", AB)
        c2 = self.removal()
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        out = change_of(w, c1.id, acts=c1.acts + c2.acts + resolve.acts)
        self.assertEqual((head_of(out)["at"], out["aids"]["removed"]), ("tip", [self.carol]))

    def test_a_nested_fork_in_one_branch_is_shown_not_refused(self):
        w = self.w
        c1 = w.device_add("alice2", AB)
        c2 = self.removal()
        d1, d2 = w.device_add("bob2", AB, c1), w.device_add("bob3", ("bob", "carol"), c1)
        resolve = w.resolve(AB, [c1, c2], c1, [c2])
        out = change_of(w, w.id, acts=c1.acts + c2.acts + d1.acts + d2.acts + resolve.acts)
        self.assertEqual(out["reason"], "ok")
        self.assertEqual((head_of(out)["at"], head_of(out)["parent"], out["aids"]["removed"]), ("fork", c1.id, [self.carol]))

    def test_the_kids_are_sorted_and_listed_once(self):
        w = self.w
        first, second = w.device_remove("carol", AB), w.device_remove("bob", ("alice", "carol"), None, salt="2")
        out = change_of(w, w.id, acts=first.acts + second.acts)
        self.assertEqual(out["aids"]["removed"], sorted([kid_of("carol"), kid_of("bob")]))


class Wiring(unittest.TestCase):
    def test_the_command_is_in_the_conformance_table_and_takes_the_json_input(self):
        w = World()
        value = lineage_value(w, (w.doc, w.sigs(w.doc, ALL)))
        out = io.BytesIO()
        core.run(conformance.build_commands(FakeVitni()), ["genesis-aids"], io.BytesIO(json.dumps(value).encode()), out)
        self.assertEqual(out.getvalue(), b'{"aids":null,"reason":"ok"}\n')


if __name__ == "__main__":
    unittest.main()
