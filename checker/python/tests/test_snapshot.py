"""CF-13 the snapshot `{acts, docs, org}`: one shape, read once, by `sync`, `admit` and `pool`.

`snapshot.parse` is the only reader. It returns the snapshot in its canonical form: `acts` sorted and unique,
`docs` one `{doc, sigs}` entry per document hash (entries for one document are one entry, `sigs` united, sorted,
unique), sorted by that hash. The size is that of the canonical form (RS9).
"""
import json
import random
import unittest
from unittest import mock

from handsal_check import admit, errors, genesis, pool, snapshot, sync

from .fold_world import World
from .genesis_fixtures import point

W = World()
OTHER = World(name="OTHER")
ORG = W.id


def raw(acts=(), docs=(), org=ORG, **more):
    return {"acts": acts if type(acts) is not tuple else list(acts), "docs": docs if type(docs) is not tuple else list(docs),
            "org": org, **more}


def entry(world, sigs=()):
    return {"doc": world.doc, "sigs": list(sigs)}


class Shape(unittest.TestCase):
    def test_a_good_snapshot_is_read_in_its_canonical_form(self):
        got, rest = snapshot.parse(raw(["b", "a", "b"], [entry(W, ["y", "x"])]))
        self.assertEqual(got, snapshot.Snapshot(["a", "b"], [{"doc": W.doc, "sigs": ["x", "y"]}], ORG))
        self.assertEqual(rest, {})

    def test_the_object_is_closed(self):
        for extra in ("pin", "lineage", "now", "item", "x"):
            with self.assertRaises(errors.Malformed, msg=extra):
                snapshot.parse({**raw(), extra: None})
        for key in ("acts", "docs", "org"):
            with self.assertRaises(errors.Malformed, msg=key):
                snapshot.parse({k: v for k, v in raw().items() if k != key})

    def test_the_caller_names_the_members_it_adds(self):
        got, rest = snapshot.parse(raw(item={"act": "x", "sigs": []}), extra=("item",))
        self.assertEqual(rest, {"item": {"act": "x", "sigs": []}})
        with self.assertRaises(errors.Malformed):
            snapshot.parse(raw(), extra=("item",))   # a member it named is required

    def test_every_member_is_checked(self):
        good = entry(W, ["s"])
        for name, bad in {
            "not an object": [],
            "acts not a list": raw(acts="x"),
            "an act that is no string": raw(acts=[1]),
            "docs not a list": raw(docs={}),
            "an entry with other keys": raw(docs=[{"doc": W.doc}]),
            "an entry with an extra key": raw(docs=[{**good, "x": 1}]),
            "sigs not a list": raw(docs=[{"doc": W.doc, "sigs": "s"}]),
            "a sig that is no string": raw(docs=[{"doc": W.doc, "sigs": [1]}]),
            "a doc that is no object": raw(docs=[{"doc": "x", "sigs": []}]),
            "a doc outside the subset": raw(docs=[{"doc": {"n": 1}, "sigs": []}]),
            "an org that is no hashstr": raw(org="x"),
        }.items():
            with self.subTest(case=name), self.assertRaises(errors.Malformed):
                snapshot.parse(bad)


class Canonical(unittest.TestCase):
    def test_entries_for_one_document_are_united_and_the_size_is_canonical(self):   # CF-13 S2
        docs = [entry(OTHER, ["z"]), entry(W, ["b", "a"]), entry(W, ["c", "a"])]
        got, _ = snapshot.parse(raw(["q", "p", "q"], docs))
        self.assertEqual(len(got.docs), 2)
        united = next(e for e in got.docs if e["doc"] == W.doc)
        self.assertEqual(united["sigs"], ["a", "b", "c"])
        self.assertEqual([genesis.doc_hash(e["doc"]) for e in got.docs],
                         sorted(genesis.doc_hash(d["doc"]) for d in docs[:2]))
        canonical = json.dumps({"acts": ["p", "q"], "docs": got.docs, "org": ORG}, sort_keys=True,
                               separators=(",", ":")).encode()
        self.assertEqual(snapshot.canonical_size(got), len(canonical))
        again = list(docs)
        random.Random(7).shuffle(again)
        other, _ = snapshot.parse(raw(["q", "q", "p"], again))
        self.assertEqual((other, snapshot.canonical_size(other)), (got, len(canonical)))

    def test_the_size_is_measured_of_a_candidate_without_building_the_input_twice(self):
        got, _ = snapshot.parse(raw(["a"], [entry(W, ["s"])]))
        bigger = snapshot.canonical_size(got, extra_acts=["bb", "a"], extra_docs=[entry(OTHER, ["t"])])
        grown, _ = snapshot.parse(raw(["a", "bb"], [entry(W, ["s"]), entry(OTHER, ["t"])]))
        self.assertEqual(bigger, snapshot.canonical_size(grown))


class OneParser(unittest.TestCase):
    def test_one_parser_serves_sync_admit_and_pool(self):   # CF-13 S1
        snap = raw(["b", "a"], [entry(W, ["s"])])
        with mock.patch.object(snapshot, "parse", wraps=snapshot.parse) as parse:
            via_sync = sync.parse_input(snap)
            via_admit = admit.parse_input({**snap, "item": {"act": "x", "sigs": []}})
            via_pool = pool.parse_input({**snap, "agree": point("alice.agree")})
        self.assertEqual(parse.call_count, 3)
        self.assertEqual(via_sync, via_admit.snapshot)
        self.assertEqual(via_sync, via_pool.snapshot)
        self.assertIsInstance(via_sync, snapshot.Snapshot)


class Paths(unittest.TestCase):
    """The documents by hash and the walk of `prev` that `sync` and the server's store checks share."""

    def test_the_index_is_by_document_hash(self):
        got, _ = snapshot.parse(raw(docs=[entry(W), entry(OTHER)]))
        self.assertEqual(set(snapshot.by_hash(got)), {W.id, OTHER.id})

    def test_the_path_runs_from_the_original_to_the_document_by_prev(self):
        doc = W.change_doc(W.id)
        later = W.change_doc(W.id, prev=doc, name="LATER")
        sibling = W.change_doc(W.id, name="SIBLING")
        got, _ = snapshot.parse(raw(docs=[entry(W), {"doc": doc, "sigs": ["c"]}, {"doc": later, "sigs": []},
                                          {"doc": sibling, "sigs": []}]))
        path = snapshot.path_to(snapshot.by_hash(got), genesis.doc_hash(later))
        self.assertEqual([e["doc"] for e in path], [W.doc, doc, later])
        self.assertIsNone(snapshot.path_to(snapshot.by_hash(got), "uEiAnotthere00000000000000000000000000000000000"))
        orphan, _ = snapshot.parse(raw(docs=[{"doc": later, "sigs": []}]))   # its prev is not there
        self.assertEqual(snapshot.path_to(snapshot.by_hash(orphan), genesis.doc_hash(later)), [])


if __name__ == "__main__":
    unittest.main()
