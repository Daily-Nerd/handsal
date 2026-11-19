"""CF-14 `compact`: the drop lists of the retained set, server and conformance builds.

`compact` takes exactly the snapshot of CF-13, runs the store checks of `admit` without the registration case and
answers `{"drop":{"acts":A,"sigs":G},"reason":"ok"}` or `{"drop":null,"reason":R}`. It writes nothing; the caller
deletes what `drop` lists. The retained set itself is tested in `test_retain`; here are the command, its input and
its codes, and the cost of one call on a padded store (design risk 6), measured by counting calls to the verifier.
"""
import unittest
from unittest import mock

from handsal_check import admit, chain, compact, epoch, errors, genesis, quorum, render_genesis, resolve, retain

from .act_builder import FakeVitni, Unavailable, memo, with_signature
from .fold_world import World
from .linear_world import acts_of, chain as linear_chain
from .genesis_fixtures import change, policy
from .store_world import ALL, AB, LOW, PROFILES, Counting, after, entry, opened, retained_of, snap_of


def original(w):
    return entry(w.doc, w.sigs(w.doc, ALL))


def go(w, acts=(), docs=None, allow_fixture=True, vitni=None, **extra):
    docs = [original(w)] if docs is None else docs
    value = {"acts": list(acts), "docs": docs, "org": w.id, **extra}
    return compact.run(compact.parse_input(value), PROFILES, allow_fixture, memo(vitni),
                       render_genesis.render_size)


class Contract(unittest.TestCase):
    def test_the_input_is_the_closed_snapshot_and_the_answer_is_the_drop_lists(self):   # CF-14 S10
        w = World()
        good = {"acts": [], "docs": [original(w)], "org": w.id}
        compact.parse_input(good)
        for key in ("item", "agree", "pin", "now", "lineage", "x"):
            with self.assertRaises(errors.Malformed, msg=key):
                compact.parse_input({**good, key: None})
        for key in ("acts", "docs", "org"):
            with self.assertRaises(errors.Malformed, msg=key):
                compact.parse_input({k: v for k, v in good.items() if k != key})
        for name, bad in {"acts not a list": {**good, "acts": "x"}, "an act that is no string": {**good, "acts": [1]},
                          "org not a hashstr": {**good, "org": "x"}, "docs entry with other keys": {**good, "docs": [{}]},
                          "not an object": []}.items():
            with self.subTest(name), self.assertRaises(errors.Malformed):
                compact.parse_input(bad)
        # the answer: both lists sorted and unique, possibly empty; a refusal has no lists
        a, b = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        doc = w.change_doc(a.id)
        junk = ["zzz", "junk", "junk", ""]
        got = go(w, a.acts + b.acts + junk, [original(w), entry(doc, w.sigs(doc, ALL) + w.sigs(doc, ("dave",)))])
        dave = w.sigs(doc, ("dave",))
        self.assertEqual(got, {"drop": {"acts": sorted(set(b.acts) | {"zzz", "junk", ""}), "sigs": dave},
                               "reason": "ok"})
        self.assertEqual(go(w), {"drop": {"acts": [], "sigs": []}, "reason": "ok"})
        self.assertEqual(go(w, docs=[]), {"drop": None, "reason": "lineage_broken"})

    def test_the_answer_is_the_lists_of_the_retained_set(self):   # SD13: one owner of what a store drops
        w = World()
        a, b = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        acts = a.acts + b.acts + ["junk"]
        docs = [original(w), entry(w.change_doc(a.id), [])]
        docs[1]["sigs"] = w.sigs(docs[1]["doc"], ALL)
        snap = snap_of(acts, docs, w.id)
        want = retain.dropped(snap, retained_of(snap))
        got = go(w, acts, docs)
        self.assertEqual((got["drop"]["acts"], got["drop"]["sigs"]), want)

    def test_it_writes_nothing_and_reads_no_pin_clock_or_store(self):
        w = World()
        before = go(w, ["junk"])
        self.assertEqual(before["drop"]["acts"], ["junk"])
        self.assertEqual(go(w, ["junk"]), before)   # pure: the same input, the same answer


class StoreChecks(unittest.TestCase):
    """The store checks of CF-11 without the registration case: first failure wins."""

    def test_no_original_is_lineage_broken_and_a_lone_original_is_no_exception(self):
        w, other = World(), World(name="OTHER")
        self.assertEqual(go(w, docs=[]), {"drop": None, "reason": "lineage_broken"})
        self.assertEqual(go(w, docs=[original(other)]), {"drop": None, "reason": "lineage_broken"})

    def test_a_document_that_is_no_valid_link_answers_its_gp_15_code(self):
        w = World()
        bad = w.change_doc(w.id)
        bad["members"] = list(reversed(bad["members"]))
        self.assertEqual(go(w, docs=[original(w), entry(bad, w.sigs(bad, ALL))]),
                         {"drop": None, "reason": "doc_not_sorted"})

    def test_a_document_that_names_no_stored_prev_is_lineage_broken(self):
        w = World()
        orphan = w.change_doc(w.id, prev=World(name="OTHER").doc)
        self.assertEqual(go(w, docs=[original(w), entry(orphan, w.sigs(orphan, ALL))]),
                         {"drop": None, "reason": "lineage_broken"})

    def test_the_fixture_profile_is_refused_in_the_server_build_only(self):   # CF-10
        w = World()
        self.assertEqual(go(w, allow_fixture=False), {"drop": None, "reason": "fixture_profile"})
        self.assertEqual(go(w, allow_fixture=True)["reason"], "ok")

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable_and_drops_nothing(self):
        w = World()
        self.assertEqual(go(w, ["junk"], vitni=Unavailable()), {"drop": None, "reason": "verifier_unavailable"})


class Operator(unittest.TestCase):
    """CF-14 operator rules: document admission is serialized with computing and applying a drop list."""

    def test_a_document_admitted_between_computing_and_applying_a_list_loses_its_head_path(self):   # SD7, CF-14 rule
        w = World()
        on_path, beside = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        docs = [original(w), entry(w.change_doc(on_path.id), w.sigs(w.change_doc(on_path.id), ALL))]
        acts = on_path.acts + beside.acts
        listed = go(w, acts, docs)["drop"]                      # t0: computed; `beside` is off the only successor path
        self.assertTrue(set(beside.acts) <= set(listed["acts"]))
        sibling = w.change_doc(beside.id, name="SIBLING")      # t1: a second successor whose head is `beside`
        item = {"doc": sibling, "sigs": w.sigs(sibling, ALL)}
        value = {"acts": acts, "docs": docs, "org": w.id, "item": item}
        self.assertEqual(admit.run(admit.parse_input(value), PROFILES, True, memo())["reason"], "ok")
        docs.append(entry(sibling, item["sigs"]))
        stale = after(snap_of(acts, docs, w.id), listed["acts"], listed["sigs"])   # t2: the old list is applied
        self.assertEqual(go(w, stale.acts, docs), {"drop": None, "reason": "genesis_head_unknown"})
        # a list computed with the document keeps the head path: the lock must cover compute and apply together
        again = go(w, acts, docs)["drop"]
        self.assertFalse(set(beside.acts) & set(again["acts"]))


class Cost(unittest.TestCase):
    """Design risk 6: `compact` is linear in the store. Measured on a padded store by what it asks the verifier and
    what it visits, never by time alone: junk and unanchored acts cost no verification, and the retained set asks
    nothing that the fold did not ask already."""

    def wide(self, width, twins=False):
        """A fork of `width` children of the root (each a `device.add` with its endorsements), and, with `twins`,
        a second valid text of every primary."""
        w = World()
        steps = [w.device_add("alice2", AB, salt=str(i)) for i in range(width)]
        acts = [text for step in steps for text in step.acts]
        return w, steps, acts

    def calls(self, w, acts, *, extra_docs=()):
        """`(calls of `compact`, calls of the fold alone)` over the vitni that counts. The fold alone opens every
        document, builds every act tree and judges every resolve: everything a reader asks of the store."""
        docs = [original(w)] + list(extra_docs)
        counted, fold_only = Counting(), Counting()
        got = compact.run(compact.parse_input({"acts": acts, "docs": docs, "org": w.id}), PROFILES, True,
                          memo(counted), render_genesis.render_size)
        self.assertEqual(got["reason"], "ok")
        for found in opened(snap_of(acts, docs, w.id), fold_only).values():
            found.build()
            resolves = resolve.Resolves(found)
            for node in list(found.nodes.values()):
                resolves.at(node)
        return counted.calls, fold_only.calls

    def test_compact_asks_the_verifier_nothing_that_the_fold_does_not_ask(self):
        w, steps, acts = self.wide(10)
        resolve = w.resolve(AB, steps[:2], steps[0], [steps[1]])
        stranger = w.endorse("dave", steps[0].primary, w.id).jws
        total, fold_only = self.calls(w, acts + resolve.acts + [stranger])
        self.assertEqual(total, fold_only)

    def test_the_verifications_grow_with_the_nodes_and_junk_costs_none(self):
        w, _, small = self.wide(10)
        _, _, big = self.wide(20)
        none = self.calls(w, [])[0]                                                 # the original's receipts
        calls_small = self.calls(w, small)[0]
        calls_big = self.calls(w, big)[0]
        self.assertEqual(calls_big - none, 2 * (calls_small - none))                # linear in the nodes
        junk = ["%06d" % i + "x" * 200 for i in range(2000)]
        orphan = World(name="OTHER").device_add("alice2", AB, salt="o").acts       # unanchored acts of another org
        self.assertEqual(self.calls(w, small + junk + orphan)[0], calls_small)     # none for strings no one reads

    def test_a_twin_of_every_primary_costs_at_most_one_more_verification_per_node(self):
        w, steps, acts = self.wide(10)
        twins = [with_signature(step.primary, LOW).jws for step in steps]
        base = self.calls(w, acts)[0]
        with_twins = self.calls(w, acts + twins)[0]
        self.assertLessEqual(with_twins - base, 10)

    def test_the_keys_of_a_question_do_not_grow_with_the_chain(self):
        def widest(steps):
            w = World()
            vitni = FakeVitni()
            self.assertEqual(go(w, acts_of(linear_chain(w, steps)), vitni=vitni)["reason"], "ok")
            return max(len(keys) for _, keys, _ in vitni.calls)

        self.assertEqual(widest(10), widest(5))

    def test_every_sibling_document_reaches_the_authority_check_and_builds_nothing_again(self):   # CF-13: O(1) per document
        """Siblings hang at the same epoch, so `_check_change` runs once for each against an epoch that is built
        already: it must find it built. A `compact` that rebuilt the previous epoch per document validates the nodes
        of the epoch once for every sibling (a source is untrusted: it can store as many siblings as it likes)."""
        w, _, acts = self.wide(5)

        def work(siblings):
            docs = [original(w)]
            for i in range(siblings):
                doc = w.change_doc(w.id, name="SIBLING%d" % i)
                docs.append(entry(doc, w.sigs(doc, ALL)))
            with mock.patch.object(chain, "Bag", wraps=chain.Bag) as bags, \
                    mock.patch.object(quorum, "check_primary", wraps=quorum.check_primary) as nodes, \
                    mock.patch.object(epoch, "Epoch", wraps=epoch.Epoch) as epochs, \
                    mock.patch.object(epoch, "_check_change", wraps=epoch._check_change) as checked:
                got = go(w, acts, docs=docs, allow_fixture=True)
            self.assertEqual(got["reason"], "ok")
            return nodes.call_count, bags.call_count, epochs.call_count, checked.call_count

        none, few, many = work(0), work(3), work(6)
        self.assertEqual((few[3], many[3]), (3, 6))   # each sibling reached the authority check
        self.assertEqual(few[0], none[0])             # the 5 nodes of the epoch validated once, not once per sibling
        self.assertEqual(many[0], none[0])
        self.assertEqual(many[1], few[1])             # one bag for the store, however many documents
        self.assertEqual((few[2] - none[2], many[2] - none[2]), (3, 6))   # one epoch per document and no more

    def test_every_document_of_a_chain_is_folded_once_whatever_the_length(self):   # design risk 6: one link per document
        def chain_of(length):
            w, docs, previous = World(), [], None
            docs.append(original(w))
            previous = w.doc
            for i in range(length):
                doc = w.change_doc(genesis.doc_hash(previous), name="C%d" % i, prev=previous)
                docs.append(entry(doc, w.sigs(doc, ALL)))
                previous = doc
            return w, docs

        for length in (3, 9):
            w, docs = chain_of(length)
            with mock.patch.object(epoch, "Epoch", wraps=epoch.Epoch) as epochs, \
                    mock.patch.object(chain, "Bag", wraps=chain.Bag) as bags:
                self.assertEqual(go(w, docs=docs, allow_fixture=True)["reason"], "ok")
            self.assertEqual((epochs.call_count, bags.call_count), (length + 1, 1), msg=length)


if __name__ == "__main__":
    unittest.main()
