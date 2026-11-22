"""CF-14 the retained set: what a store keeps, and why nothing it drops changes an answer.

`retain.retained` is built on the fold's own `Epoch`, `Resolves`, `endorse`, `quorum` and `genesis_sigs`; these tests
check each class of design 21.2 (every dropped class dropped, every kept class kept) and then the theorem itself
as a property over generated stores: for every pin whose document is open, the answers of `fold`, `check-act`,
`enrolled`, `recheck-act`, `head` and `genesis-check` (the fold commands) are the same over the store and over its
retained set, the retained set of the retained set drops nothing, and so does any subset of a drop. `sync` is the
seventh command CF-14 names and the only writer: it answers the same over an admit-closed store, its retained set and a
dependents-first prefix of its drop list, and it refuses a raw store that holds an act nothing settles, so it is
compared apart from the six. `store_world` builds the stores from a seed, so a failure names it.
"""
import os
import random
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from handsal_check import chain, checkact, enrolled, foldcmd, genesis, genesis_check, genesis_sigs, quorum, recheck, retain, snapshot, store_posix, sync, verifier
from handsal_check import state as state_module
from handsal_check import head as head_cmd
from handsal_check import store as storefile

from . import old_retain
from .act_builder import BAD, HIGH, FakeVitni, build, head_of, kid_of, memo, with_signature
from .checkact_world import NOW, Scenario, probe_for
from .fold_world import World
from .test_builds import Clock, Probe
from .test_enrolled import FIXTURE, production_world
from .store_world import (ALL, AB, LOW, PRODUCTION_ONLY, PROFILES, REG, after, compacted, entry, later_world, opened, random_store,
                          retained_of, snap_of)
from .profile_sets import production_of
from .shared_reads import Reads
from .sync_worlds import SyncWorlds, admit_closed, dependents_first, parsed, position, sibling_store

TIMED = ("now", "seen", "synced_at", "tip_statement", "next")
DEVICES = ("alice", "alice2", "bob2", "alice3", "frank")   # a device of the original and keys the generator adds in its epochs


def store(w, acts, *changes, sigs=ALL):
    """The snapshot of the organization of `w`: its original and the change documents `changes` (each with the
    receipts of `sigs`), and the strings `acts`."""
    docs = [entry(w.doc, w.sigs(w.doc, ALL))] + [entry(doc, w.sigs(doc, sigs)) for doc in changes]
    return snap_of(acts, docs, w.id)


def dropped(snap):
    """`(drop.acts, drop.sigs)` of the whole store `snap`."""
    return retain.dropped(snap, retained_of(snap))


def gone(snap):
    return set(dropped(snap)[0])


class Classes(unittest.TestCase):
    """Design 21.2: the retained set, class by class."""

    def setUp(self):
        self.w = World()
        w = self.w
        self.a = w.device_add("alice2", AB)
        self.b = w.device_add("bob2", AB, self.a)           # a child of a
        self.f = w.device_add("alice3", ("alice", "carol"))  # a fork child at the root
        self.change = w.change_doc(self.a.id)                # closes epoch 0 at a

    # -- kept
    def test_an_open_epoch_is_kept_whole_a_fork_and_its_losing_branch_included(self):   # D: nothing, CF-14 S1
        w = self.w
        resolve = w.resolve(AB, [self.a, self.f], self.a, [self.f])
        acts = self.a.acts + self.b.acts + self.f.acts + resolve.acts
        self.assertEqual(dropped(store(w, acts)), ([], []))

    def test_every_valid_endorsement_is_kept_and_none_is_chosen(self):   # SD2 (c): an override names them by id
        w = self.w
        carol = w.endorse("carol", self.a.primary, w.id)   # a second counting endorsement, by another person
        snap = store(w, self.a.acts + [carol.jws])
        self.assertEqual(gone(snap), set())

    def test_the_possession_endorsement_of_a_new_key_is_kept(self):   # FO-07
        self.assertIn(self.a.pop.jws, retained_of(store(self.w, self.a.acts)).acts)

    def test_a_change_keeps_the_path_to_its_head_with_the_endorsements_of_those_acts(self):   # D1, GP-19
        w = self.w
        snap = store(w, self.a.acts + self.b.acts + self.f.acts, self.change)
        kept = retained_of(snap).acts
        self.assertTrue(set(self.a.acts) <= kept)
        self.assertEqual(gone(snap), set(self.b.acts) | set(self.f.acts))

    def test_two_sibling_changes_keep_both_paths(self):   # CF-14 S3, GP-12
        w = self.w
        other = w.change_doc(self.f.id, name="SIBLING")
        snap = store(w, self.a.acts + self.b.acts + self.f.acts, self.change, other)
        self.assertEqual(gone(snap), set(self.b.acts))

    def test_a_change_at_the_root_keeps_nothing_of_the_epoch(self):   # CF-14 S2
        w = self.w
        snap = store(w, self.a.acts + self.b.acts + self.f.acts, w.change_doc(w.id))
        self.assertEqual(gone(snap), set(self.a.acts + self.b.acts + self.f.acts))

    def test_the_acts_of_the_epoch_after_a_change_are_kept_whole(self):
        w = self.w
        w1 = later_world(w, self.change)
        c1 = w1.device_add("alice4", AB)
        c2 = w1.device_add("bob3", ("alice", "carol"), person="alice")   # a fork in the open epoch
        snap = store(w, self.a.acts + c1.acts + c2.acts, self.change)
        self.assertEqual(gone(snap), set())

    # -- dropped
    def test_a_resolve_of_a_closed_epoch_is_dropped_the_path_node_beside_it_too(self):   # D2
        w = self.w
        resolve = w.resolve(AB, [self.a, self.f], self.a, [self.f])
        snap = store(w, self.a.acts + self.f.acts + resolve.acts, self.change)
        self.assertEqual(gone(snap), set(resolve.acts) | set(self.f.acts))

    def test_strings_that_are_no_chain_item_are_dropped(self):   # D3, CF-14 S4
        w = self.w
        verdict = Scenario(w).verdict().jws
        receipt = w.sigs(w.doc, ("alice",))[0]
        schema = build("alice", "device.add", org=w.id, body={"x": "y"}, parent=w.id).jws
        junk = ["junk", "", "a.b.c", verdict, receipt, schema]
        self.assertEqual(gone(store(w, self.a.acts + junk)), set(junk))

    def test_an_act_of_another_organization_is_dropped(self):   # D3
        other = World(name="OTHER")
        foreign = other.device_add("alice2", AB)
        self.assertEqual(gone(store(self.w, self.a.acts + foreign.acts)), set(foreign.acts))

    def test_an_act_of_another_organization_at_a_node_of_ours_is_dropped(self):   # D3, anchored
        other = World(name="OTHER")
        foreign = self.w.device_add("bob2", AB, self.a, org=other.id)
        self.assertEqual(gone(store(self.w, self.a.acts + foreign.acts)), set(foreign.acts))

    def test_an_invalid_twin_is_dropped_and_of_two_valid_copies_the_smaller_text_is_kept(self):   # D4, ACT-12
        w = self.w
        bad = with_signature(self.a.primary, BAD).jws
        high = with_signature(self.a.primary, HIGH).jws
        low = with_signature(self.a.primary, LOW).jws
        snap = store(w, self.a.acts + [bad, high, low])
        self.assertEqual(gone(snap), {bad, high, max(low, self.a.primary.jws)})
        self.assertIn(min(low, self.a.primary.jws), retained_of(snap).acts)

    def test_a_stranger_and_a_high_s_endorsement_are_dropped(self):   # D5, FO-08
        w = self.w
        stranger = w.endorse("dave", self.a.primary, w.id).jws
        high = w.endorse("carol", self.a.primary, w.id, sig=HIGH).jws
        bad = w.endorse("carol", self.a.primary, w.id, sig=BAD).jws
        self.assertEqual(gone(store(w, self.a.acts + [stranger, high, bad])), {stranger, high, bad})

    def test_a_pending_primary_an_unanchored_act_and_a_resolve_that_is_no_applicable_one_are_dropped(self):   # D7
        w = self.w
        pending = w.device_add("bob3", ("bob",))              # one person: no quorum, no node
        orphan = w.device_add("carol2", AB, World(name="OTHER").device_add("alice2", AB))   # its parent is no node
        lone = w.resolve(AB, [self.a, self.f], self.a, [self.f])   # f is not stored: a candidate that is no child
        snap = store(w, self.a.acts + pending.acts + orphan.acts + lone.acts)
        self.assertEqual(gone(snap), set(pending.acts + orphan.acts + lone.acts))

    def test_a_receipt_that_counts_for_nothing_is_dropped_and_one_that_counts_is_kept(self):   # D6, GP-15, GP-19
        w = self.w
        doc = w.change_doc(w.id, people=("alice", "frank", "grace"))   # frank and grace are new: possession
        counting = w.sigs(doc, ("alice", "frank", "grace", "bob"))     # bob: an old role holder, authority
        useless = w.sigs(doc, ("dave",)) + w.sigs(doc, ("carol",), head=None) + w.sigs(doc, ("carol",), sig=HIGH)
        snap = snap_of([], [entry(w.doc, w.sigs(w.doc, ALL)), entry(doc, counting + useless)], w.id)
        acts_gone, sigs_gone = dropped(snap)
        self.assertEqual((acts_gone, set(sigs_gone)), ([], set(useless)))

    def test_one_copy_per_receipt_id_of_a_receipt_the_smaller_text(self):   # D4 for receipts
        w = self.w
        twin = w.sigs(w.doc, ("alice",), sig=LOW)[0]
        first = w.sigs(w.doc, ("alice",))[0]
        snap = snap_of([], [entry(w.doc, w.sigs(w.doc, ALL) + [twin])], w.id)
        self.assertEqual(dropped(snap), ([], [max(twin, first)]))

    def test_a_text_that_a_document_keeps_is_never_listed_as_dropped(self):   # SD5 (d): the lists are kept apart
        w = self.w
        doc = w.change_doc(w.id)
        mine = w.sigs(doc, ALL)
        # the receipts of `doc` also sit in the `sigs` of the original, where they count for nothing
        snap = snap_of([], [entry(w.doc, w.sigs(w.doc, ALL) + mine), entry(doc, mine)], w.id)
        self.assertEqual(dropped(snap), ([], []))


class Theorem(unittest.TestCase):
    """CF-14: the answers over the retained set are those over the whole store, for every pin that is open.

    The generator draws pending primaries and orphans, in the cone of an open pin among other places (8 and 25 over the
    24 seeds, for the open pins), so the raw-store test here meets both; the cases it cannot draw, a group split in two
    calls and a relay deleting a primary's endorsements first, are `test_sync.Undecided` and `DropList`."""

    SEEDS = range(24)

    @staticmethod
    def open_pins(snap):
        """The hashes of the documents no document of `snap` has as its `prev`: the pins that are open."""
        closed = {e["doc"].get("prev") for e in snap.docs}
        return [key for key in snapshot.by_hash(snap) if key not in closed]

    @staticmethod
    def synced(snap, pin):
        """What `sync` answers and writes for the snapshot `snap` of a machine pinned at `pin`: the reason, and the
        store it leaves (its acts, lineage and `next`; `synced_at` is the fixed clock)."""
        with tempfile.TemporaryDirectory() as tmp:
            port = store_posix.PosixStore(tmp, os.getuid())
            got = sync.run(sync.parse_input({"acts": list(snap.acts), "docs": list(snap.docs), "org": snap.org}), PRODUCTION_ONLY, memo(), lambda *args: None, Probe(pin), port, Clock(NOW))
            path = Path(port.path(snap.org))
            kept = storefile.parse(path.read_bytes()) if path.exists() else None
            return got, kept and (kept.acts, kept.lineage, kept.next)

    @staticmethod
    def answers(snap, heads):
        """`{(pin, command, argument): answer}` of the six fold commands of the theorem for every open pin: `fold`,
        `check-act` and `recheck-act` (a head each), `enrolled` (a device each), `head` and `genesis-check`."""
        s, out, vitni = Scenario(World(profile=production_of(FIXTURE))), {}, FakeVitni()
        for key in Theorem.open_pins(snap):
            path = snapshot.path_to(snapshot.by_hash(snap), key)
            lineage = [{"doc": e["doc"], "sigs": e["sigs"]} for e in path]
            pin = probe_for(path[-1]["doc"], snap.org)
            fold = foldcmd.parse_input({"acts": list(snap.acts), "lineage": lineage, "org": snap.org, "pin": pin})
            out[key, "fold", None] = foldcmd.run(fold, PRODUCTION_ONLY, False, memo(vitni))
            genesis = genesis_check.parse_input({"acts": list(snap.acts), "lineage": lineage})
            out[key, "genesis-check", None] = genesis_check.run(genesis, PRODUCTION_ONLY, False, memo(vitni))
            for device in DEVICES:
                data = {"acts": list(snap.acts), "device_kid": kid_of(device), "lineage": lineage, "now": NOW,
                        "org": snap.org, "next": "no", "pin": pin, "synced_at": NOW, "tip_statement": None}
                inp = enrolled.parse_input(data, conformance_build=True)
                out[key, "enrolled", device] = enrolled.run(inp, PRODUCTION_ONLY, False, memo(vitni))
            asked = {"acts": list(snap.acts), "lineage": lineage, "now": NOW, "org": snap.org, "next": "no",
                     "pin": pin, "synced_at": NOW, "tip_statement": None}
            out[key, "head", None] = head_cmd.run(head_cmd.parse_input(asked, conformance_build=True), PRODUCTION_ONLY, False, memo(vitni))
            for head in heads:
                value = s.value(s.verdict(head=head_of(head)), acts=list(snap.acts), lineage=lineage, pin=pin,
                                next="no")
                out[key, "check-act", head] = checkact.run(checkact.parse_input(value), PRODUCTION_ONLY, False,
                                                           memo(vitni))
                again = recheck.parse_input({k: v for k, v in value.items() if k not in TIMED})
                out[key, "recheck-act", head] = recheck.run(again, PRODUCTION_ONLY, False, memo(vitni))
        return out

    @staticmethod
    def syncs(snap):
        """`{pin: (answer, store left)}` of `sync` for every open pin of `snap`."""
        return {key: Theorem.synced(snap, probe_for(snapshot.path_to(snapshot.by_hash(snap), key)[-1]["doc"], snap.org))
                for key in Theorem.open_pins(snap)}

    def heads(self, stored, seed):
        rng = random.Random(seed)
        return rng.sample(stored.ids, min(2, len(stored.ids))) + ["A" * 43]

    def test_every_answer_is_the_same_over_the_retained_set_and_over_the_whole_store(self):   # CF-14 S8
        total = 0
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                snap = snap_of(stored.acts, stored.docs, stored.org)
                smaller = compacted(snap)
                total += len(snap.acts) - len(smaller.acts)
                heads = self.heads(stored, seed)
                self.assertEqual(self.answers(smaller, heads), self.answers(snap, heads))
        self.assertGreater(total, 100)   # the stores are not trivial: the generator does build droppable bulk

    def test_sync_over_an_admit_closed_store_and_over_its_retained_set_leaves_the_same_store(self):   # CF-14 S8
        total = 0
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                closed = admit_closed(snap_of(stored.acts, stored.docs, stored.org))
                smaller = compacted(closed)
                total += len(closed.acts) - len(smaller.acts)
                whole, kept = self.syncs(closed), self.syncs(smaller)
                self.assertEqual([got["reason"] for got, _ in whole.values() if got["reason"] == "snapshot_incomplete"], [])
                self.assertEqual(kept, whole)
        self.assertGreater(total, 50)   # and there was something to drop

    @staticmethod
    def holds_an_open_act(raw, closed, pin):
        """Whether the raw store `raw` holds, for a machine pinned at the document hash `pin`, an act that a relay
        would not have admitted (its receipt id is not in `closed`) and that is a pending primary or an orphan in the
        cone: its chain of parents reaches a document of the cone, or leaves the union. Written from the refusal of a raw store with an open act and the
        positions of the documents, not from `retain.undecided`: an act below a document off the pinned lineage or
        before the pin is decided, and so is an endorsement of an act that is a node, of an endorsement, or of a
        document."""
        acts = parsed(raw.acts, raw.org, REG.wire)
        admitted = set(parsed(closed.acts, closed.org, REG.wire))
        documents = {genesis.doc_hash(item["doc"]): item["doc"] for item in raw.docs}
        for act in acts.values():
            if act.id in admitted:
                continue
            if act.method == chain.ENDORSE:
                target = acts.get(act.parent)
                if act.parent in documents or act.parent in admitted or (target is not None and target.method == chain.ENDORSE):
                    continue
            root = act.parent
            while root in acts:
                root = acts[root].parent
            if root not in documents or position(documents, documents[pin], root) == "cone":
                return True
        return False

    def test_sync_over_a_raw_store_is_snapshot_incomplete_or_leaves_what_the_admit_closed_store_leaves(self):   # CF-13
        refused = taken = 0
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                raw = snap_of(stored.acts, stored.docs, stored.org)
                admitted = admit_closed(raw)
                closed = self.syncs(admitted)
                for key, (got, kept) in self.syncs(raw).items():
                    # refused exactly when the raw store holds a pending primary or an orphan in the cone: the
                    # admit-closed store drops those same acts, so it cannot say when a drop was silent
                    self.assertEqual(got["reason"] == "snapshot_incomplete", self.holds_an_open_act(raw, admitted, key))
                    if got["reason"] == "snapshot_incomplete":
                        refused += 1
                        self.assertEqual((got["synced_at"], kept), (None, None))   # nothing written
                    else:
                        taken += 1
                        self.assertEqual((got, kept), closed[key])
        self.assertGreater(refused, 10)   # the raw stores hold pending primaries and orphans in the cone
        self.assertGreater(taken, 10)     # and some hold none, which `sync` takes as the whole store

    def test_compacting_the_retained_set_drops_nothing(self):   # CF-14 S8
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                once = compacted(snap_of(stored.acts, stored.docs, stored.org))
                self.assertEqual(dropped(once), ([], []))
                self.assertEqual(compacted(once), once)

    def test_any_subset_of_a_drop_keeps_the_answers(self):   # CF-14 S9
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                snap = snap_of(stored.acts, stored.docs, stored.org)
                rng = random.Random(seed)
                acts_gone, sigs_gone = dropped(snap)
                part = after(snap, [a for a in acts_gone if rng.random() < 0.5],
                             [s for s in sigs_gone if rng.random() < 0.5])
                heads = self.heads(stored, seed)
                self.assertEqual(self.answers(part, heads), self.answers(snap, heads))

    def test_sync_over_a_dependents_first_prefix_of_a_drop_list_leaves_the_same_store(self):   # CF-14 S9
        prefixes = 0
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                stored = random_store(seed, production_of(FIXTURE))
                closed = admit_closed(snap_of(stored.acts, stored.docs, stored.org))
                rng = random.Random(seed)
                acts_gone, sigs_gone = dropped(closed)
                order = dependents_first(closed, acts_gone)
                prefix = order[:rng.randint(0, len(order))]
                prefixes += bool(prefix) and len(prefix) < len(order)
                part = after(closed, prefix, [s for s in sigs_gone if rng.random() < 0.5])
                self.assertEqual(self.syncs(part), self.syncs(closed))
        self.assertGreater(prefixes, 5)   # most prefixes are proper: neither empty nor the whole list

    def test_the_generator_reaches_the_classes_the_theorem_is_about(self):
        seen = set()
        for seed in self.SEEDS:
            stored = random_store(seed, production_of(FIXTURE))
            snap = snap_of(stored.acts, stored.docs, stored.org)
            seen.add(("closed", any(e["doc"].get("prev") for e in snap.docs)))
            prevs = [e["doc"]["prev"] for e in snap.docs if e["doc"].get("prev")]
            seen.add(("sibling", len(set(prevs)) < len(prevs)))
            nodes = [n for found in opened(snap).values() for n in found.nodes.values() if n.act is not None]
            seen.add(("member", any(n.act.method == "local:handsal.member.add" for n in nodes)))
            kept = retained_of(snap).receipts   # a receipt the store keeps that is no possession receipt: authority only
            for item in snap.docs:
                if any(not genesis_sigs.counting(item["doc"], [t], snap.org, REG.wire, FakeVitni())
                       for t in kept[genesis.doc_hash(item["doc"])]):
                    seen.add(("authority-only", True))
        self.assertTrue({("closed", True), ("sibling", True), ("member", True), ("authority-only", True)} <= seen, seen)


class DropList(unittest.TestCase):
    """CF-14, the duties of a source: a drop list names every dependent of what it removes, and a relay that applies it
    dependents first leaves no reader at an open pin refused."""

    @staticmethod
    def dependents_missing(snap):
        """The strings of `snap` whose `parent` is a removed receipt id and that the drop list does not name."""
        gone_acts, _ = dropped(snap)
        kept = set(snap.acts) - set(gone_acts)
        read = lambda text: chain.read(text, REG.wire, snap.org)
        kept_ids = {act.id for act in map(read, kept) if act is not None}
        removed = {act.id for act in map(read, gone_acts) if act is not None} - kept_ids
        return sorted(text for text in kept if (act := read(text)) is not None and act.parent in removed)

    def test_a_drop_list_holds_every_dependent(self):   # CF-14
        named = 0
        for seed in range(24):
            for name, make in (("random", random_store), ("sibling", sibling_store)):
                with self.subTest(seed=seed, store=name):
                    stored = make(seed, production_of(FIXTURE))
                    snap = snap_of(stored.acts, stored.docs, stored.org)
                    named += len(dropped(snap)[0])
                    self.assertEqual(self.dependents_missing(snap), [])
        self.assertGreater(named, 500)   # the lists are not empty: there are strings to name

    def setUp(self):
        self.s = Scenario(production_world())
        self.k = SyncWorlds(self.s)
        self.docs = self.s.lineage + [self.k.dh[1]]
        self.at = {"D1": probe_for(self.s.w.doc, self.s.w.id), "DH": self.k.pinned_at(self.k.dh[0])}

    def reader(self, acts, at):
        """`(reason, stored acts)` of a fresh reader pinned at `at` ("D1" or "DH") given the strings `acts`."""
        got, kept = Theorem.synced(snap_of(acts, self.docs, self.s.w.id), self.at[at])
        return got["reason"], None if kept is None else len(kept[0])

    def test_a_drop_list_applied_dependents_first_refuses_no_reader_at_an_open_pin(self):   # CF-14
        k = self.k
        whole = snap_of(k.a.acts + k.f.acts, self.docs, self.s.w.id)
        order = dependents_first(whole, dropped(whole)[0])
        self.assertEqual(order[-1], k.f.acts[0])   # f's primary goes after both strings that endorse it
        states = [after(whole, order[:count]).acts for count in range(len(order) + 1)]
        self.assertEqual([self.reader(acts, "DH") for acts in states], [("ok", 3)] * len(states))
        self.assertEqual([self.reader(acts, "D1") for acts in states],
                         [("epoch_superseded", 6), ("snapshot_incomplete", None), ("snapshot_incomplete", None),
                          ("epoch_superseded", 3)])   # the pin D1 is superseded: refused until the last deletion

    def test_a_drop_list_applied_parents_first_refuses_both_readers(self):   # CF-14
        k = self.k
        parents_first = k.a.acts + k.f.acts[1:]   # f's primary is gone while strings that endorse it remain
        self.assertEqual(self.reader(parents_first, "D1"), ("snapshot_incomplete", None))
        self.assertEqual(self.reader(parents_first, "DH"), ("snapshot_incomplete", None))

    def test_a_relay_that_applied_part_of_its_list_refuses_both_pins_until_it_applies_the_rest(self):   # CF-14
        k = self.k
        partial = snap_of(k.a.acts + k.g.acts, self.docs, self.s.w.id)   # g stays, its parent f is gone
        self.assertEqual(self.reader(partial.acts, "DH"), ("snapshot_incomplete", None))
        self.assertEqual(self.reader(partial.acts, "D1"), ("snapshot_incomplete", None))
        after_list = after(partial, *dropped(partial)).acts
        self.assertEqual(sorted(after_list), sorted(k.a.acts))   # the list took f and g, and nothing of a
        self.assertEqual(self.reader(after_list, "DH"), ("ok", 3))
        self.assertEqual(self.reader(after_list, "D1"), ("epoch_superseded", 3))


class Superseded(unittest.TestCase):
    """CF-14, a pin the store supersedes: what the theorem does not claim, pinned as it is. A machine pinned at the
    original while the store holds a change at `a`: its epoch is closed in the store, so compaction keeps only the
    path to `a`, and the fork at the root (`a` against `f`) is gone."""

    def setUp(self):
        self.w = World(profile=production_of(FIXTURE))
        w = self.w
        self.a, self.f = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        self.change = w.change_doc(self.a.id)
        self.whole = store(w, self.a.acts + self.f.acts, self.change)
        self.small = compacted(self.whole)

    def answers(self, snap, next_="no", device="alice", w=None, on_path=None):
        """`(fold error, recheck-act of a head on the path, check-act, enrolled of `device`)` for the machine pinned
        at the original of `w` (default the world of the test), `on_path` the head of its successor."""
        w, on_path = w or self.w, on_path or self.a.id
        lineage, pin = [entry(w.doc, w.sigs(w.doc, ALL))], probe_for(w.doc, w.id)
        s, vitni, acts = Scenario(w), FakeVitni(), list(snap.acts)
        folded = foldcmd.run(foldcmd.parse_input({"acts": acts, "lineage": lineage, "org": w.id, "pin": pin}), PRODUCTION_ONLY, False, memo(vitni))
        value = s.value(s.verdict(head=head_of(on_path)), acts=acts, lineage=lineage, pin=pin, next=next_)
        again = recheck.parse_input({k: v for k, v in value.items() if k not in TIMED})
        data = {"acts": acts, "device_kid": kid_of(device), "lineage": lineage, "now": NOW, "org": w.id,
                "next": next_, "pin": pin, "synced_at": NOW, "tip_statement": None}
        return (folded.get("error"), recheck.run(again, PRODUCTION_ONLY, False, memo(vitni))["reason"],
                checkact.run(checkact.parse_input(value), PRODUCTION_ONLY, False, memo(vitni))["reason"],
                enrolled.run(enrolled.parse_input(data, conformance_build=True), PRODUCTION_ONLY, False,
                             memo(vitni))["reason"])

    def headed(self, snap, next_="yes", w=None):
        """`head` of the machine pinned at the original of `w`: `(head, reason)`."""
        w = w or self.w
        data = {"acts": list(snap.acts), "lineage": [entry(w.doc, w.sigs(w.doc, ALL))], "now": NOW, "org": w.id,
                "next": next_, "pin": probe_for(w.doc, w.id), "synced_at": NOW, "tip_statement": None}
        got = head_cmd.run(head_cmd.parse_input(data, conformance_build=True), PRODUCTION_ONLY, False,
                           memo())
        return got["head"], got["reason"]

    def checked(self, snap, signer):
        """`(reason, class)` of `check-act` for an act of `signer` at `next` `"yes"`."""
        w, s = self.w, Scenario(self.w)
        value = s.value(s.verdict(signer=signer, head=head_of(self.a.id)), acts=list(snap.acts),
                        lineage=[entry(w.doc, w.sigs(w.doc, ALL))], pin=probe_for(w.doc, w.id), next="yes")
        got = checkact.run(checkact.parse_input(value), PRODUCTION_ONLY, False, memo())
        return got["reason"], got["class"]

    def fold_of(self, snap, w=None):
        w = w or self.w
        value = {"acts": list(snap.acts), "lineage": [entry(w.doc, w.sigs(w.doc, ALL))], "org": w.id,
                 "pin": probe_for(w.doc, w.id)}
        return foldcmd.run(foldcmd.parse_input(value), PRODUCTION_ONLY, False, memo())

    def test_the_fork_the_compaction_removed_is_the_only_difference_and_the_machine_is_told(self):
        self.assertLess(len(self.small.acts), len(self.whole.acts))
        # the readers that are told `next` say `epoch_superseded` either way: the fork is a verdict about an open tip
        for snap in (self.whole, self.small):
            self.assertEqual(self.answers(snap, "yes")[2:], ("epoch_superseded", "epoch_superseded"))
            self.assertEqual(self.headed(snap), (None, "epoch_superseded"))   # `head` reads `next` too, and has no head
        # `fold` and `recheck-act` read no `next`: the whole store has a fork at the root, so `a` is past a fork
        # parent (`stale_view`); the compacted store keeps only the path to the head `a` of the successor, so `a` is a
        # node of the accepted chain. The head is one the successor's signers chose (GP-19), and it is the answer
        # the machine gives after its re-pin
        self.assertEqual(self.answers(self.whole)[:2], ("fork", "stale_view"))
        self.assertEqual(self.answers(self.small)[:2], (None, "ok"))

    def test_enrolled_can_answer_local_key_unknown_over_the_compacted_store_where_the_whole_store_answered_the_fork(self):
        """CF-14 scope, W-B: `enrolled` reads the device (step 5) before the view (step 6). A device that lives only
        on the branch the compaction removed is `local_key_unknown` over the compacted store; over the whole store the
        fork is converted to `epoch_superseded` first. Both are refusals, and a machine with `next` `yes` is never
        enrolled, over either store, whatever the device."""
        self.assertEqual(self.answers(self.whole, "yes", "alice3")[3], "epoch_superseded")
        self.assertEqual(self.answers(self.small, "yes", "alice3")[3], "local_key_unknown")
        # `check-act` signed by that key: the whole store converts the fork before step 9, the compacted one reaches it
        self.assertEqual(self.checked(self.whole, "alice3"), ("epoch_superseded", None))
        self.assertEqual(self.checked(self.small, "alice3"), ("unknown_key", None))
        self.assertEqual(self.checked(self.whole, "alice"), ("epoch_superseded", None))           # a key the state holds:
        self.assertEqual(self.checked(self.small, "alice"), ("epoch_superseded", "apple-se-bio"))   # same reason, a class
        for snap in (self.whole, self.small):
            for device in ("alice", "alice2", "alice3", "bob", "carol"):
                self.assertNotEqual(self.answers(snap, "yes", device)[3], "ok", msg=device)
        # `head` reads no device: over both stores it answers `epoch_superseded`, where `check-act` and `enrolled`
        # answer it for a key the state holds, and it never differs between the stores
        self.assertEqual(self.headed(self.whole), self.headed(self.small))

    def test_fold_over_the_compacted_store_can_be_a_state_with_another_tip_where_the_whole_store_was_a_state(self):
        """CF-14 scope, W-B: with no fork the whole store's tip is the end of its accepted chain, and the compacted
        store's is the end of the path to H: the two are states and they differ. The answers that authorize read
        `next`: `check-act` and `enrolled` refuse `epoch_superseded` for every device the whole store holds."""
        w = World(profile=production_of(FIXTURE))
        a = w.device_add("alice2", AB)
        b = w.device_add("bob2", AB, a)      # a child of a, past the head a of the successor
        change = w.change_doc(a.id)
        whole = store(w, a.acts + b.acts, change)
        small = compacted(whole)
        self.assertLess(len(small.acts), len(whole.acts))
        before, after_ = self.fold_of(whole, w), self.fold_of(small, w)
        self.assertNotIn("error", before)
        self.assertNotIn("error", after_)
        self.assertNotEqual(before, after_)
        self.assertEqual(self.answers(whole, "yes", "bob2", w, a.id)[2:], ("epoch_superseded", "epoch_superseded"))
        # the device of the removed node is unknown over the compacted store, a refusal and not an `ok`
        self.assertEqual(self.answers(small, "yes", "bob2", w, a.id)[3], "local_key_unknown")
        for snap in (whole, small):
            for device in ("alice", "alice2", "bob2"):
                self.assertNotEqual(self.answers(snap, "yes", device, w, a.id)[3], "ok", msg=device)
            self.assertEqual(self.headed(snap, "yes", w), (None, "epoch_superseded"))   # no head, over either store

    def test_a_machine_that_syncs_a_compacted_snapshot_is_told_in_the_same_write(self):   # CF-09 step 5, SD4
        w = self.w
        with tempfile.TemporaryDirectory() as tmp:
            port = store_posix.PosixStore(tmp, os.getuid())
            snap = self.small
            got = sync.run(sync.parse_input({"acts": list(snap.acts), "docs": list(snap.docs), "org": w.id}), PRODUCTION_ONLY, memo(), lambda *args: None, Probe(probe_for(w.doc, w.id)), port,
                           Clock(NOW))
            self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
            self.assertEqual(storefile.parse(Path(port.path(w.id)).read_bytes()).next, "yes")


def new_read_endorsements(found, parsed, texts):
    """`retain.read_endorsements` over `texts` read one by one, as `admit` reads an item's `sigs`."""
    readings = [act for act in (chain.read(text, found.bag.wire, found.bag.org) for text in texts) if act is not None]
    return retain.read_endorsements(parsed, readings)


def old_verified(epoch, group, keys):
    """`endorse.verified` as it was: a text of the group verifies against the whole map `keys`."""
    method = group.act.method
    return any(verifier.is_low_s(copy.signature) and epoch.vitni.verify(copy.jws, keys, method) == "ok"
               for copy in group.copies)


def old_possession(epoch, group, state, person, kid, sign):
    """`endorse.possession` as it was: the whole map plus the new key as active."""
    keys = {owner: dict(entries) for owner, entries in state.keys_map().items()}
    keys.setdefault(person, {})[kid] = verifier.key_entry(sign, "active")
    for endorsement in epoch.bag.endorsements_of(group.act):
        if (endorsement.act.kid == kid and endorsement.act.performer == person
                and old_verified(epoch, endorsement, keys)):
            return True
    return False


def old_kept_endorsements(base, parent, parsed, readings):
    """`retain.kept_endorsements` as it was: the usable kids are read off the whole map."""
    keys, new_key = parent.state.keys_map(), quorum.introduced(parsed)
    usable = {kid for entries in keys.values() for kid in entries}
    if new_key is not None:
        usable.add(new_key[1])
    kept, seen = [], set()
    for kid, text, alone in readings:
        if kid not in usable:
            continue
        found = alone.bag.endorsements_of(parsed)[0]
        if found.act.id in seen:
            continue
        group = alone.bag.groups[parsed.id]
        if (old_verified(alone, found, keys)
                or (new_key is not None and old_possession(alone, group, parent.state, *new_key))):
            seen.add(found.act.id)
            kept.append(text)
    return sorted(kept)


class ReadsOneEntry(unittest.TestCase):
    """CF-14: the endorsements a store keeps are the same, and asked about the same way, whether the usable kids are
    read off the whole map of the state or one kid at a time. A kid is usable when the state has an entry for it or
    when it is the new key."""

    @staticmethod
    def sites(found):
        """`(parent node, parsed act, texts)` for every act of the epoch `found`, the texts every string of the store
        that is a copy of an endorsement group of it; each side reads them as it reads."""
        found.build()
        out = []
        for node in list(found.nodes.values()):
            if node.act is None:
                continue
            parsed = found.bag.groups[node.id].act
            texts = [copy.jws for group in found.bag.endorsements_of(parsed) for copy in group.copies]
            out.append((node.parent, parsed, texts))
        return out

    def test_the_kept_texts_and_the_questions_are_those_of_the_whole_map_over_generated_stores(self):
        anything = False
        for seed in range(8):
            store_ = random_store(seed)
            snap = snap_of(store_.acts, store_.docs, store_.org)
            old, new = FakeVitni(), FakeVitni()
            for run, read_of, kept_of, vitni in (("old", old_retain.read_endorsements, old_kept_endorsements, old),
                                                 ("new", new_read_endorsements, retain.kept_endorsements, new)):
                kept = []
                for found in opened(snap, vitni).values():
                    for parent, parsed, texts in self.sites(found):
                        kept.append(kept_of(found, parent, parsed, read_of(found, parsed, texts)))
                if run == "old":
                    want = kept
                else:
                    self.assertEqual(kept, want, msg=seed)
            self.assertEqual({(j, m) for j, _, m in new.calls}, {(j, m) for j, _, m in old.calls}, msg=seed)
            anything = anything or any(want)
        self.assertTrue(anything)

    def test_each_kind_of_kid_is_kept_or_dropped_as_before(self):
        w = World(extra=("bob2",))
        removal = w.device_remove("bob2", ("alice", "carol"))
        step = w.device_add("alice2", ("alice", "bob"), removal)
        revoked = w.endorse("bob2", step.primary, removal.id)                       # a kid of the state, removed
        other = w.endorse("carol", step.primary, removal.id, performer="alice")      # a kid of another person
        stranger = w.endorse("dave", step.primary, removal.id)                       # no key of the state
        texts = [step.endorsements["bob"].jws, step.pop.jws, revoked.jws, other.jws, stranger.jws]
        found = w.epoch(removal, step, *texts[:2])
        parent = found.nodes[removal.id]
        parsed = found.bag.groups[step.id].act
        readings = new_read_endorsements(found, parsed, texts)
        self.assertEqual(len(readings), 5)
        kept = retain.kept_endorsements(found, parent, parsed, readings)
        self.assertEqual(kept, old_kept_endorsements(found, parent, parsed,
                                                     old_retain.read_endorsements(found, parsed, texts)))
        self.assertEqual(set(kept), {step.endorsements["bob"].jws, step.pop.jws})   # bob counts, the new key proves
        self.assertEqual(parent.state.keys_for("bob", kid_of("bob2"))["bob"][kid_of("bob2")]["status"], "revoked")

    def test_an_endorsement_by_a_signer_the_state_has_no_entry_for_is_neither_kept_nor_asked(self):
        w = World()
        step = w.device_add("alice2", AB)
        vitni = FakeVitni()
        found = w.epoch(step, vitni=vitni)
        stranger = w.endorse("dave", step.primary, w.id)   # no key of the state, and not the new key
        texts = [step.endorsements["bob"].jws, step.pop.jws, stranger.jws]
        parsed = found.bag.groups[step.id].act
        readings = new_read_endorsements(found, parsed, texts)
        self.assertEqual(len(readings), 3)
        vitni.calls.clear()
        kept = retain.kept_endorsements(found, found.root, parsed, readings)
        self.assertEqual(set(kept), {step.endorsements["bob"].jws, step.pop.jws})
        self.assertNotIn(stranger.jws, [text for text, _, _ in vitni.calls])

    def test_the_state_is_read_one_kid_at_a_time_and_never_projected_whole(self):
        w = World()
        step = w.device_add("alice2", AB)
        found = w.epoch(step)
        texts = [step.endorsements["bob"].jws, step.pop.jws, w.endorse("dave", step.primary, w.id).jws]
        parsed = found.bag.groups[step.id].act
        readings = new_read_endorsements(found, parsed, texts)
        parent = types.SimpleNamespace(state=state_module.State(found.root.state.members, found.root.state.devices))
        with mock.patch.object(state_module.State, "keys_map", side_effect=AssertionError("the whole map")), Reads() as reads:
            kept = retain.kept_endorsements(found, parent, parsed, readings)
        self.assertEqual(set(kept), {step.endorsements["bob"].jws, step.pop.jws})
        self.assertEqual(reads.walked, 0)

    def test_compaction_projects_no_state_to_its_whole_map(self):
        store_ = random_store(3)
        snap = snap_of(store_.acts, store_.docs, store_.org)
        with mock.patch.object(state_module.State, "keys_map", side_effect=AssertionError("the whole map")):
            self.assertTrue(retain.retained(opened(snap), retain.closing_heads(snap.docs), snap).acts)


class EndorsementsKeptAsBefore(unittest.TestCase):
    """CF-14: the endorsements kept for an act are the same texts, and the verifier is asked the same questions, as
    when each text was judged in an epoch of its own over the act and that text (`old_retain`). Over every node of
    generated stores, with the texts of the store, texts that are not in it, a twin with a bad signature and a text
    signed by a kid no state holds, as `admit` offers an item's signatures. Bound: seeds 0 to 7, the whole class is
    under 2 s."""

    SEEDS = range(8)
    OTHERS = 5   # texts of the store offered besides the endorsements of the act itself

    @staticmethod
    def offers(found, group, snap):
        """`[(what, texts)]`: the texts offered for the act `group`, four ways."""
        parsed = group.act
        stored = [copy.jws for item in found.bag.endorsements_of(parsed) for copy in item.copies]
        bad = [with_signature(copy, BAD).jws for item in found.bag.endorsements_of(parsed) for copy in item.copies]
        stranger = build("dave", "act.endorse", org=found.bag.org, body={"act": parsed.id}, parent=parsed.id,
                         parent_performer=parsed.performer, head=head_of(parsed.parent)).jws
        return [("stored", stored), ("store", stored + list(snap.acts[:EndorsementsKeptAsBefore.OTHERS]) + ["junk"]),
                ("bad twins", stored + bad), ("stranger", stored + [stranger] + bad[:1])]

    def run_pipeline(self, seed, how):
        """`{(node id, what): kept texts}` and the questions that reached the verifier, for one pipeline."""
        stored = random_store(seed, production_of(PROFILES))
        snap = snap_of(stored.acts, stored.docs, stored.org)
        vitni, out = FakeVitni(), {}
        for found in opened(snap, vitni).values():
            found.build()
            for node in list(found.nodes.values()):
                if node.act is None:
                    continue
                group = found.bag.groups[node.id]
                for what, texts in self.offers(found, group, snap):
                    if how == "old":
                        got = old_retain.kept_endorsements(found, node.parent, group.act,
                                                           old_retain.read_endorsements(found, group.act, texts))
                    elif how == "new":
                        got = retain.kept_endorsements(found, node.parent, group.act,
                                                       new_read_endorsements(found, group.act, texts))
                    elif what == "stored":
                        got = retain.kept_act(found, group, node.parent)[1]
                    else:
                        continue
                    out[(genesis.doc_hash(found.doc), node.id, what)] = got
        return out, Counter(vitni.calls)

    def test_the_kept_texts_and_the_questions_are_those_of_an_epoch_per_text_over_generated_stores(self):
        anything = False
        for seed in self.SEEDS:
            old, old_questions = self.run_pipeline(seed, "old")
            new, new_questions = self.run_pipeline(seed, "new")
            self.assertEqual(new, old, msg=seed)
            self.assertEqual(new_questions, old_questions, msg=seed)
            for (doc, node, what), kept in old.items():
                if what == "bad twins":   # a twin of a stored receipt id is never the text kept
                    self.assertEqual(kept, old[(doc, node, "stored")], msg=(seed, node))
            anything = anything or any(old.values())
        self.assertTrue(anything)

    def test_the_kept_texts_of_an_act_are_those_of_an_epoch_per_text_over_generated_stores(self):
        anything = False
        for seed in self.SEEDS:
            old, _ = self.run_pipeline(seed, "old")
            act, _ = self.run_pipeline(seed, "act")
            self.assertEqual(act, {key: old[key] for key in act}, msg=seed)
            anything = anything or any(act.values())
        self.assertTrue(anything)


if __name__ == "__main__":
    unittest.main()
