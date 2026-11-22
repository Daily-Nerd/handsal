"""CF-09 `handsal-check sync`: the only writer of the store.

`run` takes the pin probe, the store port and the clock as arguments, like the production table does, so each test
gives them: a recording probe, a real `PosixStore` over a temporary home, and a fixed clock. Nothing here touches
the real home. Each refusal leaves the store byte for byte (or absent), writes no clock read and answers
`{reason, synced_at: null}`.

The store holds the retained set of what the machine has read (CF-14): `sync` writes the union of the stored and the
input acts after the fold and the retained set (`retain`), measured on that retained store, and records `next`, the
fact that a valid successor of the pinned document is known (SD4, VR-12).
"""
import contextlib
import inspect
import json
import os
import random
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import chain, encoding, errors, genesis, genesis_sigs, ijson, opening, policy as policy_module, profiles, registry, render_genesis, retain, store, store_posix
from handsal_check import epoch as epoch_module
from handsal_check import snapshot, sync, verifier

from .act_builder import FakeVitni, Unavailable, head_of, memo
from .checkact_world import NOW, Scenario, probe_for
from .test_builds import Clock, Probe, production_input, production_table, run
from .fold_world import World
from .genesis_fixtures import change, policy
from .store_world import AB, LOW, POOLS, Counting, after, grow, later_world, random_store, retained_of
from . import v042_tree
from .sync_worlds import (SyncWorlds, admit_closed, dependents_first, parsed, position, read_oracle, release_profiles,
                          sibling_store)
from .test_enrolled import FIXTURE, PRODUCTION_ONLY, production_world, value as enrolled_value
from .profile_sets import production_of, synthetic_set

REG = registry.load()
LATER = "2026-01-01T09:00:00Z"
MAX = 16777216


def canon(lineage):
    """The stored form of a lineage: each entry's `sigs` sorted and unique (CF-09)."""
    return [{"doc": entry["doc"], "sigs": sorted(set(entry["sigs"]))} for entry in lineage]


def snap(acts, docs, org):
    """The `sync` input of the snapshot `{acts, docs, org}`, read by the one parser (CF-13)."""
    return sync.parse_input({"acts": list(acts), "docs": docs, "org": org})


def wire(s, **over):
    """The probe object of the pin of the scenario `s`, with the members of `over` replaced."""
    return {**s.value()["pin"], **over}


def absent(s, reason):
    return wire(s, bytes_b64="", owner_ok=False, reason=reason)


class Case(unittest.TestCase):
    profile_set = PRODUCTION_ONLY   # the editions the machine under test implements

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.port = store_posix.PosixStore(self.root, os.getuid())
        self.s = Scenario(production_world())
        self.org = self.s.w.id
        self.clock = Clock(NOW)

    def inp(self, acts=(), docs=None, org=None):
        return snap(acts, self.s.lineage if docs is None else docs, org or self.org)

    def sync(self, acts=(), *, probe=None, vitni=None, port=None, docs=None, org=None, clock=None):
        probe = probe or Probe(wire(self.s))
        return sync.run(self.inp(acts, docs, org), self.profile_set, memo(vitni), lambda *args: None,
                        probe, port or self.port, clock or self.clock)

    @property
    def path(self):
        return Path(self.port.path(self.org))

    def stored(self):
        return store.parse(self.path.read_bytes())

    def refused(self, code, got):
        self.assertEqual(got, {"reason": code, "synced_at": None})


class Writing(Case):
    def test_a_first_sync_creates_the_store_private_and_stamps_the_clock(self):
        got = self.sync()
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.clock.calls, 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.path.parent).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        view = self.stored()
        self.assertEqual((view.acts, view.lineage, view.synced_at), ([], canon(self.s.lineage), NOW))

    def test_a_second_sync_keeps_every_retained_act(self):   # CF-09 S6, CF-13 S3
        step = self.s.w.device_add("alice2", ("alice", "bob"))
        self.assertEqual(self.sync(step.acts)["reason"], "ok")
        every = store.canonical(step.acts)
        self.assertEqual(self.stored().acts, every)
        for subset in (step.acts[:1], [], step.acts):
            self.clock.value = LATER
            self.assertEqual(self.sync(subset), {"reason": "ok", "synced_at": LATER})
            self.assertEqual(self.stored().acts, every)
            self.assertEqual(self.stored().synced_at, LATER)   # a sync that adds nothing still refreshes the clock

    def test_a_new_act_is_added_to_the_stored_ones(self):
        first = self.s.w.device_add("alice2", ("alice", "bob"))
        second = self.s.w.device_add("bob2", ("bob", "alice"), first)
        self.sync(first.acts)
        self.sync(second.acts)
        self.assertEqual(self.stored().acts, store.canonical(first.acts + second.acts))

    def test_a_forked_union_is_written_as_fork(self):
        c1 = self.s.w.device_add("alice2", ("alice", "bob"))
        c2 = self.s.w.device_add("alice3", ("alice", "carol"))
        self.assertEqual(self.sync(c1.acts)["reason"], "ok")
        self.clock.value = LATER
        self.assertEqual(self.sync(c2.acts), {"reason": "fork", "synced_at": LATER})
        self.assertEqual((self.stored().acts, self.stored().synced_at), (store.canonical(c1.acts + c2.acts), LATER))
        self.assertEqual(self.sync(c1.acts)["reason"], "fork")   # the stored fork stays: the set only grows

    def test_a_leftover_temporary_file_is_replaced(self):
        self.sync()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(b"half a store")
        self.assertEqual(self.sync()["reason"], "ok")
        self.assertFalse(tmp.exists())


class Refusing(Case):
    def test_a_lineage_of_another_org_is_refused_and_the_store_is_unchanged(self):
        self.sync()
        before = self.path.read_bytes()
        other = Scenario(production_world(name="OTHER"))
        self.clock.calls = 0
        self.refused("lineage_broken", self.sync(docs=other.lineage))
        self.assertEqual((self.path.read_bytes(), self.clock.calls), (before, 0))

    def test_every_pin_reason_is_refused_before_a_directory_exists(self):
        s = self.s
        for reason in ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected"):
            with self.subTest(reason=reason):
                self.refused(reason, self.sync(probe=Probe(absent(s, reason))))
        self.assertEqual(os.listdir(self.root), [])

    def test_no_pin_or_a_wsl2_host_creates_no_directory(self):   # CF-09 S9
        for reason in ("pin_missing", "pin_probe_unprotected"):
            self.refused(reason, self.sync(probe=Probe(absent(self.s, reason))))
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(self.clock.calls, 0)

    def test_a_pin_of_another_profile_or_org_is_refused_first(self):
        other = Scenario(production_world(name="OTHER"))
        self.refused("pin_org_mismatch", self.sync(probe=Probe(other.value()["pin"])))
        self.assertEqual(os.listdir(self.root), [])

    def test_the_fixture_profile_is_refused(self):
        fixture = Scenario()   # the pin and the lineage name the fixture profile, which the profile set knows
        got = sync.run(snap([], fixture.lineage, fixture.w.id), profiles.load(), memo(),
                       lambda *args: None, Probe(fixture.value()["pin"]), self.port, self.clock)
        self.refused("fixture_profile", got)
        self.assertEqual(os.listdir(self.root), [])

    def test_a_verifier_that_cannot_answer_writes_nothing(self):   # CF-09 S9
        self.refused("verifier_unavailable", self.sync(vitni=Unavailable()))
        self.assertFalse(self.path.exists())
        self.assertEqual(self.clock.calls, 0)
        self.sync()
        before = self.path.read_bytes()
        self.refused("verifier_unavailable", self.sync(vitni=Unavailable()))
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_fold_error_writes_nothing(self):
        self.sync()
        before = self.path.read_bytes()
        w = self.s.w
        unsigned = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), w.id, people=("alice", "bob", "carol"),
                          pol=policy(), name="NEXT")   # a change nobody signed: no receipt anywhere
        broken = self.s.lineage + [{"doc": unsigned, "sigs": []}]
        got = self.sync(docs=broken, probe=Probe(probe_for(unsigned, w.id)))
        self.assertEqual(got, {"reason": "genesis_unsigned", "synced_at": None})
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_malformed_store_is_refused_and_never_overwritten(self):   # CF-09 S10
        self.sync()
        self.path.write_bytes(b"not a store\n")
        self.refused("store_malformed", self.sync())
        self.assertEqual(self.path.read_bytes(), b"not a store\n")
        os.chmod(self.path, 0o666)
        self.refused("store_owner", self.sync())
        self.assertEqual(self.path.read_bytes(), b"not a store\n")
        self.assertEqual(self.clock.calls, 1)

    def test_a_retained_store_over_max_input_is_store_full(self):   # CF-09 S5, L15
        w = self.s.w
        first = w.device_add("alice2", AB)
        second = w.device_add("bob2", AB, first)
        lineage = canon(self.s.lineage)
        small = len(store.encode(first.acts, lineage, "no", NOW))
        big = len(store.encode(first.acts + second.acts, lineage, "no", NOW))
        self.assertLess(small, big)
        # the limit is scaled down so that the retained store of `second` is over it and the one before is not:
        # the order of the answers is what is tested, the real MAX_INPUT is the same constant
        with mock.patch.object(ijson, "MAX_INPUT", (small + big) // 2):
            self.assertEqual(self.sync(first.acts), {"reason": "ok", "synced_at": NOW})
            before, calls = self.path.read_bytes(), self.clock.calls
            self.refused("store_full", self.sync(second.acts))
            self.assertEqual((self.path.read_bytes(), self.clock.calls), (before, calls))   # nothing written
            self.assertEqual(self.sync(["z" * 10])["reason"], "ok")   # what is dropped does not count: a small input fits

    def test_a_union_the_retained_set_shrinks_under_max_input_is_written(self):   # CF-09 S5
        junk = ["%06d" % i + "x" * 1_000_000 for i in range(15)]
        with self.port.lock(self.org) as held:
            held.write(store.encode(junk, canon(self.s.lineage), "no", NOW))
        self.assertLess(self.path.stat().st_size, MAX)
        # 15 MB held and 2 MB more: the union is over MAX_INPUT, the retained store is not
        self.assertEqual(self.sync(["y" * 2_000_000]), {"reason": "ok", "synced_at": NOW})
        self.assertEqual((self.stored().acts, self.stored().lineage), ([], canon(self.s.lineage)))
        self.assertEqual(self.clock.calls, 1)

    def test_a_write_failure_is_store_unavailable_and_keeps_the_old_store(self):
        self.sync()
        before = self.path.read_bytes()
        os.chmod(self.path.parent, 0o500)
        self.addCleanup(os.chmod, self.path.parent, 0o700)
        self.refused("store_unavailable", self.sync(["more"]))
        self.assertEqual(self.path.read_bytes(), before)


    def test_a_directory_sync_that_fails_after_the_rename_refuses_and_a_later_sync_converges(self):   # CF-09 S4
        first = self.s.w.device_add("alice2", ("alice", "bob"))
        second = self.s.w.device_add("bob2", ("bob", "alice"), first)
        self.sync(first.acts)
        real_fsync = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "disk")
            real_fsync(fd)

        self.clock.value = LATER
        with mock.patch.object(store_posix.os, "fsync", fsync):
            self.refused("store_unavailable", self.sync(second.acts))   # not durable: no `synced_at` is answered
        self.assertEqual((self.stored().acts, self.stored().synced_at), (store.canonical(first.acts + second.acts), LATER))
        self.assertEqual(self.sync(), {"reason": "ok", "synced_at": LATER})   # the next sync finds a superset and goes on
        self.assertEqual(self.stored().acts, store.canonical(first.acts + second.acts))


class Docs(Case):
    """CF-09 S19 to S21 (RS13): `sync` picks the pinned path out of `docs` itself, so no transport reads the pin."""

    def successors(self):
        """The original, the change the pin will name, a sibling change and a later change beyond it."""
        w = self.s.w
        everyone = ("alice", "bob", "carol")
        pinned = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), w.id, people=everyone, pol=policy(), name="NEXT")
        sibling = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), w.id, people=everyone, pol=policy(), name="SIBLING")
        beyond = change(production_of(FIXTURE), w.id, genesis.doc_hash(pinned), w.id, people=everyone, pol=policy(), name="BEYOND")
        entry = lambda doc: {"doc": doc, "sigs": w.sigs(doc, everyone)}
        return pinned, sibling, beyond, entry

    def test_the_pinned_path_is_stored_and_no_other_document_is_stored(self):   # CF-09 S19
        w = self.s.w
        pinned, sibling, beyond, entry = self.successors()
        docs = [entry(beyond), entry(sibling), self.s.lineage[0], entry(pinned)]
        got = self.sync(docs=docs, probe=Probe(probe_for(pinned, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().lineage, canon([self.s.lineage[0], entry(pinned)]))

    def test_the_pinned_document_absent_is_genesis_pin_mismatch_and_creates_no_directory(self):   # CF-09 S20
        w = self.s.w
        pinned, sibling, beyond, entry = self.successors()
        got = self.sync(docs=[self.s.lineage[0], entry(sibling)], probe=Probe(probe_for(pinned, w.id)))
        self.refused("genesis_pin_mismatch", got)
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(self.clock.calls, 0)

    def test_a_missing_link_is_lineage_broken(self):
        w = self.s.w
        pinned, sibling, beyond, entry = self.successors()
        self.refused("lineage_broken", self.sync(docs=[entry(beyond)], probe=Probe(probe_for(beyond, w.id))))
        self.refused("lineage_broken", self.sync(docs=[], probe=Probe(probe_for(pinned, w.id))))
        self.assertEqual(os.listdir(self.root), [])

    def test_a_pin_reason_comes_before_the_lineage_reasons(self):
        pinned, sibling, beyond, entry = self.successors()
        self.refused("pin_missing", self.sync(docs=[], probe=Probe(absent(self.s, "pin_missing"))))
        self.assertEqual(os.listdir(self.root), [])

    def test_duplicate_entries_for_one_document_are_united(self):
        first, second = self.s.lineage[0]["sigs"][:2], self.s.lineage[0]["sigs"][1:]
        docs = [{"doc": self.s.w.doc, "sigs": first}, {"doc": self.s.w.doc, "sigs": second}]
        self.assertEqual(self.sync(docs=docs)["reason"], "ok")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))

    def test_a_re_pinned_machine_with_an_old_store_heals_on_the_next_sync(self):   # CF-09 S21
        w = self.s.w
        pinned, sibling, beyond, entry = self.successors()
        step = w.device_add("alice2", ("alice", "bob"))
        self.assertEqual(self.sync(step.acts)["reason"], "ok")   # the store under the original pin
        before = self.stored()
        self.assertEqual(before.lineage, canon(self.s.lineage))
        # the ceremony re-pinned and its own `sync` failed: the pin names the change (at the step), the store is old
        at_step = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), step.id, people=("alice", "bob", "carol"),
                         pol=policy(), name="NEXT")
        self.clock.value = LATER
        got = self.sync(docs=[self.s.lineage[0], entry(at_step), entry(sibling)], probe=Probe(probe_for(at_step, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": LATER})
        healed = self.stored()
        self.assertEqual(healed.lineage, canon([self.s.lineage[0], entry(at_step)]))
        self.assertEqual(healed.acts, before.acts)   # the path to the head of the change is kept
        self.assertEqual((healed.next, healed.synced_at), ("no", LATER))


class Retaining(Case):
    """CF-09 steps 4 to 8: the store holds the retained set of everything the machine has read (CF-14)."""

    def change_at(self, head, name="NEXT", sigs="all"):
        """`(doc, entry)` of a change of the organization at `head`; `sigs` is the receipts, none to make it invalid."""
        w = self.s.w
        doc = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), head, people=("alice", "bob", "carol"),
                     pol=policy(), name=name)
        return doc, {"doc": doc, "sigs": w.sigs(doc, ("alice", "bob", "carol")) if sigs == "all" else []}

    def test_a_closed_epoch_keeps_the_path_to_its_successor_and_drops_the_rest(self):   # CF-09 S18, L9 (c)
        w = self.s.w
        a = w.device_add("alice2", AB)
        b = w.device_add("bob2", AB, a)                                     # below the head
        f = w.device_add("alice3", ("alice", "carol"))                      # beside the path
        self.assertEqual(self.sync(a.acts + b.acts + f.acts)["reason"], "fork")
        self.assertEqual(self.stored().acts, store.canonical(a.acts + b.acts + f.acts))   # open: kept whole, a fork too
        doc, entry = self.change_at(a.id)
        longer = self.s.lineage + [entry]
        later = later_world(w, doc).device_add("alice4", AB)
        self.clock.value = LATER
        got = self.sync(later.acts, docs=longer, probe=Probe(probe_for(doc, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": LATER})
        self.assertEqual(self.stored().lineage, canon(longer))
        self.assertEqual(self.stored().acts, store.canonical(a.acts + later.acts))   # the path stays, b and f go

    def test_a_change_at_the_root_drops_every_act_of_the_closed_epoch(self):   # CF-09 S18, CF-14 S2
        w = self.s.w
        add = w.device_add("alice2", AB)
        self.assertEqual(self.sync(add.acts)["reason"], "ok")
        doc, entry = self.change_at(w.id)
        later = later_world(w, doc).device_add("alice3", AB)
        got = self.sync(later.acts, docs=self.s.lineage + [entry], probe=Probe(probe_for(doc, w.id)))
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(self.stored().acts, store.canonical(later.acts))

    def test_a_string_that_is_no_chain_item_is_not_stored(self):   # CF-09 S22, FO-06, CF-14 D3
        w = self.s.w
        step = w.device_add("alice2", AB)
        verdict = self.s.verdict().jws
        receipt = w.sigs(w.doc, ("alice",))[0]
        foreign = World(name="OTHER").device_add("alice2", AB).acts
        junk = ["junk", "", "a.b.c", verdict, receipt] + foreign
        self.assertEqual(self.sync(step.acts + junk)["reason"], "ok")
        self.assertEqual(self.stored().acts, store.canonical(step.acts))
        self.assertEqual(self.sync(junk)["reason"], "ok")   # and a second source's junk does not come back
        self.assertEqual(self.stored().acts, store.canonical(step.acts))

    def test_an_act_whose_parent_is_no_node_is_refused_alone_and_stored_with_a_whole_snapshot(self):   # CF-13
        w = self.s.w
        first = w.device_add("alice2", AB)
        second = w.device_add("bob2", AB, first)
        self.refused("snapshot_incomplete", self.sync(second.acts))   # the child alone: its parent is in no union
        self.assertFalse(self.path.exists())
        self.assertEqual(self.sync(first.acts + second.acts)["reason"], "ok")   # a snapshot carries whole groups
        self.assertEqual(self.stored().acts, store.canonical(first.acts + second.acts))

    def test_an_act_with_a_missing_signature_is_refused_until_it_is_whole(self):   # CF-09 S22: a pending primary is no node yet
        pending = self.s.w.device_add("alice2", ("alice",))
        self.refused("snapshot_incomplete", self.sync(pending.acts))
        self.assertFalse(self.path.exists())

    def test_the_acts_of_a_descendant_epoch_are_kept_with_a_partial_snapshot(self):   # CF-09 S23, SD3
        w = self.s.w
        old = w.device_add("alice2", AB)
        doc, entry = self.change_at(w.id)                                   # a successor of the pinned original
        w1 = later_world(w, doc)
        c1, c2 = w1.device_add("alice4", AB), w1.device_add("bob3", AB)     # a fork in the epoch after the change
        got = self.sync(old.acts + c1.acts + c2.acts, docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual(self.stored().acts, store.canonical(old.acts + c1.acts + c2.acts))
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))      # the pinned path only: no other document

    def test_the_nodes_of_a_valid_sibling_epoch_are_cached_and_never_read(self):   # CF-14 D8, GP-21
        w = self.s.w
        doc, entry = self.change_at(w.id)
        other, other_entry = self.change_at(w.id, name="SIBLING")
        ours = later_world(w, doc).device_add("alice4", AB)
        theirs = later_world(w, other).device_add("alice4", AB, salt="s")
        docs = self.s.lineage + [entry, other_entry]
        pin = Probe(probe_for(doc, w.id))
        self.assertEqual(self.sync(ours.acts + theirs.acts, docs=docs, probe=pin)["reason"], "ok")
        both = self.stored()
        self.assertEqual(both.acts, store.canonical(ours.acts + theirs.acts))   # the sibling's nodes stay: its source builds on them
        self.assertEqual(both.lineage, canon(self.s.lineage + [entry]))        # and nothing of it is a document of the store
        self.path.unlink()
        self.assertEqual(self.sync(ours.acts, docs=docs, probe=pin)["reason"], "ok")
        alone = self.stored()
        self.assertEqual((both.lineage, both.next), (alone.lineage, alone.next))   # what a reader reads does not depend on the cache

    def test_the_receipts_of_the_lineage_are_the_ones_that_count_united_with_the_stored_ones(self):   # CF-09 step 4, CF-14
        w = self.s.w
        everyone = w.sigs(w.doc, ("alice", "bob", "carol"))
        stranger = w.sigs(w.doc, ("dave",))
        twin = w.sigs(w.doc, ("alice",), sig=LOW)
        first = self.sync(docs=[{"doc": w.doc, "sigs": everyone + stranger + ["junk"]}])
        self.assertEqual(first["reason"], "ok")
        self.assertEqual(self.stored().lineage, canon([{"doc": w.doc, "sigs": everyone}]))   # only the counting ones
        self.assertEqual(self.sync(docs=[{"doc": w.doc, "sigs": twin + everyone}])["reason"], "ok")
        kept = self.stored().lineage[0]["sigs"]
        self.assertEqual(len(kept), 3)                                                       # one text per receipt id
        self.assertEqual(sorted(set(kept) & set(twin + everyone)), kept)

    def test_the_stored_lineage_keeps_its_receipts_when_a_later_source_carries_fewer(self):   # CF-09 step 4
        w = self.s.w
        self.assertEqual(self.sync()["reason"], "ok")
        few = [{"doc": w.doc, "sigs": w.sigs(w.doc, ("alice", "bob", "carol"))[:1]}]
        self.assertEqual(self.sync(docs=few)["reason"], "ok")   # the union holds the stored receipts: the pin folds
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))


class Next(Case):
    """CF-09 step 7 and SD4: `next` says that the store holds a valid successor of the pinned document."""

    def change_at(self, head, name="NEXT", sigs="all"):
        w = self.s.w
        doc = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), head, people=("alice", "bob", "carol"),
                     pol=policy(), name=name)
        return doc, {"doc": doc, "sigs": w.sigs(doc, ("alice", "bob", "carol")) if sigs == "all" else []}

    def test_a_valid_successor_of_the_pin_sets_next_and_an_invalid_one_does_not(self):   # CF-09 S24
        w = self.s.w
        _, unsigned = self.change_at(w.id, name="UNSIGNED", sigs="none")   # no receipt: genesis_unsigned
        self.assertEqual(self.sync(docs=self.s.lineage + [unsigned]), {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().next, "no")
        step = w.device_add("alice2", AB)
        later, entry = self.change_at(step.id, name="LATER")
        # H is a node the machine has not read: the successor is invalid for now, and valid once the act arrives
        self.assertEqual(self.sync(docs=self.s.lineage + [entry])["reason"], "ok")
        self.assertEqual(self.stored().next, "no")
        self.assertEqual(self.sync(step.acts, docs=self.s.lineage + [entry]),
                         {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual(self.stored().next, "yes")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))   # the successor is not stored

    def test_a_fork_at_a_superseded_pin_is_epoch_superseded_as_in_the_readers(self):   # VR-02 6 (i), GP-13 step 4: one order
        w = self.s.w
        acts = w.device_add("alice2", AB).acts + w.device_add("alice3", ("alice", "carol")).acts
        _, entry = self.change_at(w.id)
        self.assertEqual(self.sync(acts)["reason"], "fork")
        self.assertEqual(self.sync(acts, docs=self.s.lineage + [entry]), {"reason": "epoch_superseded", "synced_at": NOW})

    def test_a_verifier_that_fails_on_a_successor_is_no_verdict_on_it(self):   # CF-09 step 5: only a document code is ignored
        w = self.s.w
        _, entry = self.change_at(w.id)

        class FailsOn(FakeVitni):
            def verify(self, jws, keys, method):
                if jws in entry["sigs"]:
                    raise verifier.VerifierUnavailable("down")
                return super().verify(jws, keys, method)

        self.refused("verifier_unavailable", self.sync(docs=self.s.lineage + [entry], vitni=FailsOn()))
        self.assertFalse(self.path.exists())

    def test_a_successor_of_another_lineage_than_the_pin_does_not_set_next(self):
        w = self.s.w
        doc, entry = self.change_at(w.id)
        under = {"doc": change(production_of(FIXTURE), w.id, genesis.doc_hash(doc), w.id, people=("alice", "bob", "carol"),
                               pol=policy(), name="BEYOND"), "sigs": []}
        under["sigs"] = w.sigs(under["doc"], ("alice", "bob", "carol"))
        # pinned at the change: its own descendant (invalid: H is no node of that epoch) does not set `next`
        got = self.sync(docs=self.s.lineage + [entry, under], probe=Probe(probe_for(doc, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().next, "no")

    def test_next_stays_yes_while_the_pin_stays_and_is_recomputed_after_a_re_pin(self):   # CF-09 S25
        w = self.s.w
        doc, entry = self.change_at(w.id)
        self.assertEqual(self.sync(docs=self.s.lineage + [entry])["reason"], "epoch_superseded")
        # a source that does not hold the successor: the pin is the same, the knowledge is not undone
        self.clock.value = LATER
        self.assertEqual(self.sync(docs=self.s.lineage), {"reason": "epoch_superseded", "synced_at": LATER})
        self.assertEqual(self.stored().next, "yes")
        # the person re-pins to the successor: `next` is about the new pin, and nothing is known of its successor
        self.assertEqual(self.sync(docs=self.s.lineage + [entry], probe=Probe(probe_for(doc, w.id)))["reason"], "ok")
        self.assertEqual(self.stored().next, "no")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage + [entry]))
        # and a later sync under the new pin that does not hold the successor stays "no"
        self.assertEqual(self.sync(docs=self.s.lineage + [entry], probe=Probe(probe_for(doc, w.id)))["reason"], "ok")

    def test_a_superseded_pin_is_written_with_epoch_superseded(self):   # CF-09 S26
        w = self.s.w
        doc, entry = self.change_at(w.id)
        got = self.sync(docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual((self.clock.calls, self.stored().next, self.stored().synced_at), (1, "yes", NOW))
        # the reason wins over `fork`: the store says what a reader must do first
        c1, c2 = w.device_add("alice2", AB), w.device_add("alice3", ("alice", "carol"))
        self.assertEqual(self.sync(c1.acts + c2.acts, docs=self.s.lineage + [entry])["reason"], "epoch_superseded")
        self.assertEqual(self.stored().acts, store.canonical(c1.acts + c2.acts))

    def test_a_superseded_store_answers_epoch_superseded_to_the_readers_of_the_machine(self):   # VR-12, GP-13
        doc, entry = self.change_at(self.s.w.id)
        self.sync(docs=self.s.lineage + [entry])
        probe = Probe(wire(self.s))
        table = production_table(probe, Clock(NOW), PRODUCTION_ONLY, self.port)
        got = run(table, "check-act", {k: v for k, v in self.s.value(self.s.verdict()).items()
                                      if k not in ("pin", "now", "acts", "lineage", "next", "synced_at", "tip_statement")})
        self.assertEqual((got["valid"], got["reason"]), (False, "epoch_superseded"))


class Order(Case):
    """CF-09 S27 (SD9): the store is the retained set of the union, so two admit-closed snapshots give one store
    whichever `sync` runs first."""

    def written(self, snapshots, docs, probe):
        """The bytes of the store after the `snapshots` (lists of acts) synced in order, over a fresh store."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        port = store_posix.PosixStore(tmp.name, os.getuid())
        for acts in snapshots:
            got = self.sync(acts, docs=docs, probe=probe, port=port)
            self.assertIn(got["reason"], ("ok", "fork"))
        return Path(port.path(self.org)).read_bytes()

    def closure(self, steps, picked):
        """The steps of `picked` and every ancestor of them: a snapshot closed under the parent (admit-closed)."""
        by_id = {step.id: step for step in steps}
        found = {}
        for step in picked:
            while step is not None and step.id not in found:
                found[step.id] = step
                step = by_id.get(step.parent_id)
        return [text for step in found.values() for text in step.acts]

    def test_the_union_of_admit_closed_snapshots_does_not_depend_on_the_order(self):   # CF-09 S27
        w = self.s.w
        for seed in range(12):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                _, early = grow(w, rng, POOLS[0], rng.randint(4, 10))
                chosen = rng.choice([None] + early)
                head = chosen.id if chosen else w.id
                doc = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), head, people=("alice", "bob", "carol"),
                             pol=policy(), name="NEXT")
                docs = self.s.lineage + [{"doc": doc, "sigs": w.sigs(doc, ("alice", "bob", "carol"))}]
                w1 = later_world(w, doc)
                _, late = grow(w1, rng, POOLS[1], rng.randint(2, 6))
                steps = early + late
                # every snapshot carries the path to H: a pin at the change needs it to fold
                needed = [chosen] if chosen else []
                one = self.closure(steps, needed + [step for step in steps if rng.random() < 0.5])
                two = self.closure(steps, needed + [step for step in steps if rng.random() < 0.5])
                probe = Probe(probe_for(doc, w.id))
                forward = self.written([one, two], docs, probe)
                backward = self.written([two, one], docs, probe)
                at_once = self.written([one + two], docs, probe)
                self.assertEqual(forward, backward)
                self.assertEqual(forward, at_once)   # the union in one snapshot is the same store
                # and it is the retained set of the union under the pinned lineage, computed by `compact`'s own rule
                kept = store.parse(forward)
                whole = snap(one + two, docs, w.id)
                epochs = opening.open_store(whole, PRODUCTION_ONLY, False, memo(),
                                            render_genesis.render_size)
                expected = retain.retained(epochs, retain.closing_heads(docs), whole)
                self.assertEqual(kept.acts, sorted(expected.acts))


class Cost(Case):
    """Design risk 6: `sync` is linear in the store. Measured on a padded store by what it asks the verifier, never by
    time alone: junk, other organizations' acts and unanchored acts cost no verification, and a sync that adds
    nothing asks the same questions again (the store is re-folded, not accumulated)."""

    def calls(self, acts, docs=None, second=False):
        """The verifier calls of one `sync` of `acts` over a fresh store, or of the second of two."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        port = store_posix.PosixStore(tmp.name, os.getuid())
        if second:
            self.sync(acts, port=port, docs=docs)
        counted = Counting()
        got = self.sync(acts, port=port, vitni=counted, docs=docs)
        self.assertIn(got["reason"], ("ok", "fork"))
        return counted.calls

    def wide(self, width):
        w = self.s.w
        return [text for i in range(width) for text in w.device_add("alice2", AB, salt=str(i)).acts]

    def test_the_verifications_grow_with_the_nodes_and_junk_costs_none(self):
        none = self.calls([])
        small, big = self.calls(self.wide(10)), self.calls(self.wide(20))
        self.assertEqual(big - none, 2 * (small - none))                          # linear in the nodes
        junk = ["%06d" % i + "x" * 200 for i in range(2000)]
        unanchored = World(name="OTHER").device_add("alice2", AB, salt="o").acts   # another organization's acts
        self.assertEqual(self.calls(self.wide(10) + junk + unanchored), small)    # none for strings no one reads

    def junk_documents(self, count):
        """`count` documents of a hostile source that pass possession and fail at the authority check (GP-15 step 7):
        three fresh persons, each signing with their own key, hang at the pin and name a real node as their head.
        Each one makes `_check_change` run, so a rebuild of the epoch before it, per document, shows in `work`."""
        w, found = self.s.w, []
        for i in range(count):
            doc = change(production_of(FIXTURE), w.id, genesis.doc_hash(w.doc), w.id,
                         people=("dave", "frank", "grace"), pol=policy(), name="JUNK%d" % i)
            found.append({"doc": doc, "sigs": w.sigs(doc, ("dave", "frank", "grace"))})
        return found

    def work(self, junk):
        """`(act texts parsed, bags built, tree nodes validated, epochs built, documents hashed)` by one `sync` with
        `junk` documents in `docs`, and how many of them reached the authority check: the structural cost, which a
        memoized verifier cannot hide (design risk 6)."""
        from handsal_check import acts as acts_module, chain, epoch as epoch_module, quorum
        acts = self.wide(5)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        port = store_posix.PosixStore(tmp.name, os.getuid())
        with mock.patch.object(acts_module, "parse", wraps=acts_module.parse) as parsed, \
                mock.patch.object(chain, "Bag", wraps=chain.Bag) as bags, \
                mock.patch.object(quorum, "check_primary", wraps=quorum.check_primary) as nodes, \
                mock.patch.object(epoch_module, "Epoch", wraps=epoch_module.Epoch) as epochs, \
                mock.patch.object(genesis, "doc_hash", wraps=genesis.doc_hash) as hashed, \
                mock.patch.object(epoch_module, "_check_change", wraps=epoch_module._check_change) as checked:
            got = self.sync(acts, port=port, docs=self.s.lineage + self.junk_documents(junk))
        self.assertIn(got["reason"], ("ok", "fork"))
        return tuple(m.call_count for m in (parsed, bags, nodes, epochs, hashed, checked))

    def test_a_junk_document_costs_a_parse_and_no_rebuild(self):   # CF-13: a source is untrusted; work per document is O(1)
        none, few, many = self.work(0), self.work(12), self.work(24)
        self.assertEqual((few[5] - none[5], many[5] - none[5]), (12, 24))   # each one reached the authority check
        for index in (0, 4):   # act texts parsed (the signatures of the document) and documents hashed: a constant per document
            self.assertEqual(many[index] - few[index], few[index] - none[index], msg=index)
        self.assertEqual(few[1:4], none[1:4])    # no bag, tree node or epoch built for a document no one authorized
        self.assertEqual(many[1:4], none[1:4])   # (a rebuilt previous epoch would validate its nodes again, once per document)

    def test_a_second_sync_asks_what_the_first_asked_and_no_more(self):
        acts = self.wide(10)
        self.assertEqual(self.calls(acts, second=True), self.calls(acts))

    def test_the_retained_set_asks_the_verifier_nothing_the_fold_did_not_ask(self):
        """The fold of the pinned path builds every epoch; retaining adds no question to the ones it asked."""
        acts = self.wide(10)
        from handsal_check import epoch as epoch_module
        counted = Counting()
        epochs = epoch_module.fold_lineage(self.s.lineage, acts, PRODUCTION_ONLY, False, memo(counted))
        epochs[-1].build()
        self.assertEqual(self.calls(acts), counted.calls)


class Recording:
    """A store port that records what `sync` asks of it, in order."""

    def __init__(self, old=None):
        self.events, self.old = [], old

    def read(self, org):   # a read with no lock: `sync` must never use it
        self.events.append("read without the lock")
        return self.old

    @contextlib.contextmanager
    def lock(self, org):
        self.events.append("lock")
        try:
            yield self.Held(self)
        finally:
            self.events.append("unlock")

    class Held:
        def __init__(self, port):
            self.port = port

        def read(self):
            self.port.events.append("read")
            return self.port.old

        def write(self, raw):
            self.port.events.extend(("write temporary", "rename"))
            self.port.old = raw


class Ordering(Case):
    def test_the_read_happens_inside_the_lock(self):   # CF-09 S11, SS5
        port = Recording()
        probe = Probe(wire(self.s))
        self.assertEqual(self.sync(port=port, probe=probe)["reason"], "ok")
        self.assertEqual(port.events, ["lock", "read", "write temporary", "rename", "unlock"])

    def test_the_second_sync_reads_what_the_first_wrote(self):
        port = Recording()
        step = self.s.w.device_add("alice2", ("alice", "bob"))
        self.sync(step.acts, port=port)
        port.events.clear()
        self.sync([], port=port)
        self.assertEqual(store.parse(port.old).acts, store.canonical(step.acts))

    def test_a_refusal_never_reaches_the_write(self):
        port = Recording()
        self.refused("verifier_unavailable", self.sync(port=port, vitni=Unavailable()))
        self.assertEqual(port.events, ["lock", "read", "unlock"])

    def test_the_pin_is_read_once_and_before_the_lock(self):
        port, probe = Recording(), Probe(absent(self.s, "pin_missing"))
        self.sync(port=port, probe=probe)
        self.assertEqual((port.events, probe.asked), ([], [self.org]))


class Siblings(Case):
    """CF-09 step 6 over every valid document of the call (CF-14 D8): what the sources of the machine still build on
    stays in the store, so an act of a lineage the pin is not on is never answered `ok` and forgotten."""

    def setUp(self):
        super().setUp()
        self.k = SyncWorlds(self.s)

    def test_a_growing_sibling_lineage_is_never_refused_while_the_reader_holds_its_nodes(self):   # CF-14
        k = self.k
        at_c1 = Probe(k.pinned_at(k.c1_doc[0]))
        for acts, stored in ((k.c1.acts + k.x0.acts, 6), (k.y0.acts, 9), (k.z0.acts, 12),
                             (k.c1.acts + k.x0.acts + k.y0.acts + k.z0.acts, 12)):
            with self.subTest(stored=stored):
                self.assertEqual(self.sync(acts, docs=k.sib_docs, probe=at_c1), {"reason": "ok", "synced_at": NOW})
                self.assertEqual(len(self.stored().acts), stored)

    def test_a_descendant_served_with_one_receipt_of_three_loses_no_stored_act(self):   # CF-14
        k = self.k
        first = self.sync(k.c1.acts + k.x2.acts, docs=self.s.lineage + [k.d2[1]])
        self.assertEqual((first["reason"], len(self.stored().acts)), ("epoch_superseded", 6))
        thin = self.sync(docs=self.s.lineage + [k.thin_d2])
        self.assertEqual((thin["reason"], len(self.stored().acts)), ("epoch_superseded", 6))
        more = self.sync(k.y2.acts, docs=self.s.lineage + [k.d2[1]])
        self.assertEqual((more["reason"], len(self.stored().acts)), ("epoch_superseded", 9))

    def test_a_second_source_without_the_descendant_loses_no_stored_act(self):   # CF-14
        k = self.k
        self.assertEqual(self.sync(k.c1.acts + k.x2.acts, docs=self.s.lineage + [k.d2[1]])["reason"], "epoch_superseded")
        self.assertEqual(self.sync(docs=self.s.lineage)["reason"], "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 6)
        self.assertEqual(self.sync(k.y2.acts, docs=self.s.lineage + [k.d2[1]])["reason"], "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 9)

    def test_a_middle_document_absent_loses_no_stored_act(self):   # CF-14
        k = self.k
        every = self.s.lineage + [k.d2[1], k.d3[1]]
        got = self.sync(k.c1.acts + k.x2.acts + k.x3.acts, docs=every)
        self.assertEqual((got["reason"], len(self.stored().acts)), ("epoch_superseded", 9))
        got = self.sync(docs=self.s.lineage + [k.d3[1]])
        self.assertEqual((got["reason"], len(self.stored().acts)), ("epoch_superseded", 9))


class Docs_(Case):
    pass


class Undecided(Case):
    """CF-09 step 6: `sync` writes only if no input act a fold may read is undecided by facts no larger union
    reverses. Such an act the store does not hold refuses the call whole, with nothing written."""

    def setUp(self):
        super().setUp()
        self.k = SyncWorlds(self.s)
        self.d2 = self.s.lineage + [self.k.d2[1]]

    def incomplete(self, got):
        self.refused("snapshot_incomplete", got)

    def alice_at_the_removal(self):
        """The `check-act` reason of alice's verdict at the head the removal made, on the store of the machine."""
        table = production_table(Probe(wire(self.s)), Clock(NOW), PRODUCTION_ONLY, self.port)
        return run(table, "check-act", production_input(self.s.value(self.k.alice_at_rm())))["reason"]

    def test_a_child_before_its_parent_is_snapshot_incomplete_and_writes_nothing(self):   # CF-09 step 6
        k = self.k
        self.incomplete(self.sync(k.rm.acts))
        self.assertFalse(self.path.exists())
        self.assertEqual(self.clock.calls, 0)
        self.assertEqual(self.sync(k.c1.acts), {"reason": "ok", "synced_at": NOW})
        self.assertEqual(len(self.stored().acts), 3)
        self.assertEqual(self.sync(k.c1.acts + k.rm.acts), {"reason": "ok", "synced_at": NOW})
        self.assertEqual(len(self.stored().acts), 5)
        self.assertEqual(self.alice_at_the_removal(), "revoked_key")

    def test_a_removal_whose_parent_is_stored_is_kept_as_an_increment(self):   # CF-09 step 6
        k = self.k
        self.assertEqual(self.sync(k.c1.acts)["reason"], "ok")
        self.assertEqual(self.sync(k.rm.acts)["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 5)
        self.assertEqual(self.alice_at_the_removal(), "revoked_key")

    def test_a_split_group_is_refused_until_it_is_whole(self):   # CF-09 step 6
        k = self.k
        self.assertEqual(self.sync(k.c1.acts)["reason"], "ok")
        for half in (k.rm.acts[:1], k.rm.acts[1:]):
            self.incomplete(self.sync(half))
            self.assertEqual(len(self.stored().acts), 3)
        self.assertEqual(self.sync(k.c1.acts + k.rm.acts)["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 5)
        self.assertEqual(self.alice_at_the_removal(), "revoked_key")

    def test_an_act_of_a_descendant_epoch_whose_document_is_absent_is_refused(self):   # CF-09 step 6
        k = self.k
        self.incomplete(self.sync(k.x2.acts))
        self.assertFalse(self.path.exists())
        self.assertEqual(self.sync(k.c1.acts + k.x2.acts, docs=self.d2)["reason"], "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 6)
        self.incomplete(self.sync(k.y2.acts))
        self.assertEqual(len(self.stored().acts), 6)
        self.assertEqual(self.sync(k.y2.acts, docs=self.d2)["reason"], "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 9)

    def test_an_act_of_a_descendant_whose_head_the_input_lacks_is_refused(self):   # CF-09 step 6
        k = self.k
        self.incomplete(self.sync(k.x2.acts, docs=self.d2))
        self.assertEqual(self.sync(k.c1.acts + k.x2.acts, docs=self.d2)["reason"], "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 6)
        self.path.unlink()
        self.incomplete(self.sync(k.x3.acts, docs=self.s.lineage + [k.d2[1], k.d3[1]]))
        self.assertEqual(self.sync(k.c1.acts + k.x2.acts + k.x3.acts, docs=self.s.lineage + [k.d2[1], k.d3[1]])["reason"],
                         "epoch_superseded")
        self.assertEqual(len(self.stored().acts), 9)

    def test_a_second_source_that_re_offers_a_stored_act_without_its_document_is_not_refused(self):   # CF-09 step 6: the store holds it
        k = self.k
        self.assertEqual(self.sync(k.c1.acts + k.x2.acts, docs=self.d2)["reason"], "epoch_superseded")
        got = self.sync(k.x2.acts, docs=self.s.lineage)   # D2 is absent: the act is open, and it is held
        self.assertIn(got["reason"], ("ok", "epoch_superseded"))
        self.assertIsNotNone(got["synced_at"])
        self.assertEqual(len(self.stored().acts), 6)

    def test_an_endorsement_of_an_endorsement_is_decided_unread_and_never_refused(self):   # CF-09 step 6: only primaries are endorsed
        k = self.k
        over = k.w.endorse("carol", k.c1.endorsements["bob"], k.c1.id)   # carol endorses bob's endorsement of c1
        self.assertEqual(self.sync(k.c1.acts)["reason"], "ok")
        got = self.sync([over.jws])
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().acts, store.canonical(k.c1.acts))   # nothing reads it: it is not stored

    def test_a_fresh_reader_is_refused_a_thin_descendant_and_a_missing_middle_document(self):   # CF-14
        k = self.k
        self.incomplete(self.sync(k.c1.acts + k.x2.acts, docs=self.s.lineage + [k.thin_d2]))
        self.incomplete(self.sync(k.c1.acts + k.x2.acts + k.x3.acts, docs=self.s.lineage + [k.d3[1]]))
        self.assertFalse(self.path.exists())

    def test_a_forged_change_off_the_lineage_leaves_nothing_stored(self):   # CF-09 step 6
        k = self.k
        doc, entry, act = k.forged_off
        at_c1 = Probe(k.pinned_at(k.c1_doc[0]))
        self.assertEqual(self.sync(k.c1.acts, docs=self.s.lineage + [k.c1_doc[1]], probe=at_c1)["reason"], "ok")
        got = self.sync(act.acts, docs=self.s.lineage + [k.c1_doc[1], entry], probe=at_c1)
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().acts, store.canonical(k.c1.acts))

    def test_a_forged_descendant_of_the_pin_with_an_act_below_is_refused_and_with_none_is_ok(self):   # CF-09 step 6
        k = self.k
        doc, entry, act = k.forged_descendant
        at_c1 = Probe(k.pinned_at(k.c1_doc[0]))
        docs = self.s.lineage + [k.c1_doc[1], entry]
        self.assertEqual(self.sync(k.c1.acts, docs=docs[:2], probe=at_c1)["reason"], "ok")
        self.incomplete(self.sync(act.acts, docs=docs, probe=at_c1))
        self.assertEqual(self.sync(docs=docs, probe=at_c1), {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().next, "no")

    def test_a_refused_sync_leaves_the_view_to_age_and_fail_closed(self):   # CF-09 step 6
        k = self.k
        self.assertEqual(self.sync()["reason"], "ok")
        self.clock.value = "2026-01-02T00:30:01Z"                         # one second past max_view_age_s
        self.incomplete(self.sync(k.rm.acts))
        self.assertEqual(self.stored().synced_at, NOW)                    # the refusal wrote nothing, not the clock
        table = production_table(Probe(wire(self.s)), Clock(self.clock.value), PRODUCTION_ONLY, self.port)
        got = run(table, "enrolled", production_input(enrolled_value(self.s)))
        self.assertEqual(got, {"enrolled": False, "reason": "stale_view"})

    def test_a_late_sibling_is_refused_once_and_a_full_snapshot_settles_it(self):   # CF-09 step 6
        k = self.k
        at_c1 = Probe(k.pinned_at(k.c1_doc[0]))
        before = self.s.lineage + [k.c1_doc[1]]
        every = before + [k.late_doc[1]]
        self.assertEqual(self.sync(k.c1.acts + k.beside.acts, docs=before, probe=at_c1)["reason"], "ok")
        self.assertEqual(self.sync(k.lx.acts, docs=every, probe=at_c1)["reason"], "ok")
        self.incomplete(self.sync(k.ly.acts, docs=every, probe=at_c1))
        full = k.c1.acts + k.beside.acts + k.lx.acts + k.ly.acts
        self.assertEqual(self.sync(full, docs=every, probe=at_c1)["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 12)
        self.assertEqual(self.sync(k.lz.acts, docs=every, probe=at_c1)["reason"], "ok")

    def test_a_re_pinned_reader_is_refused_an_act_below_one_it_dropped_and_a_full_snapshot_settles_it(self):   # CF-09 step 6
        k = self.k
        docs = self.s.lineage + [k.dh[1]]
        at_dh = Probe(k.pinned_at(k.dh[0]))
        self.assertEqual(self.sync(k.a.acts + k.f.acts, docs=docs)["reason"], "epoch_superseded")
        self.assertEqual(self.sync(docs=docs, probe=at_dh)["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 3)                     # f was beside the path to a: dropped
        self.incomplete(self.sync(k.g.acts, docs=docs, probe=at_dh))
        got = self.sync(k.a.acts + k.f.acts + k.g.acts + k.h_act.acts, docs=docs, probe=at_dh)
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 6)


class Deciding(Case):
    """The lock and the read happen once and `decide` is pure: it answers what `run` writes, touching no port."""

    def steps(self):
        """`[[(acts, docs, pinned document or None)]]`: sequences of calls against one store, covering what the
        other classes of this file pin one by one."""
        w, k = self.s.w, self.k
        a = w.device_add("alice2", AB)
        b = w.device_add("bob2", AB, a)
        f = w.device_add("alice3", ("alice", "carol"))
        pending = w.device_add("carol2", ("alice",))
        doc, entry = k.doc_at(w.id)
        later = later_world(w, doc).device_add("alice4", AB)
        grown = self.s.lineage + [entry]
        junk = ["junk", "", "a.b.c", self.s.verdict().jws]
        return [
            [([], None, None), (a.acts, None, None), (a.acts[:1], None, None), ([], None, None)],
            [(a.acts + f.acts, None, None), (b.acts, None, None), (a.acts + b.acts + junk, None, None)],
            [(a.acts + b.acts + f.acts, None, None), (later.acts, grown, doc), (later.acts, grown, doc)],
            [(a.acts, None, None), (a.acts, grown, None), ([], self.s.lineage, None)],
            [(pending.acts, None, None), (b.acts, None, None), (a.acts + b.acts, None, None)],
            [(k.c1.acts + k.x0.acts, k.sib_docs, None), (k.y0.acts, k.sib_docs, None), (k.rm.acts, None, None)],
            [(k.x2.acts, self.s.lineage + [k.d2[1]], None), (k.c1.acts + k.x2.acts, self.s.lineage + [k.d2[1]], None)],
            [([], self.s.lineage + [k.foreign[1]], None), (k.c1.acts, self.s.lineage + [k.foreign[1]], None)],
        ]

    def setUp(self):
        super().setUp()
        self.k = SyncWorlds(self.s)

    @staticmethod
    def no_host():
        """A context in which a file open, a descriptor open and every read of a clock raise: what `decide` may not do."""
        def refuse(name):
            def raiser(*args, **kwargs):
                raise AssertionError("decide reached the host through " + name)
            return raiser
        stack = contextlib.ExitStack()
        for target in ("builtins.open", "io.open", "os.open", "time.time", "time.time_ns", "time.monotonic",
                       "time.monotonic_ns", "time.perf_counter"):
            stack.enter_context(mock.patch(target, refuse(target)))
        return stack

    def test_the_host_is_closed_to_decide_and_the_guard_is_real(self):   # CF-09 step 3
        with self.no_host():
            for call in (lambda: open(os.devnull), lambda: os.open(os.devnull, os.O_RDONLY),
                         __import__("time").time, __import__("time").monotonic):
                with self.assertRaises(AssertionError):
                    call()

    def test_decide_returns_what_run_writes_for_every_call_of_every_sequence(self):
        for number, sequence in enumerate(self.steps()):
            port = Recording()
            for at, (acts, docs, pin) in enumerate(sequence):
                with self.subTest(sequence=number, call=at):
                    wire_ = wire(self.s) if pin is None else self.k.pinned_at(pin)
                    old = store.NOTHING if port.old is None else store.parse(port.old)
                    before = port.old
                    got = self.sync(acts, docs=docs, probe=Probe(wire_), port=port)
                    inp = self.inp(acts, docs)
                    index = snapshot.by_hash(inp)
                    lineage, _ = sync._pinned_path(index, self.org, Probe(wire_).read(self.org))
                    try:
                        with self.no_host():   # purity: no file, no descriptor, no clock inside `decide`
                            made = sync.decide(old, inp, index, lineage, self.profile_set, memo(None), lambda *args: None)
                    except errors.Refused as err:
                        self.assertEqual(got["reason"], err.code)
                        self.assertEqual((got["synced_at"], port.old), (None, before))
                        continue
                    self.assertEqual(got["reason"], "epoch_superseded" if made.next == "yes" else made.reason)
                    self.assertEqual(port.old, store.encode(made.acts, made.lineage, made.next, NOW))


class Reader:
    """A machine over one source: its own store, pinned at one document, syncing what the source offers."""

    def __init__(self, test, pin_doc, org):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.port, self.org, self.pin_doc = store_posix.PosixStore(tmp.name, os.getuid()), org, pin_doc

    def call(self, acts, docs):
        """The answer of one `sync` of the strings `acts` with `docs`."""
        return sync.run(snap(acts, docs, self.org), PRODUCTION_ONLY, memo(None), lambda *args: None,
                        Probe(probe_for(self.pin_doc, self.org)), self.port, Clock(NOW))

    def stored(self):
        path = Path(self.port.path(self.org))
        return store.parse(path.read_bytes()) if path.exists() else None

    def acts(self):
        held = self.stored()
        return frozenset() if held is None else frozenset(held.acts)


ACCEPTED = ("ok", "fork", "epoch_superseded")


def generated(seeds):
    """`(seed, kind, raw snapshot)` of the random stores and of the stores with sibling changes."""
    for seed in seeds:
        for kind, make in (("random", random_store), ("sibling", sibling_store)):
            made = make(seed, production_of(FIXTURE))
            yield seed, kind, snapshot.Snapshot(made.acts, made.docs, made.org)


def pins_of(raw, rng, count=2):
    """Documents of `raw` to pin a reader at: the path to each must fold."""
    keys = sorted(snapshot.by_hash(raw).items())
    return [doc["doc"] for _, doc in rng.sample(keys, min(count, len(keys)))]


class Properties(unittest.TestCase):
    """Over generated stores, read against the last release (`read_oracle`): what a machine stores and what it refuses."""

    SEEDS = range(16)

    def sources(self, raw, pin, rng):
        """The `docs` a source may serve a machine pinned at `pin`, one way per call: every document; every one but a
        document off the pinned path; or every one with one receipt of those off the path (a source that strips)."""
        path = {genesis.doc_hash(item["doc"]) for item in snapshot.path_to(snapshot.by_hash(raw), genesis.doc_hash(pin))}
        off = [item for item in raw.docs if genesis.doc_hash(item["doc"]) not in path]
        way = rng.choice(("every", "omits", "strips")) if off else "every"
        if way == "omits":
            gone = rng.choice(off)
            return [item for item in raw.docs if item is not gone]
        if way == "strips":
            return [item if item not in off else {"doc": item["doc"], "sigs": item["sigs"][:1]} for item in raw.docs]
        return raw.docs

    def test_no_write_loses_a_text_the_last_release_reads_over_everything_offered(self):   # CF-09 step 6
        calls = losses = 0
        for seed, kind, raw in generated(self.SEEDS):
            rng = random.Random(seed)
            closed = admit_closed(raw)
            for pin in pins_of(raw, rng):
                with self.subTest(seed=seed, kind=kind, pin=genesis.doc_hash(pin)[:8]):
                    reader, offered = Reader(self, pin, raw.org), set()
                    for _ in range(8):
                        part = self.part(closed, rng, pin)
                        before = reader.acts()
                        got = reader.call(part, self.sources(raw, pin, rng))
                        calls += 1
                        if got["reason"] not in ACCEPTED:
                            self.assertEqual((got["synced_at"], reader.acts()), (None, before))   # nothing written
                            continue
                        offered |= set(part) | before
                        read = read_oracle(offered, raw.docs, pin, raw.org)
                        self.assertIsNotNone(read)
                        lost = (before & read) - reader.acts()
                        losses += len(lost)
                        self.assertEqual(lost, set())
        self.assertGreater(calls, 300)

    def test_the_read_part_of_the_union_does_not_depend_on_the_order(self):   # CF-09 S27
        closed_runs = 0
        for seed, kind, raw in generated(self.SEEDS):
            rng = random.Random(seed)
            closed = admit_closed(raw)
            for pin in pins_of(raw, rng):
                with self.subTest(seed=seed, kind=kind, pin=genesis.doc_hash(pin)[:8]):
                    read = read_oracle(closed.acts, closed.docs, pin, raw.org)
                    self.assertIsNotNone(read)
                    one, two = self.part(closed, rng, pin), self.part(closed, rng, pin)
                    seen = []
                    for parts in ((one, two), (two, one), ()):
                        reader = Reader(self, pin, raw.org)
                        for part in parts:
                            reader.call(part, raw.docs)   # a partial call may be refused: the final snapshot settles it
                        self.assertIn(reader.call(closed.acts, closed.docs)["reason"], ACCEPTED)
                        held = reader.stored()
                        self.assertLessEqual(read, set(held.acts))   # what a fold reads is stored
                        seen.append((frozenset(held.acts) & read, held.lineage, held.next))
                    closed_runs += 1
                    self.assertEqual(seen[0], seen[1])
                    self.assertEqual(seen[0], seen[2])   # and equals the reader that was given only the closed snapshot
        self.assertGreater(closed_runs, 40)

    def structure(self, closed):
        """`(acts, members, named)` of the admit-closed store `closed`: its acts by receipt id; its groups (a primary with
        the endorsements that name it) by the id of the primary; and `named(key)`, the groups an act cannot come before,
        the one it hangs at and every one its body names (a resolve names the candidates it chooses between)."""
        acts = parsed(closed.acts, closed.org, REG.wire)
        members = {}
        for text in closed.acts:
            act = chain.read(text, REG.wire, closed.org)
            if act is not None:
                key = act.parent if act.method == chain.ENDORSE and act.parent in acts else act.id
                members.setdefault(key, []).append(text)

        def named(key):
            body = json.dumps(acts[key].body)
            return {other for other in members if other != key and (other == acts[key].parent or other in body)}

        return acts, members, named

    def part(self, closed, rng, pin):
        """The strings of a snapshot closed under the parent: a random share of the groups of `closed`, each with
        what it hangs at and names, and the nodes a machine pinned at `pin` needs to fold its path."""
        acts, members, named = self.structure(closed)
        wanted = set()
        for item in snapshot.path_to(snapshot.by_hash(closed), genesis.doc_hash(pin)):
            if item["doc"].get("head") in acts:
                wanted.add(item["doc"]["head"])
        wanted |= {key for key in members if rng.random() < 0.4}
        found, pending = set(), sorted(wanted)
        while pending:
            key = pending.pop()
            if key not in found and key in members:
                found.add(key)
                pending.extend(named(key))
        return [text for key in sorted(found) for text in members[key]]

    def admission(self, closed, rng):
        """`[("doc", entry) or ("acts", texts)]`: the events of a relay that holds `closed`, in the order it can have
        admitted them. A document comes after the acts of the epoch it succeeds (an epoch with a successor admits no
        more acts), its own epoch follows it, and a group is a primary with the endorsements that name it."""
        acts, members, named = self.structure(closed)

        def epoch_of(key):
            """The hash of the document the chain of acts from `key` hangs at, and how deep `key` sits."""
            height = 0
            while acts[key].parent in acts:
                key, height = acts[key].parent, height + 1
            return acts[key].parent, height

        epochs = {}
        for key in members:
            root, height = epoch_of(key)
            epochs.setdefault(root, []).append((height, key))
        children = {}
        for item in closed.docs:
            children.setdefault(item["doc"].get("prev"), []).append(item)
        events = []

        def ordered(keys):
            """`keys` with every group after the groups it names."""
            done, out = set(), []

            def place(key):
                if key in done:
                    return
                done.add(key)
                for other in sorted(named(key) & set(keys)):
                    place(other)
                out.append(key)

            for key in keys:
                place(key)
            return out

        def visit(item):
            events.append(("doc", item))
            for key in ordered([key for _, key in sorted(epochs.get(genesis.doc_hash(item["doc"]), ()))]):
                events.append(("acts", members[key]))
            later = list(children.get(genesis.doc_hash(item["doc"]), ()))
            rng.shuffle(later)
            for successor in later:
                visit(successor)

        visit(children[None][0])
        return events

    def test_an_honest_feed_in_admission_order_is_refused_only_for_a_late_sibling_and_one_full_snapshot_repairs_it(self):   # CF-09 step 6
        refusals = feeds = 0
        for seed, kind, raw in generated(self.SEEDS):
            rng = random.Random(seed)
            closed = admit_closed(raw)
            documents = {genesis.doc_hash(item["doc"]): item["doc"] for item in closed.docs}
            acts = parsed(closed.acts, closed.org, REG.wire)
            for pin in pins_of(raw, rng):
                with self.subTest(seed=seed, kind=kind, pin=genesis.doc_hash(pin)[:8]):
                    events = self.admission(closed, rng)
                    at = next(number for number, (what, item) in enumerate(events) if what == "doc" and item["doc"] == pin)
                    sent, served = [], []
                    for what, item in events[:at + 1]:
                        if what == "doc":
                            served.append(item)
                        else:
                            sent += item
                    reader = Reader(self, pin, raw.org)
                    self.assertIn(reader.call(sent, served)["reason"], ACCEPTED)   # the whole state when it was pinned
                    feeds += 1
                    later = events[at + 1:]
                    while later:
                        width = rng.randint(1, 6)
                        chunk, later = later[:width], later[width:]
                        offered = [text for what, item in chunk if what == "acts" for text in item]
                        served += [item for what, item in chunk if what == "doc"]
                        union = {act.id for act in parsed(reader.acts() | set(offered), closed.org, REG.wire).values()}
                        got = reader.call(offered, served)
                        sent += offered
                        if got["reason"] in ACCEPTED:
                            continue
                        refusals += 1
                        self.assertEqual(got["reason"], "snapshot_incomplete")
                        # the late-sibling case: an act whose parent is in no union, below a document off the pinned
                        # lineage (its head was dropped before the sibling was admitted)
                        causes = set()
                        for text in offered:
                            act = chain.read(text, REG.wire, closed.org)
                            if act is None or act.parent in union or act.parent in documents:
                                continue
                            root = act.parent
                            while root in acts:
                                root = acts[root].parent
                            causes.add(position(documents, pin, root))
                        self.assertTrue(causes and causes <= {"off"}, causes)
                        self.assertIn(reader.call(sent, served)["reason"], ACCEPTED)   # one full snapshot
        self.assertGreater(feeds, 20)
        self.assertGreater(refusals, 0)   # the late sibling does occur in sibling stores: the claim is not vacuous

    def test_a_drop_list_applied_dependents_first_never_refuses_a_warm_reader_or_a_fresh_one_at_an_open_pin(self):   # CF-14
        states = refused = 0
        for seed, kind, raw in generated(range(8)):
            closed = admit_closed(raw)
            gone_acts, gone_sigs = retain.dropped(closed, retained_of(closed))
            order = dependents_first(closed, gone_acts)
            counts = sorted({0, len(order)} | {len(order) * step // 6 for step in range(1, 6)})
            later = {genesis.doc_hash(item["doc"]).__str__(): item["doc"].get("prev") for item in closed.docs}
            leaves = [item["doc"] for item in closed.docs if genesis.doc_hash(item["doc"]) not in later.values()]
            every = [item["doc"] for item in closed.docs]
            warm = {}
            for pin in every:
                reader = Reader(self, pin, raw.org)
                if reader.call(closed.acts, closed.docs)["reason"] in ACCEPTED:
                    warm[genesis.doc_hash(pin)] = reader
            for count in counts:
                state = after(closed, order[:count], gone_sigs)
                for pin in leaves:
                    with self.subTest(seed=seed, kind=kind, removed=count, reader="fresh", pin=genesis.doc_hash(pin)[:8]):
                        got = Reader(self, pin, raw.org).call(state.acts, state.docs)
                        states += 1
                        self.assertNotEqual(got["reason"], "snapshot_incomplete")
                for key, reader in warm.items():
                    with self.subTest(seed=seed, kind=kind, removed=count, reader="warm", pin=key[:8]):
                        got = reader.call(state.acts, state.docs)
                        states += 1
                        refused += got["reason"] == "snapshot_incomplete"
                        self.assertNotEqual(got["reason"], "snapshot_incomplete")
        self.assertGreater(states, 400)


class Downgrade(Case):
    """CF-09, the format is unchanged: a machine that goes back to the last release loses only the cache."""

    def setUp(self):
        super().setUp()
        self.k = SyncWorlds(self.s)

    def asked(self, probe):
        table = production_table(probe, Clock(NOW), PRODUCTION_ONLY, self.port)
        return [run(table, "check-act", production_input(self.s.value(self.s.verdict(head=head))))
                for head in (head_of(genesis.doc_hash(self.k.c1_doc[0])), head_of(self.k.c1.id))]

    def test_the_last_release_reads_a_store_with_a_nine_act_cache_and_drops_only_the_cache(self):   # CF-09 step 6
        k = self.k
        at_c1 = Probe(k.pinned_at(k.c1_doc[0]))
        for acts in (k.c1.acts + k.x0.acts, k.y0.acts):
            self.assertEqual(self.sync(acts, docs=k.sib_docs, probe=at_c1)["reason"], "ok")
        self.assertEqual(len(self.stored().acts), 9)
        before = self.asked(at_c1)
        release = v042_tree.load("v0.4.2")
        module = lambda name: v042_tree.module(release, name)
        got = module("sync").run(module("sync").parse_input({"acts": [], "docs": k.sib_docs, "org": self.org}),
                                 release_profiles(), module("verifier").Memoized(FakeVitni()), lambda *args: None,
                                 at_c1, self.port, self.clock)
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual((len(self.stored().acts), self.stored().lineage), (3, canon(self.s.lineage + [k.c1_doc[1]])))
        self.assertEqual(self.asked(at_c1), before)   # no answer of a command that reads the store changed
        self.assertEqual(before[0]["reason"], "ok")   # and one of them is a real answer, not a refusal


class Input(unittest.TestCase):
    def test_the_input_is_the_closed_object_of_acts_docs_and_org(self):   # CF-09 S14
        s = Scenario(production_world())
        good = {"acts": [], "docs": s.lineage, "org": s.w.id}
        self.assertEqual(sync.parse_input(good), snap([], s.lineage, s.w.id))
        self.assertEqual(sync.parse_input(good).docs, canon(s.lineage))
        for key in ("pin", "now", "at", "synced_at", "tip_statement", "witness", "lineage", "extra"):
            with self.subTest(key=key):
                with self.assertRaises(errors.Malformed):
                    sync.parse_input({**good, key: None})
        for name, bad in {
            "no acts": {k: v for k, v in good.items() if k != "acts"},
            "no docs": {k: v for k, v in good.items() if k != "docs"},
            "no org": {k: v for k, v in good.items() if k != "org"},
            "a lineage instead of docs": {"acts": [], "lineage": s.lineage, "org": s.w.id},
            "an act that is no string": {**good, "acts": [1]},
            "acts not a list": {**good, "acts": "x"},
            "a docs entry with other keys": {**good, "docs": [{"doc": {}}]},
            "a sig that is no string": {**good, "docs": [{"doc": {}, "sigs": [1]}]},
            "an org that is no hashstr": {**good, "org": "x"},
            "not an object": [],
        }.items():
            with self.subTest(case=name):
                with self.assertRaises(errors.Malformed):
                    sync.parse_input(bad)

    def test_a_malformed_input_reaches_neither_the_probe_nor_the_store(self):
        s = Scenario(production_world())
        probe, port = Probe(s.value()["pin"]), Recording()
        table = production_table(probe, Clock(), PRODUCTION_ONLY, port)
        for key in ("pin", "now", "synced_at", "tip_statement", "witness"):
            got = run(table, "sync", {"acts": [], "docs": s.lineage, "org": s.w.id, key: None})
            self.assertEqual(got, {"error": "malformed_input"}, key)
        self.assertEqual((probe.asked, port.events), ([], []))


UNKNOWN = encoding.hashstr(b"an edition this release does not implement")
THREE = ("alice", "bob", "carol")


class Foreign(Case):
    """CF-09 step 5, the foreign successor (GP-22): a direct successor of the pinned document under a
    hash of no catalog entry sets `next` when the pinned policy's quorum signed it at a head of the pinned epoch,
    and is ignored when it did not. Every forged case comes before the authorized ones."""

    def successor(self, head=None, signers=THREE, name="LATER", profile=UNKNOWN, **over):
        w = self.s.w
        doc = change(profile, over.pop("org", w.id), over.pop("prev", genesis.doc_hash(w.doc)), head or w.id,
                     people=THREE, pol=policy(), name=name)
        return {"doc": doc, "sigs": w.sigs(doc, signers)}

    def ignored(self, entry, acts=()):
        got = self.sync(acts, docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().next, "no")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))

    def test_a_forged_successor_under_an_unknown_profile_does_not_supersede(self):   # CF-09 S30
        self.ignored(self.successor(signers=("alice",)))   # below the quorum of two
        w = production_world(extra=("dave", "grace"), members=(("dave", "member"), ("grace", "member")))
        self.s = Scenario(w, signers=THREE + ("dave", "grace"))
        self.org = w.id
        self.path.exists() and self.path.unlink()
        self.ignored(self.successor(signers=("dave", "grace")))   # two persons, no `genesis.change` role
        w = production_world()
        self.s, self.org = Scenario(w), w.id
        self.path.unlink()
        gone = w.device_remove("alice", ("bob", "carol"))
        self.ignored(self.successor(head=gone.id, signers=("alice", "bob")), gone.acts)   # alice's key is not clean at H

    def test_an_unknown_profile_successor_with_a_bad_head_or_link_is_ignored(self):   # CF-09 S31
        w = self.s.w
        other = encoding.hashstr(b"another organization")
        self.ignored(self.successor(head=encoding.hashstr(b"no node of this epoch")))
        self.path.unlink()
        self.ignored(self.successor(prev=encoding.hashstr(b"another document")))
        self.path.unlink()
        self.ignored(self.successor(org=other))

    def test_a_downgrade_or_a_fixture_successor_is_not_foreign(self):   # CF-09 S32
        class Two(Foreign):
            profile_set = synthetic_set(2)

            def setUp(inner):
                super().setUp()
                inner.first, inner.second = inner.profile_set.production_hashes()
        for older, newer in ((1, 0), (0, "fixture")):
            case = Two("test_a_downgrade_or_a_fixture_successor_is_not_foreign")
            case.setUp()
            self.addCleanup(case.doCleanups)
            hashes = case.profile_set.production_hashes()
            fixtures = case.profile_set.fixture_hashes()
            world = World(profile=hashes[older])
            case.s, case.org = Scenario(world), world.id
            profile = fixtures[1] if newer == "fixture" else hashes[newer]
            entry = case.successor(profile=profile)
            case.ignored(entry)

    def test_the_lineage_itself_says_who_is_foreign_and_who_is_not(self):   # CF-09 S32, S36
        got = synthetic_set(2)
        first, second = got.production_hashes()
        w = World(profile=second)
        self.s, self.org = Scenario(w), w.id
        tip = epoch_module.Lineage.empty([], got, False, memo()).extend_all(self.s.lineage)
        self.assertTrue(tip.moved_by(self.successor()))                                    # unlisted and authorized
        self.assertFalse(tip.moved_by(self.successor(signers=("alice",))))                 # unlisted, below the quorum
        self.assertFalse(tip.moved_by(self.successor(profile=first)))                      # a downgrade is not foreign
        self.assertFalse(tip.moved_by(self.successor(profile=got.fixture_hashes()[1])))    # nor a fixture hash
        self.assertFalse(tip.moved_by(self.successor(profile=second)))                     # nor a listed edition
        self.assertFalse(epoch_module.Lineage.empty([], got, False, memo()).moved_by(self.successor()))   # no pin

    def test_the_first_foreign_successor_that_closes_the_epoch_stops_the_asking(self):   # CF-09 S29
        """`next` is a yes or a no: once one authorized successor has answered it, no other direct successor of the
        pinned document is asked of the verifier, so a pile of them costs what one costs."""
        def calls(names):
            vitni = FakeVitni()
            docs = self.s.lineage + [self.successor(name=name) for name in names]
            self.path.exists() and self.path.unlink()
            got = self.sync(docs=docs, vitni=vitni)
            self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
            self.assertEqual(self.stored().next, "yes")
            return len(vitni.calls)
        one = calls(["ONE"])
        self.assertGreater(one, 0)
        self.assertEqual(calls(["ONE", "TWO", "THREE", "FOUR"]), one)

    def test_an_authorized_successor_under_an_unknown_profile_sets_next_and_is_not_stored(self):   # CF-09 S29
        w = self.s.w
        step = w.device_add("alice2", AB)
        entry = self.successor(head=step.id)
        got = self.sync(step.acts, docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual(self.stored().next, "yes")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))

    def test_a_foreign_successor_keeps_next_yes_until_a_re_pin(self):   # CF-09 S33
        w = self.s.w
        entry = self.successor()
        self.assertEqual(self.sync(docs=self.s.lineage + [entry])["reason"], "epoch_superseded")
        self.clock.value = LATER
        self.assertEqual(self.sync(), {"reason": "epoch_superseded", "synced_at": LATER})   # the successor is not offered
        self.assertEqual(self.stored().next, "yes")
        # a release that implements the successor's edition, pinned at it: `next` is recomputed
        implementing = synthetic_set(2)
        self.profile_set = implementing
        w2 = World(profile=implementing.production_hashes()[0])
        self.s, self.org = Scenario(w2), w2.id
        self.path.exists() and self.path.unlink()
        self.assertEqual(self.sync()["reason"], "ok")
        later = {"doc": change(implementing.production_hashes()[1], w2.id, genesis.doc_hash(w2.doc), w2.id,
                               people=THREE, pol=policy(), name="LATER")}
        later["sigs"] = w2.sigs(later["doc"], THREE)
        pinned_there = Probe(probe_for(later["doc"], w2.id))
        got = self.sync(docs=self.s.lineage + [later], probe=pinned_there)
        self.assertEqual(got, {"reason": "ok", "synced_at": LATER})
        self.assertEqual(self.stored().next, "no")

    def test_a_verifier_that_fails_on_a_foreign_successor_is_no_verdict_on_it(self):   # CF-09 S34
        entry = self.successor()

        class FailsOn(FakeVitni):
            def verify(self, jws, keys, method):
                if jws in entry["sigs"]:
                    raise verifier.VerifierUnavailable("down")
                return super().verify(jws, keys, method)

        self.refused("verifier_unavailable", self.sync(docs=self.s.lineage + [entry], vitni=FailsOn()))
        self.assertFalse(self.path.exists())

    def test_one_authorized_foreign_sibling_is_enough(self):   # CF-09 S35
        forged = self.successor(signers=("alice",), name="FORGED")
        real = self.successor(name="REAL")
        for docs in ([forged, real], [real, forged]):
            if self.path.exists():
                self.path.unlink()
            got = self.sync(docs=self.s.lineage + docs)
            self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
            self.assertEqual(self.stored().next, "yes")

    def test_a_foreign_successor_is_decided_by_its_four_checks_and_no_other_step(self):   # CF-09 S36
        w = self.s.w
        entry = self.successor(signers=("alice", "bob"))   # no possession by any listed device but alice and bob
        entry["doc"]["policy"]["classes"].insert(0, {"class": "a-class-this-release-cannot-read", "user_verification": "none"})
        entry["doc"]["devices"][0] = dict(entry["doc"]["devices"][0], label="a carry that changed")   # GP-20
        entry["sigs"] = w.sigs(entry["doc"], ("alice", "bob"))
        seen = []   # what each later step of GP-15 was asked about: the pinned documents may be, the successor may not
        for owner, name in ((genesis_sigs, "check_possession"), (policy_module, "validate"),
                            (render_genesis, "render_size"), (epoch_module, "_check_carried")):
            real = getattr(owner, name)

            def watch(*args, _real=real, _name=name, **kw):
                seen.append((_name, json.dumps(args[0], sort_keys=True, default=str)))
                return _real(*args, **kw)
            patcher = mock.patch.object(owner, name, side_effect=watch)
            patcher.start()
            self.addCleanup(patcher.stop)
        got = sync.run(self.inp(docs=self.s.lineage + [entry]), self.profile_set, memo(), render_genesis.render_size,
                       Probe(wire(self.s)), self.port, self.clock)
        self.assertTrue(seen)   # the pinned path itself went through those steps
        self.assertEqual([name for name, text in seen if "a-class-this-release-cannot-read" in text or '"LATER"' in text], [])
        self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual(self.stored().next, "yes")


class Pins(Case):
    """What `sync` already does and must keep doing whatever it learns to refuse, over the worlds of `sync_worlds`.
    Written green before the refusal rule: each is a fact of the store the rule must not move."""

    def setUp(self):
        super().setUp()
        self.k = SyncWorlds(self.s)

    def test_the_store_holds_the_pinned_path_only_in_the_one_format_whatever_documents_are_offered(self):   # CF-09 S19
        k = self.k
        got = self.sync(k.c1.acts + k.x0.acts, docs=k.sib_docs)
        self.assertEqual(got["reason"], "epoch_superseded")
        self.assertEqual(self.stored().lineage, canon(self.s.lineage))
        self.assertEqual(json.loads(self.path.read_bytes())["v"], "handsal-store/1")
        self.assertEqual(sorted(json.loads(self.path.read_bytes())), ["acts", "lineage", "next", "synced_at", "v", "witness"])

    def test_a_string_chain_read_rejects_is_dropped_next_to_acts_of_a_sibling_lineage(self):   # CF-09 S22
        k = self.k
        junk = ["junk", "", "a.b.c", self.s.verdict().jws, k.w.sigs(k.w.doc, ("alice",))[0]]
        junk += World(name="OTHER").device_add("alice2", AB).acts
        self.assertEqual(self.sync(k.c1.acts + junk, docs=k.sib_docs)["reason"], "epoch_superseded")
        self.assertEqual(self.stored().acts, store.canonical(k.c1.acts))
        self.assertEqual(self.sync(junk, docs=k.sib_docs)["reason"], "epoch_superseded")
        self.assertEqual(self.stored().acts, store.canonical(k.c1.acts))

    def test_a_foreign_successor_whose_head_is_absent_or_no_node_leaves_next_no(self):   # CF-09 S31
        k = self.k
        for name, entry in (("absent head", k.foreign[1]), ("random head", k.foreign_random_head[1])):
            with self.subTest(name):
                self.path.exists() and self.path.unlink()
                self.assertEqual(self.sync(docs=self.s.lineage + [entry]), {"reason": "ok", "synced_at": NOW})
                self.assertEqual((self.stored().next, self.stored().lineage), ("no", canon(self.s.lineage)))
        self.path.unlink()
        got = self.sync(k.c1.acts, docs=self.s.lineage + [k.foreign[1]])   # the head arrives: it is a successor
        self.assertEqual((got["reason"], self.stored().next), ("epoch_superseded", "yes"))

    def test_next_never_goes_from_yes_to_no_under_one_pin(self):   # CF-09 S25
        k = self.k
        self.assertEqual(self.sync(k.c1.acts, docs=k.sib_docs)["reason"], "epoch_superseded")
        thin = [{"doc": k.c1_doc[0], "sigs": k.c1_doc[1]["sigs"][:1]}]
        for docs in (self.s.lineage, self.s.lineage + thin, self.s.lineage + [k.c1_doc[1]]):
            self.assertEqual(self.sync(docs=docs)["reason"], "epoch_superseded")
            self.assertEqual(self.stored().next, "yes")

    def test_every_sibling_store_opens(self):
        for seed in range(60):
            with self.subTest(seed=seed):
                made = sibling_store(seed)
                self.assertTrue(opening.open_store(snapshot.Snapshot(made.acts, made.docs, made.org), PRODUCTION_ONLY, True,
                                                 memo(None), render_genesis.render_size))

    def test_a_sibling_store_has_three_changes_of_the_original_and_one_seed_one_store(self):
        for seed in (0, 1, 2):
            with self.subTest(seed=seed):
                first, again = sibling_store(seed), sibling_store(seed)
                self.assertEqual((first.acts, first.docs, first.ids), (again.acts, again.docs, again.ids))
                root = genesis.doc_hash(first.docs[0]["doc"])
                self.assertEqual(sum(1 for item in first.docs if item["doc"].get("prev") == root), 3)


if __name__ == "__main__":
    unittest.main()
