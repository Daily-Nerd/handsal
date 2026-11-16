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
import json
import os
import random
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import admit, errors, genesis, ijson, profiles, registry, render_genesis, retain, store, store_posix
from handsal_check import sync, verifier

from .act_builder import FakeVitni, Unavailable
from .checkact_world import NOW, Scenario, probe_for
from .test_builds import Clock, Probe, production_table, run
from .fold_world import World
from .genesis_fixtures import change, policy
from .store_world import AB, LOW, POOLS, Counting, grow, later_world
from .test_enrolled import FIXTURE, PRODUCTION_ONLY, production_world
from .profile_sets import production_of

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
        return sync.run(self.inp(acts, docs, org), REG, PRODUCTION_ONLY, vitni or FakeVitni(), lambda *args: None,
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
        got = sync.run(snap([], fixture.lineage, fixture.w.id), REG, profiles.load(), FakeVitni(),
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

    def test_a_union_the_retained_set_shrinks_under_max_input_is_written(self):   # CF-09 S5, SD10
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

    def test_an_act_whose_parent_is_no_node_is_not_stored_and_a_whole_snapshot_is(self):   # SD9, CF-13
        w = self.s.w
        first = w.device_add("alice2", AB)
        second = w.device_add("bob2", AB, first)
        self.assertEqual(self.sync(second.acts)["reason"], "ok")   # the child alone: nothing is held pending
        self.assertEqual(self.stored().acts, [])
        self.assertEqual(self.sync(first.acts + second.acts)["reason"], "ok")   # a snapshot carries whole groups
        self.assertEqual(self.stored().acts, store.canonical(first.acts + second.acts))

    def test_an_act_with_a_missing_signature_is_not_stored(self):   # CF-09 S22: a pending primary is no node
        pending = self.s.w.device_add("alice2", ("alice",))
        self.assertEqual(self.sync(pending.acts)["reason"], "ok")
        self.assertEqual(self.stored().acts, [])

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

    def test_the_acts_of_an_epoch_off_the_pinned_lineage_are_not_stored(self):   # CF-14 D8, GP-21
        w = self.s.w
        doc, entry = self.change_at(w.id)
        other, other_entry = self.change_at(w.id, name="SIBLING")
        ours = later_world(w, doc).device_add("alice4", AB)
        theirs = later_world(w, other).device_add("alice4", AB, salt="s")
        docs = self.s.lineage + [entry, other_entry]
        self.assertEqual(self.sync(ours.acts + theirs.acts, docs=docs, probe=Probe(probe_for(doc, w.id)))["reason"], "ok")
        self.assertEqual(self.stored().acts, store.canonical(ours.acts))

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
                epochs = admit.open_store(whole, REG, PRODUCTION_ONLY, False, verifier.Memoized(FakeVitni()),
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
        epochs = epoch_module.fold_lineage(self.s.lineage, acts, REG, PRODUCTION_ONLY, False, counted)
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


if __name__ == "__main__":
    unittest.main()
