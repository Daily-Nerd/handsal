"""CF-09 `handsal-check sync`: the only writer of the store.

`run` takes the pin probe, the store port and the clock as arguments, like the production table does, so each test
gives them: a recording probe, a real `PosixStore` over a temporary home, and a fixed clock. Nothing here touches
the real home. Each refusal leaves the store byte for byte (or absent), writes no clock read and answers
`{reason, synced_at: null}`.
"""
import contextlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import errors, genesis, profiles, registry, store, store_posix, sync

from .act_builder import FakeVitni, Unavailable
from .checkact_world import NOW, Scenario, probe_for
from .test_builds import Clock, Probe, production_table, run
from .fold_world import World
from .genesis_fixtures import change, policy
from .test_enrolled import FIXTURE, PRODUCTION_ONLY, production_world

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

    def test_a_second_sync_never_drops_an_act(self):
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

    def test_junk_strings_are_kept_and_a_child_before_its_parent_is_not_lost(self):   # FO-06, SS3
        first = self.s.w.device_add("alice2", ("alice", "bob"))
        second = self.s.w.device_add("bob2", ("bob", "alice"), first)
        self.assertEqual(self.sync(second.acts + ["junk", ""])["reason"], "ok")   # the child alone: no parent yet
        self.assertEqual(self.sync(first.acts)["reason"], "ok")
        self.assertEqual(self.stored().acts, store.canonical(first.acts + second.acts + ["junk", ""]))

    def moves_to_a_later_epoch(self, at_the_root):
        """Sync an epoch 1 act, then sync only an epoch 2 act under the longer lineage; the stored acts after."""
        w = self.s.w
        add = w.device_add("alice2", ("alice", "bob"))
        self.assertEqual(self.sync(add.acts)["reason"], "ok")   # epoch 1, under the original lineage
        doc = change(FIXTURE.production, w.id, genesis.doc_hash(w.doc), w.id if at_the_root else add.id,
                     people=("alice", "bob", "carol"), pol=policy(), name="NEXT")
        longer = self.s.lineage + [{"doc": doc, "sigs": w.sigs(doc, ("alice", "bob", "carol"))}]
        w2 = World()
        w2.doc, w2.id, w2.org = doc, genesis.doc_hash(doc), w.id   # epoch 2 roots at the change document
        later = w2.device_add("alice3", ("alice", "bob"))
        self.clock.value = LATER
        got = self.sync(later.acts, docs=longer, probe=Probe(probe_for(doc, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": LATER})
        self.assertEqual(self.stored().lineage, canon(longer))
        return add, later

    def test_a_lineage_that_moves_to_a_later_epoch_keeps_every_stored_act(self):   # CF-09 S18, L9 (c)
        add, later = self.moves_to_a_later_epoch(at_the_root=False)   # the change follows the stored act
        self.assertEqual(self.stored().acts, store.canonical(add.acts + later.acts))

    def test_a_stored_act_the_new_epoch_does_not_need_is_kept_too(self):   # CF-09 S18: the fold would not miss it
        add, later = self.moves_to_a_later_epoch(at_the_root=True)   # the change is at the root, beside the stored act
        self.assertEqual(self.stored().acts, store.canonical(add.acts + later.acts))

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
        broken = [{"doc": self.s.w.doc, "sigs": []}]   # no counting signature on the original
        got = self.sync(docs=broken)
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

    def test_a_union_over_max_input_is_store_full(self):   # CF-09 S5, L15
        junk = ["%06d" % i + "x" * 1_000_000 for i in range(15)]
        with self.port.lock(self.org) as held:
            held.write(store.encode(junk, canon(self.s.lineage), NOW))
        before = self.path.read_bytes()
        self.assertLess(len(before), MAX)
        self.refused("store_full", self.sync(["y" * 2_000_000]))
        self.assertEqual((self.path.read_bytes(), self.clock.calls), (before, 0))
        self.assertEqual(self.sync(["z" * 10])["reason"], "ok")   # the same store still takes a small act

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
        pinned = change(FIXTURE.production, w.id, genesis.doc_hash(w.doc), w.id, people=everyone, pol=policy(), name="NEXT")
        sibling = change(FIXTURE.production, w.id, genesis.doc_hash(w.doc), w.id, people=everyone, pol=policy(), name="SIBLING")
        beyond = change(FIXTURE.production, w.id, genesis.doc_hash(pinned), w.id, people=everyone, pol=policy(), name="BEYOND")
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
        # the ceremony re-pinned and its own `sync` failed: the pin names the change, the store is old
        self.clock.value = LATER
        got = self.sync(docs=[self.s.lineage[0], entry(pinned), entry(sibling)], probe=Probe(probe_for(pinned, w.id)))
        self.assertEqual(got, {"reason": "ok", "synced_at": LATER})
        healed = self.stored()
        self.assertEqual(healed.lineage, canon([self.s.lineage[0], entry(pinned)]))
        self.assertEqual(healed.acts, before.acts)   # the set only grows
        self.assertEqual(healed.synced_at, LATER)


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
