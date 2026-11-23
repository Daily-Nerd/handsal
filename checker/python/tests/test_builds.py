"""T3.57 and T3.58 two builds of one pure core, and the commands of CF-03 they share (CF-08), plus `sync` and `version`
in the production build (CF-09, CF-03).

The conformance build takes `pin`, `now` and the store's content (`acts`, `lineage`, `next`, `synced_at`,
`tip_statement`) as
data and accepts both profiles. The production build reads the pin through a probe, `now` from a clock and the
chain from the store, all in process and all constructor arguments (the entry point passes the platform probe, the
system clock and the user's store; no flag and no input reaches them), refuses an input that carries any of those
keys, and refuses the fixture profile. The tests give the production table a recording probe, a recording store and
a fixed clock, and prove that it answers what the conformance table answers for the same data.
"""
import ast
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import (commands, conformance, core, encoding, errors, genesis, pinfile, production, server, store,
                           store_posix, verifier)

from . import spec_tables
from .act_builder import BAD, FakeVitni, head_of, with_signature
from .checkact_world import NOW, Scenario, probe_for
from .test_enrolled import PRODUCTION_ONLY, production_world, relay_scenario, value as enrolled_value
from .genesis_fixtures import change, point, policy
from .genesis_fixtures import org as make_org
from .fold_world import World
from .test_commands import Forcing, builds
from .profile_sets import production_of, synthetic_set, without_fixture_kids
from .store_world import BatchStub

SPEC = Path(__file__).resolve().parents[3] / "spec" / "profile-interfaces.md"
TABLES = spec_tables.check_rows(SPEC.read_text(encoding="utf-8"))   # the sentences of CF-08 and CF-10, read, never counted
PRODUCTION_TABLE, CONFORMANCE_TABLE = TABLES["production"], TABLES["conformance"]
SHARED = PRODUCTION_TABLE & CONFORMANCE_TABLE   # the commands both builds share (CF-03)
ADMISSION = CONFORMANCE_TABLE - PRODUCTION_TABLE   # what the conformance build has and the production build lacks
STATE_KEYS = ("acts", "lineage", "next", "synced_at", "tip_statement")
ANCIENT = "2025-12-29T00:00:00Z"   # more than max_view_age_s (a day) before NOW
FUTURE = "2026-01-01T01:00:00Z"    # more than clock_skew_s (five minutes) after NOW


class Probe:
    """A recording probe: returns the `Probe` of the wire object it was built from."""

    def __init__(self, wire):
        self.wire, self.asked = wire, []

    def read(self, org_id):
        self.asked.append(org_id)
        return pinfile.Probe.from_json(self.wire)


class Clock:
    def __init__(self, value=NOW):
        self.value, self.calls = value, 0

    def __call__(self):
        self.calls += 1
        return self.value


class Store:
    """A recording store port: `read` answers the bytes it was built with or the refusal `code`. A reader never
    takes the lock, so `lock` fails the test."""

    def __init__(self, raw=None, code=None):
        self.raw, self.code, self.asked = raw, code, []

    @classmethod
    def of(cls, scenario, acts=(), synced_at=NOW, next="no"):
        """The store `sync` would have written for `scenario`."""
        return cls(store.encode(acts, scenario.lineage, next, synced_at))

    def read(self, org_id):
        self.asked.append(org_id)
        if self.code:
            raise errors.Refused(self.code)
        return self.raw

    def lock(self, org_id):
        raise AssertionError("a reader took the lock")


MISSING = "store_missing"


def run(table, command, value):
    out = io.BytesIO()
    core.run(table, [command], io.BytesIO(json.dumps(value).encode()), out)
    return json.loads(out.getvalue())


def conformance_table(profs=None):
    return conformance.build_commands(FakeVitni(), load_profiles=lambda: profs) if profs else \
        conformance.build_commands(FakeVitni())


def production_table(probe, clock=None, profs=None, port=None):
    clock = clock or Clock()
    port = port or Store(code=MISSING)
    if profs is None:
        return production.build_commands(FakeVitni(), probe, clock, port)
    return production.build_commands(FakeVitni(), probe, clock, port, load_profiles=lambda: profs)


def production_input(value):
    """The production form of a conformance input of `check-act` or `enrolled`: no `pin`, no `now`, and none of
    the five keys the store supplies."""
    return {k: v for k, v in value.items() if k not in ("pin", "now") + STATE_KEYS}


def recheck_input(value):
    """The `recheck-act` form of a `check-act` input: without the keys that name a moment."""
    return {k: v for k, v in value.items() if k not in ("next", "now", "seen", "synced_at", "tip_statement")}


class Tables(unittest.TestCase):
    def test_the_conformance_build_wires_the_shared_commands_and_the_admission_commands(self):   # CF-03, CF-08
        self.assertEqual(set(conformance.build_commands(FakeVitni())), CONFORMANCE_TABLE)

    def test_the_default_tables_wire_them_too(self):
        self.assertEqual(set(conformance.COMMANDS), CONFORMANCE_TABLE)
        self.assertEqual(set(production.COMMANDS), PRODUCTION_TABLE)

    # The test name is the one the spec's S16 line cites. What it checks is the production table against its
    # sentence in CF-08, and that the conformance build answers `unsupported_command` to `sync`; no count is asserted.
    def test_the_conformance_build_has_no_sync_and_the_production_table_is_the_spec_sentence(self):   # CF-09 S16
        self.assertEqual(set(production.build_commands(FakeVitni(), Probe({}), Clock(), Store())), PRODUCTION_TABLE)
        self.assertIn("sync", PRODUCTION_TABLE - CONFORMANCE_TABLE)
        for table in (conformance.build_commands(FakeVitni()), conformance.COMMANDS):
            self.assertEqual(run(table, "sync", {"acts": [], "docs": [], "org": "x"}),
                             {"error": "unsupported_command"})

    def test_the_production_build_has_neither_admit_pool_nor_compact(self):   # CF-08: the server build owns them
        table = production.build_commands(FakeVitni(), Probe({}), Clock(), Store())
        for command in sorted(ADMISSION):
            self.assertEqual(run(table, command, {}), {"error": "unsupported_command"}, command)

    def test_one_function_builds_both_tables(self):
        # the only difference between the builds is data: the entry point picks it, nothing else
        self.assertIs(conformance.BUILD.__class__, commands.Build)
        self.assertIs(production.BUILD.__class__, commands.Build)
        self.assertTrue(conformance.BUILD.conformance and conformance.BUILD.allow_fixture)
        self.assertFalse(production.BUILD.conformance or production.BUILD.allow_fixture)

    def test_no_command_is_unsupported_in_either_build(self):
        for command in sorted(SHARED - {"subset"}):
            for table in (conformance.build_commands(FakeVitni()),
                          production.build_commands(FakeVitni(), Probe({}), Clock(), Store())):
                self.assertEqual(run(table, command, {}), {"error": "malformed_input"}, command)


class Production(unittest.TestCase):
    def setUp(self):
        self.s = Scenario(production_world())
        self.wire = self.s.value()["pin"]
        self.probe, self.clock, self.port = Probe(self.wire), Clock(), Store.of(self.s)
        self.table = production_table(self.probe, self.clock, PRODUCTION_ONLY, self.port)

    def table_over(self, port):
        return production_table(self.probe, self.clock, PRODUCTION_ONLY, port)

    def test_check_act_reads_the_pin_the_clock_and_the_store_in_process(self):
        act = self.s.verdict()
        value = production_input(self.s.value(act))
        got = run(self.table, "check-act", value)
        self.assertEqual((got["valid"], got["reason"]), (True, "ok"))
        self.assertEqual((self.probe.asked, self.clock.calls, self.port.asked), ([self.s.w.id], 1, [self.s.w.id]))

    def test_it_answers_what_the_conformance_build_answers_for_the_same_data(self):
        act = self.s.verdict()
        full = self.s.value(act)
        self.assertEqual(run(self.table, "check-act", production_input(full)),
                         run(conformance_table(PRODUCTION_ONLY), "check-act", full))

    def test_the_chain_comes_from_the_store_not_from_the_caller(self):   # VR-01, CF-09
        step = self.s.w.device_add("alice2", ("alice", "bob"))
        act = self.s.verdict(head={"id": step.id, "kind": "chain"})
        full = self.s.value(act, acts=step.acts)
        held = Store.of(self.s, step.acts)
        got = run(self.table_over(held), "check-act", production_input(full))
        self.assertEqual((got["valid"], got["reason"]), (True, "ok"))
        self.assertEqual(got, run(conformance_table(PRODUCTION_ONLY), "check-act", full))
        without = run(self.table, "check-act", production_input(full))   # the store holds no such act
        self.assertEqual((without["valid"], without["reason"]), (False, "stale_view"))

    def test_recheck_act_reads_the_pin_in_process_and_never_the_clock(self):   # VR-17, CF-08
        act = self.s.verdict()
        value = production_input(recheck_input(self.s.value(act)))
        got = run(self.table, "recheck-act", value)
        self.assertEqual((got["rechecked"], got["reason"]), (True, "ok"))
        self.assertEqual((self.probe.asked, self.clock.calls, self.port.asked), ([self.s.w.id], 0, [self.s.w.id]))

    def test_recheck_act_answers_what_the_conformance_build_answers_for_the_same_data(self):
        act = self.s.verdict()
        full = recheck_input(self.s.value(act))
        self.assertEqual(run(self.table, "recheck-act", production_input(full)),
                         run(conformance_table(PRODUCTION_ONLY), "recheck-act", full))

    def test_a_decision_is_decided_by_the_production_build_like_any_non_chain_act(self):   # VR-18, CF-08
        act = self.s.decision()
        full = self.s.decision_value(act)
        got = run(self.table, "check-act", production_input(full))
        self.assertEqual((got["valid"], got["reason"]), (True, "ok"))
        self.assertEqual((self.probe.asked, self.clock.calls), ([self.s.w.id], 1))
        self.assertEqual(got, run(conformance_table(PRODUCTION_ONLY), "check-act", full))
        wrong = production_input(self.s.decision_value(act, consumer="archive"))
        self.assertEqual(run(self.table, "check-act", wrong)["reason"], "consumer_mismatch")
        again = production_input(recheck_input(full))
        got = run(self.table, "recheck-act", again)
        self.assertEqual((got["rechecked"], got["reason"]), (True, "ok"))
        self.assertEqual(got, run(conformance_table(PRODUCTION_ONLY), "recheck-act", recheck_input(full)))
        self.assertEqual(self.clock.calls, 2)

    def test_enrolled_is_true_for_a_valid_production_machine(self):
        value = production_input(enrolled_value(self.s))
        self.assertEqual(run(self.table, "enrolled", value), {"enrolled": True, "reason": "ok"})
        self.assertEqual((self.probe.asked, self.clock.calls, self.port.asked), ([self.s.w.id], 1, [self.s.w.id]))

    def test_fold_reads_the_pin_in_process_and_takes_its_bag_explicitly(self):
        value = {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id}
        got = run(self.table, "fold", value)
        self.assertEqual(got["spec"], production_of(PRODUCTION_ONLY))
        self.assertEqual((self.probe.asked, self.port.asked), ([self.s.w.id], []))   # no store read (CF-08)

    def test_genesis_check_reads_no_store(self):
        run(self.table, "genesis-check", {"acts": [], "lineage": self.s.lineage})
        self.assertEqual((self.probe.asked, self.port.asked), ([], []))

    def test_genesis_aids_reads_no_pin_no_store_and_no_clock(self):   # CF-08, SG-12: the aids depend on the input alone
        """The ceremony asks it before any pin exists, so a probe that has no pin, a store that is missing and a clock
        that must not be read are all the machine state it may touch: none."""
        missing = {**self.wire, "bytes_b64": "", "owner_ok": False, "reason": "pin_missing"}
        probe, clock, port = Probe(missing), Clock(), Store(code=MISSING)
        table = production_table(probe, clock, PRODUCTION_ONLY, port)
        two = change(production_of(PRODUCTION_ONLY), self.s.w.id, genesis.doc_hash(self.s.w.doc), self.s.w.id,
                     people=("alice", "bob", "carol"), pol=policy(), name="NEXT")
        lineage = self.s.lineage + [{"doc": two, "sigs": self.s.w.sigs(two, ("alice", "bob", "carol"))}]
        got = run(table, "genesis-aids", {"acts": [], "lineage": lineage})
        self.assertEqual(got["reason"], "ok")
        self.assertEqual(got["aids"]["head"], {"at": "tip", "place": "tip", "tip": self.s.w.id})
        self.assertEqual((probe.asked, port.asked, clock.calls), ([], [], 0))
        self.assertEqual(got, run(conformance_table(PRODUCTION_ONLY), "genesis-aids", {"acts": [], "lineage": lineage}))

    def test_genesis_aids_refuses_a_key_of_the_machine(self):   # a pin, a clock or a store view is not an input of it
        base = {"acts": [], "lineage": self.s.lineage}
        for key, value in (("pin", self.wire), ("now", NOW), ("org", self.s.w.id), ("next", "no"), ("synced_at", NOW)):
            self.assertEqual(run(self.table, "genesis-aids", {**base, key: value}), {"error": "malformed_input"}, key)
        self.assertEqual((self.probe.asked, self.port.asked, self.clock.calls), ([], [], 0))

    def test_a_probe_failure_is_its_reason(self):
        failed = {**self.wire, "bytes_b64": "", "owner_ok": False, "reason": "pin_probe_unavailable"}
        table = production_table(Probe(failed), profs=PRODUCTION_ONLY)
        value = production_input(enrolled_value(self.s))
        self.assertEqual(run(table, "enrolled", value), {"enrolled": False, "reason": "pin_probe_unavailable"})
        self.assertEqual(run(table, "fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id}),
                         {"error": "pin_probe_unavailable"})

    def test_an_input_carrying_pin_or_now_is_malformed_input(self):   # CF-03, CF-07: the production build refuses `pin` and `now`
        fold_base = {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id}
        for command, base in (("check-act", production_input(self.s.value(self.s.verdict()))),
                              ("enrolled", production_input(enrolled_value(self.s))), ("fold", fold_base)):
            for key in ("pin", "now"):
                value = dict(base)
                value[key] = self.wire if key == "pin" else NOW
                self.assertEqual(run(self.table, command, value), {"error": "malformed_input"}, (command, key))
        self.assertEqual(self.probe.asked, [])   # refused before anything was read
        self.assertEqual((self.clock.calls, self.port.asked), (0, []))

    def test_production_refuses_acts_lineage_synced_at_and_tip_statement(self):   # VR-01, VR-17, GP-13
        full = self.s.value(self.s.verdict())
        bases = (("check-act", production_input(full)), ("recheck-act", production_input(recheck_input(full))),
                 ("enrolled", production_input(enrolled_value(self.s))))
        extra = {"acts": [], "lineage": self.s.lineage, "next": "no", "synced_at": NOW, "tip_statement": None}
        for command, base in bases:
            self.assertNotEqual(run(self.table, command, base), {"error": "malformed_input"}, command)   # the control
        self.probe.asked.clear()
        self.port.asked.clear()
        self.clock.calls = 0
        for command, base in bases:
            for key, value in extra.items():
                self.assertEqual(run(self.table, command, {**base, key: value}), {"error": "malformed_input"},
                                 (command, key))
        self.assertEqual((self.probe.asked, self.port.asked, self.clock.calls), ([], [], 0))   # read nothing first

    def test_a_relay_input_is_malformed_input_in_both_builds(self):   # VR-01, VR-08 S2
        full = self.s.value(self.s.verdict())
        shapes = (("check-act", production_input), ("recheck-act", lambda v: production_input(recheck_input(v))))
        for command, shape in shapes:
            self.assertNotEqual(run(self.table, command, shape(full)), {"error": "malformed_input"}, command)   # control
        self.probe.asked.clear()
        for command, shape in shapes:
            self.assertEqual(run(self.table, command, {**shape(full), "relay": "r.example"}),
                             {"error": "malformed_input"})
        for command, value in (("check-act", full), ("recheck-act", recheck_input(full))):
            self.assertEqual(run(conformance_table(PRODUCTION_ONLY), command, {**value, "relay": "r.example"}),
                             {"error": "malformed_input"}, command)
        self.assertEqual(self.probe.asked, [])   # refused before anything was read

    def test_head_refuses_every_state_key_and_reads_nothing_first(self):   # VR-19 S7
        base = {"org": self.s.w.id}
        self.assertEqual(run(self.table, "head", base),
                         {"head": {"id": self.s.w.id, "kind": "chain"}, "reason": "ok"})   # the control
        self.probe.asked.clear()
        self.port.asked.clear()
        self.clock.calls = 0
        extra = {"acts": [], "lineage": self.s.lineage, "next": "no", "now": NOW, "pin": self.wire,
                 "synced_at": NOW, "tip_statement": None}
        for key, item in extra.items():
            self.assertEqual(run(self.table, "head", {**base, key: item}), {"error": "malformed_input"}, key)
        self.assertEqual(run(self.table, "head", {}), {"error": "malformed_input"})
        self.assertEqual((self.probe.asked, self.port.asked, self.clock.calls), ([], [], 0))   # read nothing first

    def test_head_reads_the_store_once_per_call(self):   # VR-19 S7, CF-08, CF-09
        port = Store.of(self.s)
        table = self.table_over(port)
        run(table, "head", {"org": self.s.w.id})
        self.assertEqual(port.asked, [self.s.w.id])
        run(table, "head", {"org": self.s.w.id})
        self.assertEqual(len(port.asked), 2)   # once per call, never cached between calls
        self.assertEqual((self.probe.asked, self.clock.calls), ([self.s.w.id] * 2, 2))   # the pin and the clock too

    def test_head_answers_store_missing_after_the_pin_reasons(self):   # VR-19 S7, VR-02 step 6 (f)
        none = Store(code=MISSING)

        def answer(probe=None, port=none, profs=PRODUCTION_ONLY, org=None):
            table = production_table(probe or Probe(self.wire), Clock(), profs, port)
            got = run(table, "head", {"org": org or self.s.w.id})
            return got.get("reason", got.get("error")), got.get("head", "absent")
        self.assertEqual(answer(), (MISSING, None))
        gone = {**self.wire, "bytes_b64": "", "owner_ok": False, "reason": "pin_missing"}
        self.assertEqual(answer(Probe(gone)), ("pin_missing", None))   # the pin reasons come first
        fixture = Scenario()
        self.assertEqual(answer(Probe(fixture.value()["pin"]), profs=None, org=fixture.w.id),
                         ("fixture_profile", None))   # and the fixture profile before the store reason
        for code in ("store_owner", "store_malformed", "store_unavailable"):
            self.assertEqual(answer(port=Store(code=code)), (code, None))

    def test_head_answers_what_the_conformance_build_answers_for_the_same_data(self):   # CF-08
        steps = self.s.w.device_add("alice2", ("alice", "bob"))
        port = Store.of(self.s, acts=steps.acts)
        got = run(self.table_over(port), "head", {"org": self.s.w.id})
        data = {"acts": steps.acts, "lineage": self.s.lineage, "next": "no", "now": NOW,
                "org": self.s.w.id, "pin": self.wire, "synced_at": NOW, "tip_statement": None}
        self.assertEqual(got, run(conformance_table(PRODUCTION_ONLY), "head", data))
        self.assertEqual(got, {"head": {"id": steps.id, "kind": "chain"}, "reason": "ok"})

    def test_the_conformance_build_still_requires_the_five_keys(self):
        table = conformance_table(PRODUCTION_ONLY)
        for command, base in (("check-act", self.s.value(self.s.verdict())), ("enrolled", enrolled_value(self.s))):
            for key in STATE_KEYS:
                value = {k: v for k, v in base.items() if k != key}
                self.assertEqual(run(table, command, value), {"error": "malformed_input"}, (command, key))

    def test_recheck_act_refuses_pin_and_every_key_that_names_a_moment(self):   # VR-17, CF-08
        base = production_input(recheck_input(self.s.value(self.s.verdict())))
        extra = {"pin": self.wire, "now": NOW, "seen": [], "synced_at": NOW, "tip_statement": None, "next": "no"}
        for key, value in extra.items():
            self.assertEqual(run(self.table, "recheck-act", {**base, key: value}), {"error": "malformed_input"}, key)
        self.assertEqual((self.probe.asked, self.clock.calls), ([], 0))

    def test_a_malformed_input_never_reaches_the_probe(self):
        value = production_input(enrolled_value(self.s))
        del value["org"]
        self.assertEqual(run(self.table, "enrolled", value), {"error": "malformed_input"})
        self.assertEqual((self.probe.asked, self.port.asked), ([], []))

    def test_the_conformance_build_requires_what_production_refuses(self):
        table = conformance_table(PRODUCTION_ONLY)
        for command, base in (("check-act", self.s.value(self.s.verdict())), ("enrolled", enrolled_value(self.s))):
            for key in ("pin", "now"):
                value = {k: v for k, v in base.items() if k != key}
                self.assertEqual(run(table, command, value), {"error": "malformed_input"}, (command, key))

    def test_production_reads_the_store_once_per_call(self):   # CF-08, CF-09
        full = self.s.value(self.s.verdict())
        for command, value in (("check-act", production_input(full)),
                               ("recheck-act", production_input(recheck_input(full))),
                               ("enrolled", production_input(enrolled_value(self.s)))):
            port = Store.of(self.s)
            run(self.table_over(port), command, value)
            self.assertEqual(port.asked, [self.s.w.id], command)
        port = Store.of(self.s)
        table = self.table_over(port)
        run(table, "check-act", production_input(full))
        run(table, "check-act", production_input(full))
        self.assertEqual(len(port.asked), 2)   # once per call, never cached between calls

    def test_a_missing_store_comes_after_the_pin_reasons_and_steps_1_to_5(self):   # VR-02 step 6 (f), CF-09 S1
        s, none = self.s, Store(code=MISSING)
        good = {"check-act": production_input(s.value(s.verdict())),
                "recheck-act": production_input(recheck_input(s.value(s.verdict()))),
                "enrolled": production_input(enrolled_value(s))}
        def answer(command, value, probe=None, port=none, profs=PRODUCTION_ONLY):
            table = production_table(probe or Probe(self.wire), Clock(), profs, port)
            got = run(table, command, value)
            return got.get("reason", got.get("error"))
        for command, base in good.items():
            with self.subTest(command=command):
                self.assertEqual(answer(command, base), MISSING)
                # steps 1 to 5 answer first: a malformed act is reported before a missing store
                if command != "enrolled":
                    self.assertEqual(answer(command, {**base, "jws": "not.a.jws!"}), "jws_shape")
                # the pin reasons come first
                gone = {**self.wire, "bytes_b64": "", "owner_ok": False, "reason": "pin_missing"}
                self.assertEqual(answer(command, base, Probe(gone)), "pin_missing")
        # fixture_profile comes before the store reason
        fixture = Scenario()
        for command, base in (("check-act", production_input(fixture.value(fixture.verdict()))),
                              ("enrolled", production_input(enrolled_value(fixture)))):
            self.assertEqual(answer(command, base, Probe(fixture.value()["pin"]), profs=None), "fixture_profile",
                             command)

    def test_every_store_reason_is_the_answer_of_all_three_commands(self):
        full = self.s.value(self.s.verdict())
        for code in ("store_missing", "store_owner", "store_malformed", "store_unavailable"):
            port = Store(code=code)
            self.assertEqual(run(self.table_over(port), "check-act", production_input(full))["reason"], code)
            self.assertEqual(run(self.table_over(port), "recheck-act",
                                 production_input(recheck_input(full)))["reason"], code)
            self.assertEqual(run(self.table_over(port), "enrolled", production_input(enrolled_value(self.s))),
                             {"enrolled": False, "reason": code})
        bad = Store(b"not a store\n")   # bytes that are not `handsal-store/1` are `store_malformed`
        self.assertEqual(run(self.table_over(bad), "check-act", production_input(full))["reason"], "store_malformed")

    def test_a_store_of_another_org_is_lineage_broken(self):   # SS2: no `org` member, the lineage is the org
        other = Scenario(production_world(name="OTHER"))
        port = Store.of(other)
        full = self.s.value(self.s.verdict())
        self.assertEqual(run(self.table_over(port), "check-act", production_input(full))["reason"], "lineage_broken")

    def test_synced_at_comes_from_the_store_and_its_age_is_judged(self):   # VR-12
        full = self.s.value(self.s.verdict())
        check = production_input(full)
        for synced_at, reason in ((NOW, "ok"), (ANCIENT, "stale_view"), (FUTURE, "view_in_future")):
            port = Store.of(self.s, synced_at=synced_at)
            self.assertEqual(run(self.table_over(port), "check-act", check)["reason"], reason, synced_at)
            enrolled = run(self.table_over(port), "enrolled", production_input(enrolled_value(self.s)))
            self.assertEqual((enrolled["enrolled"], enrolled["reason"]), (reason == "ok", reason), synced_at)
        old = Store.of(self.s, synced_at=ANCIENT)   # `recheck-act` never reads the age (VR-17)
        got = run(self.table_over(old), "recheck-act", production_input(recheck_input(full)))
        self.assertEqual((got["rechecked"], got["reason"]), (True, "ok"))

    def test_next_is_read_from_the_store_and_refused_as_input(self):   # VR-12 S6, VR-17 S17, CF-09
        full = self.s.value(self.s.verdict())
        check, enrolled = production_input(full), production_input(enrolled_value(self.s))
        for next_, reason in (("no", "ok"), ("yes", "epoch_superseded")):
            port = Store.of(self.s, next=next_)
            self.assertEqual(run(self.table_over(port), "check-act", check)["reason"], reason, next_)
            got = run(self.table_over(port), "enrolled", enrolled)
            self.assertEqual((got["enrolled"], got["reason"]), (reason == "ok", reason), next_)
        # the store's `next` is not what the caller says: an input that carries `next` is refused before any read
        self.probe.asked.clear()
        self.clock.calls = 0
        for command, base in (("check-act", check), ("enrolled", enrolled)):
            for value in ("no", "yes", "maybe"):
                port = Store.of(self.s)
                self.assertEqual(run(self.table_over(port), command, {**base, "next": value}),
                                 {"error": "malformed_input"}, (command, value))
                self.assertEqual(port.asked, [], command)
        self.assertEqual((self.probe.asked, self.clock.calls), ([], 0))
        # `recheck-act` names a view and not a moment: it refuses `next` in both builds, and the store's does not move it
        again = production_input(recheck_input(full))
        self.assertEqual(run(self.table_over(Store.of(self.s, next="no")), "recheck-act", {**again, "next": "no"}),
                         {"error": "malformed_input"})
        self.assertEqual(run(conformance_table(PRODUCTION_ONLY), "recheck-act", {**recheck_input(full), "next": "no"}),
                         {"error": "malformed_input"})
        got = run(self.table_over(Store.of(self.s, next="yes")), "recheck-act", again)
        self.assertEqual((got["rechecked"], got["reason"]), (True, "ok"))
        # the store's own failure still comes first
        self.assertEqual(run(self.table_over(Store(code="store_missing")), "check-act", check)["reason"], "store_missing")

    def test_a_foreign_successor_makes_the_commands_epoch_superseded(self):   # VR-12 S8
        """A store whose `next` is `"yes"` because of a foreign successor reads as any superseded pin: the store keeps
        one fact and the commands read it (`sync` decides it, test_sync)."""
        full = self.s.value(self.s.verdict())
        port = Store.of(self.s, next="yes")
        self.assertEqual(run(self.table_over(port), "check-act", production_input(full))["reason"], "epoch_superseded")
        got = run(self.table_over(port), "enrolled", production_input(enrolled_value(self.s)))
        self.assertEqual((got["enrolled"], got["reason"]), (False, "epoch_superseded"))
        got = run(self.table_over(port), "head", {"org": self.s.w.id})
        self.assertEqual((got["head"], got["reason"]), (None, "epoch_superseded"))

    def test_relay_mode_with_the_reserved_null_slot_is_witness_missing(self):   # WT-03, SS7
        s = relay_scenario()
        table = production_table(Probe(s.value()["pin"]), Clock(), PRODUCTION_ONLY, Store.of(s))
        got = run(table, "check-act", production_input(s.value(s.verdict())))
        self.assertEqual((got["valid"], got["reason"]), (False, "witness_missing"))
        self.assertEqual(run(table, "enrolled", production_input(enrolled_value(s))),
                         {"enrolled": False, "reason": "witness_missing"})


class OneReader(unittest.TestCase):
    """CF-08 S4: the store has one reader. `store.load` is reached by `production.fill` alone, so a command added later
    gets its chain from the same read or from none, and a second reader turns this red. The walk resolves the
    imports of the store module under any name (`from . import store as s`, `import handsal_check.store`,
    `from .store import load as l`, ...) and counts every reference to `load` through them, called or only passed on."""

    SRC = Path(__file__).resolve().parents[1] / "src" / "handsal_check"

    @staticmethod
    def load_references(source, module="handsal_check.production"):
        """The names of the functions of `source` (a module of the package) that reference `store.load`, by any
        import form; a reference outside every function is named `<module>`."""
        tree, package = ast.parse(source), module.rsplit(".", 1)[0]
        modules, loads = set(), set()   # dotted names bound to the store module / bare names bound to `load`
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == package + ".store":
                        modules.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                base = package if node.level else (node.module or "")
                if node.level:
                    base = ".".join(package.split(".")[:len(package.split(".")) - node.level + 1])
                    base = ".".join(part for part in (base, node.module) if part)
                for alias in node.names:
                    if base == package and alias.name == "store":
                        modules.add(alias.asname or "store")
                    elif base == package + ".store" and alias.name == "load":
                        loads.add(alias.asname or "load")

        def dotted(node):
            parts = []
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            return ".".join([node.id] + parts[::-1]) if isinstance(node, ast.Name) else None

        found = set()

        def walk(node, where):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                where = node.name
            hit = (isinstance(node, ast.Name) and node.id in loads) or (
                isinstance(node, ast.Attribute) and node.attr == "load" and dotted(node.value) in modules)
            if hit:
                found.add(where)
            for child in ast.iter_child_nodes(node):
                walk(child, where)
        walk(tree, "<module>")
        return found

    def test_the_walk_sees_every_way_to_name_load(self):   # the guard's own test: a plant per import form
        forms = {
            "from . import store\ndef f(p):\n    return store.load(p, 1)\n": {"f"},
            "from . import store as s\ndef f(p):\n    return s.load(p, 1)\n": {"f"},
            "from .store import load\ndef f(p):\n    return load(p, 1)\n": {"f"},
            "from .store import load as l\ndef f(p):\n    return l(p, 1)\n": {"f"},
            "from .store import parse, load as l\nREAD = l\n": {"<module>"},
            "import handsal_check.store\ndef f(p):\n    return handsal_check.store.load(p, 1)\n": {"f"},
            "import handsal_check.store as hs\ndef f(p):\n    return hs.load(p, 1)\n": {"f"},
            "from handsal_check import store as s\ndef f(p):\n    return s.load(p, 1)\n": {"f"},
            "from handsal_check.store import load as l\ndef f(p):\n    return map(l, [p])\n": {"f"},
            "from . import store\ndef f(p):\n    return store.parse(p)\n": set(),   # other names are not readers
            "from . import errors\ndef f(load):\n    return load(1)\n": set(),   # an unrelated `load`
        }
        for source, expected in forms.items():
            self.assertEqual(self.load_references(source), expected, source)

    def test_the_store_has_one_reader(self):   # CF-08 S4
        callers = set()
        for path in sorted(self.SRC.glob("*.py")):
            if path.name != "store.py":
                callers |= {(path.name, name) for name in self.load_references(
                    path.read_text(), "handsal_check." + path.stem)}
        self.assertEqual(callers, {("production.py", "fill")})


class FixtureProfile(unittest.TestCase):
    """CF-07, CF-08: the fixture profile is refused (`fixture_profile`) by every production command, and
    accepted by the conformance build."""

    def setUp(self):
        self.s = Scenario()
        self.wire = self.s.value()["pin"]
        self.table = production_table(Probe(self.wire), port=Store.of(self.s))

    def test_check_act(self):
        got = run(self.table, "check-act", production_input(self.s.value(self.s.verdict())))
        self.assertEqual((got["valid"], got["reason"]), (False, "fixture_profile"))

    def test_enrolled(self):
        got = run(self.table, "enrolled", production_input(enrolled_value(self.s)))
        self.assertEqual(got, {"enrolled": False, "reason": "fixture_profile"})

    def test_fold(self):
        got = run(self.table, "fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id})
        self.assertEqual(got, {"error": "fixture_profile"})

    def test_recheck_act(self):
        got = run(self.table, "recheck-act", production_input(recheck_input(self.s.value(self.s.verdict()))))
        self.assertEqual((got["rechecked"], got["reason"]), (False, "fixture_profile"))

    def test_genesis_check(self):
        got = run(self.table, "genesis-check", {"acts": [], "lineage": self.s.lineage})
        self.assertEqual((got["valid"], got["reason"], got["pin"]), (False, "fixture_profile", None))

    def test_the_conformance_build_accepts_it(self):
        table = conformance_table()
        self.assertTrue(run(table, "genesis-check", {"acts": [], "lineage": self.s.lineage})["valid"])
        self.assertNotIn("error", run(table, "fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id,
                                                      "pin": self.wire}))
        self.assertEqual(run(table, "enrolled", enrolled_value(self.s)), {"enrolled": False, "reason": "fixture_profile"})


class OutputKeys(unittest.TestCase):
    """CF-15: the output keys of an issued command are frozen. `check-act` and `recheck-act` give the keys CF-03 names
    and neither carries `performer_id` or `ts`: a consumer reads them from the payload of the same JWS (VR-17)."""

    def setUp(self):
        self.s = Scenario(production_world())
        wire = self.s.value()["pin"]
        self.table = production_table(Probe(wire), Clock(), PRODUCTION_ONLY, Store.of(self.s))

    def test_check_act_and_recheck_act_have_exactly_the_keys_of_cf03_and_no_payload_field(self):
        value = production_input(self.s.value(self.s.verdict()))
        checked = run(self.table, "check-act", value)
        rechecked = run(self.table, "recheck-act", recheck_input(value))
        self.assertEqual((checked["valid"], rechecked["rechecked"]), (True, True))
        self.assertEqual(set(checked), {"class", "reason", "receipt_id", "valid"})
        self.assertEqual(set(rechecked), {"class", "not_proven", "reason", "receipt_id", "rechecked"})
        for got in (checked, rechecked):
            self.assertFalse({"performer_id", "ts"} & set(got))


class Pure(unittest.TestCase):
    def test_the_commands_that_need_no_state_answer_the_same_in_both_builds(self):
        point = {"x": "A" * 43, "y": "B" * 43}
        tables = (conformance.build_commands(FakeVitni()),
                  production.build_commands(FakeVitni(), Probe({}), Clock(), Store()))
        for command, value in (("kid", point), ("render", {}), ("kid", {})):
            self.assertEqual(run(tables[0], command, value), run(tables[1], command, value), command)


class SyntheticEditions(unittest.TestCase):
    """CF-08 over an injected three-edition set (every edition has its own registry value and its own two hashes):
    the conformance build implements both kinds of every edition, the production and the server build implement the
    production hash of every edition and refuse every fixture hash, and a hash of no edition is `profile_mismatch`
    in all of them. The set lists no fixture kid, so the fixture keys sign a document of any edition."""

    PEOPLE = ("alice", "bob", "carol")

    def setUp(self):
        self.set = without_fixture_kids(synthetic_set(3))
        self.production, self.fixture = self.set.production_hashes(), self.set.fixture_hashes()
        self.unknown = encoding.hashstr(b"an edition no entry lists")

    def lineage(self, profile):
        w = World(profile=profile)
        return {"acts": [], "lineage": [{"doc": w.doc, "sigs": w.sigs(w.doc, self.PEOPLE)}]}

    def snapshot(self, profile):
        w = World(profile=profile)
        return {"acts": [], "docs": [{"doc": w.doc, "sigs": w.sigs(w.doc, self.PEOPLE)}], "org": w.id}

    def genesis_check(self, table, profile):
        return run(table, "genesis-check", self.lineage(profile))["reason"]

    def compact(self, profile):
        table = server.build_commands(FakeVitni(), load_profiles=lambda: self.set)
        return run(table, "compact", self.snapshot(profile))["reason"]

    def test_a_lineage_of_two_supported_editions_is_decided_like_the_conformance_build(self):   # CF-08 S7
        first, second = self.production[:2]
        w = World(profile=first)
        doc = change(second, w.id, genesis.doc_hash(w.doc), w.id, pol=policy())
        s = Scenario(w)
        s.lineage = [s.lineage[0], {"doc": doc, "sigs": w.sigs(doc, self.PEOPLE)}]
        act = s.verdict(head=head_of(genesis.doc_hash(doc)))   # a head in the epoch of the second edition
        full = s.value(act, pin=probe_for(doc, w.id), next="no")
        wanted = run(conformance_table(self.set), "check-act", full)
        got = run(production_table(Probe(full["pin"]), Clock(), self.set, Store.of(s)), "check-act", production_input(full))
        self.assertEqual((wanted["valid"], wanted["reason"]), (True, "ok"))
        self.assertEqual(got, wanted)

    def test_the_conformance_build_resolves_both_kinds_of_every_edition(self):
        table = conformance_table(self.set)
        for profile in self.production + self.fixture:
            self.assertEqual(self.genesis_check(table, profile), "ok", profile)

    def test_the_production_build_refuses_every_fixture_hash_of_every_edition(self):
        table = production_table(Probe({}), profs=self.set)
        for profile in self.production:
            self.assertEqual(self.genesis_check(table, profile), "ok", profile)
        for profile in self.fixture:
            self.assertEqual(self.genesis_check(table, profile), "fixture_profile", profile)

    def test_the_server_build_refuses_every_fixture_hash_of_every_edition(self):
        for profile in self.production:
            self.assertEqual(self.compact(profile), "ok", profile)
        for profile in self.fixture:
            self.assertEqual(self.compact(profile), "fixture_profile", profile)

    def test_a_hash_of_no_edition_is_profile_mismatch_in_every_build(self):
        for table in (conformance_table(self.set), production_table(Probe({}), profs=self.set)):
            self.assertEqual(self.genesis_check(table, self.unknown), "profile_mismatch")
        self.assertEqual(self.compact(self.unknown), "profile_mismatch")


class OneBatch(unittest.TestCase):
    """The production build asks the verifier in one `verify-batch` round per call, and says what it said one question
    at a time. Every command of the table runs over a store that holds a chain (a device added), with a probe, a
    clock and a store port that count what they are asked."""

    def setUp(self):
        self.s = Scenario(production_world())
        self.wire = self.s.value()["pin"]
        self.step = self.s.w.device_add("alice2", ("alice", "bob"))
        self.act = self.s.verdict(head={"id": self.step.id, "kind": "chain"})

    def full(self, act=None):
        return self.s.value(act or self.act, acts=self.step.acts)

    def cases(self, act=None):
        """`{command: (production input, conformance input)}`: the same data, supplied by the host or by the caller."""
        full, org, w = self.full(act), self.s.w.id, self.s.w
        state = {"acts": self.step.acts, "lineage": self.s.lineage, "next": "no", "now": NOW, "org": org,
                 "pin": self.wire, "synced_at": NOW, "tip_statement": None}
        held = enrolled_value(self.s, acts=self.step.acts)
        lineage = {"acts": [], "lineage": self.s.lineage}
        two = change(production_of(PRODUCTION_ONLY), org, genesis.doc_hash(w.doc), org,
                     people=("alice", "bob", "carol"), pol=policy(), name="NEXT")
        aids = {"acts": [], "lineage": self.s.lineage + [{"doc": two, "sigs": w.sigs(two, ("alice", "bob", "carol"))}]}
        return {"check-act": (production_input(full), full),
                "recheck-act": (production_input(recheck_input(full)), recheck_input(full)),
                "enrolled": (production_input(held), held),
                "head": ({"org": org}, state),
                "fold": ({**lineage, "org": org}, {**lineage, "org": org, "pin": self.wire}),
                "genesis-check": (lineage, lineage), "genesis-aids": (aids, aids)}

    def hosts(self):
        probe, clock, port = Probe(self.wire), Clock(), Store.of(self.s, self.step.acts)
        return probe, clock, port

    def production(self, vitni, hosts):
        probe, clock, port = hosts
        return production.build_commands(vitni, probe, clock, port, load_profiles=lambda: PRODUCTION_ONLY)

    @staticmethod
    def oracle(vitni):
        """The conformance table: `per_call`, one question at a time, over the data the caller gives."""
        return conformance.build_commands(vitni, load_profiles=lambda: PRODUCTION_ONLY)

    @staticmethod
    def counts(hosts):
        probe, clock, port = hosts
        return (len(probe.asked), clock.calls, len(port.asked))

    # what one call of each command asks of the host: (probe reads, clock reads, store reads), exactly
    READS = {"check-act": (1, 1, 1), "recheck-act": (1, 0, 1), "enrolled": (1, 1, 1), "head": (1, 1, 1),
             "fold": (1, 0, 0), "genesis-check": (0, 0, 0), "genesis-aids": (0, 0, 0)}

    def test_every_command_asks_one_round_and_never_one_question_alone(self):
        for command, (given, _) in self.cases().items():
            with self.subTest(command=command):
                stub = BatchStub()
                got = run(self.production(stub, self.hosts()), command, given)
                self.assertNotIn("error", got)
                self.assertEqual((stub.rounds, stub.singles), (1, []))
                self.assertEqual(len(stub.batched), len(set(stub.batched)))   # each distinct question once

    def test_the_questions_are_the_ones_the_one_at_a_time_call_asks(self):
        for command, (given, data) in self.cases().items():
            with self.subTest(command=command):
                batch, single = BatchStub(), BatchStub()
                got = run(self.production(batch, self.hosts()), command, given)
                self.assertEqual(got, run(self.oracle(single), command, data))
                self.assertEqual(set(batch.batched), set(single.singles))
                self.assertGreater(len(single.singles), 0)

    def test_a_bad_item_signature_is_two_builds_in_one_round(self):   # the item is asked inside `opened`
        bad = with_signature(self.act, BAD)
        for act, builds_wanted in ((self.act, 1), (bad, 2)):
            given, data = self.cases(act)["check-act"]
            with self.subTest(item="honest" if act is self.act else "bad signature"):
                stub, single = BatchStub(), BatchStub()
                with builds() as count:
                    got = run(self.production(stub, self.hosts()), "check-act", given)
                self.assertEqual((count.n, stub.rounds, stub.singles), (builds_wanted, 1, []))
                self.assertEqual(got, run(self.oracle(single), "check-act", data))
                self.assertEqual(got["reason"] == "ok", act is self.act)

    def test_the_bytes_are_those_of_one_question_at_a_time_at_every_question_and_the_host_is_read_once(self):
        reasons = set()
        for command, (given, data) in self.cases().items():
            honest = self.hosts()
            run(self.production(BatchStub(), honest), command, given)
            self.assertEqual(self.counts(honest), self.READS[command], command)
            asked = BatchStub()
            run(self.oracle(asked), command, data)
            self.assertGreater(len(asked.singles), 0)
            for index, target in enumerate(asked.singles):
                for how in ("verdict", "unavailable"):
                    with self.subTest(command=command, index=index, of=len(asked.singles), how=how):
                        make = ((lambda: dict(inner=Forcing(FakeVitni(), target))) if how == "verdict" else
                                (lambda: dict(fails=lambda got, target=target: got == target)))
                        hosts, batch, single = self.hosts(), BatchStub(**make()), BatchStub(**make())
                        got = run(self.production(batch, hosts), command, given)
                        self.assertEqual(got, run(self.oracle(single), command, data))
                        self.assertEqual(self.counts(hosts), self.READS[command])   # exactly once, whichever answer is not ok
                        reasons.add(json.dumps(got, sort_keys=True))
        self.assertGreater(len(reasons), len(self.cases()))   # the forced answers moved outputs, not one per command


class OneMemoPerCall(unittest.TestCase):
    """The memo of a call is made at the command boundary (`commands.per_call`, `commands.per_batch`): one per call,
    over the verifier the table was given, for every command that asks the verifier and for each build."""

    ALL = ("alice", "bob", "carol")

    def calls(self, table_of, command, value):
        """The memos made by one call of `command` over the table of `table_of(raw verifier)`, and the verifier."""
        made, raw = [], FakeVitni()
        with self.recording(made):
            run(table_of(raw), command, value)
        return made, raw

    @staticmethod
    def recording(made):
        """Notes every memo made, the guess of a batched call (`Speculating`) among them: they all start in
        `Memoized.__init__`. A call whose answers are all `ok` makes one memo; the real pass of a batched call that
        met a verdict other than `ok` makes a second (`commands.per_batch`)."""
        real = verifier.Memoized.__init__

        def init(memo, *args, **kw):
            real(memo, *args, **kw)
            made.append(memo)

        return mock.patch.object(verifier.Memoized, "__init__", init)

    def values(self):
        w = World()
        entry = {"doc": w.doc, "sigs": w.sigs(w.doc, self.ALL)}
        change = w.change_doc(w.id)
        snapshot = {"acts": [], "docs": [entry], "org": w.id}
        lineage = {"acts": [], "lineage": [entry]}
        return w, {"admit": {**snapshot, "item": {"doc": change, "sigs": w.sigs(change, self.ALL)}},
                   "pool": {**snapshot, "agree": point("alice.agree")},
                   "compact": snapshot,
                   "fold": {**lineage, "org": w.id, "pin": probe_for(w.doc, w.id)},
                   "genesis-check": lineage, "genesis-aids": lineage, "check-act": {}, "recheck-act": {},
                   "enrolled": {}, "head": {}}

    def test_each_command_of_the_conformance_table_makes_one_memo_over_the_raw_verifier(self):
        _, values = self.values()
        for command, value in sorted(values.items()):
            made, raw = self.calls(conformance.build_commands, command, value)
            self.assertEqual(len(made), 1, command)
            self.assertIs(made[0].inner, raw, command)

    def test_sync_of_the_production_table_makes_one_memo_over_the_raw_verifier(self):
        scenario = Scenario(production_world())
        org = scenario.w.id
        value = {"acts": [], "docs": scenario.lineage, "org": org}
        with tempfile.TemporaryDirectory() as tmp:
            def table_of(vitni):
                return production.build_commands(vitni, Probe(probe_for(scenario.w.doc, org)), Clock(),
                                                 store_posix.PosixStore(tmp, os.getuid()))

            made, raw = self.calls(table_of, "sync", value)
        self.assertEqual(len(made), 1)
        self.assertIs(made[0].inner, raw)

    def test_a_call_after_another_makes_its_own_memo(self):
        _, values = self.values()
        table_made = []
        raw = FakeVitni()
        with self.recording(table_made):
            table = conformance.build_commands(raw)
            run(table, "pool", values["pool"])
            run(table, "pool", values["pool"])
        self.assertEqual(len(table_made), 2)
        self.assertIsNot(table_made[0], table_made[1])


if __name__ == "__main__":
    unittest.main()
