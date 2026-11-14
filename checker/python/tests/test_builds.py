"""T3.57 and T3.58 two builds of one pure core, and the eight commands of CF-03 in both (CF-08), plus `sync` in the
production build (CF-09).

The conformance build takes `pin`, `now` and the store's content (`acts`, `lineage`, `synced_at`, `tip_statement`) as
data and accepts both profiles. The production build reads the pin through a probe, `now` from a clock and the
chain from the store, all in process and all constructor arguments (the entry point passes the platform probe, the
system clock and the user's store; no flag and no input reaches them), refuses an input that carries any of those
keys, and refuses the fixture profile. The tests give the production table a recording probe, a recording store and
a fixed clock, and prove that it answers what the conformance table answers for the same data.
"""
import io
import json
import unittest

from handsal_check import commands, conformance, core, errors, pinfile, production, store

from .act_builder import FakeVitni
from .checkact_world import NOW, Scenario
from .test_enrolled import PRODUCTION_ONLY, production_world, relay_scenario, value as enrolled_value
from .genesis_fixtures import org as make_org

EIGHT = {"check-act", "recheck-act", "fold", "render", "subset", "kid", "genesis-check", "enrolled"}
NINE = EIGHT | {"sync"}
STATE_KEYS = ("acts", "lineage", "synced_at", "tip_statement")
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
    def of(cls, scenario, acts=(), synced_at=NOW):
        """The store `sync` would have written for `scenario`."""
        return cls(store.encode(acts, scenario.lineage, synced_at))

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
    the four keys the store supplies."""
    return {k: v for k, v in value.items() if k not in ("pin", "now") + STATE_KEYS}


def recheck_input(value):
    """The `recheck-act` form of a `check-act` input: without the keys that name a moment."""
    return {k: v for k, v in value.items() if k not in ("now", "seen", "synced_at", "tip_statement")}


class Tables(unittest.TestCase):
    def test_the_conformance_build_wires_exactly_the_eight_commands(self):
        self.assertEqual(set(conformance.build_commands(FakeVitni())), EIGHT)

    def test_the_default_tables_wire_them_too(self):
        self.assertEqual(set(conformance.COMMANDS), EIGHT)
        self.assertEqual(set(production.COMMANDS), NINE)

    def test_the_conformance_build_has_no_sync_and_the_production_table_has_nine_commands(self):   # CF-09 S16
        self.assertEqual(set(production.build_commands(FakeVitni(), Probe({}), Clock(), Store())), NINE)
        for table in (conformance.build_commands(FakeVitni()), conformance.COMMANDS):
            self.assertEqual(run(table, "sync", {"acts": [], "lineage": [], "org": "x"}),
                             {"error": "unsupported_command"})

    def test_one_function_builds_both_tables(self):
        # the only difference between the builds is data: the entry point picks it, nothing else
        self.assertIs(conformance.BUILD.__class__, commands.Build)
        self.assertIs(production.BUILD.__class__, commands.Build)
        self.assertTrue(conformance.BUILD.conformance and conformance.BUILD.allow_fixture)
        self.assertFalse(production.BUILD.conformance or production.BUILD.allow_fixture)

    def test_no_command_is_unsupported_in_either_build(self):
        for command in sorted(EIGHT - {"subset"}):
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
        self.assertEqual(got["spec"], PRODUCTION_ONLY.production)
        self.assertEqual((self.probe.asked, self.port.asked), ([self.s.w.id], []))   # no store read (CF-08)

    def test_genesis_check_reads_no_store(self):
        run(self.table, "genesis-check", {"acts": [], "lineage": self.s.lineage})
        self.assertEqual((self.probe.asked, self.port.asked), ([], []))

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
        extra = {"acts": [], "lineage": self.s.lineage, "synced_at": NOW, "tip_statement": None}
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

    def test_the_conformance_build_still_requires_the_four_keys(self):
        table = conformance_table(PRODUCTION_ONLY)
        for command, base in (("check-act", self.s.value(self.s.verdict())), ("enrolled", enrolled_value(self.s))):
            for key in STATE_KEYS:
                value = {k: v for k, v in base.items() if k != key}
                self.assertEqual(run(table, command, value), {"error": "malformed_input"}, (command, key))

    def test_recheck_act_refuses_pin_and_every_key_that_names_a_moment(self):   # VR-17, CF-08
        base = production_input(recheck_input(self.s.value(self.s.verdict())))
        extra = {"pin": self.wire, "now": NOW, "seen": [], "synced_at": NOW, "tip_statement": None}
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

    def test_relay_mode_with_the_reserved_null_slot_is_witness_missing(self):   # WT-03, SS7
        s = relay_scenario()
        table = production_table(Probe(s.value()["pin"]), Clock(), PRODUCTION_ONLY, Store.of(s))
        got = run(table, "check-act", production_input(s.value(s.verdict())))
        self.assertEqual((got["valid"], got["reason"]), (False, "witness_missing"))
        self.assertEqual(run(table, "enrolled", production_input(enrolled_value(s))),
                         {"enrolled": False, "reason": "witness_missing"})


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


class Pure(unittest.TestCase):
    def test_the_commands_that_need_no_state_answer_the_same_in_both_builds(self):
        point = {"x": "A" * 43, "y": "B" * 43}
        tables = (conformance.build_commands(FakeVitni()),
                  production.build_commands(FakeVitni(), Probe({}), Clock(), Store()))
        for command, value in (("kid", point), ("render", {}), ("kid", {})):
            self.assertEqual(run(tables[0], command, value), run(tables[1], command, value), command)


if __name__ == "__main__":
    unittest.main()
