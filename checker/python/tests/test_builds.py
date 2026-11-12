"""T3.57 and T3.58 two builds of one pure core, and the seven commands of CF-03 in both (CF-08).

The conformance build takes `pin` and `now` as data and accepts both profiles. The production build reads
the pin through a probe and `now` from a clock, both in process and both constructor arguments (the entry
point passes the platform probe and the system clock; no flag and no input reaches them), refuses an input
that carries either key, and refuses the fixture profile. The tests give the production table a recording
probe and a fixed clock, and prove that it answers what the conformance table answers for the same data.
"""
import io
import json
import unittest

from handsal_check import commands, conformance, core, pinfile, production

from .act_builder import FakeVitni
from .checkact_world import NOW, Scenario
from .test_enrolled import PRODUCTION_ONLY, production_world, value as enrolled_value
from .genesis_fixtures import org as make_org

SEVEN = {"check-act", "fold", "render", "subset", "kid", "genesis-check", "enrolled"}


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


def run(table, command, value):
    out = io.BytesIO()
    core.run(table, [command], io.BytesIO(json.dumps(value).encode()), out)
    return json.loads(out.getvalue())


def conformance_table(profs=None):
    return conformance.build_commands(FakeVitni(), load_profiles=lambda: profs) if profs else \
        conformance.build_commands(FakeVitni())


def production_table(probe, clock=None, profs=None):
    clock = clock or Clock()
    if profs is None:
        return production.build_commands(FakeVitni(), probe, clock)
    return production.build_commands(FakeVitni(), probe, clock, load_profiles=lambda: profs)


def production_input(value):
    """The production form of a conformance input: without `pin` and `now`."""
    return {k: v for k, v in value.items() if k not in ("pin", "now")}


class Tables(unittest.TestCase):
    def test_both_builds_wire_exactly_the_seven_commands(self):
        self.assertEqual(set(conformance.build_commands(FakeVitni())), SEVEN)
        self.assertEqual(set(production.build_commands(FakeVitni(), Probe({}), Clock())), SEVEN)

    def test_the_default_tables_wire_them_too(self):
        self.assertEqual(set(conformance.COMMANDS), SEVEN)
        self.assertEqual(set(production.COMMANDS), SEVEN)

    def test_one_function_builds_both_tables(self):
        # the only difference between the builds is data: the entry point picks it, nothing else
        self.assertIs(conformance.BUILD.__class__, commands.Build)
        self.assertIs(production.BUILD.__class__, commands.Build)
        self.assertTrue(conformance.BUILD.conformance and conformance.BUILD.allow_fixture)
        self.assertFalse(production.BUILD.conformance or production.BUILD.allow_fixture)

    def test_no_command_is_unsupported_in_either_build(self):
        for command in sorted(SEVEN - {"subset"}):
            for table in (conformance.build_commands(FakeVitni()),
                          production.build_commands(FakeVitni(), Probe({}), Clock())):
                self.assertEqual(run(table, command, {}), {"error": "malformed_input"}, command)


class Production(unittest.TestCase):
    def setUp(self):
        self.s = Scenario(production_world())
        self.wire = self.s.value()["pin"]
        self.probe, self.clock = Probe(self.wire), Clock()
        self.table = production_table(self.probe, self.clock, PRODUCTION_ONLY)

    def test_check_act_reads_the_pin_and_the_clock_in_process(self):
        act = self.s.verdict()
        value = production_input(self.s.value(act))
        got = run(self.table, "check-act", value)
        self.assertEqual((got["valid"], got["reason"]), (True, "ok"))
        self.assertEqual((self.probe.asked, self.clock.calls), ([self.s.w.id], 1))

    def test_it_answers_what_the_conformance_build_answers_for_the_same_data(self):
        act = self.s.verdict()
        full = self.s.value(act)
        self.assertEqual(run(self.table, "check-act", production_input(full)),
                         run(conformance_table(PRODUCTION_ONLY), "check-act", full))

    def test_enrolled_is_true_for_a_valid_production_machine(self):
        value = production_input(enrolled_value(self.s))
        self.assertEqual(run(self.table, "enrolled", value), {"enrolled": True, "reason": "ok"})
        self.assertEqual((self.probe.asked, self.clock.calls), ([self.s.w.id], 1))

    def test_fold_reads_the_pin_in_process(self):
        value = {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id}
        got = run(self.table, "fold", value)
        self.assertEqual(got["spec"], PRODUCTION_ONLY.production)
        self.assertEqual(self.probe.asked, [self.s.w.id])

    def test_a_probe_failure_is_its_reason(self):
        failed = {**self.wire, "bytes_b64": "", "owner_ok": False, "reason": "pin_probe_unavailable"}
        table = production_table(Probe(failed), profs=PRODUCTION_ONLY)
        value = production_input(enrolled_value(self.s))
        self.assertEqual(run(table, "enrolled", value), {"enrolled": False, "reason": "pin_probe_unavailable"})
        self.assertEqual(run(table, "fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id}),
                         {"error": "pin_probe_unavailable"})

    def test_an_input_carrying_pin_or_now_is_malformed_input(self):   # cli/prod-pin-input-refused, prod-now-input-refused
        for command, base in (("check-act", self.s.value(self.s.verdict())), ("enrolled", enrolled_value(self.s)),
                              ("fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id, "pin": self.wire})):
            for key in ("pin", "now"):
                value = production_input(base)
                value[key] = self.wire if key == "pin" else NOW
                self.assertEqual(run(self.table, command, value), {"error": "malformed_input"}, (command, key))
        self.assertEqual(self.probe.asked, [])   # refused before anything was read
        self.assertEqual(self.clock.calls, 0)

    def test_a_malformed_input_never_reaches_the_probe(self):
        value = production_input(enrolled_value(self.s))
        del value["org"]
        self.assertEqual(run(self.table, "enrolled", value), {"error": "malformed_input"})
        self.assertEqual(self.probe.asked, [])

    def test_the_conformance_build_requires_what_production_refuses(self):
        table = conformance_table(PRODUCTION_ONLY)
        for command, base in (("check-act", self.s.value(self.s.verdict())), ("enrolled", enrolled_value(self.s))):
            for key in ("pin", "now"):
                value = {k: v for k, v in base.items() if k != key}
                self.assertEqual(run(table, command, value), {"error": "malformed_input"}, (command, key))


class FixtureProfile(unittest.TestCase):
    """cli/prod-fixture-profile-refused: the fixture profile is refused by every production command, and
    accepted by the conformance build."""

    def setUp(self):
        self.s = Scenario()
        self.wire = self.s.value()["pin"]
        self.table = production_table(Probe(self.wire))

    def test_check_act(self):
        got = run(self.table, "check-act", production_input(self.s.value(self.s.verdict())))
        self.assertEqual((got["valid"], got["reason"]), (False, "fixture_profile"))

    def test_enrolled(self):
        got = run(self.table, "enrolled", production_input(enrolled_value(self.s)))
        self.assertEqual(got, {"enrolled": False, "reason": "fixture_profile"})

    def test_fold(self):
        got = run(self.table, "fold", {"acts": [], "lineage": self.s.lineage, "org": self.s.w.id})
        self.assertEqual(got, {"error": "fixture_profile"})

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
        tables = (conformance.build_commands(FakeVitni()), production.build_commands(FakeVitni(), Probe({}), Clock()))
        for command, value in (("kid", point), ("render", {}), ("kid", {})):
            self.assertEqual(run(tables[0], command, value), run(tables[1], command, value), command)


if __name__ == "__main__":
    unittest.main()
