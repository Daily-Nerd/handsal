"""T16.1 characterization: what the checker answers about profiles today, before the profile set exists.

Every test here is green on the first run by design. Each one pins today's behavior so the rows that
restructure it (T16.4 to T16.8) have a net, and none edits a source file. A test that pins a structure
on purpose says which later row removes it, so that row changes the test knowingly and not by accident.
"""
import inspect
import io
import json
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import (cli, commands, coredata, encoding, errors, genesis, genesis_check, ijson, profiles,
                           registry)

from . import test_sync
from .act_builder import FakeVitni
from .checkact_world import NOW, Scenario
from .genesis_fixtures import change, org, policy
from .store_world import AB
from .test_enrolled import production_world

ROOT = Path(__file__).resolve().parents[3]
PINS = json.loads((ROOT / "conformance" / "pins.json").read_text())
PROFILES = profiles.load()
UNKNOWN = encoding.hashstr(b"an edition this build does not implement")

# The canonical bytes of the registry wire part, hashed once. The wire part is what a parser may read
# before any profile is known (I3): `methods`, `act_extra_key_types`, `binding`, `enums`, and the
# constants outside the evaluation part. T16.5 builds `Registry.wire` and must reproduce this digest.
WIRE_DIGEST = "uEiAgAeRs0Do396Yp2uhzY4UYe8T--TzRzTrXazRS9vedyg"
EVALUATION_CONSTANTS = ("clock_skew_s", "max_tip_age_s", "max_validity_s", "max_view_age_s", "persons", "relays")


def code_of(call, *args):
    try:
        call(*args)
    except errors.Refused as err:
        return err.code
    return None


class Hashes(unittest.TestCase):
    def test_today_exactly_one_production_and_one_fixture_hash_and_both_are_the_pinned_ones(self):
        self.assertEqual(profiles.KINDS, ("production", "fixture"))
        self.assertEqual(PROFILES.production, PINS["production_profile"])
        self.assertEqual(PROFILES.fixture, PINS["fixture_profile"])
        self.assertNotEqual(PROFILES.production, PROFILES.fixture)

    def test_no_other_hash_is_an_implemented_profile(self):
        self.assertEqual([h for h in (PROFILES.production, PROFILES.fixture, UNKNOWN) if PROFILES.implemented(h)],
                         [PROFILES.production, PROFILES.fixture])


class Kinds(unittest.TestCase):
    def test_kind_answers_production_fixture_and_none(self):
        self.assertEqual(PROFILES.kind(PROFILES.production), "production")
        self.assertEqual(PROFILES.kind(PROFILES.fixture), "fixture")
        self.assertIsNone(PROFILES.kind(UNKNOWN))
        for not_a_string in (None, 5, b"x", ["a"]):
            self.assertIsNone(PROFILES.kind(not_a_string))


class DocumentCodes(unittest.TestCase):
    """GP-15 step 2 as `genesis.check_document` answers it today (the `first_kind` form T16.4 replaces)."""

    def ctx(self, allow_fixture):
        return genesis.Context(registry.load(), PROFILES, allow_fixture)

    def answer(self, doc, allow_fixture=True, first_kind=None):
        return code_of(genesis.check_document, doc, self.ctx(allow_fixture), first_kind)

    def test_an_unknown_profile_is_profile_mismatch_in_either_build(self):
        doc = org(UNKNOWN)
        self.assertEqual(self.answer(doc, True), "profile_mismatch")
        self.assertEqual(self.answer(doc, False), "profile_mismatch")

    def test_a_fixture_profile_is_fixture_profile_where_the_build_refuses_it_and_accepted_elsewhere(self):
        doc = org(PROFILES.fixture)
        self.assertEqual(self.answer(doc, False), "fixture_profile")
        self.assertEqual(code_of(genesis.check_document, doc, self.ctx(True)), None)

    def test_a_document_of_the_other_kind_than_the_original_is_fixture_profile(self):
        self.assertEqual(self.answer(org(PROFILES.fixture), True, "production"), "fixture_profile")
        self.assertEqual(self.answer(org(PROFILES.production), True, "fixture"), "fixture_profile")

    def test_a_production_document_over_a_fixture_original_is_a_mix_in_the_production_build_too(self):
        self.assertEqual(self.answer(org(PROFILES.production), False, "fixture"), "fixture_profile")
        self.assertEqual(self.answer(org(PROFILES.production), True, "fixture"), "fixture_profile")

    def test_an_original_of_the_same_kind_as_the_lineage_is_not_a_mix(self):
        self.assertEqual(genesis.check_document(org(PROFILES.fixture), self.ctx(True), "fixture"), "fixture")


class WireBytes(unittest.TestCase):
    def test_the_registry_wire_part_has_one_digest(self):
        doc = ijson.loads(coredata.read_checked(coredata.REGISTRY))
        constants = doc["constants"]
        self.assertTrue(set(EVALUATION_CONSTANTS) <= set(constants))
        wire = {"act_extra_key_types": doc["act_extra_key_types"], "binding": doc["binding"],
                "constants": {k: v for k, v in constants.items() if k not in EVALUATION_CONSTANTS},
                "enums": doc["enums"], "methods": doc["methods"]}
        raw = json.dumps(wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(encoding.hashstr(raw), WIRE_DIGEST)


class TwoInjectedValues(unittest.TestCase):
    """The D2 hidden link: the registry and the profiles are two values read apart, joined by nothing.
    Pinned as a structure on purpose; T16.4 collapses them into one `ProfileSet` and rewrites these two."""

    def run_command(self, table, command, value):
        out = io.BytesIO()
        from handsal_check import core
        core.run(table, [command], io.BytesIO(json.dumps(value).encode()), out)
        return json.loads(out.getvalue())

    def lineage_input(self):
        from .fold_world import World
        w = World()
        return {"acts": [], "lineage": [{"doc": w.doc, "sigs": w.sigs(w.doc, ("alice", "bob", "carol"))}]}

    def test_the_command_tables_read_the_registry_and_take_the_profiles_as_a_second_loader(self):
        for name in ("table", "admission"):
            self.assertIn("load_profiles", inspect.signature(getattr(commands, name)).parameters)
        asked = []

        def loader():
            asked.append("profiles")
            return PROFILES

        build = commands.Build(True, True)
        with mock.patch.object(registry, "load", wraps=registry.load) as reg_load:
            table = commands.table(build, FakeVitni(), load_profiles=loader)
            answer = self.run_command(table, "genesis-check", self.lineage_input())
        self.assertEqual(answer["reason"], "ok")
        self.assertEqual((reg_load.call_count, asked), (1, ["profiles"]))

    def test_the_render_command_of_cli_loads_both_by_itself(self):
        with mock.patch.object(registry, "load", wraps=registry.load) as reg_load, \
                mock.patch.object(profiles, "load", wraps=profiles.load) as prof_load:
            cli.render_command({"attachments": {}, "kid": "x", "method": "m", "payload": {}})
        self.assertEqual((reg_load.call_count, prof_load.call_count), (1, 1))


class ForeignSuccessor(test_sync.Case):
    """D1: today a valid successor under a profile this build does not implement is ignored."""

    def successor(self, profile):
        w = self.s.w
        step = w.device_add("alice2", AB)
        doc = change(profile, w.id, genesis.doc_hash(w.doc), step.id, people=("alice", "bob", "carol"),
                     pol=policy(), name="LATER")
        return step, {"doc": doc, "sigs": w.sigs(doc, ("alice", "bob", "carol"))}

    def test_the_control_a_known_profile_successor_with_the_same_authority_sets_next(self):
        step, entry = self.successor(test_sync.FIXTURE.production)
        got = self.sync(step.acts, docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "epoch_superseded", "synced_at": NOW})
        self.assertEqual(self.stored().next, "yes")

    # T16.8 rewrites this test into its inverse for an authorized document (the foreign-successor rule,
    # owner S2) and keeps it as the ignored case for a forged one.
    def test_today_a_successor_under_an_unknown_profile_is_ignored_and_next_stays_no(self):
        step, entry = self.successor(UNKNOWN)
        got = self.sync(step.acts, docs=self.s.lineage + [entry])
        self.assertEqual(got, {"reason": "ok", "synced_at": NOW})
        self.assertEqual(self.stored().next, "no")
        self.assertEqual(self.stored().lineage, test_sync.canon(self.s.lineage))


if __name__ == "__main__":
    unittest.main()
