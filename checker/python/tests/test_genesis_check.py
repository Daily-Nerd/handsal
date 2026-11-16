"""T3.36 `genesis-check` (CF-03, GP-21): validate every link of a lineage and emit the pin line.

Input `{acts, lineage}` and nothing else; the last lineage entry is the candidate document with its
signatures. Output `{pin, reason, valid}`: `pin` is the exact pin line (GP-05, with its LF) when valid,
else null. It validates GP-03 for the original and GP-19 for each change against the path to its H, in
GP-15 order per document, and returns the first failure.
"""
import io
import json
import unittest

from handsal_check import conformance, errors, genesis, genesis_check, pinfile

from .act_builder import FakeVitni, Unavailable, genesis_sign
from .fold_world import World
from .genesis_fixtures import device

ALL = ("alice", "bob", "carol")


def no_render(doc, previous):
    return None


def value_for(w, *docs_and_sigs, acts=()):
    return {"acts": list(acts), "lineage": [{"doc": d, "sigs": s} for d, s in docs_and_sigs]}


def original(w):
    return w.doc, w.sigs(w.doc, ALL)


def run(value, vitni=None, render=no_render, allow_fixture=True):
    from .fold_world import PROFILES, REG
    return genesis_check.run(genesis_check.parse_input(value), PROFILES, allow_fixture, vitni or FakeVitni(), render)


class Input(unittest.TestCase):
    def test_exactly_acts_and_lineage(self):
        w = World()
        good = value_for(w, original(w))
        genesis_check.parse_input(good)
        for bad in ({"acts": []}, {"lineage": []}, dict(good, extra=1), dict(good, acts={}), dict(good, lineage="x"),
                    dict(good, acts=[3]), dict(good, org=w.id), [], None):
            with self.assertRaises(errors.Malformed):
                genesis_check.parse_input(bad)

    def test_entries_are_doc_and_sigs(self):
        w = World()
        for entry in ({"doc": w.doc}, {"doc": w.doc, "sigs": [1]}, {"doc": w.doc, "sigs": [], "x": 1}, 7):
            with self.assertRaises(errors.Malformed):
                genesis_check.parse_input({"acts": [], "lineage": [entry]})


class Valid(unittest.TestCase):
    def test_a_signed_original_gives_the_pin_line(self):
        w = World()
        out = run(value_for(w, original(w)))
        line = pinfile.line(w.id, w.id, w.doc["profile"]).decode("ascii")
        self.assertEqual(out, {"pin": line, "reason": "ok", "valid": True})
        self.assertTrue(out["pin"].endswith("\n"))
        self.assertEqual(json.loads(out["pin"]), {"genesis": w.id, "org": w.id, "spec": w.doc["profile"], "v": "handsal-pin/1"})

    def test_the_pin_names_the_last_document_and_the_original_org(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        doc = w.change_doc(tip.id)
        out = run(value_for(w, original(w), (doc, w.sigs(doc, ALL)), acts=tip.acts))
        self.assertEqual(json.loads(out["pin"])["genesis"], genesis.doc_hash(doc))
        self.assertEqual(json.loads(out["pin"])["org"], w.id)

    def test_a_forged_middle_link_is_the_first_failure_even_when_the_last_is_fine(self):
        w = World()
        tip = w.device_add("alice2", ("alice", "bob"))
        mid = w.change_doc(tip.id, people=("alice", "frank", "grace"), name="MID")      # one counted person only
        last = w.change_doc(w.id, name="LAST", prev=mid)
        out = run(value_for(w, original(w), (mid, w.sigs(mid, ("alice", "frank", "grace"))),
                            (last, w.sigs(last, ALL)), acts=tip.acts))
        self.assertEqual(out, {"pin": None, "reason": "genesis_change_unauthorized", "valid": False})


class Failures(unittest.TestCase):
    def test_every_failure_has_no_pin(self):
        w = World()
        out = run(value_for(w, (w.doc, w.sigs(w.doc, ("alice", "bob")))))
        self.assertEqual(out, {"pin": None, "reason": "genesis_unsigned", "valid": False})

    def test_an_empty_lineage_is_lineage_broken(self):
        self.assertEqual(run({"acts": [], "lineage": []}), {"pin": None, "reason": "lineage_broken", "valid": False})

    def test_the_verifier_being_down_is_a_reason_not_a_pin(self):
        w = World()
        self.assertEqual(run(value_for(w, original(w)), vitni=Unavailable()),
                         {"pin": None, "reason": "verifier_unavailable", "valid": False})

    def test_a_fixture_lineage_is_refused_where_the_build_refuses_it(self):
        w = World()
        self.assertEqual(run(value_for(w, original(w)), allow_fixture=False),
                         {"pin": None, "reason": "fixture_profile", "valid": False})

    def test_the_default_render_size_step_is_the_genesis_render(self):
        from .fold_world import PROFILES, REG
        w = World()
        got = genesis_check.run(genesis_check.parse_input(value_for(w, original(w))), PROFILES, True, FakeVitni())
        self.assertTrue(got["valid"])
        big = World(people=("alice", "bob", "carol", "dave", "grace"),
                    extra=("alice2", "alice3", "alice4", "bob2", "bob3", "carol2", "dave2"))
        got = genesis_check.run(genesis_check.parse_input(value_for(big, (big.doc, []))), PROFILES, True, FakeVitni())
        self.assertEqual(got, {"pin": None, "reason": "genesis_render_too_large", "valid": False})


class Command(unittest.TestCase):
    def test_the_conformance_build_offers_it_with_an_injected_verifier(self):
        w = World()
        commands = conformance.build_commands(FakeVitni(), no_render)
        out = io.BytesIO()
        from handsal_check import core
        core.run(commands, ["genesis-check"], io.BytesIO(json.dumps(value_for(w, original(w))).encode()), out)
        self.assertEqual(json.loads(out.getvalue())["valid"], True)
        self.assertTrue(out.getvalue().endswith(b"\n"))

    def test_bad_input_is_malformed_input(self):
        commands = conformance.build_commands(FakeVitni(), no_render)
        out = io.BytesIO()
        from handsal_check import core
        core.run(commands, ["genesis-check"], io.BytesIO(b'{"acts":[]}'), out)
        self.assertEqual(out.getvalue(), b'{"error":"malformed_input"}\n')


if __name__ == "__main__":
    unittest.main()
