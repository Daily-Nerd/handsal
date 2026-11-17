"""CF-10 the server build `handsal-check-server`: exactly `admit`, `pool` and `compact`, no pin, no clock, no store, no
`--vitni`, no fixture profile, vitni only at the fixed Linux path, and no output that proves a person (I1).
"""
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

from handsal_check import commands, core, genesis, server, verifier

from .act_builder import FakeVitni
from .fold_world import World
from .genesis_fixtures import change, policy
from .profile_sets import synthetic_set
from .test_enrolled import PRODUCTION_ONLY, production_world

SRC = Path(__file__).resolve().parents[1] / "src"
ALL = ("alice", "bob", "carol")
OTHERS = ("check-act", "recheck-act", "enrolled", "fold", "sync", "head", "render", "kid", "subset", "genesis-check",
          "genesis-aids", "version", "", "ADMIT")
FORBIDDEN = {"valid", "rechecked", "enrolled"}
THREE = {"admit", "pool", "compact"}


def run(table, command, value):
    out = io.BytesIO()
    core.run(table, [command] if command is not None else [], io.BytesIO(json.dumps(value).encode()), out)
    return json.loads(out.getvalue())


def original(w):
    return {"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}


def inputs(w):
    """One input per command and per outcome: a good one, one the store refuses, a malformed one."""
    step = w.device_add("alice2", ("alice", "bob"))
    snap = {"acts": [], "docs": [original(w)], "org": w.id}
    return [("admit", {**snap, "item": {"act": step.primary.jws, "sigs": step.acts[1:]}}),
            ("admit", {**snap, "docs": [], "item": {"act": step.primary.jws, "sigs": []}}),
            ("admit", {"acts": "x"}),
            ("pool", {**snap, "agree": {"x": "A" * 43, "y": "A" * 43}}),
            ("pool", {**snap, "docs": [], "agree": {"x": "A" * 43, "y": "A" * 43}}),
            ("compact", {**snap, "acts": ["junk"]}),
            ("compact", {**snap, "docs": []}),
            ("compact", {"acts": "x"})]


class Table(unittest.TestCase):
    def test_the_table_is_exactly_admit_pool_and_compact_and_no_output_proves_anything(self):   # CF-10 S1
        table = server.build_commands(FakeVitni())
        self.assertEqual(set(table), THREE)
        self.assertEqual(set(server.COMMANDS), THREE)
        for command in OTHERS:
            for built in (table, server.COMMANDS):
                self.assertEqual(run(built, command, {}), {"error": "unsupported_command"}, command)
        self.assertEqual(run(table, None, {}), {"error": "unsupported_command"})
        w = World()
        for command, value in inputs(w):
            got = run(table, command, value)
            self.assertFalse(FORBIDDEN & set(got), (command, got))
            self.assertLessEqual(set(got), {"reason", "store", "in_pool", "drop", "error"})

    def test_the_build_is_neither_conformance_nor_fixture_tolerant(self):
        self.assertFalse(server.BUILD.conformance or server.BUILD.allow_fixture)
        self.assertIs(server.BUILD.__class__, commands.Build)

    def test_a_fixture_profile_is_refused(self):   # CF-10 S2, GP-18
        w = World()
        table = server.build_commands(FakeVitni())
        snap = {"acts": [], "docs": [original(w)], "org": w.id}
        step = w.device_add("alice2", ("alice", "bob"))
        got = run(table, "admit", {**snap, "item": {"act": step.primary.jws, "sigs": step.acts[1:]}})
        self.assertEqual(got, {"reason": "fixture_profile", "store": None})
        from .genesis_fixtures import point
        self.assertEqual(run(table, "pool", {**snap, "agree": point("alice.agree")}),
                         {"in_pool": False, "reason": "fixture_profile"})
        self.assertEqual(run(table, "compact", snap), {"drop": None, "reason": "fixture_profile"})


class Verifier(unittest.TestCase):
    def test_the_verifier_is_the_linux_path_and_no_probe_or_store_port_is_built(self):   # CF-10 S3
        self.assertEqual(verifier.INSTALLED["linux"], ["/opt/handsal/bin/vitni-verify"])
        self.assertEqual(server.VERIFIER.argv, ["/opt/handsal/bin/vitni-verify"])
        self.assertIs(server.VERIFIER.owner_check, verifier.check_admin_owned)
        # a fresh interpreter: importing and building the server reaches no probe and no store port
        code = ("import sys; sys.path.insert(0, %r); import handsal_check.server as s; "
                "print(sorted(m for m in sys.modules if m.startswith('handsal_check.') and "
                "m.split('.')[1] in ('host','probe_posix','probe_wsl','store_posix','production','conformance','pinfile_probe')))"
                % str(SRC))
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "[]", out.stdout + out.stderr)

    def test_there_is_no_vitni_option_and_no_environment_override(self):
        w = World()
        step = w.device_add("alice2", ("alice", "bob"))
        value = {"acts": [], "docs": [original(w)], "item": {"act": step.primary.jws, "sigs": step.acts[1:]},
                 "org": w.id}
        out = io.BytesIO()
        server.main(["--vitni", "/bin/true", "admit"], io.BytesIO(json.dumps(value).encode()), out)
        self.assertEqual(json.loads(out.getvalue()), {"error": "unsupported_command"})   # an option is no command

    def test_a_missing_verifier_is_verifier_unavailable_never_a_pass(self):   # 20.10
        w = production_world()
        step = w.device_add("alice2", ("alice", "bob"))
        value = {"acts": [], "docs": [original(w)], "item": {"act": step.primary.jws, "sigs": step.acts[1:]},
                 "org": w.id}
        table = server.build_commands(verifier.VitniCli(["/nonexistent/vitni-verify"]),
                                      load_profiles=lambda: PRODUCTION_ONLY)
        self.assertEqual(run(table, "admit", value), {"reason": "verifier_unavailable", "store": None})
        snap = {"acts": [], "docs": [original(w)], "org": w.id}
        self.assertEqual(run(table, "compact", snap), {"drop": None, "reason": "verifier_unavailable"})


class Editions(unittest.TestCase):
    def test_organizations_on_different_editions_are_admitted(self):   # CF-10 S4
        """One organization still under the first edition and one that migrated to the second are admitted by one
        server build that implements both (GP-22 I1)."""
        got = synthetic_set(2)
        first, second = got.production_hashes()
        table = server.build_commands(FakeVitni(), load_profiles=lambda: got)
        old = World(profile=first)
        step = old.device_add("alice2", ("alice", "bob"))
        self.assertEqual(run(table, "admit", {"acts": [], "docs": [original(old)], "org": old.id,
                                              "item": {"act": step.primary.jws, "sigs": step.acts[1:]}})["reason"], "ok")
        moved = World(profile=first)
        doc = change(second, moved.id, genesis.doc_hash(moved.doc), moved.id, pol=policy())
        docs = [original(moved), {"doc": doc, "sigs": moved.sigs(doc, ALL)}]
        root = type("Root", (), {"id": genesis.doc_hash(doc), "performer": None})()
        step = moved.device_add("alice2", ("alice", "bob"), root)
        self.assertEqual(run(table, "admit", {"acts": [], "docs": docs, "org": moved.id,
                                              "item": {"act": step.primary.jws, "sigs": step.acts[1:]}})["reason"], "ok")


if __name__ == "__main__":
    unittest.main()
