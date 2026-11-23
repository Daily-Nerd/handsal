"""CF-10 the server build `handsal-check-server`: exactly the commands and the modes the spec names for it, no pin, no
clock, no store, no `--vitni`, no fixture profile, vitni only at the fixed Linux path, and no output that proves a
person (I1).

The commands and the modes are read from the spec text (`spec_tables`), never from a list kept here: a command wired
into the server build without the spec text that names it fails these tests, and so does `serve` or any other argument
list the spec does not name.
"""
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from handsal_check import commands, conformance, core, genesis, production, server, verifier

from . import spec_tables
from .act_builder import FakeVitni
from .fold_world import World
from .genesis_fixtures import change, policy
from .profile_sets import synthetic_set
from .test_enrolled import PRODUCTION_ONLY, production_world

SRC = Path(__file__).resolve().parents[1] / "src"
SPEC = Path(__file__).resolve().parents[3] / "spec" / "profile-interfaces.md"
ALL = ("alice", "bob", "carol")
OTHERS = ("check-act", "recheck-act", "enrolled", "fold", "sync", "head", "render", "kid", "subset", "genesis-check",
          "genesis-aids", "serve", "", "ADMIT")
FORBIDDEN = {"valid", "rechecked", "enrolled"}
UNSUPPORTED = {"error": "unsupported_command"}


SpecTextError = spec_tables.SpecTextError
NAMED = spec_tables.table(SPEC.read_text(encoding="utf-8"), "server")


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
    def test_every_other_command_is_unsupported_and_no_output_proves_anything(self):   # CF-10 S1
        table = server.build_commands(FakeVitni())
        self.assertEqual(set(table), NAMED)
        self.assertEqual(set(server.COMMANDS), NAMED)
        for command in OTHERS:
            for built in (table, server.COMMANDS):
                self.assertEqual(run(built, command, {}), {"error": "unsupported_command"}, command)
        self.assertEqual(run(table, None, {}), {"error": "unsupported_command"})
        w = World()
        for command, value in inputs(w):
            got = run(table, command, value)
            self.assertFalse(FORBIDDEN & set(got), (command, got))
            self.assertLessEqual(set(got), {"reason", "store", "in_pool", "drop", "active", "pool", "impl", "profiles",
                                            "spec", "error"})

    def test_the_server_table_and_modes_are_the_spec_sentences(self):   # CF-10 S5
        """The table of the build and the argument lists it serves are the two sentences of CF-10, and the CF-03 rows
        that name builds agree with the sentences of all three builds."""
        text = SPEC.read_text(encoding="utf-8")
        spec_tables.check_rows(text)
        self.assertEqual(set(server.COMMANDS), spec_tables.table(text, "server"))
        self.assertEqual(spec_tables.modes(text, "server"), {"serve"})
        for mode in spec_tables.modes(text, "server"):   # a mode is served: an empty stream ends it with exit 0
            out = io.BytesIO()
            self.assertEqual(server.main([mode], io.BytesIO(b""), out), 0, mode)
            self.assertEqual(out.getvalue(), b"", mode)
        out = io.BytesIO()   # and an argument list that is no mode is a command like any other
        self.assertEqual(server.main(["serve", "admit"], io.BytesIO(b"{}"), out), 0)
        self.assertEqual(json.loads(out.getvalue()), UNSUPPORTED)

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


class SpecSurface(unittest.TestCase):
    """The server build exposes exactly what the published spec text names for it (CF-03, CF-08, CF-10)."""

    def test_the_server_entry_answers_every_command_the_spec_does_not_name_as_unsupported(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertEqual(set(server.COMMANDS), NAMED)
        known = set(spec_tables.command_rows(text)) | set(conformance.COMMANDS) | set(production.COMMANDS) | {"serve"}
        self.assertLess(NAMED, known)   # the control: the probe holds names the spec gives the server and names it does not
        modes = spec_tables.modes(text, "server")
        for command in sorted(known - modes):
            out = io.BytesIO()
            self.assertEqual(server.main([command], io.BytesIO(b"[]"), out), 0, command)
            got = json.loads(out.getvalue())
            if command in NAMED:
                self.assertEqual(got, {"error": "malformed_input"}, command)   # a command of the table read its input
            else:
                self.assertEqual(got, UNSUPPORTED, command)

    def test_a_reading_of_the_spec_that_finds_anything_else_fails(self):   # the controls of the sentence reader
        text = SPEC.read_text(encoding="utf-8")
        sentence = re.search(r"Its table is exactly [^;]*;", section_of(text, "CF-10"))[0]
        modes = re.search(r"(?i:its modes are exactly) `serve`;", spec_tables.section(text, "CF-10"))[0]
        names = sorted(NAMED)
        broken = {"prose instead of the table": "Its commands are listed elsewhere;",
                  "no names": "Its table is exactly the admission commands;",
                  "a word that is no name": sentence.replace(" and ", " but not "),
                  "a name CF-03 lacks": sentence.replace("`" + names[0] + "`", "`nope`"),
                  "a CF-03 row the sentence lacks": re.sub(r"`%s`( \([A-Z]{2}-\d+\))?,? ?" % re.escape(names[0]), "",
                                                            sentence, 1)}
        for name, replacement in broken.items():
            changed = text.replace(sentence, replacement)
            with self.subTest(name):
                self.assertNotEqual(changed, text)
                with self.assertRaises(SpecTextError):
                    spec_tables.check_rows(changed)
        with self.subTest("a mode sentence that is prose"):
            with self.assertRaises(SpecTextError):
                spec_tables.modes(text.replace(modes, "It serves a stream;"), "server")
        with self.subTest("no CF-10"):
            with self.assertRaises(SpecTextError):
                spec_tables.table(text.replace("### CF-10 ", "### CF-ten "), "server")


def section_of(text, rid):
    return spec_tables.section(text, rid)


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


STUB = str(Path(__file__).resolve().parent / "data" / "stub_vitni.py")


class Batching(unittest.TestCase):
    """The server asks vitni for all the questions of a call in one `verify-batch` process."""

    def admit_value(self):
        w = production_world()
        step = w.device_add("alice2", ("alice", "bob"))
        return {"acts": [], "docs": [original(w)], "item": {"act": step.primary.jws, "sigs": step.acts[1:]}, "org": w.id}

    def test_the_server_verifier_is_the_batch_one_at_the_linux_path(self):
        self.assertIs(type(server.VERIFIER), verifier.VitniBatch)
        self.assertEqual(server.VERIFIER.argv, ["/opt/handsal/bin/vitni-verify"])
        self.assertIs(server.VERIFIER.owner_check, verifier.check_admin_owned)

    def test_a_vitni_without_verify_batch_is_verifier_unavailable_and_is_not_asked_one_by_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, log = Path(tmp) / "old_vitni.py", Path(tmp) / "asked"
            old.write_text("import sys\nsys.stdin.read()\nopen(sys.argv[1], 'a').write(sys.argv[2] + '\\n')\n"
                           "print('{\"error\":\"unsupported_command\"}')\n")
            table = server.build_commands(verifier.VitniBatch([sys.executable, str(old), str(log)], owner_check=None),
                                          load_profiles=lambda: PRODUCTION_ONLY)
            got = run(table, "admit", self.admit_value())
            asked = log.read_text().split()
        self.assertEqual(got, {"reason": "verifier_unavailable", "store": None})
        self.assertEqual(set(asked), {"verify-batch"})   # no silent fallback to `verify`

    def test_the_questions_of_a_call_are_one_batch_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "asked"
            table = server.build_commands(verifier.VitniBatch([sys.executable, STUB, str(log)], owner_check=None),
                                          load_profiles=lambda: PRODUCTION_ONLY)
            run(table, "admit", self.admit_value())
            asked = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([a["command"] for a in asked], ["verify-batch"])
        self.assertGreater(asked[0]["count"], 1)


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
