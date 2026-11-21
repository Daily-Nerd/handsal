"""CF-10 the server build `handsal-check-server`: exactly the commands the spec names for it, no pin, no clock, no
store, no `--vitni`, no fixture profile, vitni only at the fixed Linux path, and no output that proves a person (I1).

The commands are read from the spec text, never from a list kept here: a command wired into the server build without
the spec text that names it fails these tests, and so does `serve` or any other argument list the spec does not name.
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

from .act_builder import FakeVitni
from .fold_world import World
from .genesis_fixtures import change, policy
from .profile_sets import synthetic_set
from .test_enrolled import PRODUCTION_ONLY, production_world

SRC = Path(__file__).resolve().parents[1] / "src"
SPEC = Path(__file__).resolve().parents[3] / "spec" / "profile-interfaces.md"
ALL = ("alice", "bob", "carol")
OTHERS = ("check-act", "recheck-act", "enrolled", "fold", "sync", "head", "render", "kid", "subset", "genesis-check",
          "genesis-aids", "version", "", "ADMIT")
FORBIDDEN = {"valid", "rechecked", "enrolled"}
UNSUPPORTED = {"error": "unsupported_command"}


class SpecTextError(Exception):
    """The spec text does not say what the server table is in the one form these tests read."""


def section(text, rid):
    """The text of requirement `rid` (`### <rid> ...` up to the next `### `), or `SpecTextError`."""
    found = re.search(r"^### %s .*?(?=^### )" % re.escape(rid), text, re.M | re.S)
    if found is None:
        raise SpecTextError("no section %s" % rid)
    return found[0]


def command_rows(text):
    """`{command: input cell}` of the CF-03 command table."""
    rows = dict(re.findall(r"^\| `([a-z-]+)` \| ([^|]*) \|", section(text, "CF-03"), re.M))
    if not rows:
        raise SpecTextError("CF-03 has no command table")
    return rows


def server_table(text):
    """The commands the spec names as the whole table of the server build: the names of the one CF-10 sentence `Its
    table is exactly ...;`. The sentence holds names, requirement ids, commas and `and`, and nothing else; every name
    is a CF-03 command, and the CF-03 rows that name the server build are the same set. Anything else raises, so a
    reading that finds nothing never holds the build to nothing."""
    sentences = re.findall(r"Its table is exactly ([^;.]*)[;.]", section(text, "CF-10"))
    if len(sentences) != 1:
        raise SpecTextError("CF-10 has %d sentences that give the server table, not one" % len(sentences))
    names = frozenset(re.findall(r"`([a-z-]+)`", sentences[0]))
    rest = re.sub(r"`[a-z-]+`|\(CF-\d+\)|,|\band\b", "", sentences[0]).strip()
    if not names or rest:
        raise SpecTextError("the CF-10 table sentence is not a list of commands: %r" % sentences[0])
    rows = command_rows(text)
    if names - set(rows):
        raise SpecTextError("CF-10 names commands CF-03 does not: %s" % sorted(names - set(rows)))
    marked = {name for name, cell in rows.items() if "server build" in cell}
    if marked != names:
        raise SpecTextError("CF-03 marks %s for the server build, CF-10 names %s" % (sorted(marked), sorted(names)))
    return names


NAMED = server_table(SPEC.read_text(encoding="utf-8"))


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


class SpecSurface(unittest.TestCase):
    """The server build exposes exactly what the published spec text names for it (CF-03, CF-08, CF-10)."""

    def test_the_server_entry_answers_every_command_the_spec_does_not_name_as_unsupported(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertEqual(set(server.COMMANDS), NAMED)
        known = set(command_rows(text)) | set(conformance.COMMANDS) | set(production.COMMANDS) | {"serve"}
        self.assertLess(NAMED, known)   # the control: the probe holds names the spec gives the server and names it does not
        for command in sorted(known):
            out = io.BytesIO()
            self.assertEqual(server.main([command], io.BytesIO(b"{}"), out), 0, command)
            got = json.loads(out.getvalue())
            if command in NAMED:
                self.assertEqual(got, {"error": "malformed_input"}, command)   # a command of the table read its input
            else:
                self.assertEqual(got, UNSUPPORTED, command)

    def test_the_spec_names_admit_pool_and_compact_and_a_reading_that_finds_anything_else_fails(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertEqual(NAMED, {"admit", "pool", "compact"})
        sentence = "Its table is exactly `admit` (CF-11), `pool` (CF-12) and `compact` (CF-14);"
        self.assertIn(sentence, text)
        broken = {"no sentence": text.replace(sentence, "Its commands are listed elsewhere;"),
                  "no names": text.replace(sentence, "Its table is exactly the admission commands;"),
                  "a word that is no name": text.replace(sentence, sentence.replace(" and ", " but not ")),
                  "a name CF-03 lacks": text.replace(sentence, sentence.replace("`compact`", "`nope`")),
                  "a CF-03 row it lacks": text.replace(sentence, sentence.replace(", `pool` (CF-12)", "")),
                  "no CF-10": text.replace("### CF-10 ", "### CF-1O ")}
        for name, changed in broken.items():
            with self.subTest(name):
                self.assertNotEqual(changed, text)
                with self.assertRaises(SpecTextError):
                    server_table(changed)


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
