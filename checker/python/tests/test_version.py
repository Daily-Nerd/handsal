"""CF-03 `version`: what a build is, from the data packed in it and nothing else.

`{}` in, `{impl, profiles, spec}` out, in the production and the server build; the conformance build has no such
command and no vector runs it. The expected values are computed here from the packed catalog by the owner of the
edition set (`profiles`), not read back from the command.
"""
import io
import json
import unittest
from pathlib import Path

from handsal_check import conformance, core, coredata, emit, production, profiles, server

from .act_builder import FakeVitni
from .test_builds import Clock, Probe, Store

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"


def ask(table, value):
    """The raw output line of `version` over `table` for the JSON `value`."""
    out = io.BytesIO()
    core.run(table, ["version"], io.BytesIO(json.dumps(value).encode()), out)
    return out.getvalue()


def tables():
    """The two builds that have `version`, built over test doubles that count what they are asked."""
    probe, clock, port = Probe({}), Clock(), Store()
    return {"production": production.build_commands(FakeVitni(), probe, clock, port),
            "server": server.build_commands(FakeVitni())}, (probe, clock, port)


def packed():
    """The production hashes the packed catalog gives, oldest first: its rows, then the current core when the
    newest row is not it. Computed from the data directory, never from `ProfileSet`."""
    root = coredata.root(None)
    rows = profiles.parse_catalog(root.joinpath(*profiles.CATALOG).read_bytes())
    found = [row["production"] for row in rows]
    now = profiles.profile_hash("production", coredata.load_manifest(None))
    return found if found and found[-1] == now else found + [now]


class Answer(unittest.TestCase):
    def test_version_equals_the_packed_catalog(self):   # CF-03 S10
        want = emit.emit_result({"impl": "handsal-check-python", "profiles": packed(), "spec": packed()[-1]}) + b"\n"
        self.assertGreaterEqual(len(packed()), 2)   # the catalog holds more than one edition, so the order is tested
        for name, table in tables()[0].items():
            with self.subTest(build=name):
                self.assertEqual(ask(table, {}), want)
                self.assertEqual(list(json.loads(want)), ["impl", "profiles", "spec"])

    def test_the_answer_reads_no_pin_no_store_and_no_clock(self):
        built, (probe, clock, port) = tables()
        ask(built["production"], {})
        self.assertEqual((probe.asked, clock.calls), ([], 0))
        self.assertEqual(port.asked, [])


class Input(unittest.TestCase):
    def test_a_non_empty_input_is_malformed_input(self):   # CF-03 S10
        for name, table in tables()[0].items():
            for value in ({"a": 1}, {"org": "x"}, {"pin": {}}, [], [{}], "{}", 1, None, True):
                with self.subTest(build=name, value=value):
                    self.assertEqual(ask(table, value), b'{"error":"malformed_input"}\n')

    def test_unparseable_input_is_unparseable_input(self):
        out = io.BytesIO()
        core.run(tables()[0]["server"], ["version"], io.BytesIO(b"{"), out)
        self.assertEqual(out.getvalue(), b'{"error":"unparseable_input"}\n')


class Builds(unittest.TestCase):
    def test_the_conformance_build_has_no_version(self):   # CF-03 S10
        self.assertNotIn("version", conformance.COMMANDS)
        self.assertEqual(ask(conformance.build_commands(FakeVitni()), {}), b'{"error":"unsupported_command"}\n')

    def test_no_vector_runs_version(self):
        commands = set()
        for path in sorted(VECTORS.rglob("*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "command" in doc:
                commands.add(doc["command"])
        self.assertGreater(len(commands), 5)   # the scan reads vectors
        self.assertNotIn("version", commands)


if __name__ == "__main__":
    unittest.main()
