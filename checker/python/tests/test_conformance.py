"""The conformance build's wiring: the verifier is a constructor argument, given on the command line
by the test runner as `--vitni` items, and never read from the environment (CF-05, CF-08)."""
import io
import json
import os
import sys
import unittest
from pathlib import Path

from handsal_check import conformance, core, errors

from .fold_world import World

DATA = Path(__file__).resolve().parent / "data"
FAKE = [sys.executable, str(DATA / "fake_vitni_cli.py")]
ALL = ("alice", "bob", "carol")


def run(argv, value):
    out = io.BytesIO()
    code = conformance.main(argv, io.BytesIO(json.dumps(value).encode()), out)
    return code, out.getvalue()


def vitni_args(argv=FAKE):
    return [item for part in argv for item in ("--vitni", part)]


class Options(unittest.TestCase):
    def test_leading_vitni_items_are_the_verifier_argv(self):
        given, rest = conformance._options(["--vitni", "/a", "--vitni", "/b", "fold"])
        self.assertEqual((given, rest), (["/a", "/b"], ["fold"]))
        self.assertEqual(conformance._options(["fold"]), (None, ["fold"]))

    def test_an_option_without_a_value_is_a_crash_not_a_default(self):
        with self.assertRaises(ValueError):
            conformance._options(["--vitni"])

    def test_a_relative_verifier_path_is_refused(self):
        with self.assertRaises(ValueError):
            run(["--vitni", "vitni-verify", "kid"], {})

    def test_the_pure_commands_do_not_need_a_verifier(self):
        code, out = run(vitni_args() + ["subset"], {})
        self.assertEqual(code, 0)


class EndToEnd(unittest.TestCase):
    """The checker through a real subprocess verifier."""

    def test_genesis_check_through_a_subprocess_verifier(self):
        w = World()
        value = {"acts": [], "lineage": [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}]}
        commands = conformance.build_commands(
            conformance.verifier.VitniCli(FAKE, owner_check=None), lambda doc, previous: None)
        out = io.BytesIO()
        core.run(commands, ["genesis-check"], io.BytesIO(json.dumps(value).encode()), out)
        self.assertTrue(json.loads(out.getvalue())["valid"])

    def test_a_missing_verifier_is_verifier_unavailable_not_a_skip(self):
        w = World()
        value = {"acts": [], "lineage": [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}]}
        commands = conformance.build_commands(
            conformance.verifier.VitniCli([sys.executable, "/nonexistent/vitni"], owner_check=None),
            lambda doc, previous: None)
        out = io.BytesIO()
        core.run(commands, ["genesis-check"], io.BytesIO(json.dumps(value).encode()), out)
        self.assertEqual(json.loads(out.getvalue()), {"pin": None, "reason": "verifier_unavailable", "valid": False})

    def test_the_default_wiring_has_the_genesis_render_and_no_stand_in(self):
        w = World()
        value = {"acts": [], "lineage": [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}]}
        code, out = run(vitni_args() + ["genesis-check"], value)
        self.assertEqual((code, json.loads(out)["valid"]), (0, True))

    def test_the_environment_does_not_choose_the_verifier(self):
        os.environ["HANDSAL_VITNI_CLI"] = FAKE[1]
        try:
            self.assertEqual(conformance.COMMANDS["genesis-check"].raw, False)
            from handsal_check import verifier
            self.assertEqual(verifier.VitniCli.installed(platform="linux").__class__.__name__, "Absent")
        finally:
            del os.environ["HANDSAL_VITNI_CLI"]


if __name__ == "__main__":
    unittest.main()
