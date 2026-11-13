import json
import os
import subprocess
import sys
import tempfile
import unittest

import run

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STUB = os.path.join(DATA, "stub_impl.py")


def impl(mode):
    return [sys.executable, STUB, mode]


def write_vector(directory, name, **fields):
    path = os.path.join(directory, name.replace("/", "_") + ".json")
    with open(path, "w") as fh:
        json.dump(dict(name=name, **fields), fh)
    return path


class LoadTests(unittest.TestCase):
    def test_vector_without_anchor_is_rejected(self):
        # cf/anchor-required
        with tempfile.TemporaryDirectory() as d:
            path = write_vector(d, "cf/no-anchor", command="fold", input={})
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_vector_needs_exactly_one_input_form(self):
        with tempfile.TemporaryDirectory() as d:
            both = write_vector(d, "cf/both", command="fold", input={}, input_raw="{}", anchor="x")
            none = write_vector(d, "cf/none", command="fold", anchor="x")
            for path in (both, none):
                with self.assertRaises(run.VectorError):
                    run.load_vector(path)

    def test_vector_needs_name_and_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.json")
            with open(path, "w") as fh:
                json.dump({"input": {}, "anchor": "x"}, fh)
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_generator_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "_gen"))
            write_vector(os.path.join(d, "_gen"), "x/y", command="fold", input={})
            write_vector(d, "a/b", command="fold", input={}, anchor="x")
            names = [v["name"] for v in run.load_vectors(d)]
            self.assertEqual(names, ["a/b"])

    def test_missing_anchor_aborts_the_run_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cf/no-anchor", command="fold", input={})
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=_Sink())
            self.assertEqual(code, 2)


class _Sink:
    def __init__(self):
        self.text = ""

    def write(self, s):
        self.text += s


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def run_harness(self, impls, *extra):
        out = _Sink()
        args = ["--vectors", self.dir]
        for i in impls:
            args += ["--impl", " ".join(i)]
        code = run.main(args + list(extra), out=out)
        return code, out.text

    def test_pass(self):
        write_vector(self.dir, "cf/pass", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok")])
        self.assertEqual(code, 0)
        self.assertIn("PASS cf/pass", text)

    def test_anchor_fail(self):
        write_vector(self.dir, "cf/anchor", command="fold", input={"a": 1},
                     anchor='{"bytes":999,"command":"fold"}')
        code, text = self.run_harness([impl("ok")])
        self.assertEqual(code, 1)
        self.assertIn("ANCHOR-FAIL cf/anchor", text)

    def test_diverge(self):
        # cf/harness-diverge-selftest
        write_vector(self.dir, "cf/harness-diverge-selftest", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("diverge")])
        self.assertEqual(code, 1)
        self.assertIn("DIVERGE cf/harness-diverge-selftest", text)

    def test_two_agreeing_impls_pass(self):
        write_vector(self.dir, "cf/two", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("ok")])
        self.assertEqual(code, 0)
        self.assertIn("PASS cf/two", text)

    def test_two_impls_agreeing_on_a_wrong_answer_is_anchor_fail(self):
        write_vector(self.dir, "cf/wrong", command="fold", input={"a": 1},
                     anchor='{"bytes":1,"command":"fold"}')
        code, text = self.run_harness([impl("ok"), impl("ok")])
        self.assertIn("ANCHOR-FAIL cf/wrong", text)
        self.assertEqual(code, 1)

    def test_crash_is_not_a_pass(self):
        write_vector(self.dir, "cf/crash", command="fold", input={"a": 1},
                     anchor='{"bytes":8,"command":"fold"}')
        code, text = self.run_harness([impl("crash")])
        self.assertEqual(code, 1)
        self.assertIn("ANCHOR-FAIL cf/crash", text)

    def test_group_filter(self):
        write_vector(self.dir, "jcs/a", command="fold", input={}, anchor='{"bytes":3,"command":"fold"}')
        write_vector(self.dir, "cli/b", command="fold", input={}, anchor='{"bytes":999,"command":"fold"}')
        code, text = self.run_harness([impl("ok")], "--group", "jcs")
        self.assertEqual(code, 0)
        self.assertIn("PASS jcs/a", text)
        self.assertNotIn("cli/b", text)

    def test_zero_selected_vectors_is_a_failure(self):
        write_vector(self.dir, "jcs/a", command="fold", input={}, anchor="x")
        code, _ = self.run_harness([impl("ok")], "--group", "nothing")
        self.assertEqual(code, 2)


class ImplTests(unittest.TestCase):
    def test_relative_command_is_refused(self):
        # no PATH lookup
        code = run.main(["--vectors", DATA, "--impl", "python3 stub"], out=_Sink())
        self.assertEqual(code, 2)

    def test_impl_is_required(self):
        self.assertEqual(run.main(["--vectors", DATA], out=_Sink()), 2)

    def test_parse_impl_accepts_absolute_argv(self):
        self.assertEqual(run.parse_impl("/bin/echo a b"), ["/bin/echo", "a", "b"])

    def test_environment_does_not_choose_the_command(self):
        os.environ["HANDSAL_IMPL"] = "/nonexistent"
        self.addCleanup(os.environ.pop, "HANDSAL_IMPL")
        self.assertEqual(run.main(["--vectors", DATA], out=_Sink()), 2)


class PaddingTests(unittest.TestCase):
    def test_padded_stdin_is_one_byte_over_max_input(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"acts": [], "note": ""},
                  "pad": ["note"], "anchor": "x"}
        data = run.build_stdin(vector)
        self.assertEqual(len(data), run.MAX_INPUT + 1)
        self.assertEqual(data[-1:], b"\n")
        parsed = json.loads(data)
        self.assertEqual(parsed["acts"], [])
        self.assertEqual(set(parsed["note"]), {"a"})

    def test_padding_reaches_a_nested_string(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"x": {"y": ["", "s"]}},
                  "pad": ["x", "y", 1], "anchor": "x"}
        data = run.build_stdin(vector)
        self.assertEqual(len(data), run.MAX_INPUT + 1)
        self.assertTrue(json.loads(data)["x"]["y"][1].startswith("s"))

    def test_pad_target_must_be_a_string(self):
        vector = {"name": "cli/over", "command": "fold", "input": {"n": 1},
                  "pad": ["n"], "anchor": "x"}
        with self.assertRaises(run.VectorError):
            run.build_stdin(vector)

    def test_pad_needs_input_not_input_raw(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_vector(d, "cli/bad", command="fold", input_raw="{}", pad=["a"], anchor="x")
            with self.assertRaises(run.VectorError):
                run.load_vector(path)

    def test_nothing_is_stored(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cli/over", command="fold", input={"note": ""}, pad=["note"], anchor="x")
            total = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
            self.assertLess(total, 1024)

    def test_padded_vector_reaches_the_stub(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cli/over", command="fold", input={"note": ""}, pad=["note"],
                         anchor='{"bytes":%d,"command":"fold"}' % (run.MAX_INPUT + 1))
            out = _Sink()
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)


class StdinTests(unittest.TestCase):
    def test_input_is_compact_json_plus_lf(self):
        vector = {"name": "a/b", "command": "fold", "input": {"b": 1, "a": "é"}, "anchor": "x"}
        self.assertEqual(run.build_stdin(vector), '{"b":1,"a":"é"}\n'.encode("utf-8"))

    def test_input_raw_is_passed_through_byte_for_byte(self):
        raw = '{"a":1,"a":2}'
        vector = {"name": "a/b", "command": "fold", "input_raw": raw, "anchor": "x"}
        self.assertEqual(run.build_stdin(vector), raw.encode("utf-8"))

    def test_input_raw_reaches_the_impl_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "a/raw", command="subset", input_raw='{"a":1,"a":2}',
                         anchor='{"bytes":13,"command":"subset"}')
            out = _Sink()
            code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)


class CommandsSubsetTests(unittest.TestCase):
    def test_commands_subset_skips_checker_only_commands(self):
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "rnd/a", command="render", input={}, anchor='{"bytes":3,"command":"render"}')
            write_vector(d, "fld/b", command="fold", input={}, anchor='{"bytes":999,"command":"fold"}')
            out = _Sink()
            code = run.main(["--vectors", d, "--commands", "render,emit",
                             "--impl", " ".join(impl("ok"))], out=out)
            self.assertEqual(code, 0, out.text)
            self.assertIn("PASS rnd/a", out.text)
            self.assertNotIn("fld/b", out.text)


class RoleTests(unittest.TestCase):
    """CF-04: the harness owns which vectors a checker and a signer run."""

    def _dir(self, d):
        for name, command in (("rnd/a", "render"), ("sgn/e", "emit"), ("fld/f", "fold"),
                              ("cli/x", "x"), ("jcs/s", "subset")):
            write_vector(d, name, command=command, input={},
                         anchor='{"bytes":3,"command":"%s"}' % command)

    def _run(self, d, *extra):
        out = _Sink()
        code = run.main(["--vectors", d, "--impl", " ".join(impl("ok"))] + list(extra), out=out)
        return code, out.text

    def test_signer_role_runs_render_and_emit_only(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "signer")
            self.assertIn("PASS rnd/a", text)
            self.assertIn("PASS sgn/e", text)
            for other in ("fld/f", "cli/x", "jcs/s"):
                self.assertNotIn(other, text)

    def test_checker_role_runs_every_command_but_emit(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "checker")
            self.assertNotIn("sgn/e", text)
            for name in ("rnd/a", "fld/f", "cli/x", "jcs/s"):
                self.assertIn(name, text)

    def test_commands_still_filters_within_a_role(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, text = self._run(d, "--role", "signer", "--commands", "emit")
            self.assertIn("sgn/e", text)
            self.assertNotIn("rnd/a", text)

    def test_unknown_role_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            self._dir(d)
            code, _ = self._run(d, "--role", "both")
            self.assertEqual(code, 2)


class IsolatedScriptTests(unittest.TestCase):
    """The harness is run as a script under -I, which drops the script dir from sys.path."""

    def test_run_py_works_under_isolated_mode(self):
        # Discover adds the conformance dir to sys.path, which hid a missing path setup.
        script = os.path.join(os.path.dirname(HERE), "run.py")
        with tempfile.TemporaryDirectory() as d:
            write_vector(d, "cf/pass", command="fold", input={"a": 1},
                         anchor='{"bytes":8,"command":"fold"}')
            proc = subprocess.run(
                [sys.executable, "-I", script, "--vectors", d, "--impl", " ".join(impl("ok"))],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=d)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn("PASS cf/pass", proc.stdout.decode())


if __name__ == "__main__":
    unittest.main()
