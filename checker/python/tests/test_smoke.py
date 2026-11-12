import io
import subprocess
import sys
import unittest
from importlib import metadata

SCRIPTS = {
    "handsal-check": "handsal_check.production:main",
    "handsal-check-conformance": "handsal_check.conformance:main",
}


def run_main(main, argv, stdin_bytes):
    out = io.BytesIO()
    code = main(argv, io.BytesIO(stdin_bytes), out)
    return code, out.getvalue()


class EntryPoints(unittest.TestCase):
    def test_both_console_scripts_are_declared_and_load(self):
        eps = {e.name: e for e in metadata.entry_points(group="console_scripts")
               if e.name in SCRIPTS}
        self.assertEqual(set(eps), set(SCRIPTS))
        for name, target in SCRIPTS.items():
            self.assertEqual(eps[name].value, target)
            self.assertTrue(callable(eps[name].load()))


class EmptyDispatch(unittest.TestCase):
    def check(self, target):
        mod, _, fn = target.partition(":")
        main = getattr(__import__(mod, fromlist=[fn]), fn)
        code, out = run_main(main, ["x"], b"{}")
        self.assertEqual(code, 0)
        self.assertEqual(out, b'{"error":"unsupported_command"}\n')

    def test_production_runs_empty_input(self):
        self.check(SCRIPTS["handsal-check"])

    def test_conformance_runs_empty_input(self):
        self.check(SCRIPTS["handsal-check-conformance"])

    def test_no_command_is_unsupported(self):
        from handsal_check.production import main
        code, out = run_main(main, [], b"{}")
        self.assertEqual((code, out), (0, b'{"error":"unsupported_command"}\n'))


class BuildSplit(unittest.TestCase):
    def test_production_never_loads_the_conformance_build(self):
        code = ("import sys, handsal_check.production;"
                "sys.exit(1 if 'handsal_check.conformance' in sys.modules else 0)")
        r = subprocess.run([sys.executable, "-I", "-c", code])
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
