"""Invariant 6: one pure fold. The checker's rules read no clock, no file, no environment and
start no process: the impure edge (probe, clock, vitni) is filled in after parse, in the few modules
named here, and every other module may import only the pure part of the standard library.
Adding an import to a pure module is the way that boundary rots, so it fails here first."""
import ast
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "handsal_check"

# The modules that touch the host: the entry point and its arguments, the clock, the pin probe,
# the vitni process, and the files compiled into the build.
EDGE = {"conformance.py", "core.py", "coredata.py", "host.py", "probe_posix.py", "verifier.py"}
# What a pure module may import from the standard library: data structures, encodings, a pattern
# matcher and calendar arithmetic. Nothing here reads state outside its arguments.
PURE_STDLIB = {"base64", "binascii", "calendar", "collections", "hashlib", "json", "re"}


def imported(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


class PureCore(unittest.TestCase):
    def test_the_edge_modules_exist(self):
        for name in EDGE:
            self.assertTrue((SRC / name).is_file(), name)

    def test_a_pure_module_imports_only_the_pure_standard_library(self):
        for path in sorted(SRC.glob("*.py")):
            if path.name in EDGE:
                continue
            with self.subTest(module=path.name):
                self.assertEqual(imported(path) - PURE_STDLIB, set())

    def test_the_edge_is_where_the_host_is_touched(self):
        """If a module of the edge list no longer imports anything impure it belongs in the pure set."""
        impure = {"os", "sys", "time", "subprocess", "pathlib", "platform", "importlib", "stat", "errno"}
        for name in EDGE:
            with self.subTest(module=name):
                self.assertTrue(imported(SRC / name) & impure, "%s is pure now: drop it from EDGE" % name)


if __name__ == "__main__":
    unittest.main()
