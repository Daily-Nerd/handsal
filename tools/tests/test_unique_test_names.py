"""Every test module keeps unique class and method names.

unittest finds tests by name. A second class or method with the same name
replaces the first without any error, and the first one silently never runs.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_DIRS = (
    "tools/tests",
    "tools/throwaway/tests",
    "checker/python/tests",
    "conformance/tests",
    "conformance/vectors/_gen/tests",
)


def duplicates(source):
    """Return (line, dotted name, first line) for each repeated class or method name."""
    found = []
    classes = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name in classes:
            found.append((node.lineno, node.name, classes[node.name]))
        classes[node.name] = node.lineno
        methods = {}
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in methods:
                    found.append((item.lineno, node.name + "." + item.name, methods[item.name]))
                methods[item.name] = item.lineno
    return found


class Detector(unittest.TestCase):
    def test_repeated_class_is_found(self):
        src = "class A:\n    pass\nclass A:\n    pass\n"
        self.assertEqual(duplicates(src), [(3, "A", 1)])

    def test_repeated_method_is_found(self):
        src = "class A:\n    def f(self): pass\n    def f(self): pass\n"
        self.assertEqual(duplicates(src), [(3, "A.f", 2)])

    def test_same_method_in_two_classes_is_fine(self):
        src = "class A:\n    def f(self): pass\nclass B:\n    def f(self): pass\n"
        self.assertEqual(duplicates(src), [])


class Repo(unittest.TestCase):
    def test_test_directories_exist(self):
        for rel in TEST_DIRS:
            self.assertTrue((ROOT / rel).is_dir(), rel)

    def test_no_test_module_repeats_a_class_or_method_name(self):
        problems = []
        for rel in TEST_DIRS:
            for path in sorted((ROOT / rel).rglob("*.py")):
                for line, name, first in duplicates(path.read_text(encoding="utf-8")):
                    problems.append(f"{path.relative_to(ROOT)}:{line} {name} (first at line {first})")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
