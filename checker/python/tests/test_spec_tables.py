"""The reader of the table and mode sentences (`spec_tables`), its controls, and the rule that no test counts commands.

The three builds state their tables in one sentence each (CF-08 for production and conformance, CF-10 for the
server). These tests hold every build to its sentence and the sentences to the CF-03 rows, and they hold the reader to
its own contract: a text it cannot read exactly raises, never reads as an empty set.
"""
import ast
import io
import json
import re
import unittest
from pathlib import Path

from handsal_check import conformance, core, production, server

from . import spec_tables
from .spec_tables import SpecTextError

TESTS = Path(__file__).resolve().parent
SPEC = TESTS.parents[2] / "spec" / "profile-interfaces.md"
TEXT = SPEC.read_text(encoding="utf-8")
BUILT = {"production": production, "conformance": conformance, "server": server}
NUMBER_WORDS = ("two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen",
                "fourteen", "fifteen")


def sentence(build, lead):
    return re.search(r"(?i:%s) [^;]*;" % re.escape(lead), spec_tables._owner(TEXT, build))[0]


class Sentences(unittest.TestCase):
    def test_each_build_has_exactly_the_commands_of_its_sentence(self):
        tables = spec_tables.check_rows(TEXT)
        for build, module in BUILT.items():
            with self.subTest(build=build):
                self.assertEqual(set(module.COMMANDS), tables[build])
                self.assertEqual(set(module.build_commands(*_doubles(build))), tables[build])

    def test_the_modes_are_served_and_no_other_argument_list_is(self):
        for build, module in BUILT.items():
            names = spec_tables.modes(TEXT, build)
            for mode in names:
                with self.subTest(build=build, mode=mode):
                    out = io.BytesIO()
                    self.assertEqual(module.main([mode], io.BytesIO(b""), out), 0)
                    self.assertEqual(out.getvalue(), b"")   # an empty stream ends the process, nothing is written
            if "serve" not in names:
                with self.subTest(build=build, mode="serve"):
                    out = io.BytesIO()
                    module.main(["serve"], io.BytesIO(b""), out)
                    self.assertEqual(json.loads(out.getvalue()), {"error": "unsupported_command"})

    def test_a_command_of_the_conformance_table_that_no_other_build_has_is_marked_in_cf03(self):
        tables = spec_tables.check_rows(TEXT)
        rows = spec_tables.command_rows(TEXT)
        for name in tables["server"] - tables["conformance"] | tables["conformance"] - tables["production"]:
            self.assertIsNotNone(spec_tables.marked(rows[name]), name)


def _doubles(build):
    from .act_builder import FakeVitni
    if build == "production":
        from .test_builds import Clock, Probe, Store
        return FakeVitni(), Probe({}), Clock(), Store()
    return (FakeVitni(),)


class Controls(unittest.TestCase):
    """A text the reader cannot read exactly is an error, whichever build is asked."""

    def test_a_table_sentence_replaced_by_prose_raises(self):
        for build in spec_tables.BUILDS:
            old = sentence(build, "Its table is exactly")
            for name, replacement in {"prose": "Its commands are listed elsewhere;",
                                      "no names": "Its table is exactly the shared commands;",
                                      "a stray word": old.replace(" and ", " but not "),
                                      "no sentence at all": ""}.items():
                with self.subTest(build=build, replacement=name):
                    changed = TEXT.replace(old, replacement)
                    self.assertNotEqual(changed, TEXT)
                    with self.assertRaises(SpecTextError):
                        spec_tables.table(changed, build)

    def test_a_second_table_sentence_raises(self):
        for build in spec_tables.BUILDS:
            old = sentence(build, "Its table is exactly")
            with self.subTest(build=build):
                with self.assertRaises(SpecTextError):
                    spec_tables.table(TEXT.replace(old, old + " " + old), build)

    def test_a_name_the_command_table_lacks_raises(self):
        for build in spec_tables.BUILDS:
            old = sentence(build, "Its table is exactly")
            with self.subTest(build=build):
                with self.assertRaises(SpecTextError):
                    spec_tables.table(TEXT.replace(old, old.replace("`kid`", "`nope`").replace("`admit`", "`nope`")),
                                      build)

    def test_a_row_that_names_the_wrong_build_raises(self):
        rows = spec_tables.command_rows(TEXT)
        row = next(name for name, cell in rows.items() if spec_tables.marked(cell) == {"production"})
        changed = re.sub(r"(\| `%s` \| [^|]*?)production build" % re.escape(row), r"\1conformance build", TEXT, 1)
        self.assertNotEqual(changed, TEXT)
        with self.assertRaises(SpecTextError):
            spec_tables.check_rows(changed)

    def test_a_mode_sentence_that_is_prose_or_contradicts_itself_raises(self):
        for build in spec_tables.BUILDS:
            old = sentence(build, "Its modes are exactly") if spec_tables.modes(TEXT, build) else None
            with self.subTest(build=build):
                if old is not None:
                    with self.assertRaises(SpecTextError):
                        spec_tables.modes(TEXT.replace(old, "It serves a stream;"), build)
                    with self.assertRaises(SpecTextError):
                        spec_tables.modes(TEXT.replace(old, old + " It has no modes;"), build)
                else:
                    with self.assertRaises(SpecTextError):
                        spec_tables.modes(re.sub(r"(?i:it has no modes);", "it has some modes;", TEXT), build)

    def test_a_build_or_a_section_that_does_not_exist_raises(self):
        with self.assertRaises(SpecTextError):
            spec_tables.table(TEXT, "nope")
        with self.assertRaises(SpecTextError):
            spec_tables.table(TEXT.replace("### CF-10 ", "### CF-ten "), "server")
        with self.assertRaises(SpecTextError):
            spec_tables.table(TEXT.replace("- **conformance**", "- **conformant**"), "conformance")


class NoCounts(unittest.TestCase):
    """No test asserts how many commands a table has, and no test name or docstring says it in words: a count is false
    the day a table grows, and the sentence of the spec is the one place the list lives."""

    def trees(self):
        for path in sorted(TESTS.glob("*.py")):
            yield path, ast.parse(path.read_text(encoding="utf-8"))

    def test_no_test_compares_the_size_of_a_command_table_with_a_number(self):
        found = []
        for path, tree in self.trees():
            for node in ast.walk(tree):
                for left, right in _comparisons(node):
                    if _is_len_of_commands(left) and isinstance(right, ast.Constant) and isinstance(right.value, int):
                        found.append("%s:%d" % (path.name, node.lineno))
        self.assertEqual(found, [])

    def test_no_test_name_or_message_counts_commands_in_words(self):
        found = []
        counted = re.compile(r"\btables? (?:has|have|holds?) (?:exactly )?(?:%s)\b" % "|".join(NUMBER_WORDS), re.I)
        for path, tree in self.trees():
            if path.name == Path(__file__).name:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and counted.search(node.name.replace("_", " ")):
                    found.append("%s:%d %s" % (path.name, node.lineno, node.name))
        self.assertEqual(found, [])

    def test_the_scan_sees_a_count_when_there_is_one(self):   # the control: the scan is not vacuous
        tree = ast.parse("def test_the_table_has_eleven_commands(self):\n    self.assertEqual(len(production.COMMANDS), 11)\n")
        hits = [node for node in ast.walk(tree) for left, right in _comparisons(node)
                if _is_len_of_commands(left) and isinstance(right, ast.Constant)]
        self.assertEqual(len(hits), 1)
        self.assertRegex("the production table has eleven commands", r"\btables? (?:has|have) (?:eleven)\b")


def _comparisons(node):
    """`(left, right)` pairs of a comparison or of an `assertEqual(a, b)` call."""
    if isinstance(node, ast.Compare) and len(node.comparators) == 1:
        yield node.left, node.comparators[0]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "assertEqual"
            and len(node.args) >= 2):
        yield node.args[0], node.args[1]
        yield node.args[1], node.args[0]


def _is_len_of_commands(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"
            and len(node.args) == 1 and re.search(r"(?i)commands|[_.]table|\btable\b", ast.unparse(node.args[0])))


if __name__ == "__main__":
    unittest.main()
