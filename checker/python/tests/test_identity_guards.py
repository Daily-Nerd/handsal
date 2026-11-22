"""The maskers of the moved `open_store` fail on any change beyond the one they name.

Each control starts from the text at the tag and applies the move by text, then one more change: the guard has to
accept the move alone and refuse the move with anything added. A guard that accepted both would guard nothing.
"""
import ast
import unittest

from . import v042_tree
from .identity_guards import (MOVED, TAG, check_exception, docstrings_may_differ, functions,
                              reads_open_store_from_opening, the_functions_moved_out_of_admit)

OLD = {name: text.decode("utf-8") for name, text in v042_tree.sources(TAG).items()}


def rerouted(name):
    """The module `name` of the tag with `open_store` read from `opening`, the move and nothing else."""
    text = OLD[name]
    assert text.count("admit.open_store(") == 1 and text.count("from . import admit, ") == 1
    return text.replace("admit.open_store(", "opening.open_store(").replace("from . import admit, ", "from . import opening, ")


class Callers(unittest.TestCase):
    def test_the_move_alone_is_accepted_for_every_caller(self):
        for name in ("pool", "compact", "agreepoints"):
            with self.subTest(module=name):
                check_exception((reads_open_store_from_opening,), OLD[name], rerouted(name))

    def test_the_move_with_one_more_change_is_refused(self):
        for name in ("pool", "compact", "agreepoints"):
            plants = {"a statement": rerouted(name) + "\nX = 1\n",
                      "a changed call": rerouted(name).replace("opening.open_store(", "opening.open_store(None and ", 1),
                      "the old module still imported": rerouted(name).replace("from . import opening, ",
                                                                                 "from . import admit, opening, ")}
            for what, text in plants.items():
                with self.subTest(module=name, plant=what), self.assertRaises(AssertionError):
                    check_exception((reads_open_store_from_opening,), OLD[name], text)

    def test_a_swap_of_the_names_an_import_binds_is_refused(self):
        """The move changes which module is imported, never what name a module is bound to: an import that binds
        `retain as snapshot, snapshot as retain` is a change the masker must not hide."""
        for name in ("pool", "compact", "agreepoints"):
            text = rerouted(name)
            names = [part.strip() for part in text.split("from . import ", 1)[1].split("\n", 1)[0].split(",")]
            self.assertTrue(len(names) >= 2, name)
            first, second = names[1], names[2]   # two names the move does not touch
            planted = text.replace("from . import " + ", ".join(names[:3]),
                                   "from . import %s, %s as %s, %s as %s" % (names[0], first, second, second, first), 1)
            self.assertNotEqual(planted, text, name)
            with self.subTest(module=name), self.assertRaises(AssertionError):
                check_exception((reads_open_store_from_opening, docstrings_may_differ), OLD[name], planted)

    def test_a_text_that_never_moved_is_refused(self):
        with self.assertRaises(AssertionError):
            check_exception((reads_open_store_from_opening,), OLD["pool"], OLD["pool"] + "\n# unchanged but for this\nX = 1\n")

    def test_a_changed_note_needs_the_docstring_masker_beside_the_move(self):
        text = rerouted("compact").replace('"""`compact` (CF-14)', '"""`compact`, changed (CF-14)', 1)
        self.assertNotEqual(text, rerouted("compact"))
        check_exception((reads_open_store_from_opening, docstrings_may_differ), OLD["compact"], text)
        with self.assertRaises(AssertionError):
            check_exception((reads_open_store_from_opening,), OLD["compact"], text)

    def test_the_move_masker_finds_nothing_in_a_text_that_never_moved(self):
        with self.assertRaises(AssertionError):
            check_exception((reads_open_store_from_opening, docstrings_may_differ), OLD["pool"], OLD["pool"] + "\n")

    def test_a_docstring_alone_and_never_a_statement(self):
        reworded = OLD["agreepoints"].replace("`agree-points`:", "`agree-points` (reworded):", 1)
        self.assertNotEqual(reworded, OLD["agreepoints"])
        check_exception((docstrings_may_differ,), OLD["agreepoints"], reworded)
        with self.assertRaises(AssertionError):
            check_exception((docstrings_may_differ,), OLD["agreepoints"], OLD["agreepoints"] + "\nX = 1\n")


class Opening(unittest.TestCase):
    def good(self):
        moved = "\n\n".join(_source("admit", name) for name in MOVED)
        return '"""A note."""\nfrom . import epoch, errors, snapshot\n\n\n' + moved + "\n"

    def test_the_two_functions_alone_are_accepted(self):
        the_functions_moved_out_of_admit(self.good())

    def test_a_changed_statement_in_a_moved_function_is_refused(self):
        with self.assertRaises(AssertionError):
            the_functions_moved_out_of_admit(self.good().replace('"lineage_broken"', '"lineage_broke"', 1))

    def test_a_third_function_or_statement_is_refused(self):
        for extra in ("\n\ndef third():\n    return 1\n", "\n\nX = 1\n"):
            with self.subTest(extra=extra), self.assertRaises(AssertionError):
                the_functions_moved_out_of_admit(self.good() + extra)

    def test_a_missing_function_is_refused(self):
        with self.assertRaises(AssertionError):
            the_functions_moved_out_of_admit(self.good().split("def open_store")[0])


def _source(module, name):
    """The source text of the top-level function `name` of the tag's `module`."""
    text = OLD[module]
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return "\n".join(text.splitlines()[node.lineno - 1:node.end_lineno])
    raise AssertionError(name)


class Functions(unittest.TestCase):
    def test_a_name_the_text_lacks_is_an_error(self):
        with self.assertRaises(AssertionError):
            functions("def a():\n    pass\n", ("a", "b"))


if __name__ == "__main__":
    unittest.main()
