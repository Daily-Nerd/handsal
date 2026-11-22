"""`open_store` and `_lineage_order` live in `opening`, moved verbatim from `admit` (the last release's text).

The store is opened the same way by every command that reads one, so the opening belongs to no command. It sat in
`admit`, a module the fold commands imported only for it, which tied the files an answer of the fold depends on to the
file of the command that is allowed to change. Moving it takes `admit` out of that set; the move must not change a
statement, so the functions are compared with the tag's, as syntax trees.
"""
import ast
import unittest

from handsal_check import admit, opening

from . import v042_tree
from .fold_commands import ENTRY_POINTS
from .identity_guards import MOVED, TAG, functions
from .test_fold_identity import PACKAGE, closure, read_sources


class Moved(unittest.TestCase):
    def test_the_functions_are_those_of_the_tag_syntax_tree_for_syntax_tree(self):
        old = functions(v042_tree.sources(TAG)["admit"].decode("utf-8"), MOVED)
        new = functions((PACKAGE / "opening.py").read_text(encoding="utf-8"), MOVED)
        self.assertEqual(new, old)

    def test_the_module_holds_nothing_else_but_imports_and_its_note(self):
        body = ast.parse((PACKAGE / "opening.py").read_text(encoding="utf-8")).body
        rest = [node for node in body if not isinstance(node, (ast.Import, ast.ImportFrom))
                and not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))]
        self.assertEqual(sorted(node.name for node in rest), sorted(MOVED))

    def test_admit_keeps_no_alias_and_no_copy(self):
        for name in MOVED:
            with self.subTest(name=name):
                self.assertFalse(hasattr(admit, name))
        text = (PACKAGE / "admit.py").read_text(encoding="utf-8")
        self.assertEqual([node.name for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)
                          and node.name in MOVED], [])

    def test_the_opening_is_the_one_every_reader_of_a_store_calls(self):
        for name in ("pool", "compact", "agreepoints"):
            with self.subTest(module=name):
                text = (PACKAGE / (name + ".py")).read_text(encoding="utf-8")
                self.assertIn("opening.open_store(", text)
                self.assertNotIn("admit.open_store", text)

    def test_admit_is_outside_the_closure_of_the_fold_commands(self):
        reached = closure(read_sources(PACKAGE), ENTRY_POINTS)
        self.assertIn("opening", reached)
        self.assertNotIn("admit", reached)


if __name__ == "__main__":
    unittest.main()
