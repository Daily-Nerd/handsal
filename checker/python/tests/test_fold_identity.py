"""The files an answer of the fold depends on are the files of the last release.

An edition that changes no evaluation rule has no reason to touch the code that evaluates. The set of modules those
answers depend on is computed here from the imports of the commands that read a fold (`fold_commands`) (never listed by hand, so a
new import is followed on its own), and each file of it must be byte-identical to the same path at the tag. A file may
differ only through a named exception: an entry of `EXCEPTIONS` is a guard that reads the old and the new text and
raises when the change is more than the one it names. A file that differs and has no entry fails the test.

The tag is read the way the older-edition tests read theirs, from the git history of the checkout, and a tag that is
not fetched is an error, never a skip. The differential test (`test_fold_differential`) answers the question this one
cannot, whether the answers are the same; this one answers the question that test cannot, whether the code is.
"""
import ast
import tempfile
import unittest
from pathlib import Path

from . import v042_tree
from .fold_commands import ENTRY_POINTS, HELD_BY_THE_CLOSURE, NOT_FOLD_COMMANDS

TAG = "v0.4.2"
PACKAGE = Path(__file__).resolve().parents[1] / "src" / "handsal_check"

# module name -> guard(old_text, new_text). The guard raises AssertionError unless the change is the one it names; its
# first docstring line says what that is and why. No file is exempt without one.
EXCEPTIONS = {}


def read_sources(directory):
    """`{module name: bytes}` of the `.py` files of a package directory."""
    return {path.stem: path.read_bytes() for path in sorted(Path(directory).glob("*.py"))}


def imports_of(name, text, modules):
    """The modules of the package that `text` (the source of `name`) imports, from every import statement in it.
    An import it cannot follow is an error: a closure that skipped it would miss a file."""
    found = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] == "handsal_check" for alias in node.names):
            raise ValueError("%s imports the package by absolute name" % name)
        if isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if (node.module or "").split(".")[0] == "handsal_check":
                    raise ValueError("%s imports %s by absolute name" % (name, node.module))
                continue
            if node.level != 1:
                raise ValueError("%s imports from level %d" % (name, node.level))
            names = [node.module] if node.module else [alias.name for alias in node.names]
            for target in names:
                if target not in modules:
                    raise ValueError("%s imports %s, which is no module of the package" % (name, target))
                found.add(target)
    return found


def wired_commands(directory):
    """The command modules the wiring files of the package in `directory` run: `commands.py` and every module that
    imports it, read for the calls `name.run(...)`. A name that is no module of the package cannot be judged and is an
    error; a module whose `run` does not take `inp` first (`core`, `serve`) is no command."""
    sources = {path.stem: ast.parse(path.read_text(encoding="utf-8")) for path in sorted(Path(directory).glob("*.py"))}

    def relative_imports(tree):
        return {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level == 1
                for alias in node.names} | {node.module for node in ast.walk(tree)
                                            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module}

    def takes_inp(name):
        runs = [node for node in sources[name].body if isinstance(node, ast.FunctionDef) and node.name == "run"]
        return bool(runs) and bool(runs[0].args.args) and runs[0].args.args[0].arg == "inp"

    wiring = [name for name, tree in sources.items() if name == "commands" or "commands" in relative_imports(tree)]
    found = set()
    for name in wiring:
        for node in ast.walk(sources[name]):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                    and isinstance(node.func.value, ast.Name)):
                target = node.func.value.id
                if target not in sources:
                    raise ValueError("%s.py runs %s, which is no module of the package" % (name, target))
                if takes_inp(target):
                    found.add(target)
    return found


def closure(sources, entries):
    """The names of `entries` and every module they import, transitively."""
    modules = set(sources)
    seen, todo = set(), list(entries)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(imports_of(name, sources[name], modules))
    return seen


def differences(new, old, entries=ENTRY_POINTS, exceptions=None):
    """What is wrong with `new` against `old` (both `{module: bytes}`): one line per file of the closure of `new`
    that is not at `old`, differs without an exception, or whose exception is stale or whose guard refuses."""
    exceptions = EXCEPTIONS if exceptions is None else exceptions
    wrong = []
    reached = closure(new, entries)
    for name in sorted(reached):
        if name not in old:
            wrong.append("%s.py is not at %s" % (name, TAG))
        elif name in exceptions:
            if new[name] == old[name]:
                wrong.append("%s.py has an exception and does not differ" % name)
                continue
            try:
                exceptions[name](old[name].decode("utf-8"), new[name].decode("utf-8"))
            except AssertionError as err:
                wrong.append("%s.py: its exception refuses the change: %s" % (name, err))
        elif new[name] != old[name]:
            wrong.append("%s.py differs from %s" % (name, TAG))
    for name in sorted(set(exceptions) - reached):
        wrong.append("%s.py has an exception and is not a dependency of the fold" % name)
    return wrong


class Closure(unittest.TestCase):
    def test_the_closure_follows_every_import_of_a_module(self):
        sources = {"a": b"from . import b\nimport os", "b": b"def f():\n    from .c import x\n", "c": b"", "d": b""}
        self.assertEqual(closure(sources, ["a"]), {"a", "b", "c"})

    def test_an_import_it_cannot_follow_is_an_error(self):
        for text in (b"import handsal_check.x", b"from handsal_check import x", b"from .. import x", b"from . import nowhere",
                     b"from .nowhere import x"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                closure({"a": text, "x": b""}, ["a"])

    def test_every_module_a_build_wires_is_an_entry_point_or_named_as_not_one(self):
        """The wiring files are found, not listed (`commands.py` and every module that imports it, so a build that
        wires more commands is read too): a command module one of them runs that is neither an entry point nor
        excused with a reason fails here, so a new fold-reading command cannot stay out of the closure."""
        run = wired_commands(PACKAGE)
        self.assertEqual(sorted(run - set(ENTRY_POINTS) - set(NOT_FOLD_COMMANDS)), [])
        self.assertEqual(sorted(set(ENTRY_POINTS) - run), [], "an entry point no build runs")
        self.assertEqual(sorted(set(NOT_FOLD_COMMANDS) - run), [], "an excuse for a module no build runs")
        self.assertTrue(all(reason.strip() for reason in NOT_FOLD_COMMANDS.values()))

    def test_a_module_excused_because_the_closure_holds_it_is_in_the_closure(self):
        """An excuse that rests on a computed property is that property, asserted: when a change moves the
        dependency out of the closure, the excuse fails here and has to be replaced on purpose."""
        reached = closure(read_sources(PACKAGE), ENTRY_POINTS)
        for name in HELD_BY_THE_CLOSURE:
            with self.subTest(module=name):
                self.assertIn(name, NOT_FOLD_COMMANDS)
                self.assertIn(name, reached)

    def test_a_call_of_a_name_that_is_no_module_cannot_be_judged(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (("commands", "from . import real\nreal.run(1)\nzzmod.run(2)\n"),
                               ("real", "def run(inp, profiles):\n    pass\n")):
                (Path(tmp) / (name + ".py")).write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                wired_commands(tmp)

    def test_the_closure_of_the_package_reaches_the_fold(self):
        reached = closure(read_sources(PACKAGE), ENTRY_POINTS)
        self.assertTrue({"foldcmd", "fold", "quorum", "resolve", "endorse", "verifier", "agreepoints", "compact"} <= reached)
        self.assertNotIn("sync", reached)
        self.assertNotIn("server", reached)


class Identity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = v042_tree.sources(TAG)
        cls.new = read_sources(PACKAGE)

    def test_every_file_the_fold_depends_on_is_the_file_of_the_tag(self):
        self.assertEqual(differences(self.new, self.old), [])

    def test_the_exceptions_are_named_with_a_reason(self):
        for name, guard in EXCEPTIONS.items():
            with self.subTest(module=name):
                self.assertTrue(callable(guard))
                self.assertTrue((guard.__doc__ or "").strip(), "an exception without a reason")

    def test_a_missing_tag_is_an_error_and_never_a_skip(self):
        with self.assertRaises(v042_tree.TagMissing):
            v042_tree.sources("v0.0.0-no-such-tag")


class Controls(unittest.TestCase):
    """The guard is real if a deliberate violation makes it fail."""

    @classmethod
    def setUpClass(cls):
        cls.old = v042_tree.sources(TAG)

    def changed(self, name, text):
        """The tag tree with one module replaced: every control starts from the tag, never from the working tree,
        so a named exception the tree gains later cannot change what a control says."""
        return dict(self.old, **{name: text})

    def test_one_changed_byte_in_quorum_fails(self):
        self.assertEqual(differences(self.changed("quorum", self.old["quorum"] + b"\n"), self.old, exceptions={}),
                         ["quorum.py differs from %s" % TAG])

    def test_a_closure_module_that_imports_a_new_file_pulls_the_new_file_in(self):
        new = dict(self.changed("foldcmd", self.old["foldcmd"] + b"\nfrom . import a_new_file\n"), a_new_file=b"X = 1\n")
        self.assertEqual(differences(new, self.old, exceptions={}), ["a_new_file.py is not at %s" % TAG, "foldcmd.py differs from %s" % TAG])

    def test_a_changed_file_outside_the_closure_is_not_the_concern_of_this_test(self):
        self.assertEqual(differences(self.changed("server", self.old["server"] + b"\n"), self.old, exceptions={}), [])

    def test_a_file_with_an_exception_passes_only_through_its_guard(self):
        def accepts(old, new):
            """A trailing newline, for the test."""
            assert new == old + "\n", "more than a trailing newline"
        new = self.changed("quorum", self.old["quorum"] + b"\n")
        self.assertEqual(differences(new, self.old, exceptions={"quorum": accepts}), [])
        new = self.changed("quorum", self.old["quorum"] + b"\n# and more\n")
        self.assertEqual(differences(new, self.old, exceptions={"quorum": accepts}),
                         ["quorum.py: its exception refuses the change: more than a trailing newline"])

    def test_an_exception_for_a_file_that_does_not_differ_is_stale(self):
        self.assertEqual(differences(self.old, self.old, exceptions={"quorum": lambda old, new: None}),
                         ["quorum.py has an exception and does not differ"])

    def test_an_exception_for_a_file_outside_the_closure_is_stale(self):
        self.assertEqual(differences(self.old, self.old, exceptions={"server": lambda old, new: None}),
                         ["server.py has an exception and is not a dependency of the fold"])


if __name__ == "__main__":
    unittest.main()
