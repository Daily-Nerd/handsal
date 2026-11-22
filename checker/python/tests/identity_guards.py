"""The named exceptions of `test_fold_identity`, built so that two of them on one file compose.

A file of the fold's closure that differs from the tag must be named in `EXCEPTIONS` with a tuple of maskers. A masker
is `mask(tree, side)`: it takes the syntax tree of the old text (`side` is "old") or of the new (`side` is "new"), removes
or evens out exactly the one change it names, and says whether it found that change in the new tree. The check applies
every masker of the file to both trees in turn and requires the two to be equal, so a file with two changes passes
only with both maskers, each change adds its own to the tuple and nothing has to be merged by hand, and a masker that
finds nothing in the new tree fails (a guard for a change that is gone is stale). The first docstring line of a masker
says what it admits and why.

A module that is new is not a change to a file of the tag: `NEW_FILES` maps it to `guard(new_text)`, which compares it
with the tag itself and raises AssertionError on anything else.
"""
import ast

from . import v042_tree

TAG = "v0.4.2"


def functions(text, names):
    """`{name: ast.dump}` of the top-level functions `names` of the source `text`; a missing one is an error."""
    found = {node.name: ast.dump(node) for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}
    missing = [name for name in names if name not in found]
    if missing:
        raise AssertionError("no function %s in the text" % ", ".join(missing))
    return {name: found[name] for name in names}


def check_exception(maskers, old, new):
    """Raise AssertionError unless `new` is `old` plus exactly the changes of `maskers` (texts of one module)."""
    old_tree, new_tree = ast.parse(old), ast.parse(new)
    for mask in maskers:
        if not mask(new_tree, "new"):
            raise AssertionError("%s finds nothing to remove" % mask.__name__)
        mask(old_tree, "old")
    if ast.dump(old_tree) != ast.dump(new_tree):
        raise AssertionError("more than %s" % ", ".join(mask.__name__ for mask in maskers))


def docstrings_may_differ(tree, side):
    """Only docstrings differ: prose on a rule or on where a function now lives is not behaviour, and a moved name
    makes some of it untrue. No statement may differ."""
    found = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                node.body = node.body[1:] or [ast.Pass()]
                found = True
    return found


# The one-child test's `else` branch of `fork.walk` as the change names it: the candidates of a fork are the children,
# one chosen child is next, and more than one is the impossible state.
FORK_ELSE = """\
chosen = resolves.chosen(node)
if len(chosen) > 1:
    raise RuntimeError("two current resolves choose different children")
if not chosen:
    return Walk(accepted, Fork(node, sorted(child.id for child in node.children)))
node = epoch.nodes[next(iter(chosen))]
"""


def fork_walk_takes_one_chosen_child(tree, side):
    """FO-24 step 3 (the walk raises on two chosen children, so it keeps no branch for them): in `walk`'s loop the `else`
    branch of the one-child test is exactly `FORK_ELSE` in the new tree, and is left out of both trees; the rest of the
    module must then be equal (docstrings aside, by their own masker). A second changed definition, a changed statement
    of `walk` outside that branch, or any other computation of the candidates (a slice of them, say) is refused."""
    walks = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "walk"]
    assert len(walks) == 1, "no single `walk`"
    loops = [node for node in walks[0].body if isinstance(node, ast.While)]
    assert len(loops) == 1, "`walk` has no single loop"
    branches = [node for node in loops[0].body if isinstance(node, ast.If)]
    assert len(branches) == 1, "the loop of `walk` has no single test"
    if side == "new":
        assert [ast.dump(node) for node in branches[0].orelse] == [ast.dump(node) for node in ast.parse(FORK_ELSE).body], \
            "the candidate computation is not the one named"
    branches[0].orelse = []
    return side == "new"


def reads_open_store_from_opening(tree, side):
    """`open_store` is read from `opening` where it was read from `admit`: the module named at each call and the
    matching name of the relative import (imports in name order, each with the name it binds) differ, nothing else.
    An import that binds a module to another name is not this change."""
    calls = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "open_store" and isinstance(node.value, ast.Name):
            if side == "old" and node.value.id == "admit":
                node.value.id = "opening"
            calls += node.value.id == "opening"
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None:
            names = [("opening" if (side == "old" and alias.name == "admit" and alias.asname is None) else alias.name,
                      alias.asname) for alias in node.names]
            node.names = [ast.alias(name=name, asname=asname) for name, asname in sorted(names, key=lambda pair: (pair[0], pair[1] or ""))]
    return calls > 0 and any(isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None
                             and any(alias.name == "opening" and alias.asname is None for alias in node.names)
                             for node in ast.walk(tree))


def speculating_settles(tree, side):
    """`Speculating` gains the method `settle` (the memo of a call that turns into its real memo, a cache and no rule)
    and nothing else changes. What it must do is held by the forced-answer oracles of `test_commands`."""
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Speculating"]
    assert len(classes) == 1, "no class Speculating"
    settles = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == "settle"]
    if side == "old":
        return False
    assert len(settles) == 1, "Speculating.settle is not there exactly once"
    classes[0].body = [node for node in classes[0].body if node is not settles[0]]
    return True


MOVED = ("open_store", "_lineage_order")


def the_functions_moved_out_of_admit(new):
    """`opening.py` is new and holds `open_store` and `_lineage_order` exactly as `admit.py` has them at the tag
    (syntax tree for syntax tree), plus imports and a note and no other statement."""
    was = functions(v042_tree.sources(TAG)["admit"].decode("utf-8"), MOVED)
    assert functions(new, MOVED) == was, "a moved function is not the function of the tag"
    body = ast.parse(new).body
    rest = [node for node in body if not isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
            and not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))]
    others = [node.name for node in body if isinstance(node, ast.FunctionDef) and node.name not in MOVED]
    assert not rest and not others, "opening.py holds more than the moved functions"
