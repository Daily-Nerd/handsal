"""GP-23, I5: nothing outside the owner of the edition set asks which edition it is running under.

The profile of a document is resolved once (`ProfileSet.check_document`, `ProfileSet.resolve`) to a `Profile`, and
every later rule of that epoch reads that one answer. These checks read the source, as `test_purity` does:

1. only `profiles.py` and the composition roots (`commands`, `conformance`, `production`, `server`, `cli`) import it;
2. outside `profiles.py` no comparison has an attribute named `hash`, `position`, `label` or `version`, and no
   string literal is a hashstr (a profile hash written down is a second owner of an edition);
3. no module outside `profiles.py` names an edition label.

How a rule that differs between editions is added (design 3.5), so the next edition does not add a second owner:
a rule that differs in DATA (a class, a bound, a kid list) needs no code, because it is read from
`epoch.profile.version`; a rule that differs in CODE is one function chosen by the owner of the set and handed to the
epoch through its `Profile`, never a branch on a hash, a position or a label; a rule that crosses two epochs
(authority, the carry) is written once with the epochs it reads named, as GP-19 and GP-20 say.
"""
import ast
import json
import unittest
from pathlib import Path

from handsal_check import encoding, profiles

SRC = Path(__file__).resolve().parents[1] / "src" / "handsal_check"
ROOT = Path(__file__).resolve().parents[3]
OWNER = "profiles.py"
ROOTS = {"commands.py", "conformance.py", "production.py", "server.py", "cli.py"}
EDITION_ATTRIBUTES = {"hash", "position", "label", "version"}


def asks_for_an_edition(node):
    """`.position` and `.version` are always about an edition here; `.hash` and `.label` are when they are read off a
    profile, a version or an edition (a device has a `label` too, and a document a hash)."""
    if node.attr not in EDITION_ATTRIBUTES:
        return False
    if node.attr in ("position", "version"):
        return True
    return any(word in ast.unparse(node.value) for word in ("profile", "version", "edition"))


def labels():
    """Every edition label there is: the real catalog's and the label of a not yet released edition."""
    catalog = ROOT / "profiles" / "catalog.json"
    rows = json.loads(catalog.read_bytes()) if catalog.exists() else []
    return {row["label"] for row in rows} | {profiles.CURRENT}


def violations(source, name):
    """What `source`, the text of the module `name`, does that the guard forbids: a list of short messages."""
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and name != OWNER and name not in ROOTS:
            if node.module == "profiles" or (node.level and any(a.name == "profiles" for a in node.names)):
                found.append("imports profiles")
        if isinstance(node, ast.Compare) and name != OWNER:
            for part in [node.left] + node.comparators:
                if isinstance(part, ast.Attribute) and asks_for_an_edition(part):
                    found.append("compares .%s" % part.attr)
        if isinstance(node, ast.Constant) and type(node.value) is str and name != OWNER:
            if encoding.is_hashstr(node.value):
                found.append("writes a hashstr")
            if node.value in labels():
                found.append("names the edition label %r" % node.value)
    return found


class Guard(unittest.TestCase):
    def test_no_profile_comparison_outside_the_edition_set(self):   # GP-23 S3
        for path in sorted(SRC.glob("*.py")):
            self.assertEqual(violations(path.read_text(), path.name), [], path.name)

    def test_the_guard_sees_what_it_forbids(self):
        """Red first: each planted line is a violation, and the owner may write all of them."""
        planted = {
            "from . import profiles\n": "imports profiles",
            "from .profiles import ProfileSet\n": "imports profiles",
            "ok = epoch.profile.hash == other\n": "compares .hash",
            "ok = a.version.position < b.version.position\n": "compares .position",
            "ok = profile.version.label == 'x'\n": "compares .label",
            "ok = reg.version != 1\n": "compares .version",
            'ok = spec == "%s"\n' % encoding.hashstr(b"an edition"): "writes a hashstr",
            'ok = name == "%s"\n' % profiles.CURRENT: "names the edition label 'current'",
        }
        for source, expected in planted.items():
            self.assertIn(expected, violations(source, "rules_planted.py"), source)
            self.assertEqual(violations(source, OWNER), [], source)
        for root in sorted(ROOTS):
            self.assertNotIn("imports profiles", violations("from . import profiles\n", root))

    def test_only_the_owner_and_the_composition_roots_import_the_edition_set(self):
        importers = {path.name for path in SRC.glob("*.py")
                     if "imports profiles" in violations(path.read_text(), "x.py")}
        self.assertEqual(importers, ROOTS)


if __name__ == "__main__":
    unittest.main()
