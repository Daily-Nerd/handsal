"""GP-23, I5: nothing outside the owner of the edition set asks which edition it is running under.

The profile of a document is resolved once (`ProfileSet.check_document`, `ProfileSet.resolve`) to a `Profile`, and
every later rule of that epoch reads that one answer. These checks read the source, as `test_purity` does:

1. only `profiles.py` and the composition roots (`commands`, `conformance`, `production`, `server`, `cli`) import it;
2. outside `profiles.py` no comparison has an attribute named `hash`, `position`, `label` or `version`, and no
   string literal is a hashstr (a profile hash written down is a second owner of an edition);
3. no module outside `profiles.py` names an edition label.

How a rule that differs between editions is added, so the next edition does not add a second owner:
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


def labels():
    """Every edition label there is: the real catalog's and the label of a not yet released edition."""
    catalog = ROOT / "profiles" / "catalog.json"
    rows = json.loads(catalog.read_bytes()) if catalog.exists() else []
    return {row["label"] for row in rows} | {profiles.CURRENT}


# What only the owner of the edition set may name. A module outside it reads the rules of an edition through
# `profile.version.reg`, `profile.version.is_fixture_kid(...)` and `profile.fixture`, and nothing else: not its place
# in the catalog, its label, its hash, the list of editions, or the fixture kids as a collection.
OWNER_ONLY = {"position", "hash", "label", "fixture_kids", "editions", "production_hashes", "fixture_hashes",
              "_editions", "_by_hash", "__dict__"}
# `label` is also the name a device carries; the two modules that read a device's label are listed, so a new reader
# has to be added here, in review.
ALSO_ALLOWED = {"label": {"epoch.py", "fold_out.py"}}
DATA_OF_A_VERSION = {"reg", "is_fixture_kid"}
BARRED_CALLS = {"getattr", "setattr", "delattr", "vars", "__import__", "import_module"}


def parents(tree):
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def violations(source, name):
    """What `source`, the text of the module `name`, does that the guard forbids: a list of short messages.

    The guard is about what a module may name, not about the shape of an expression: it reads every attribute,
    name, import and call, so a local variable, a sort key or `getattr` is no way round it."""
    tree = ast.parse(source)
    if name == OWNER:
        return []
    up = parents(tree)
    found = []

    def add(message):
        if message not in found:
            found.append(message)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and name not in ROOTS:
            module = (node.module or "").split(".")
            if module[-1] == "profiles" or any(a.name == "profiles" for a in node.names):
                add("imports profiles")
        if isinstance(node, ast.Import) and name not in ROOTS:
            if any(a.name.split(".")[-1] == "profiles" for a in node.names):
                add("imports profiles")
        if isinstance(node, ast.Attribute):
            if node.attr in OWNER_ONLY and name not in ALSO_ALLOWED.get(node.attr, ()):
                add("reads .%s" % node.attr)
            if node.attr == "version" and isinstance(node.ctx, ast.Load):
                parent = up.get(node)
                data = isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in DATA_OF_A_VERSION
                argument = isinstance(parent, ast.Call) and node in parent.args
                if not (data or argument):
                    add("uses .version beyond its data")
        if isinstance(node, ast.Name) and node.id in OWNER_ONLY and node.id != "label":
            add("names %s" % node.id)
        if isinstance(node, ast.arg) and node.arg in OWNER_ONLY and node.arg != "label":
            add("names %s" % node.arg)
        if isinstance(node, ast.Call):
            callee = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if callee in BARRED_CALLS:
                add("calls %s" % callee)
        if isinstance(node, ast.Constant) and type(node.value) is str:
            if encoding.is_hashstr(node.value):
                add("writes a hashstr")
            if node.value in labels():
                add("names the edition label %r" % node.value)
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
            "ok = epoch.profile.hash == other\n": "reads .hash",
            "ok = a.version.position < b.version.position\n": "reads .position",
            "ok = profile.version.label == 'x'\n": "reads .label",
            'ok = spec == "%s"\n' % encoding.hashstr(b"an edition"): "writes a hashstr",
            'ok = name == "%s"\n' % profiles.CURRENT: "names the edition label 'current'",
        }
        for source, expected in planted.items():
            self.assertIn(expected, violations(source, "rules_planted.py"), source)
            self.assertEqual(violations(source, OWNER), [], source)
        for root in sorted(ROOTS):
            self.assertNotIn("imports profiles", violations("from . import profiles\n", root))

    def test_the_guard_sees_every_way_round_a_comparison(self):
        """The ways an edition's place can be asked for without a comparison on the attribute: through a local
        variable, a sort key, `getattr`, a list position, an absolute import, a dynamic import. The guard is about
        what a module may name, so none of them gets past it."""
        bypasses = {
            "p = epoch.profile.version.position\nok = p < 2\n": "reads .position",
            "ordered = sorted(sets, key=lambda e: e.version.position)\n": "reads .position",
            "n = getattr(epoch.profile.version, 'position')\n": "calls getattr",
            "n = editions.index(epoch.profile)\n": "names editions",
            "n = profile_set.editions()\n": "reads .editions",
            "n = profile_set.production_hashes()\n": "reads .production_hashes",
            "from handsal_check import profiles\n": "imports profiles",
            "import handsal_check.profiles as P\n": "imports profiles",
            "from handsal_check.profiles import Version\n": "imports profiles",
            "mod = importlib.import_module('handsal_check.profiles')\n": "calls import_module",
            "mod = __import__('handsal_check.profiles')\n": "calls __import__",
            "v = epoch.profile.version\nok = v is other\n": "uses .version beyond its data",
            "ok = epoch.profile.version == other\n": "uses .version beyond its data",
            "kids = epoch.profile.version.fixture_kids\n": "reads .fixture_kids",
            "d = vars(epoch.profile)\n": "calls vars",
            "d = epoch.profile.__dict__\n": "reads .__dict__",
            "def f(editions):\n    return editions\n": "names editions",
        }
        for source, expected in bypasses.items():
            self.assertIn(expected, violations(source, "rules_planted.py"), source)
            self.assertEqual(violations(source, OWNER), [], source)

    def test_what_a_rule_may_read_is_not_a_violation(self):
        allowed = (
            "entry = epoch.profile.version.reg.lookup_class(cls, epoch.fixture)\n",
            "ok = epoch.profile.version.is_fixture_kid(kid)\n",
            "_check_content(doc, profile.version, profile.fixture, not profile.fixture)\n",
            "reg = version.reg\n",
            "check(doc, ctx.profiles.current)\n",
            "ok = profiles.resolve(pin.spec).fixture\n",
        )
        for source in allowed:
            self.assertEqual(violations(source, "rules_planted.py"), [], source)
        self.assertEqual(violations("ok = device.label == entry['label']\n", "epoch.py"), [])
        self.assertEqual(violations("ok = device.label == entry['label']\n", "rules_planted.py"), ["reads .label"])

    def test_a_profile_cannot_be_unpacked_or_indexed(self):
        """Nothing the owner hands out is a tuple, so its parts cannot be read by position or by unpacking."""
        profile = profiles.load().resolve(profiles.load().production_hashes()[-1])
        with self.assertRaises(TypeError):
            hash_, fixture, version = profile
        with self.assertRaises(TypeError):
            profile[0]
        with self.assertRaises(TypeError):
            tuple(profile.version)
        with self.assertRaises(AttributeError):
            profile.hash = "x"

    def test_only_the_owner_and_the_composition_roots_import_the_edition_set(self):
        importers = {path.name for path in SRC.glob("*.py")
                     if "imports profiles" in violations(path.read_text(), "x.py")}
        self.assertEqual(importers, ROOTS)


if __name__ == "__main__":
    unittest.main()
