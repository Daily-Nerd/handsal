"""The genesis draft builder: it constructs a document and asks the checker, it owns no rule of its own.

Every scenario here names a fact the checker answers (a code, a hash, a byte string). The tools never decide
valid or invalid, so a test compares against the checker or against an independent reference.
"""
import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import manifest  # noqa: E402
import genesis_build  # noqa: E402
from handsal_check import profiles  # noqa: E402

BUILDER = TOOLS / "genesis_build.py"


def imported_modules(path):
    """The top-level module name of every import in the source at `path` (ast, never a text search)."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def isolated(code):
    """Run `code` in a fresh interpreter in isolated mode; return the completed process."""
    return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)


def point(tag):
    return {"x": tag + "x", "y": tag + "y"}


def shaped_input(**changes):
    """An input of the right shape with placeholder key text: enough for the shape reader, never for the fold."""
    value = {"name": "acme",
             "members": [{"id": "alice", "role": "maintainer"}, {"id": "bob", "role": "member"}],
             "devices": [{"person": "alice", "label": "alice mac",
                          "pubkey": {"agree": point("a"), "class": "apple-se-bio", "kid": "k1", "sign": point("s")}}]}
    value.update(changes)
    return value


class Bootstrap(unittest.TestCase):
    def test_the_draft_names_the_production_profile_of_this_checkout(self):   # XC-1b
        self.assertEqual(genesis_build.production_profile(profiles.load()), manifest.production_profile(ROOT))

    def test_foreign_handsal_check_is_refused_and_no_crypto_loaded(self):   # XC-1c
        with tempfile.TemporaryDirectory() as tmp:
            decoy = Path(tmp) / "decoy"
            (decoy / "handsal_check").mkdir(parents=True)
            (decoy / "handsal_check" / "__init__.py").write_text("", encoding="utf-8")
            done = isolated("import sys; sys.path.insert(0, %r); import handsal_check; sys.path.insert(0, %r); "
                            "import genesis_build" % (str(decoy), str(TOOLS)))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("ImportError", done.stderr)
        self.assertIn(str(decoy), done.stderr)
        self.assertIn(str(ROOT / "checker" / "python" / "src"), done.stderr)
        clean = isolated("import sys; sys.path.insert(0, %r); import genesis_build; "
                         "print(sorted(m for m in ('cryptography', 'genesis_throwaway') if m in sys.modules))"
                         % str(TOOLS))
        self.assertEqual((clean.returncode, clean.stdout.strip()), (0, "[]"), clean.stderr)

    def test_builder_imports_no_cryptography_and_no_throwaway(self):   # XC-1a
        found = imported_modules(BUILDER)
        self.assertNotIn("cryptography", found)
        self.assertNotIn("genesis_throwaway", found)


class InputShape(unittest.TestCase):
    def refusal(self, value):
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.read_input(value)
        return caught.exception.code

    def test_unknown_input_key_refused(self):   # S1.10
        extras = {"profile": "uEiA", "witness": {"mode": "none"}, "classes": [], "policy": {}, "prev": None, "extra": 1}
        for key, value in extras.items():
            with self.subTest(key=key):
                self.assertEqual(self.refusal(shaped_input(**{key: value})), "malformed_input")

    def test_defaults_persons_two_and_empty_relays(self):   # S1.11
        read = genesis_build.read_input(shaped_input())
        self.assertEqual((read["persons"], read["relays"]), ("2", []))
        given = genesis_build.read_input(shaped_input(persons="3", relays=["r.example"]))
        self.assertEqual((given["persons"], given["relays"]), ("3", ["r.example"]))

    def test_a_missing_key_a_wrong_type_and_a_nonobject_are_malformed(self):   # R1.3
        for key in ("name", "members", "devices"):
            value = shaped_input()
            del value[key]
            with self.subTest(missing=key):
                self.assertEqual(self.refusal(value), "malformed_input")
        wrong = [shaped_input(name=1), shaped_input(members={}), shaped_input(devices="x"), shaped_input(persons=2),
                 shaped_input(relays="r.example"), shaped_input(relays=[1]),
                 shaped_input(members=[{"id": "alice"}]), shaped_input(members=[{"id": "a", "role": "maintainer", "x": 1}]),
                 shaped_input(devices=[{"person": "alice", "label": "x"}]),
                 shaped_input(devices=[{"person": "alice", "label": "x", "pubkey": {"kid": "k"}}]),
                 [], "text", None]
        for value in wrong:
            with self.subTest(value=value):
                self.assertEqual(self.refusal(value), "malformed_input")

    def test_text_that_is_not_framed_json_is_unparseable(self):   # R1.3, S1.23
        for raw in (b"not json", b'{"a":1,"a":2}', b"\xff\xfe", b""):
            with self.subTest(raw=raw):
                with self.assertRaises(genesis_build.Refusal) as caught:
                    genesis_build.read_text(raw)
                self.assertEqual(caught.exception.code, "unparseable_input")
        self.assertEqual(genesis_build.read_text(b'{"name":"acme"}'), {"name": "acme"})


if __name__ == "__main__":
    unittest.main()
