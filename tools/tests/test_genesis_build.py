"""The genesis draft builder: it constructs a document and asks the checker, it owns no rule of its own.

Every scenario here names a fact the checker answers (a code, a hash, a byte string). The tools never decide
valid or invalid, so a test compares against the checker or against an independent reference.
"""
import ast
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import manifest  # noqa: E402
import genesis_build  # noqa: E402
from handsal_check import devicekey, emit, encoding, genesis, profiles  # noqa: E402

BUILDER = TOOLS / "genesis_build.py"
PUBKEYS = ROOT / "tools" / "tests" / "data" / "genesis_pubkeys.json"
VECTOR = ROOT / "conformance" / "vectors" / "jcs.emit-genesis-sign-original.json"


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


def vector():
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def vector_spec():
    """A builder input rebuilt from the document inside the signer's published vector (XC-3a)."""
    doc = vector()["input"]["attachments"]["document"]
    return {"name": doc["name"], "members": doc["members"],
            "devices": [{"person": d["person"], "label": d["label"],
                         "pubkey": {k: d[k] for k in ("agree", "class", "kid", "sign")}} for d in doc["devices"]],
            "persons": "2", "relays": ["r.example"]}


def vector_registry(profile_set, hash_):
    return profile_set.resolve(hash_).version.reg


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


class Bytes(unittest.TestCase):
    def setUp(self):
        self.profile_set = profiles.load()
        self.vector = vector()
        self.document = self.vector["input"]["attachments"]["document"]
        self.reg = vector_registry(self.profile_set, self.document["profile"])

    def built(self, spec):
        return genesis_build.document(genesis_build.read_input(spec), self.document["profile"], self.reg)

    def test_document_bytes_equal_conformance_vector_input(self):   # XC-3a
        doc = self.built(vector_spec())
        want = {k: v for k, v in self.vector["input"].items() if k != "fixed"}
        self.assertEqual(emit.emit_subset(genesis_build.sign_input(doc)), emit.emit_subset(want))

    def test_input_order_does_not_change_bytes(self):   # XC-3b
        spec = vector_spec()
        spec["relays"] = ["r.example", "a.example"]
        shuffled = {key: spec[key] for key in reversed(list(spec))}
        shuffled["members"] = list(reversed(spec["members"]))
        shuffled["relays"] = list(reversed(spec["relays"]))
        shuffled["devices"] = [{key: d[key] for key in reversed(list(d))} for d in reversed(spec["devices"])]
        self.assertNotEqual(shuffled["relays"], spec["relays"])
        self.assertEqual(genesis_build.draft_bytes(self.built(shuffled)), genesis_build.draft_bytes(self.built(spec)))

    def test_draft_is_exact_sign_stdin_with_org_equal_document_hash(self):   # S1.14
        doc = self.built(vector_spec())
        raw = genesis_build.draft_bytes(doc)
        self.assertTrue(raw.endswith(b"}\n") and not raw.endswith(b"\n\n"))
        draft = json.loads(raw)
        self.assertEqual(set(draft), {"attachments", "draft"})
        self.assertEqual(draft["attachments"], {"document": doc})
        self.assertEqual(draft["draft"], {"body": {}, "method": "local:handsal.genesis.sign",
                                          "org": encoding.hashstr(emit.emit_subset(doc))})
        self.assertEqual(draft["draft"]["org"], genesis.doc_hash(doc))

    def test_draft_bytes_come_only_from_checker_emitter(self):   # S1.13
        doc = self.built(vector_spec())
        with mock.patch.object(emit, "emit_subset", return_value=b"MARKER"):
            self.assertEqual(genesis_build.draft_bytes(doc), b"MARKER\n")
        self.assertNotIn("json", imported_modules(BUILDER))

    def test_content_change_changes_document_hash(self):   # S1.16
        spec = vector_spec()
        other = copy.deepcopy(spec)
        other["members"][0]["role"] = "member"
        self.assertNotEqual(genesis.doc_hash(self.built(spec)), genesis.doc_hash(self.built(other)))

    def test_profile_is_loaders_current_not_a_constant(self):   # S1.17
        class Stub:
            def production_hashes(self):
                return ["uEiOLD", "uEiNEW"]

            def resolve(self, value):
                return self_outer.profile_set.resolve(self_outer.document["profile"])

        self_outer = self
        doc = genesis_build.new_document(genesis_build.read_input(vector_spec()), Stub())
        self.assertEqual(doc["profile"], "uEiNEW")

    def test_the_document_has_the_precedent_shape(self):   # R1.4 to R1.10
        doc = self.built(vector_spec())
        self.assertEqual((doc["v"], doc["org"], doc["prev"]), ("handsal-genesis/1", None, None))
        self.assertNotIn("head", doc)
        self.assertEqual(doc["policy"]["witness"], {"mode": "none"})
        self.assertEqual(doc["policy"]["classes"], [{"class": "apple-se-bio", "user_verification": "biometric_only"}])

    def test_a_class_the_registry_does_not_know_is_class_unknown(self):   # R1.7
        spec = vector_spec()
        spec["devices"][0]["pubkey"]["class"] = "no-such-class"
        with self.assertRaises(genesis_build.Refusal) as caught:
            self.built(spec)
        self.assertEqual(caught.exception.code, "class_unknown")


class PublicKeyData(unittest.TestCase):
    """`data/genesis_pubkeys.json` holds the public halves of three throwaway test keys, one per holder.

    The private halves were generated once, never stored and are gone. The points are public, valid SG-03 key
    objects (`{agree, class, kid, sign}`) that are no fixture key, so a validity test can use them.
    """

    def keys(self):
        return json.loads(PUBKEYS.read_text(encoding="utf-8"))

    def test_pubkeys_data_file_is_public_valid_and_not_fixture(self):   # S1.1 input data
        keys = self.keys()
        self.assertEqual(sorted(keys), ["alice", "bob", "carol"])
        profile_set = profiles.load()
        reg = profile_set.current.reg
        kids = set()
        for holder, key in keys.items():
            with self.subTest(holder=holder):
                self.assertEqual(set(key), {"agree", "class", "kid", "sign"})
                for point_name in ("agree", "sign"):
                    self.assertEqual(set(key[point_name]), {"x", "y"})
                self.assertEqual(key["kid"], encoding.thumbprint(key["sign"]["x"], key["sign"]["y"]))
                self.assertIsNone(devicekey.defect(key["kid"], key["sign"], key["agree"]))
                self.assertFalse(any(v.is_fixture_kid(key["kid"]) for v, _, _ in profile_set.editions()))
                self.assertIsNotNone(reg.lookup_class(key["class"], False))
                kids.add(key["kid"])
        self.assertEqual(len(kids), 3)

    def test_the_data_file_carries_no_private_member(self):   # I5
        def walk(value):
            if isinstance(value, dict):
                self.assertNotIn("d", value)
                for member in value.values():
                    walk(member)
            elif isinstance(value, list):
                for member in value:
                    walk(member)
        walk(self.keys())


if __name__ == "__main__":
    unittest.main()
