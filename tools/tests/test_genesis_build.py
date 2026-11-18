"""The genesis draft builder: it constructs a document and asks the checker, it owns no rule of its own.

Every scenario here names a fact the checker answers (a code, a hash, a byte string). The tools never decide
valid or invalid, so a test compares against the checker or against an independent reference.
"""
import ast
import copy
import hashlib
import io
import json
import os
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
from handsal_check import (coredata, devicekey, emit, encoding, errors, genesis, genesis_check,  # noqa: E402
                           genesis_sigs, ijson, policy, profiles, registry, render, render_genesis)

BUILDER = TOOLS / "genesis_build.py"
PUBKEYS = ROOT / "tools" / "tests" / "data" / "genesis_pubkeys.json"
FIXTURE_KEYS = ROOT / "conformance" / "fixtures" / "keys.json"
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


def holders(*names, **overrides):
    """A builder input over the public test keys: the named holders, all maintainers, one device each."""
    keys = json.loads(PUBKEYS.read_text(encoding="utf-8"))
    value = {"name": "acme", "members": [{"id": n, "role": "maintainer"} for n in names],
             "devices": [{"person": n, "label": n + " mac", "pubkey": keys[n]} for n in names], "relays": ["r.example"]}
    value.update(overrides)
    return value


class Forbidden:
    """A verifier that must never be asked."""

    def verify(self, jws, keys, method):
        raise AssertionError("the verifier was reached")


def receipt_text(doc, kid, person="alice"):
    """A receipt shaped as the signer prints it: the signer's published payload with the fields that name this
    document and this device replaced, and a signature that is only a well-formed low-S value (never verified:
    only a verifier would judge it, and these tests give it none)."""
    payload = json.loads(bytes.fromhex(vector_anchor()))
    org = genesis.doc_hash(doc)
    payload["inputs_hash"] = org
    payload["performer_id"] = person
    payload["ext"] = {"dev.handsal/act": {"body": {}, "kid": kid, "org": org}}
    head = encoding.b64u_encode(emit.emit_subset({"alg": "ES256", "kid": kid}))
    body = encoding.b64u_encode(emit.emit_subset(payload))
    signature = encoding.b64u_encode((1).to_bytes(32, "big") * 2)
    jws = "%s.%s.%s" % (head, body, signature)
    return json.dumps({"jws": jws, "receipt_id": hashlib.sha256(jws.encode("ascii")).hexdigest()}).encode("utf-8")


def vector_anchor():
    return json.loads(json.loads(VECTOR.read_text(encoding="utf-8"))["anchor"])["payload_hex"]


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


class Validation(unittest.TestCase):
    """The single owner of validity is the checker: each refusal below is the code its own fold gives."""

    def setUp(self):
        self.profile_set = profiles.load()

    def compose(self, value):
        return genesis_build.compose(genesis_build.read_input(value), self.profile_set)

    def code(self, value):
        with self.assertRaises(genesis_build.Refusal) as caught:
            self.compose(value)
        return caught.exception

    def test_build_hardware_run_shape_validates_unsigned(self):   # S1.1
        made = self.compose(holders("alice", "bob", "carol"))
        doc = made["document"]
        self.assertEqual((len(doc["members"]), len(doc["devices"])), (3, 3))
        self.assertEqual(doc["policy"]["classes"], [{"class": "apple-se-bio", "user_verification": "biometric_only"}])
        self.assertEqual({r["persons"] for r in doc["policy"]["rules"].values()}, {"2"})
        self.assertEqual(len(doc["policy"]["rules"]), 4)
        self.assertEqual(doc["policy"]["witness"], {"mode": "none"})
        self.assertEqual(genesis_build.validate_draft(doc, self.profile_set), "genesis_unsigned")
        self.assertEqual(made["draft_bytes"], genesis_build.draft_bytes(doc))
        self.assertEqual(made["document_hash"], genesis.doc_hash(doc))
        self.assertEqual(made["hash12"], render.hash12(made["document_hash"]))
        self.assertEqual(made["draft_hash"], encoding.hashstr(made["draft_bytes"]))

    def test_empty_sigs_fold_is_genesis_unsigned_and_never_calls_verifier(self):   # S1.2
        class Recording:
            calls = 0

            def verify(self, jws, keys, method):
                Recording.calls += 1
                raise AssertionError("the verifier must not be reached")

        doc = self.compose(holders("alice", "bob", "carol"))["document"]
        inp = genesis_check.GenesisInput([], [{"doc": doc, "sigs": []}])
        self.assertEqual(genesis_check.fold(inp, self.profile_set, False, Recording()), (None, "genesis_unsigned"))
        self.assertEqual(Recording.calls, 0)

    def test_validate_draft_fails_loudly_on_fold_success(self):   # S1.3
        doc = self.compose(holders("alice", "bob", "carol"))["document"]
        with mock.patch.object(genesis_check, "fold", return_value=([object()], None)):
            with self.assertRaises(RuntimeError):
                genesis_build.validate_draft(doc, self.profile_set)

    def test_two_holders_returns_policy_unreachable(self):   # S1.4
        self.assertEqual(self.code(holders("alice", "bob")).code, "policy_unreachable")

    def test_persons_out_of_bound_returns_checker_code(self):   # S1.5
        for persons in ("1", "16"):
            with self.subTest(persons=persons):
                value = holders("alice", "bob", "carol", persons=persons)
                doc = genesis_build.new_document(genesis_build.read_input(value), self.profile_set)
                with self.assertRaises(errors.Refused) as want:
                    policy.validate(doc["policy"], doc["members"], doc["devices"], self.profile_set.current.reg, False)
                self.assertEqual(want.exception.code, "policy_out_of_bounds")
                self.assertEqual(self.code(value).code, want.exception.code)

    def test_fixture_kid_returns_fixture_key(self):   # S1.6
        keys = json.loads(FIXTURE_KEYS.read_text(encoding="utf-8"))["keys"]
        sign, agree = keys["X1.sign"], keys["X1.agree"]
        pubkey = {"agree": {"x": agree["x"], "y": agree["y"]}, "class": "apple-se-bio", "kid": sign["kid"],
                  "sign": {"x": sign["x"], "y": sign["y"]}}
        value = holders("alice", "bob", "carol")
        value["devices"][0]["pubkey"] = pubkey
        self.assertEqual(self.code(value).code, "fixture_key")

    def test_kid_not_matching_sign_returns_genesis_key_invalid(self):   # S1.7
        value = holders("alice", "bob", "carol")
        value["devices"][1]["pubkey"] = dict(value["devices"][1]["pubkey"], kid=value["devices"][0]["pubkey"]["kid"])
        refusal = self.code(value)
        self.assertEqual(refusal.code, "genesis_key_invalid")
        self.assertEqual(refusal.extra, {"device": 1, "defect": "kid_not_thumbprint"})

    def test_duplicate_kid_returns_duplicate_key(self):   # S1.8
        value = holders("alice", "bob", "carol")
        value["devices"][2] = dict(value["devices"][2], pubkey=value["devices"][0]["pubkey"])
        self.assertEqual(self.code(value).code, "duplicate_key")

    def test_non_biometric_holder_class_returns_role_key_class(self):   # S1.9
        # No active class of the shipped registry lacks biometrics, so the edition under test adds one.
        raw = ijson.loads(coredata.read_checked(coredata.REGISTRY))
        raw["key_classes"].append({"id": "acme-pin", "alg": "ES256", "hardware_bound": False,
                                   "per_signature_user_verification": True, "user_verification": "biometric_or_pin",
                                   "status": "active"})
        current = self.profile_set.editions()[-1]
        pinned = profiles.ProfileSet([profiles.Edition(profiles.Version(0, "acme", registry.Registry(raw), frozenset()),
                                                       current.production, current.fixture)])
        value = holders("alice", "bob", "carol")
        for device in value["devices"]:
            device["pubkey"] = dict(device["pubkey"], **{"class": "acme-pin"})
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.compose(genesis_build.read_input(value), pinned)
        self.assertEqual(caught.exception.code, "role_key_class")

    def test_validate_draft_returns_doc_not_sorted_for_tampered_doc(self):   # S1.12
        doc = self.compose(holders("alice", "bob", "carol"))["document"]
        doc["devices"] = list(reversed(doc["devices"]))
        self.assertEqual(genesis_build.validate_draft(doc, self.profile_set), "doc_not_sorted")


class DraftCommand(unittest.TestCase):
    def setUp(self):
        self.profile_set = profiles.load()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def draft(self, value, out, raw=None):
        stdin = io.BytesIO(json.dumps(value).encode("utf-8") if raw is None else raw)
        stdout = io.BytesIO()
        status = genesis_build.main(["draft", str(out)], stdin, stdout)
        return status, stdout.getvalue()

    def test_cli_success_writes_draft_bytes_and_prints_summary(self):   # S1.20
        out = self.dir / "draft.json"
        status, printed = self.draft(holders("alice", "bob", "carol"), out)
        made = genesis_build.compose(genesis_build.read_input(holders("alice", "bob", "carol")), self.profile_set)
        self.assertEqual(status, 0)
        self.assertEqual(out.read_bytes(), made["draft_bytes"])
        self.assertEqual(printed, emit.emit_result({k: made[k] for k in ("document_hash", "draft_hash", "hash12")}) + b"\n")
        self.assertEqual(json.loads(printed)["draft_hash"], encoding.hashstr(out.read_bytes()))

    def test_hash12_equals_render_summary_line_one(self):   # S1.15
        made = genesis_build.compose(genesis_build.read_input(holders("alice", "bob", "carol")), self.profile_set)
        line = render_genesis.summary(made["document"], None)
        self.assertIn(made["hash12"], line)
        self.assertIn(render.cut12(made["document"]["name"]), line)
        self.assertEqual(made["hash12"], render.hash12(made["document_hash"]))

    def test_cli_refuses_to_overwrite_existing_draft(self):   # S1.18
        out = self.dir / "draft.json"
        out.write_bytes(b"keep me")
        status, printed = self.draft(holders("alice", "bob", "carol"), out)
        self.assertEqual((status, json.loads(printed)), (2, {"error": "file_exists", "path": str(out)}))
        self.assertEqual(out.read_bytes(), b"keep me")
        target, link = self.dir / "elsewhere", self.dir / "link.json"
        target.write_bytes(b"other")
        link.symlink_to(target)
        status, printed = self.draft(holders("alice", "bob", "carol"), link)
        self.assertEqual((status, json.loads(printed)["error"]), (2, "file_exists"))
        self.assertEqual(target.read_bytes(), b"other")
        dangling = self.dir / "dangling.json"
        dangling.symlink_to(self.dir / "never")
        self.assertEqual(self.draft(holders("alice", "bob", "carol"), dangling)[0], 2)
        self.assertFalse((self.dir / "never").exists())

    def test_cli_writes_no_file_for_invalid_draft(self):   # S1.19
        out = self.dir / "draft.json"
        status, printed = self.draft(holders("alice", "bob"), out)
        self.assertEqual((status, printed), (2, b'{"error":"policy_unreachable"}\n'))
        self.assertFalse(out.exists())
        self.assertEqual(os.listdir(self.dir), [])

    def test_founding_builder_refuses_tmp_name(self):   # S1.21
        value = holders("alice", "bob", "carol", name="tmp-acme")
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.build(value, self.profile_set)
        self.assertEqual(caught.exception.code, "name_is_throwaway")
        out = self.dir / "draft.json"
        status, printed = self.draft(value, out)
        self.assertEqual((status, printed, out.exists()), (2, b'{"error":"name_is_throwaway"}\n', False))

    def test_tmp_inside_name_is_not_the_marker(self):   # S1.22
        built = genesis_build.build(holders("alice", "bob", "carol", name="acme-tmp-x"), self.profile_set)
        self.assertEqual(built["document"]["name"], "acme-tmp-x")

    def test_build_refuses_unknown_key_and_gives_no_draft(self):   # S1.10
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.build(holders("alice", "bob", "carol", policy={}), self.profile_set)
        self.assertEqual(caught.exception.code, "malformed_input")

    def test_cli_refuses_malformed_stdin(self):   # S1.23
        cases = {b"not json": "unparseable_input", b'{"name":"a","name":"b"}': "unparseable_input",
                 b"\xff\xfe": "unparseable_input", b"[]": "malformed_input", b'{"name":"acme"}': "malformed_input"}
        for raw, code in cases.items():
            with self.subTest(raw=raw):
                out = self.dir / "draft.json"
                status, printed = self.draft(None, out, raw=raw)
                self.assertEqual((status, json.loads(printed)), (2, {"error": code}))
                self.assertFalse(out.exists())

    def test_a_name_the_subset_cannot_write_is_the_checkers_genesis_schema(self):   # S1.23
        out = self.dir / "draft.json"
        status, printed = self.draft(holders("alice", "bob", "carol", name="caf\u00e9"), out)
        self.assertEqual((status, json.loads(printed)), (2, {"error": "genesis_schema"}))
        self.assertFalse(out.exists())

    def test_the_cli_help_is_the_module_docstring(self):   # R1.18
        done = subprocess.run([sys.executable, "-I", str(BUILDER), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0)
        self.assertIn("acme", done.stdout)
        self.assertIn(genesis_build.__doc__.strip().splitlines()[0], done.stdout)


class Assemble(unittest.TestCase):
    def setUp(self):
        self.profile_set = profiles.load()
        self.made = genesis_build.compose(genesis_build.read_input(holders("alice", "bob", "carol")), self.profile_set)
        self.doc = self.made["document"]
        self.kids = sorted(d["kid"] for d in self.doc["devices"])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def assemble(self, files, vitni=None):
        return genesis_build.assemble(self.doc, files, self.profile_set, Forbidden() if vitni is None else vitni)

    def test_assemble_zero_outputs_is_unsigned_without_verifier(self):   # S2.1
        got = self.assemble({})
        self.assertEqual(got, {"document_hash": self.made["document_hash"], "hash12": self.made["hash12"],
                               "state": "unsigned", "signed": 0, "of": 3, "missing": self.kids, "files": {}})

    def test_assemble_names_non_matching_outputs(self):   # S2.2
        other = copy.deepcopy(self.doc)
        other["name"] = "elsewhere"
        stranger = receipt_text(self.doc, encoding.b64u_encode(bytes(32)))
        files = {"a-junk": b"not json", "b-shape": b'{"jws":"x"}', "c-text": b'{"jws":"x","receipt_id":"y"}',
                 "d-other": receipt_text(other, self.kids[0]), "e-stranger": stranger, "f-numbers": b"[1]"}
        got = self.assemble(files)
        self.assertEqual(got["files"], {"a-junk": "unparseable_input", "b-shape": "malformed_input",
                                        "c-text": "not_this_document", "d-other": "not_this_document",
                                        "e-stranger": "kid_not_listed", "f-numbers": "malformed_input"})
        self.assertEqual((got["state"], got["signed"], got["missing"]), ("unsigned", 0, self.kids))

    def test_the_forged_receipt_reads_as_a_receipt_for_the_document(self):   # the helper's own check
        text = json.loads(receipt_text(self.doc, self.kids[0]))["jws"]
        act = genesis_sigs.read(text, self.doc, self.made["document_hash"], self.made["document_hash"], self.profile_set.wire)
        self.assertEqual(act.kid, self.kids[0])

    def test_assemble_refuses_change_document_with_lineage_broken(self):   # S2.11
        change = copy.deepcopy(self.doc)
        change.update(prev=self.made["document_hash"], org=self.made["document_hash"], head=self.made["document_hash"])
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.assemble(change, {}, self.profile_set, Forbidden())
        self.assertEqual(caught.exception.code, "lineage_broken")

    def test_assemble_refuses_draft_whose_org_does_not_match_document(self):   # S2.12
        raw = self.made["draft_bytes"]
        self.assertEqual(genesis_build.read_draft(raw), self.doc)
        edited = raw.replace(b"alice mac", b"alice max")
        for bad in (edited, raw[:-1], raw + b"\n", b"[]", b"nope", b'{"attachments":{"document":1},"draft":{}}'):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(genesis_build.Refusal) as caught:
                    genesis_build.read_draft(bad)
                self.assertIn(caught.exception.code, ("malformed_input", "unparseable_input"))
        with self.assertRaises(genesis_build.Refusal) as caught:
            genesis_build.read_draft(edited)
        self.assertEqual(caught.exception.code, "malformed_input")

    def run_cli(self, argv, vitni=None):
        stdout = io.BytesIO()
        status = genesis_build.main(argv, io.BytesIO(), stdout, Forbidden() if vitni is None else vitni)
        return status, json.loads(stdout.getvalue())

    def test_cli_assemble_reports_and_labels_each_file(self):   # S2.13
        draft = self.dir / "draft.json"
        draft.write_bytes(self.made["draft_bytes"])
        junk = self.dir / "junk.txt"
        junk.write_bytes(b"not json")
        status, got = self.run_cli(["assemble", str(draft), str(junk)])
        self.assertEqual(status, 0)
        self.assertEqual(set(got), {"document_hash", "hash12", "state", "signed", "of", "missing", "files"})
        self.assertEqual(got["files"], {str(junk): "unparseable_input"})
        self.assertEqual((got["state"], got["of"], got["missing"]), ("unsigned", 3, self.kids))

    def test_cli_assemble_refuses_a_draft_that_is_not_the_builders(self):   # S2.12
        draft = self.dir / "draft.json"
        draft.write_bytes(self.made["draft_bytes"].replace(b"alice mac", b"alice max"))
        status, got = self.run_cli(["assemble", str(draft)])
        self.assertEqual((status, got), (2, {"error": "malformed_input"}))


if __name__ == "__main__":
    unittest.main()
