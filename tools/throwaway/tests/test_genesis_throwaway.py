"""The throwaway genesis tool: software keys that sign receipts the checker accepts.

The tool holds no rule. It fills the signer's payload from the checker's own constants, and the checker's reader
decides whether a receipt counts. A test compares against the signer's published bytes or against the checker.
"""
import ast
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import genesis_build  # noqa: E402,F401  (first: it pins the checker of this checkout)
import genesis_throwaway  # noqa: E402
from handsal_check import (commands, emit, encoding, genesis, genesis_check, genesis_sigs, ijson, jws,  # noqa: E402
                           pinfile, profiles, verifier)

VECTOR = ROOT / "conformance" / "vectors" / "jcs.emit-genesis-sign-original.json"
PUBKEYS = ROOT / "tools" / "tests" / "data" / "genesis_pubkeys.json"
SOURCE = TOOLS / "genesis_throwaway.py"
# The order of the P-256 group, written here on its own: the tool's constant is checked against the curve, not
# against itself.
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def imported_modules(path):
    """The top-level module name of every import in the source at `path` (ast, never a text search)."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


class Payload(unittest.TestCase):
    def test_emit_payload_equals_the_signer_vector_anchor(self):   # S3.18
        vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        sign_in = {key: vector["input"][key] for key in ("attachments", "draft")}
        raw = genesis_throwaway.emit_payload(sign_in, vector["input"]["fixed"])
        self.assertEqual(raw, bytes.fromhex(json.loads(vector["anchor"])["payload_hex"]))

    def test_a_change_document_has_no_payload(self):   # R3.11: originals only
        vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        sign_in = {key: vector["input"][key] for key in ("attachments", "draft")}
        sign_in["attachments"]["document"]["prev"] = "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        with self.assertRaises(ValueError):
            genesis_throwaway.emit_payload(sign_in, vector["input"]["fixed"])


class HighS:
    """A private key that signs like the real one but always answers the high form of S."""

    def __init__(self, inner):
        self.inner = inner

    def public_key(self):
        return self.inner.public_key()

    def sign(self, data, algorithm):
        r, s = decode_dss_signature(self.inner.sign(data, algorithm))
        return encode_dss_signature(r, max(s, ORDER - s))


def org_with(key):
    """A pure document (no validation) that lists `key` and two public test keys, and the signer input for it."""
    keys = json.loads(PUBKEYS.read_text(encoding="utf-8"))
    devices = [{"person": "alice", "label": "alice laptop", "pubkey": key.pubkey()},
               {"person": "bob", "label": "bob mac", "pubkey": keys["bob"]},
               {"person": "carol", "label": "carol mac", "pubkey": keys["carol"]}]
    spec = {"name": "tmp-acme", "members": [{"id": n, "role": "maintainer"} for n in ("alice", "bob", "carol")],
            "devices": devices, "persons": "2", "relays": []}
    doc = genesis_build.new_document(spec, profiles.load())
    return doc, genesis_build.sign_input(doc)


class Signing(unittest.TestCase):
    NONCE = encoding.hashstr(b"a nonce for the tests")
    TS = "2026-11-18T10:00:00Z"

    def forced(self):
        return genesis_throwaway.SoftwareKey(HighS(ec.generate_private_key(ec.SECP256R1())),
                                             ec.generate_private_key(ec.SECP256R1()))

    def test_signature_is_low_s_self_verified_and_read_gated(self):   # S3.19
        wire = profiles.load().wire
        for name, key in (("random", genesis_throwaway.SoftwareKey.generate()), ("forced high S", self.forced())):
            with self.subTest(key=name):
                message = b"the bytes to sign"
                raw = key.sign(message)
                self.assertEqual(len(raw), 64)
                self.assertTrue(verifier.is_low_s(raw))
                point = key.pubkey()["sign"]
                numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(encoding.b64u_decode(point["x"]), "big"),
                                                        int.from_bytes(encoding.b64u_decode(point["y"]), "big"),
                                                        ec.SECP256R1())
                r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
                numbers.public_key().verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
                doc, sign_in = org_with(key)
                made = genesis_throwaway.receipt(key, sign_in, "alice", self.TS, self.NONCE, wire)
                doc_hash = genesis.doc_hash(doc)
                act = genesis_sigs.read(made["jws"], doc, doc_hash, doc_hash, wire)
                self.assertIsNotNone(act)
                self.assertEqual(act.kid, key.pubkey()["kid"])

    def test_the_forced_key_really_signs_the_high_form(self):   # the proof that the test above reaches the fold
        inner = ec.generate_private_key(ec.SECP256R1())
        _, s = decode_dss_signature(HighS(inner).sign(b"x", ec.ECDSA(hashes.SHA256())))
        self.assertGreater(s, ORDER // 2)

    def test_a_wrong_group_order_fails_loudly(self):   # the constant is checked at runtime, never trusted
        with mock.patch.object(genesis_throwaway, "_N", ORDER - 2):
            with self.assertRaises(RuntimeError):
                self.forced().sign(b"the bytes to sign")

    def test_a_receipt_the_checker_refuses_is_a_runtime_error(self):   # S3.19
        key = genesis_throwaway.SoftwareKey.generate()
        _, sign_in = org_with(key)
        with self.assertRaises(RuntimeError):
            genesis_throwaway.receipt(key, sign_in, "alice", "yesterday", self.NONCE, profiles.load().wire)

    def test_the_header_is_the_one_exact_form_and_the_id_is_the_payload_hash(self):   # R3.11
        key = genesis_throwaway.SoftwareKey.generate()
        _, sign_in = org_with(key)
        made = genesis_throwaway.receipt(key, sign_in, "alice", self.TS, self.NONCE, profiles.load().wire)
        header, payload, _ = (encoding.b64u_decode(part) for part in made["jws"].split("."))
        self.assertEqual(header, b'{"alg":"ES256","kid":"%s"}' % key.pubkey()["kid"].encode("ascii"))
        self.assertEqual(made["receipt_id"], encoding.hashstr(payload))
        self.assertEqual(set(made), {"jws", "receipt_id"})

    def test_the_public_key_is_the_checker_shape(self):   # R3.3
        from handsal_check import devicekey
        pub = genesis_throwaway.SoftwareKey.generate().pubkey()
        self.assertEqual(set(pub), {"agree", "class", "kid", "sign"})
        self.assertEqual(pub["class"], "apple-se-bio")
        self.assertIsNone(devicekey.defect(pub["kid"], pub["sign"], pub["agree"]))

    def test_the_public_key_has_the_same_shape_as_the_test_data(self):   # the data file holds the same kind of object
        keys = json.loads(PUBKEYS.read_text(encoding="utf-8"))
        made = genesis_throwaway.SoftwareKey.generate().pubkey()
        for name, ours in keys.items():
            with self.subTest(key=name):
                self.assertEqual(set(made), set(ours))
                self.assertEqual({k: set(v) for k, v in made.items() if type(v) is dict},
                                 {k: set(v) for k, v in ours.items() if type(v) is dict})
                self.assertEqual(made["class"], ours["class"])
                self.assertEqual(len(made["kid"]), len(ours["kid"]))


class Source(unittest.TestCase):
    def test_source_carries_root_cause_todo_for_unattested_class(self):   # S3.13
        lines = [line.strip() for line in SOURCE.read_text(encoding="utf-8").splitlines()]
        self.assertIn("# TODO(root-cause): class is declared, not attested (L7)", lines)

    def test_source_has_no_seed_or_fixed_key_material(self):   # S3.10
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        names |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        seeded = {"derive_private_key", "from_private_bytes", "from_private_numbers", "load_pem_private_key",
                  "load_der_private_key", "seed", "randbytes"}
        self.assertEqual(names & seeded, set())
        self.assertIn("generate_private_key", names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                self.assertIsNone(re.search(r"[0-9a-fA-F]{64}", text), text)


class Es256Vitni:
    """A test-only stand-in for vitni's verify contract: ES256 over the JWS with `cryptography`, the key and the
    person taken from the map the checker passes, the method pinned. Like vitni it accepts a high S; the profile's
    low-S rule is the checker's, so the tests can show that a high S is not counted."""

    def __init__(self):
        self.asked = 0

    def verify(self, text, keys, method):
        self.asked += 1
        parsed = jws.parse(text)
        payload = json.loads(parsed.payload)
        if payload["method"] != method:
            return "context_mismatch"
        entry = keys.get(payload["performer_id"], {}).get(parsed.kid)
        if entry is None:
            return "unknown_key"
        numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(encoding.b64u_decode(entry["x"]), "big"),
                                                int.from_bytes(encoding.b64u_decode(entry["y"]), "big"), ec.SECP256R1())
        signing = text.rsplit(".", 1)[0].encode("ascii")
        r, s = int.from_bytes(parsed.signature[:32], "big"), int.from_bytes(parsed.signature[32:], "big")
        try:
            numbers.public_key().verify(encode_dss_signature(r, s), signing, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "bad_signature"
        return "ok"


PEOPLE = ("alice", "bob", "carol")


class Org:
    """An org of three software devices, validated by the builder core, with a receipt for any of them."""

    NONCE = encoding.hashstr(b"a nonce for the tests")

    def __init__(self):
        self.profile_set = profiles.load()
        self.keys = {p: genesis_throwaway.SoftwareKey.generate() for p in PEOPLE}
        spec = {"name": "tmp-acme", "members": [{"id": p, "role": "maintainer"} for p in PEOPLE],
                "devices": [{"person": p, "label": "throwaway software key " + p, "pubkey": k.pubkey()}
                            for p, k in self.keys.items()], "persons": "2", "relays": []}
        self.made = genesis_build.compose(spec, self.profile_set)
        self.doc = self.made["document"]
        self.sign_in = genesis_build.sign_input(self.doc)

    def kid(self, person):
        return self.keys[person].pubkey()["kid"]

    def receipt(self, person, nonce=None):
        return genesis_throwaway.receipt(self.keys[person], self.sign_in, person, "2026-11-18T10:00:00Z",
                                         nonce or self.NONCE, self.profile_set.wire)

    @staticmethod
    def file(made):
        return emit.emit_result(made) + b"\n"

    def files(self, *people):
        return {"receipt-%s.json" % p: self.file(self.receipt(p)) for p in people}

    def assemble(self, files, vitni=None):
        return genesis_build.assemble(self.doc, files, self.profile_set, vitni or Es256Vitni())


def resigned(made, signature):
    """`made` with its signature replaced: the same header and payload, so the receipt still names the document."""
    head, body, _ = made["jws"].split(".")
    return {"jws": ".".join((head, body, encoding.b64u_encode(signature))), "receipt_id": made["receipt_id"]}


class Assemble(unittest.TestCase):
    def test_assemble_partial_reports_exact_missing_kid(self):   # S2.3
        org = Org()
        result = org.assemble(org.files("alice", "bob"))
        self.assertEqual((result["state"], result["signed"], result["of"]), ("partial", 2, 3))
        self.assertEqual(result["missing"], [org.kid("carol")])
        self.assertNotIn("pin", result)
        self.assertEqual(set(result["files"].values()), {"counts"})

    def test_assemble_duplicate_kid_counts_once_and_is_named(self):   # S2.4
        org = Org()
        other = encoding.hashstr(b"another nonce")
        files = {"a.json": org.file(org.receipt("alice")), "b.json": org.file(org.receipt("alice", other))}
        result = org.assemble(files)
        self.assertEqual((result["state"], result["signed"]), ("partial", 1))
        self.assertEqual(result["files"], {"a.json": "counts", "b.json": "duplicate_kid"})

    def test_assemble_high_s_and_bad_signature_not_counted(self):   # S2.5
        org = Org()
        good = org.receipt("alice")
        raw = encoding.b64u_decode(good["jws"].rsplit(".", 1)[1])
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        high = resigned(good, r.to_bytes(32, "big") + (ORDER - s).to_bytes(32, "big"))
        self.assertFalse(verifier.is_low_s(encoding.b64u_decode(high["jws"].rsplit(".", 1)[1])))
        bad = resigned(org.receipt("bob"), (1).to_bytes(32, "big") * 2)
        vitni = Es256Vitni()
        result = org.assemble({"high.json": org.file(high), "bad.json": org.file(bad)}, vitni)
        self.assertEqual(result["files"], {"bad.json": "not_counting", "high.json": "not_counting"})
        self.assertEqual((result["state"], result["signed"]), ("unsigned", 0))
        self.assertEqual(vitni.asked, 2)   # both reached vitni; the high S is refused by the checker's rule after

    def test_assemble_never_keys_by_receipt_id(self):   # S2.10
        org = Org()
        shared = encoding.hashstr(b"one id for two receipts")
        same_id = {name: org.file({**org.receipt(person), "receipt_id": shared})
                   for name, person in (("a.json", "alice"), ("b.json", "bob"))}
        self.assertEqual(org.assemble(same_id)["signed"], 2)
        first = org.receipt("alice")
        other_ids = {"a.json": org.file({**first, "receipt_id": encoding.hashstr(b"one")}),
                     "b.json": org.file({**first, "receipt_id": encoding.hashstr(b"two")})}
        result = org.assemble(other_ids)
        self.assertEqual((result["signed"], result["files"]), (1, {"a.json": "counts", "b.json": "duplicate_kid"}))

    def test_assemble_complete_pin_comes_only_from_checker_run(self):   # S2.7
        org = Org()
        files = org.files(*PEOPLE)
        result = org.assemble(files)
        self.assertEqual((result["state"], result["signed"], result["missing"]), ("complete", 3, []))
        self.assertEqual(set(result), {"document_hash", "hash12", "state", "signed", "of", "missing", "files", "pin"})
        sigs = sorted(ijson.loads(files[name])["jws"] for name in files)
        direct = genesis_check.run(genesis_check.GenesisInput([], [{"doc": org.doc, "sigs": sigs}]),
                                   org.profile_set, False, Es256Vitni())
        self.assertTrue(direct["valid"])
        self.assertEqual(result["pin"], direct["pin"])
        with mock.patch.object(pinfile, "line", return_value=b"marker line\n"):
            self.assertEqual(org.assemble(files)["pin"], "marker line\n")

    def test_a_complete_run_the_checker_refuses_returns_its_reason(self):   # I6: complete is the checker's word
        org = Org()
        refusing = mock.Mock(return_value={"pin": None, "reason": "genesis_unsigned", "valid": False})
        with mock.patch.object(genesis_check, "run", refusing):
            with self.assertRaises(genesis_build.Refusal) as caught:
                org.assemble(org.files(*PEOPLE))
        self.assertEqual(caught.exception.code, "genesis_unsigned")

    def test_assemble_verifier_unavailable_is_never_a_silent_skip(self):   # S2.9
        org = Org()
        with self.assertRaises(genesis_build.Refusal) as caught:
            org.assemble(org.files("alice"), verifier.Absent())
        self.assertEqual(caught.exception.code, "verifier_unavailable")


def run_main(argv, vitni):
    out = io.BytesIO()
    status = genesis_build.main(argv, io.BytesIO(b""), out, vitni)
    return status, ijson.loads(out.getvalue())


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.org = Org()
        self.draft = self.dir / "draft.json"
        self.draft.write_bytes(self.org.made["draft_bytes"])

    def receipts(self, *people):
        paths = []
        for name, raw in self.org.files(*people).items():
            (self.dir / name).write_bytes(raw)
            paths.append(str(self.dir / name))
        return paths

    def test_assemble_out_writes_one_ceremony_input_per_device(self):   # S2.8
        out = self.dir / "out"
        status, result = run_main(["assemble", str(self.draft), *self.receipts(*PEOPLE), "--out", str(out)], Es256Vitni())
        self.assertEqual((status, result["state"]), (0, "complete"))
        kids = sorted(d["kid"] for d in self.org.doc["devices"])
        self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(["lineage.json"] + ["ceremony-%s.json" % k for k in kids]))
        lineage = ijson.loads((out / "lineage.json").read_bytes())
        self.assertEqual(set(lineage), {"acts", "lineage"})
        self.assertEqual(lineage["acts"], [])
        for kid in kids:
            raw = (out / ("ceremony-%s.json" % kid)).read_bytes()
            value = ijson.loads(raw)
            self.assertEqual(set(value), {"acts", "device_kid", "lineage"})
            self.assertEqual((value["device_kid"], value["lineage"]), (kid, lineage["lineage"]))
            self.assertEqual(raw, emit.emit_subset(value) + b"\n")
        self.assertEqual(lineage["lineage"][0]["sigs"], sorted(lineage["lineage"][0]["sigs"]))
        # the file is a valid `genesis-check` input and the checker gives the same pin
        table = commands.table(commands.Build(False, False), Es256Vitni())
        checked = table["genesis-check"].handler(lineage)
        self.assertEqual((checked["valid"], checked["pin"]), (True, result["pin"]))

    def test_assemble_out_writes_nothing_unless_complete(self):   # R2.6
        out = self.dir / "out"
        status, result = run_main(["assemble", str(self.draft), *self.receipts("alice"), "--out", str(out)], Es256Vitni())
        self.assertEqual((status, result["state"], out.exists()), (0, "partial", False))

    def test_assemble_out_never_replaces_a_directory(self):   # R2.6
        out = self.dir / "out"
        out.mkdir()
        status, result = run_main(["assemble", str(self.draft), *self.receipts(*PEOPLE), "--out", str(out)], Es256Vitni())
        self.assertEqual((status, result["error"], list(out.iterdir())), (2, "file_exists", []))

    def test_unavailable_verifiers_give_verifier_unavailable_through_main(self):   # S2.14
        receipts = self.receipts("alice")
        for name, vitni in (("absent", verifier.Absent()),
                            ("missing binary", verifier.VitniCli([sys.executable, "/nonexistent/vitni"], owner_check=None))):
            with self.subTest(verifier=name):
                status, result = run_main(["assemble", str(self.draft), *receipts], vitni)
                self.assertEqual((status, result), (2, {"error": "verifier_unavailable"}))

    def test_assemble_complete_with_real_vitni_or_asserts_verifier_unavailable(self):   # S2.6
        argv = verifier.INSTALLED.get(sys.platform)
        try:
            verifier.check_admin_owned(argv[0])
            branch = "an administrator-owned vitni is installed at its fixed path"
        except (TypeError, verifier.VerifierUnavailable):
            branch = "no usable vitni is installed at its fixed path"
        status, result = run_main(["assemble", str(self.draft), *self.receipts(*PEOPLE)], verifier.VitniCli.installed())
        if branch.startswith("an"):
            self.assertEqual((status, result["state"]), (0, "complete"), branch)
            direct = genesis_check.run(genesis_check.GenesisInput([], [{"doc": self.org.doc, "sigs": sorted(
                ijson.loads(raw)["jws"] for raw in (Path(p).read_bytes() for p in self.receipts(*PEOPLE)))}]),
                self.org.profile_set, False, verifier.VitniCli.installed())
            self.assertEqual(result["pin"], direct["pin"], branch)
        else:
            self.assertEqual((status, result), (2, {"error": "verifier_unavailable"}), branch)


class Confinement(unittest.TestCase):
    def test_only_throwaway_imports_cryptography(self):   # S3.14
        tools = sorted(TOOLS.glob("genesis_*.py"))
        self.assertEqual([p.name for p in tools], ["genesis_build.py", "genesis_throwaway.py"])
        importing = [p.name for p in tools if "cryptography" in imported_modules(p)]
        self.assertEqual(importing, ["genesis_throwaway.py"])


if __name__ == "__main__":
    unittest.main()
