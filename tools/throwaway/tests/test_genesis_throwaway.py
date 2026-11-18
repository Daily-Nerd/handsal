"""The throwaway genesis tool: software keys that sign receipts the checker accepts.

The tool holds no rule. It fills the signer's payload from the checker's own constants, and the checker's reader
decides whether a receipt counts. A test compares against the signer's published bytes or against the checker.
"""
import ast
import json
import re
import sys
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
from handsal_check import encoding, genesis, genesis_sigs, profiles, verifier  # noqa: E402

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


class Confinement(unittest.TestCase):
    def test_only_throwaway_imports_cryptography(self):   # S3.14
        tools = sorted(TOOLS.glob("genesis_*.py"))
        self.assertEqual([p.name for p in tools], ["genesis_build.py", "genesis_throwaway.py"])
        importing = [p.name for p in tools if "cryptography" in imported_modules(p)]
        self.assertEqual(importing, ["genesis_throwaway.py"])


if __name__ == "__main__":
    unittest.main()
