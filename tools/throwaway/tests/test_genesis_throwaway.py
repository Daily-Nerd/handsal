"""The throwaway genesis tool: software keys that sign receipts the checker accepts.

The tool holds no rule. It fills the signer's payload from the checker's own constants, and the checker's reader
decides whether a receipt counts. A test compares against the signer's published bytes or against the checker.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import genesis_build  # noqa: E402,F401  (first: it pins the checker of this checkout)
import genesis_throwaway  # noqa: E402

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


class Confinement(unittest.TestCase):
    def test_only_throwaway_imports_cryptography(self):   # S3.14
        tools = sorted(TOOLS.glob("genesis_*.py"))
        self.assertEqual([p.name for p in tools], ["genesis_build.py", "genesis_throwaway.py"])
        importing = [p.name for p in tools if "cryptography" in imported_modules(p)]
        self.assertEqual(importing, ["genesis_throwaway.py"])


if __name__ == "__main__":
    unittest.main()
