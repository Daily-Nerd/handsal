"""The generator is an independent oracle: it keeps its own copy of each registry number, so a bug
in an implementation's reading of the registry does not move the expected output with it. An
independent copy is a real check only while it equals the file, so this test compares each one
with `spec/registry.json`, the one owner of the numbers (section 2.3)."""
import json
import unittest
from pathlib import Path

from lib import jcs, render, signer_emit

ROOT = Path(__file__).resolve().parents[4]
CONSTANTS = json.loads((ROOT / "spec" / "registry.json").read_text(encoding="utf-8"))["constants"]


def number(*path):
    node = CONSTANTS
    for key in path:
        node = node[key]
    return int(node["value"] if isinstance(node, dict) and "value" in node else node)


class GeneratorNumbers(unittest.TestCase):
    def test_every_copy_is_the_registry_number(self):
        copies = {
            "jcs.MAX_PAYLOAD": (jcs.MAX_PAYLOAD, number("MAX_PAYLOAD")),
            "jcs.MAX_DEPTH": (jcs.MAX_DEPTH, number("MAX_DEPTH")),
            "signer_emit.MAX_INPUT": (signer_emit.MAX_INPUT, number("MAX_INPUT")),
            "signer_emit.MAX_EXPIRES_IN_S": (signer_emit.MAX_EXPIRES_IN_S, number("MAX_EXPIRES_IN_S")),
            "render.MAX_LINES": (render.MAX_LINES, number("render_length", "max")),
            "render.MAX_REQUEST": (render.MAX_REQUEST, number("content_block", "max_source_bytes")),
            "render.MAX_REQUEST_LINES": (render.MAX_REQUEST_LINES, number("content_block", "max_block_lines")),
            "render.MAX_ESCAPED": (render.MAX_ESCAPED, number("content_block", "max_escaped_bytes_per_line")),
            "render.MAX_LINE": (render.MAX_LINE, number("render_line", "max")),
            "render.MAX_WRAP": (render.MAX_WRAP, number("render_line", "wrap_segment_max")),
        }
        for name, (copy, owner) in copies.items():
            with self.subTest(copy=name):
                self.assertEqual(copy, owner)


if __name__ == "__main__":
    unittest.main()
