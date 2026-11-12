"""T3.1 vectors cli/* base rows (CF-03, ACT-11).

The framing rows use `kid`: framing runs before any command logic (CF-03), so
the row does not depend on which command carries it.
"""
import json
import tempfile
import unittest
from pathlib import Path

import generate
from lib import keys, result

ROWS = {"cli/unsupported-command", "cli/unparseable-stdin", "cli/malformed-input",
        "cli/stdin-duplicate-key-unparseable", "cli/stdin-over-max-input-unparseable",
        "cli/kid-ok", "cli/kid-leading-zero", "cli/output-is-jcs",
        "cli/jcs-profile-recognize", "cli/render-shape"}


class CliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name)
        import groups.cli_base as module
        generate.run(out, registry=[module], known_ids=generate.shipping_ids())
        cls.v = {}
        for path in sorted(out.glob("cli.*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            cls.v[doc["name"]] = doc

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_written_rows(self):
        self.assertEqual(set(self.v), ROWS)

    def test_unsupported_command(self):
        v = self.v["cli/unsupported-command"]
        self.assertEqual((v["command"], v["input"]), ("x", {}))
        self.assertEqual(v["anchor"], '{"error":"unsupported_command"}')

    def test_unparseable_stdin_is_not_json(self):
        v = self.v["cli/unparseable-stdin"]
        self.assertIn(v["command"], ("kid",))
        self.assertEqual(v["input_raw"], "not json")
        self.assertEqual(v["anchor"], '{"error":"unparseable_input"}')

    def test_malformed_input_is_a_missing_key(self):
        v = self.v["cli/malformed-input"]
        self.assertEqual(v["command"], "kid")
        self.assertEqual(set(v["input"]), {"x"})
        self.assertEqual(v["anchor"], '{"error":"malformed_input"}')

    def test_duplicate_key_row_has_one_duplicate_and_is_otherwise_valid_json(self):
        v = self.v["cli/stdin-duplicate-key-unparseable"]
        self.assertEqual(v["command"], "kid")
        text = v["input_raw"]
        pairs = []
        json.loads(text, object_pairs_hook=lambda p: pairs.append([k for k, _ in p]) or dict(p))
        self.assertTrue(any(len(p) != len(set(p)) for p in pairs))
        self.assertEqual(v["anchor"], '{"error":"unparseable_input"}')

    def test_over_max_input_row_is_padded_by_the_harness(self):
        v = self.v["cli/stdin-over-max-input-unparseable"]
        self.assertEqual(v["command"], "kid")
        self.assertEqual(v["pad"], ["x"])
        self.assertIsInstance(v["input"]["x"], str)
        self.assertEqual(v["anchor"], '{"error":"unparseable_input"}')

    def test_kid_ok_is_the_fixture_thumbprint(self):
        v = self.v["cli/kid-ok"]
        entry = json.loads((Path(generate.CONFORMANCE) / "fixtures" / "keys.json")
                           .read_text())["keys"]["alice.sign"]
        self.assertEqual(v["input"], {"x": entry["x"], "y": entry["y"]})
        self.assertEqual(v["anchor"], result.line({"kid": entry["kid"]}))

    def test_kid_leading_zero_has_a_zero_first_byte_and_is_on_curve(self):
        import base64
        from lib import p256
        v = self.v["cli/kid-leading-zero"]
        raw = base64.urlsafe_b64decode(v["input"]["x"] + "=")
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[0], 0)
        x = int.from_bytes(raw, "big")
        y = int.from_bytes(base64.urlsafe_b64decode(v["input"]["y"] + "="), "big")
        self.assertTrue(p256.on_curve((x, y)))
        self.assertEqual(v["anchor"],
                         result.line({"kid": keys.thumbprint(v["input"]["x"], v["input"]["y"])}))

    def test_render_shape_is_an_approve_render_with_the_two_output_keys(self):
        v = self.v["cli/render-shape"]
        self.assertEqual(v["command"], "render")
        self.assertEqual(sorted(v["input"]), ["attachments", "kid", "method", "payload"])
        self.assertEqual(sorted(json.loads(v["anchor"])), ["first_line", "text"])

    def test_subset_rows(self):
        self.assertEqual(self.v["cli/jcs-profile-recognize"]["command"], "subset")
        self.assertEqual(self.v["cli/jcs-profile-recognize"]["anchor"],
                         '{"canonical":true,"reason":"ok"}')
        out = self.v["cli/output-is-jcs"]
        self.assertEqual(out["command"], "subset")
        self.assertEqual(out["anchor"],
                         '{"canonical":false,"reason":"payload_not_canonical_subset"}')


if __name__ == "__main__":
    unittest.main()
