"""T3.6 CLI dispatch with `subset` and `kid` (CF-03, ACT-11)."""
import io
import json
import unittest
from pathlib import Path

from handsal_check import conformance, production

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
ALICE = KEYS["alice.sign"]
POINT = {"x": ALICE["x"], "y": ALICE["y"]}
MAX = 16777216


def run(main, command, stdin_bytes):
    out = io.BytesIO()
    code = main([command] if command is not None else [], io.BytesIO(stdin_bytes), out)
    return code, out.getvalue()


def enc(value):
    return json.dumps(value, separators=(",", ":")).encode()


class BothBuilds(unittest.TestCase):
    """The pure commands exist in both builds and answer the same."""
    builds = (("production", production.main), ("conformance", conformance.main))

    def each(self):
        for label, main in self.builds:
            yield label, main

    def expect(self, command, stdin_bytes, line):
        for label, main in self.each():
            code, out = run(main, command, stdin_bytes)
            self.assertEqual((code, out), (0, line + b"\n"), label)

    def test_unsupported_command(self):
        self.expect("x", b"{}", b'{"error":"unsupported_command"}')
        self.expect(None, b"{}", b'{"error":"unsupported_command"}')

    def test_unknown_command_wins_over_bad_stdin(self):
        self.expect("x", b"not json", b'{"error":"unsupported_command"}')

    def test_all_eight_commands_exist_in_both_builds(self):
        for command in ("check-act", "recheck-act", "fold", "enrolled", "genesis-check", "render"):
            self.expect(command, b"{}", b'{"error":"malformed_input"}')
        self.expect("kid", b"{}", b'{"error":"malformed_input"}')
        code, out = run(production.main, "subset", b"{}")   # `subset` takes raw bytes: it answers, never errors
        self.assertEqual((code, run(conformance.main, "subset", b"{}")), (0, (0, out)))

    def test_the_commands_are_not_wired_under_another_name(self):
        for command in ("build", "emit", "pin-read", "Enrolled"):
            self.expect(command, b"{}", b'{"error":"unsupported_command"}')

    def test_kid_known_answer(self):
        self.expect("kid", enc(POINT), b'{"kid":"%s"}' % ALICE["kid"].encode())

    def test_kid_unparseable(self):
        self.expect("kid", b"not json", b'{"error":"unparseable_input"}')
        self.expect("kid", b"", b'{"error":"unparseable_input"}')

    def test_kid_duplicate_member_name(self):
        raw = b'{"x":"%s","x":"%s","y":"%s"}' % (ALICE["x"].encode(), ALICE["x"].encode(),
                                                 ALICE["y"].encode())
        self.expect("kid", raw, b'{"error":"unparseable_input"}')

    def test_kid_over_max_input_is_unparseable(self):
        doc = dict(POINT)
        doc["x"] += "a" * (MAX + 1 - len(enc(POINT)))
        raw = enc(doc)
        self.assertEqual(len(raw), MAX + 1)
        self.expect("kid", raw, b'{"error":"unparseable_input"}')

    def test_kid_malformed_input(self):
        for doc in ({"x": ALICE["x"]}, {"y": ALICE["y"]}, {}, [], "x", None,
                    {"x": 1, "y": ALICE["y"]}, {"x": ALICE["x"], "y": None},
                    dict(POINT, z="a"), {"x": "é", "y": ALICE["y"]}):
            self.expect("kid", enc(doc), b'{"error":"malformed_input"}')

    def test_subset_accepts_and_rejects_raw_bytes(self):
        self.expect("subset", b'{"a":"b"}', b'{"canonical":true,"reason":"ok"}')
        self.expect("subset", b'{"b":"x","a":"y"}',
                    b'{"canonical":false,"reason":"payload_not_canonical_subset"}')
        self.expect("subset", b"\xc3\x28",
                    b'{"canonical":false,"reason":"payload_not_canonical_subset"}')
        self.expect("subset", b'"' + b"a" * 16383 + b'"',
                    b'{"canonical":false,"reason":"payload_too_large"}')

    def test_subset_does_not_apply_the_ijson_rules(self):
        # a duplicate key is a grammar reject for `subset`, not unparseable_input
        self.expect("subset", b'{"a":"x","a":"y"}',
                    b'{"canonical":false,"reason":"payload_not_canonical_subset"}')

    def test_subset_over_max_input_is_unparseable(self):
        self.expect("subset", b'"' + b"a" * (MAX - 1) + b'"',
                    b'{"error":"unparseable_input"}')

    def test_output_is_one_line_and_exit_zero(self):
        for label, main in self.each():
            code, out = run(main, "kid", enc(POINT))
            self.assertEqual(code, 0)
            self.assertEqual(out.count(b"\n"), 1)
            self.assertTrue(out.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
