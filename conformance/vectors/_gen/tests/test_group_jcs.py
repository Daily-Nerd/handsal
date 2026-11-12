"""T3.1 vectors jcs/* (ACT-04, ACT-05).

Checks the generated files against an independent statement of what each row
must hold, then against the generator's own recognizer (lib/jcs.py).
"""
import json
import tempfile
import unittest
from pathlib import Path

import generate
from lib import jcs, result

OK = result.line({"canonical": True, "reason": "ok"})
BAD = result.line({"canonical": False, "reason": "payload_not_canonical_subset"})
BIG = result.line({"canonical": False, "reason": "payload_too_large"})

ACCEPT = {"jcs/depth-8-ok", "jcs/null-where-allowed", "jcs/raw-slash-ok",
          "jcs/empty-containers-ok"}
REJECT = {
    "jcs/number-anywhere", "jcs/true-literal", "jcs/dup-key-top", "jcs/dup-key-ext",
    "jcs/dup-key-body", "jcs/unsorted-keys", "jcs/whitespace", "jcs/escape-slash",
    "jcs/escape-quote", "jcs/escape-u0041", "jcs/escape-lone-surrogate",
    "jcs/escape-upper-hex", "jcs/raw-non-ascii-e9", "jcs/raw-del", "jcs/raw-u2028",
    "jcs/raw-newline-in-string", "jcs/bom", "jcs/invalid-utf8", "jcs/key-non-ascii",
    "jcs/depth-9", "jcs/trailing-bytes", "jcs/empty-input",
}
TOO_BIG = {"jcs/oversize"}
PAYLOAD = {"jcs/payload-null", "jcs/payload-array"}


def stdin_bytes(vector):
    if "input_raw" in vector:
        return vector["input_raw"].encode("utf-8")
    return bytes.fromhex(vector["input_hex"])


class Jcs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name)
        import groups.jcs as module
        generate.run(out, registry=[module], known_ids=generate.shipping_ids())
        cls.vectors = {}
        for path in sorted(out.glob("jcs.*.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            cls.vectors[doc["name"]] = doc

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_grammar_rows_are_all_written_and_nothing_else(self):
        self.assertEqual(set(self.vectors), ACCEPT | REJECT | TOO_BIG | PAYLOAD)

    def test_the_payload_rows_are_signed_acts_checked_by_check_act(self):
        from lib import base, es256, forge, inputs
        fx = base.Fixtures(base.fixture_profile())
        for name, root in (("jcs/payload-null", b"null"), ("jcs/payload-array", b"[]")):
            v = self.vectors[name]
            self.assertEqual(v["command"], "check-act", name)
            header, payload, sig = forge.parts(v["input"]["jws"])
            self.assertEqual(payload, root, name)
            alice = fx.key("alice")
            self.assertTrue(es256.verify((alice.x_int, alice.y_int),
                                         v["input"]["jws"].rsplit(".", 1)[0].encode(), sig), name)
            self.assertEqual(v["anchor"], inputs.check_anchor(v["input"]["jws"],
                                                              "payload_not_canonical_subset"))

    def test_all_use_the_subset_command_on_raw_bytes(self):
        for name, v in self.vectors.items():
            if name in PAYLOAD:
                continue
            self.assertEqual(v["command"], "subset", name)
            self.assertNotIn("input", v, name)
            self.assertNotIn("pad", v, name)
            self.assertNotIn("exit", v, name)

    def test_anchors(self):
        for name, v in self.vectors.items():
            if name in PAYLOAD:
                continue
            want = OK if name in ACCEPT else BIG if name in TOO_BIG else BAD
            self.assertEqual(v["anchor"], want, name)

    def test_agree_with_the_generator_recognizer(self):
        for name, v in self.vectors.items():
            if name in PAYLOAD:
                continue
            good, reason = jcs.recognize(stdin_bytes(v))
            doc = {"canonical": good, "reason": reason or "ok"}
            self.assertEqual(v["anchor"], result.line(doc), name)

    def test_exact_bytes_of_the_named_rows(self):
        raw = {n: stdin_bytes(v) for n, v in self.vectors.items() if n not in PAYLOAD}
        self.assertEqual(raw["jcs/bom"], b"\xef\xbb\xbf{}")
        self.assertEqual(raw["jcs/invalid-utf8"], b"\xc3\x28")
        self.assertEqual(raw["jcs/empty-input"], b"")
        self.assertEqual(raw["jcs/trailing-bytes"], b"{}x")
        self.assertEqual(raw["jcs/raw-del"], b'{"a":"\x7f"}')
        self.assertEqual(raw["jcs/raw-slash-ok"], b'"a/b"')
        self.assertEqual(raw["jcs/empty-containers-ok"], b'{"a":[],"b":{}}')
        self.assertEqual(raw["jcs/unsorted-keys"], b'{"b":"x","a":"y"}')
        self.assertEqual(raw["jcs/whitespace"], b'{"a": "x"}')
        self.assertEqual(raw["jcs/escape-lone-surrogate"], b'{"a":"\\ud800"}')
        self.assertEqual(raw["jcs/escape-upper-hex"], b'{"a":"\\u00E9"}')
        self.assertEqual(len(raw["jcs/oversize"]), jcs.MAX_PAYLOAD + 1)

    def test_depth_rows_are_exactly_at_and_over_the_limit(self):
        def depth(raw):
            cur = best = 0
            for byte in raw:
                if byte in b"[{":
                    cur += 1
                    best = max(best, cur)
                elif byte in b"]}":
                    cur -= 1
            return best
        self.assertEqual(depth(stdin_bytes(self.vectors["jcs/depth-8-ok"])), jcs.MAX_DEPTH)
        self.assertEqual(depth(stdin_bytes(self.vectors["jcs/depth-9"])), jcs.MAX_DEPTH + 1)

    def test_each_duplicate_row_has_sorted_keys_apart_from_the_duplicate(self):
        # only-defect: the duplicated pair is the sole reason for the reject
        for name in ("jcs/dup-key-top", "jcs/dup-key-ext", "jcs/dup-key-body"):
            raw = stdin_bytes(self.vectors[name])
            fixed = raw.replace(b'"a":"y"', b'"b":"y"')
            self.assertNotEqual(raw, fixed, name)
            self.assertEqual(jcs.recognize(fixed), (True, None), name)


if __name__ == "__main__":
    unittest.main()
