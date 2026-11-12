"""T3.4 canonical subset recognizer (ACT-04), grammar only."""
import json
import unittest
from pathlib import Path

from handsal_check import subset

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "conformance" / "vectors"
BAD = "payload_not_canonical_subset"
BIG = "payload_too_large"


def verdict(raw):
    return subset.recognize(raw)


class Limits(unittest.TestCase):
    def test_constants(self):
        self.assertEqual((subset.MAX_PAYLOAD, subset.MAX_DEPTH), (16384, 8))


class Accepts(unittest.TestCase):
    def test_table(self):
        for raw in (b"{}", b"[]", b'""', b"null", b'"a/b"', b'{"a":null}',
                    b'{"a":[],"b":{}}', b'{"a":"x","b":["y",null,{"c":"z"}]}',
                    b'"a b ~"', b'{"A":"x","a":"y"}'):
            self.assertEqual(verdict(raw), (True, "ok"), raw)

    def test_depth_eight_is_fine_nine_is_not(self):
        self.assertEqual(verdict(b"[" * 8 + b"]" * 8), (True, "ok"))
        self.assertEqual(verdict(b"[" * 9 + b"]" * 9), (False, BAD))
        self.assertEqual(verdict(b'{"a":' * 7 + b"{}" + b"}" * 7), (True, "ok"))
        self.assertEqual(verdict(b'{"a":' * 8 + b"{}" + b"}" * 8), (False, BAD))

    def test_size_limit(self):
        self.assertEqual(verdict(b'"' + b"a" * 16382 + b'"'), (True, "ok"))
        self.assertEqual(verdict(b'"' + b"a" * 16383 + b'"'), (False, BIG))

    def test_deep_input_over_the_limit_does_not_recurse_into_a_crash(self):
        self.assertEqual(verdict(b"[" * 16384), (False, BAD))


class Rejects(unittest.TestCase):
    def test_table(self):
        cases = {
            "number": b'{"a":1}', "negative": b"-1", "true": b'{"a":true}',
            "false": b"[false]", "nan": b"NaN",
            "dup top": b'{"a":"x","a":"y"}', "dup nested": b'{"a":{"b":"x","b":"y"}}',
            "unsorted": b'{"b":"x","a":"y"}', "unsorted case": b'{"a":"x","A":"y"}',
            "space": b'{"a": "x"}', "space after comma": b'["a", "b"]',
            "newline": b'{"a":"x"}\n', "leading space": b' {}',
            "slash escape": b'{"a":"\\/"}', "quote escape": b'{"a":"\\""}',
            "u0041": b'{"a":"\\u0041"}', "lone surrogate": b'{"a":"\\ud800"}',
            "upper hex": b'{"a":"\\u00E9"}', "newline escape": b'"\\n"',
            "raw e9": "{\"a\":\"é\"}".encode(), "del": b'{"a":"\x7f"}',
            "u2028": "{\"a\":\" \"}".encode(), "raw newline": b'{"a":"x\ny"}',
            "raw tab": b'"\t"', "bom": b"\xef\xbb\xbf{}", "bad utf8": b"\xc3\x28",
            "key non ascii": "{\"é\":\"x\"}".encode(),
            "trailing": b"{}x", "two values": b"{}{}", "empty": b"",
            "trailing comma": b'["a",]', "leading comma": b"[,]", "missing colon": b'{"a""b"}',
            "unterminated string": b'"abc', "unterminated object": b'{"a":"b"',
            "unterminated array": b"[", "bare word": b"nul", "nullx": b"nullx",
            "single quotes": b"{'a':'b'}", "key not string": b"{null:null}",
            "empty key then dup": b'{"":"a","":"b"}',
        }
        for label, raw in cases.items():
            self.assertEqual(verdict(raw), (False, BAD), label)

    def test_size_beats_grammar(self):
        self.assertEqual(verdict(b"\xff" * 16385), (False, BIG))


class Vectors(unittest.TestCase):
    """Every `jcs/*` and subset row of the shipped vectors, as a table test."""

    def rows(self):
        out = []
        for path in sorted(VECTORS.glob("*.json")):
            doc = json.loads(path.read_text())
            if doc["command"] == "subset":
                raw = (doc["input_raw"].encode("utf-8") if "input_raw" in doc
                       else bytes.fromhex(doc["input_hex"]))
                out.append((doc["name"], raw, doc["anchor"]))
        return out

    def test_the_rows_exist(self):
        names = [n for n, _, _ in self.rows()]
        self.assertGreaterEqual(len([n for n in names if n.startswith("jcs/")]), 30)

    def test_anchors(self):
        for name, raw, anchor in self.rows():
            ok, reason = subset.recognize(raw)
            line = '{"canonical":%s,"reason":"%s"}' % ("true" if ok else "false", reason)
            self.assertEqual(line, anchor, name)


class Parse(unittest.TestCase):
    def test_parse_returns_the_value(self):
        self.assertEqual(subset.parse(b'{"a":[null,"x"],"b":{}}'),
                         {"a": [None, "x"], "b": {}})

    def test_parse_raises_with_the_reason(self):
        with self.assertRaises(subset.SubsetError) as ctx:
            subset.parse(b'{"a":1}')
        self.assertEqual(ctx.exception.reason, BAD)
        with self.assertRaises(subset.SubsetError) as ctx:
            subset.parse(b"a" * 16385)
        self.assertEqual(ctx.exception.reason, BIG)


if __name__ == "__main__":
    unittest.main()
