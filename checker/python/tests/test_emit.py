"""T3.5 emitters (ACT-05): the subset emitter and the result-line serializer."""
import json
import unittest
from pathlib import Path

from handsal_check import emit, subset

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "conformance" / "vectors"


class SubsetEmitter(unittest.TestCase):
    def test_sorted_keys_no_whitespace_slash_unescaped(self):
        self.assertEqual(emit.emit_subset({"b": ["x", None], "a": {"c": "a/b"}}),
                         b'{"a":{"c":"a/b"},"b":["x",null]}')

    def test_arrays_keep_the_given_order(self):
        self.assertEqual(emit.emit_subset(["b", "a"]), b'["b","a"]')

    def test_keys_sort_by_byte_order(self):
        self.assertEqual(emit.emit_subset({"a": "1", "B": "2", "_": "3"}),
                         b'{"B":"2","_":"3","a":"1"}')

    def test_refuses_what_the_subset_cannot_express(self):
        for bad in (1, 1.5, True, False, b"x", ("a",), {"a": 1}, ["é"], {"é": "x"},
                    'q"', "b\\", "x\n", {1: "a"}):
            with self.assertRaises(emit.EmitError, msg=repr(bad)):
                emit.emit_subset(bad)

    def test_refuses_nesting_deeper_than_eight(self):
        value = "x"
        for _ in range(8):
            value = [value]
        emit.emit_subset(value)
        with self.assertRaises(emit.EmitError):
            emit.emit_subset([value])

    def test_refuses_over_max_payload(self):
        with self.assertRaises(emit.EmitError):
            emit.emit_subset("a" * 16383)

    def test_round_trip_over_every_accepted_subset_row(self):
        count = 0
        for path in sorted(VECTORS.glob("jcs.*.json")):
            doc = json.loads(path.read_text())
            if doc["command"] != "subset" or '"canonical":true' not in doc["anchor"]:
                continue
            raw = doc["input_raw"].encode("utf-8")
            self.assertEqual(emit.emit_subset(subset.parse(raw)), raw, doc["name"])
            count += 1
        self.assertGreaterEqual(count, 8)


class ResultLine(unittest.TestCase):
    def test_sorted_keys_and_literals(self):
        self.assertEqual(emit.emit_result({"reason": "ok", "canonical": True}),
                         b'{"canonical":true,"reason":"ok"}')
        self.assertEqual(emit.emit_result({"b": [1, None, False, {}], "a": 0}),
                         b'{"a":0,"b":[1,null,false,{}]}')

    def test_utf16_key_order_and_minimal_escapes(self):
        self.assertEqual(emit.emit_result({"～": 1, "\U0001f600": 2}),
                         '{"\U0001f600":2,"～":1}'.encode("utf-8"))
        self.assertEqual(emit.emit_result({"a": 'q"b\\n\n\t\x01/é'}),
                         '{"a":"q\\"b\\\\n\\n\\t\\u0001/é"}'.encode("utf-8"))

    def test_refuses_floats_and_other_types(self):
        for bad in (1.5, (1,), {1}, b"x", float("nan")):
            with self.assertRaises(emit.EmitError):
                emit.emit_result({"a": bad})
        with self.assertRaises(emit.EmitError):
            emit.emit_result({1: "a"})

    def test_bool_is_not_an_int(self):
        self.assertEqual(emit.emit_result([True, 1]), b"[true,1]")

    def test_equal_input_equal_bytes(self):
        a = emit.emit_result({"x": "1", "y": "2"})
        b = emit.emit_result({"y": "2", "x": "1"})
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
