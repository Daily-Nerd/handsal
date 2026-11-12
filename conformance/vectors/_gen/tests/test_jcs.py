"""T2.2 generator JCS emitter (ACT-04, ACT-05, CF-06).

The emitter is the generator's own; it never imports the checker. Known
answers come from the catalog (`jcs/*` rows). RFC 8785 examples that use
numbers, escapes or non-ASCII are outside the profile subset, so only the
examples that stay inside it (empty containers, null, key sorting of ASCII
keys) are reused.
"""
import unittest

from lib import jcs


class EmitKnownAnswers(unittest.TestCase):
    def test_sorted_keys(self):
        # jcs/unsorted-keys input, canonical form
        self.assertEqual(jcs.emit({"b": "x", "a": "y"}), b'{"a":"y","b":"x"}')

    def test_empty_containers(self):
        # jcs/empty-containers-ok
        self.assertEqual(jcs.emit({"a": [], "b": {}}), b'{"a":[],"b":{}}')

    def test_null_where_allowed(self):
        # jcs/null-where-allowed
        self.assertEqual(jcs.emit({"a": None}), b'{"a":null}')

    def test_slash_is_raw(self):
        # jcs/raw-slash-ok and jcs/emit-slash-raw
        self.assertEqual(jcs.emit("a/b"), b'"a/b"')
        self.assertEqual(jcs.emit({"label": "a/b"}), b'{"label":"a/b"}')

    def test_array_order_preserved(self):
        self.assertEqual(jcs.emit(["b", "a", None]), b'["b","a",null]')

    def test_no_whitespace_outside_strings(self):
        self.assertEqual(jcs.emit({"a": "x y"}), b'{"a":"x y"}')

    def test_byte_order_not_locale_order(self):
        # 'B' (0x42) sorts before 'a' (0x61); '_' (0x5F) between them.
        self.assertEqual(
            jcs.emit({"a": "1", "_": "2", "B": "3"}),
            b'{"B":"3","_":"2","a":"1"}',
        )

    def test_nested_sort(self):
        self.assertEqual(
            jcs.emit({"z": {"y": None, "x": []}, "a": [{"d": "1", "c": "2"}]}),
            b'{"a":[{"c":"2","d":"1"}],"z":{"x":[],"y":null}}',
        )

    def test_returns_bytes(self):
        self.assertIsInstance(jcs.emit({}), bytes)

    def test_emit_is_deterministic_over_insertion_order(self):
        a = {"k1": "v", "k2": None, "k3": ["x"]}
        b = {"k3": ["x"], "k2": None, "k1": "v"}
        self.assertEqual(jcs.emit(a), jcs.emit(b))


class EmitRefusals(unittest.TestCase):
    def refuses(self, value):
        with self.assertRaises(jcs.JcsError):
            jcs.emit(value)

    def test_numbers(self):
        # jcs/number-anywhere, jcs/emit-value-with-number-refused
        self.refuses({"a": 1})
        self.refuses({"a": 1.5})
        self.refuses(0)

    def test_booleans(self):
        # ACT-04: no true/false (bool is an int subclass in Python)
        self.refuses({"a": True})
        self.refuses({"a": False})
        self.refuses(True)

    def test_non_ascii_string(self):
        self.refuses({"a": "é"})
        self.refuses(" ")

    def test_non_ascii_key(self):
        self.refuses({"é": "x"})

    def test_del_and_controls(self):
        self.refuses("a\x7fb")
        self.refuses("a\nb")
        self.refuses("a\tb")
        self.refuses("a\x00b")

    def test_quote_and_backslash_in_string(self):
        # the subset has no escapes, so these two cannot be written at all
        self.refuses('a"b')
        self.refuses("a\\b")

    def test_quote_and_backslash_in_key(self):
        self.refuses({'a"b': "x"})
        self.refuses({"a\\b": "x"})

    def test_non_string_key(self):
        self.refuses({1: "x"})
        self.refuses({None: "x"})

    def test_bytes_and_tuples_and_sets(self):
        self.refuses(b"abc")
        self.refuses(("a",))
        self.refuses({"a"})

    def test_depth_limit(self):
        def nest(n):
            v = None
            for _ in range(n):
                v = {"a": v}
            return v

        jcs.emit(nest(8))  # jcs/depth-8-ok
        self.refuses(nest(9))  # jcs/depth-9

    def test_depth_counts_arrays(self):
        v = None
        for _ in range(9):
            v = [v]
        self.refuses(v)

    def test_size_limit(self):
        # jcs/oversize: 16385 bytes is too large, 16384 fits
        fits = {"a": "x" * (16384 - len('{"a":""}'))}
        self.assertEqual(len(jcs.emit(fits)), 16384)
        over = {"a": "x" * (16384 - len('{"a":""}') + 1)}
        with self.assertRaises(jcs.JcsError) as cm:
            jcs.emit(over)
        self.assertEqual(cm.exception.reason, "payload_too_large")

    def test_reasons(self):
        with self.assertRaises(jcs.JcsError) as cm:
            jcs.emit({"a": 1})
        self.assertEqual(cm.exception.reason, "payload_not_canonical_subset")

    def test_cyclic_value_is_refused_not_looped(self):
        d = {}
        d["a"] = d
        self.refuses(d)


class Recognize(unittest.TestCase):
    """The generator's own recognizer, used only for the ACT-05 round trip."""

    def ok(self, raw):
        self.assertEqual(jcs.recognize(raw), (True, None), raw)

    def bad(self, raw, reason="payload_not_canonical_subset"):
        self.assertEqual(jcs.recognize(raw), (False, reason), raw)

    def test_accepts_catalog_ok_rows(self):
        self.ok(b'{"a":null}')
        self.ok(b'"a/b"')
        self.ok(b'{"a":[],"b":{}}')
        self.ok(b"[" * 8 + b"]" * 8)

    def test_rejects_catalog_reject_rows(self):
        self.bad(b'{"a":1}')  # number-anywhere
        self.bad(b'{"a":true}')  # true-literal
        self.bad(b'{"b":"x","a":"y"}')  # unsorted-keys
        self.bad(b'{"a": "x"}')  # whitespace
        self.bad(b'{"a":"\\/"}')  # escape-slash
        self.bad(b'{"a":"\\""}')  # escape-quote
        self.bad(b'{"a":"\\u0041"}')  # escape-u0041
        self.bad(b'{"a":"\\ud800"}')  # lone surrogate
        self.bad('{"a":"é"}'.encode("utf-8"))  # raw non-ascii
        self.bad(b'{"a":"\x7f"}')  # raw-del
        self.bad('{"a":" "}'.encode("utf-8"))  # raw-u2028
        self.bad(b'{"a":"x\ny"}')  # raw newline in string
        self.bad(b'\xef\xbb\xbf{}')  # bom
        self.bad(b'{"a":"\xc3\x28"}')  # invalid utf-8
        self.bad('{"é":"x"}'.encode("utf-8"))  # key-non-ascii
        self.bad(b"[" * 9 + b"]" * 9)  # depth-9
        self.bad(b"{}x")  # trailing bytes
        self.bad(b"")  # empty input
        self.bad(b'{"a":"x","a":"y"}')  # dup key
        self.bad(b'{"a":{"b":"x","b":"y"}}')  # dup key nested

    def test_oversize_reason(self):
        self.bad(b'{"a":"' + b"x" * 16380 + b'"}', "payload_too_large")

    def test_roundtrip_identity(self):
        # ACT-05: emit then recognize then compare is the identity
        samples = [
            {}, [], None, "a/b",
            {"b": {"d": ["x", None, {}], "c": "y"}, "a": []},
            {"ext": {"dev.handsal/act": {"body": {"z": "1", "a": None}}}},
        ]
        for value in samples:
            raw = jcs.emit(value)
            self.ok(raw)


if __name__ == "__main__":
    unittest.main()
