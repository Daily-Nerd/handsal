"""Anchor lines: the checker's result objects as one JCS line (CF-03, RFC 8785).

A result line is not the signed subset: it has booleans and integers. This
module is the generator's own serializer for it, independent of the checker.
"""
import unittest

from lib import result


class Lines(unittest.TestCase):
    def test_sorted_keys_no_whitespace(self):
        self.assertEqual(result.line({"reason": "ok", "canonical": True}),
                         '{"canonical":true,"reason":"ok"}')

    def test_null_false_int_and_nesting(self):
        self.assertEqual(result.line({"b": [1, None, False, {}], "a": 0}),
                         '{"a":0,"b":[1,null,false,{}]}')

    def test_keys_sorted_by_utf16_code_units(self):
        # U+FF5E (BMP) sorts after U+1F600 (surrogate pair D83D...) in UTF-16
        self.assertEqual(result.line({"～": 1, "\U0001f600": 2}),
                         '{"\U0001f600":2,"～":1}')

    def test_string_escapes_are_the_minimal_set(self):
        self.assertEqual(result.line({"a": 'q"b\\n\n\t\x01/é'}),
                         '{"a":"q\\"b\\\\n\\n\\t\\u0001/é"}')

    def test_refuses_floats_and_other_types(self):
        for bad in (1.5, (1,), {1}, b"x", float("nan")):
            with self.assertRaises(TypeError):
                result.line({"a": bad})

    def test_refuses_non_string_keys(self):
        with self.assertRaises(TypeError):
            result.line({1: "a"})

    def test_bool_is_not_an_int(self):
        self.assertEqual(result.line([True, 1]), "[true,1]")


if __name__ == "__main__":
    unittest.main()
