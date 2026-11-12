"""T3.3 I-JSON reader (CF-03 input framing, RFC 7493, spec 16.21)."""
import unittest
from unittest import mock

from handsal_check import ijson

MAX = ijson.MAX_INPUT


class Size(unittest.TestCase):
    def test_limit_is_two_to_the_24(self):
        self.assertEqual(MAX, 16777216)

    def test_check_size_accepts_the_limit_and_refuses_one_more(self):
        ijson.check_size(b"a" * MAX)
        with self.assertRaises(ijson.Unparseable):
            ijson.check_size(b"a" * (MAX + 1))

    def test_size_is_judged_before_parsing(self):
        with mock.patch("json.loads") as parse:
            with self.assertRaises(ijson.Unparseable):
                ijson.loads(b" " * (MAX + 1))
            parse.assert_not_called()


class Parsing(unittest.TestCase):
    def test_reads_json(self):
        self.assertEqual(ijson.loads(b'{"a":[1,null,"x",true]}\n'),
                         {"a": [1, None, "x", True]})

    def refused(self, raw):
        with self.assertRaises(ijson.Unparseable, msg=raw[:40]):
            ijson.loads(raw)

    def test_duplicate_member_name_at_the_top(self):
        self.refused(b'{"a":"x","a":"y"}')

    def test_duplicate_member_name_nested_in_objects_and_arrays(self):
        self.refused(b'{"a":{"b":[{"c":"x","c":"y"}]}}')

    def test_same_name_in_different_objects_is_fine(self):
        self.assertEqual(ijson.loads(b'{"a":{"a":1},"b":{"a":2}}'),
                         {"a": {"a": 1}, "b": {"a": 2}})

    def test_duplicate_detection_compares_decoded_names(self):
        self.refused(b'{"a":1,"\\u0061":2}')

    def test_invalid_utf8(self):
        self.refused(b'{"a":"\xc3\x28"}')

    def test_byte_order_mark(self):
        self.refused(b'\xef\xbb\xbf{}')

    def test_lone_surrogate_in_value_and_in_name(self):
        self.refused(b'{"a":"\\ud800"}')
        self.refused(b'{"\\udc00":"a"}')
        self.refused(b'{"a":"\\ud800x"}')
        self.refused(b'{"a":["\\ude00\\ud83d"]}')

    def test_surrogate_pair_is_fine(self):
        self.assertEqual(ijson.loads(b'["\\ud83d\\ude00"]'), ["\U0001f600"])

    def test_not_json_empty_and_trailing_garbage(self):
        for raw in (b"not json", b"", b"   ", b"{}x", b"{} {}", b"{'a':1}"):
            self.refused(raw)

    def test_non_finite_numbers(self):
        for raw in (b"NaN", b"[Infinity]", b"-Infinity"):
            self.refused(raw)

    def test_very_deep_nesting_is_unparseable_not_a_crash(self):
        self.refused(b"[" * 200000 + b"]" * 200000)


if __name__ == "__main__":
    unittest.main()
