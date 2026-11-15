"""T3.11 field formats and the closed-object engine (ACT-07, ACT-09, ACT-10, section 2.2)."""
import json
import unittest
from pathlib import Path

from handsal_check import encoding, errors, registry, schema

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]
REG = registry.load()


def mutate_last(text):
    """The same string with its last character swapped for another alphabet character."""
    return text[:-1] + ("B" if text[-1] != "B" else "C")


class Hashstr(unittest.TestCase):
    def test_canonical_forms_pass(self):
        self.assertTrue(schema.is_hashstr(encoding.EMPTY_HASH))
        self.assertTrue(schema.is_hashstr(encoding.hashstr(b"abc")))

    def test_every_form_defect_fails(self):
        good = encoding.EMPTY_HASH
        self.assertFalse(schema.is_hashstr(good[:-1]))                  # 46 characters
        self.assertFalse(schema.is_hashstr(good + "A"))                 # 48 characters
        self.assertFalse(schema.is_hashstr(good[1:]))                   # no leading u
        self.assertFalse(schema.is_hashstr(good[:10] + "+" + good[11:]))  # standard alphabet
        wrong_code = "u" + encoding.b64u_encode(b"\x13\x20" + b"\0" * 32)
        self.assertFalse(schema.is_hashstr(wrong_code))                 # multihash code 0x13
        self.assertFalse(schema.is_hashstr(None))
        self.assertFalse(schema.is_hashstr(7))

    def test_nonzero_trailing_bits_fail(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        good = encoding.hashstr(b"x")
        self.assertEqual(alphabet.index(good[-1]) & 15, 0)             # canonical: spare bits clear
        bad = good[:-1] + alphabet[alphabet.index(good[-1]) | 1]
        self.assertNotEqual(bad, good)
        self.assertFalse(schema.is_hashstr(bad))


class Time(unittest.TestCase):
    def test_valid(self):
        for text in ("2026-11-08T12:00:00Z", "2026-02-28T23:59:59Z", "2028-02-29T00:00:00Z",
                     "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
            self.assertTrue(schema.is_time(text), text)

    def test_invalid(self):
        for text in ("2026-11-08T12:00:00", "2026-11-08T12:00:00+00:00", "2026-11-08T12:00:00.5Z",
                     "2026-02-30T00:00:00Z", "2026-02-29T00:00:00Z", "2026-11-08T12:00:60Z",
                     "2026-11-08t12:00:00Z", "2026-11-08T24:00:00Z", "2026-13-01T00:00:00Z",
                     "2026-00-01T00:00:00Z", "2026-11-00T00:00:00Z", "2026-11-08T12:60:00Z",
                     "2026-11-08T12:00:00z", "2026-11-08T12:00:00Z\n", "2026-11-08 12:00:00Z",
                     "٢026-11-08T12:00:00Z", "", None, 5):
            self.assertFalse(schema.is_time(text), repr(text))

    def test_the_century_leap_rule(self):
        self.assertTrue(schema.is_time("2000-02-29T00:00:00Z"))
        self.assertFalse(schema.is_time("2100-02-29T00:00:00Z"))


class Identifiers(unittest.TestCase):
    def test_member_id(self):
        for ok in ("alice", "bob2", "a1", "0z", "a-b", "x" * 32):
            self.assertTrue(schema.is_member_id(ok), ok)
        for bad in ("Alice", "a", "", "x" * 33, "-ab", "a_b", "al ice", "alice\n", "éa", None):
            self.assertFalse(schema.is_member_id(bad), repr(bad))

    def test_role_id(self):
        for ok in ("maintainer", "a", "x" * 32, "a-1"):
            self.assertTrue(schema.is_role_id(ok), ok)
        for bad in ("1a", "", "x" * 33, "A", "-a", None):
            self.assertFalse(schema.is_role_id(bad), repr(bad))

    def test_request_id(self):
        for ok in ("req-00000001", "a" * 8, "a" * 36):
            self.assertTrue(schema.is_request_id(ok), ok)
        for bad in ("a" * 7, "a" * 37, "-aaaaaaaa", "REQ-00000001", ""):
            self.assertFalse(schema.is_request_id(bad), bad)

    def test_class_id_uses_the_role_id_alphabet(self):
        self.assertTrue(schema.is_class_id("apple-se-bio"))
        self.assertTrue(schema.is_class_id("fixture-pin"))
        self.assertFalse(schema.is_class_id("Apple"))
        self.assertFalse(schema.is_class_id(""))


class Text(unittest.TestCase):
    def test_label_limits(self):
        self.assertTrue(schema.is_label("x" * 64))
        self.assertFalse(schema.is_label("x" * 65))
        self.assertFalse(schema.is_label(""))

    def test_alphabet(self):
        self.assertTrue(schema.is_label("Alice's laptop (work)"))
        for bad in ('a"b', "a\\b", "aéb", "a\x7fb", "a\tb", "a\nb", None):
            self.assertFalse(schema.is_label(bad), repr(bad))

    def test_org_name_bounds(self):
        self.assertTrue(schema.is_org_name("x" * 24))
        self.assertFalse(schema.is_org_name("x" * 25))


class Hostname(unittest.TestCase):
    def test_valid(self):
        for ok in ("r.example", "localhost", "a-b.c-d.example", "xn--bcher-kva.example", "1.example",
                   ".".join(["a" * 63] * 3 + ["b" * 61])):
            self.assertTrue(schema.is_hostname(ok), ok)

    def test_invalid(self):
        for bad in ("R.example", "r.example.", "r.example:443", "a_b.example", "-a.example", "a-.example",
                    "a..example", "", ".example", "a" * 64 + ".example", "bücher.example",
                    "xn--.example", "xn--zzé.example", ".".join(["a" * 63] * 4), None):
            self.assertFalse(schema.is_hostname(bad), repr(bad))

    def test_253_characters_is_the_limit(self):
        name = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(name), 253)
        self.assertTrue(schema.is_hostname(name))
        self.assertFalse(schema.is_hostname(name + "b"))


class Decimal(unittest.TestCase):
    def test_grammar(self):
        for ok in ("0", "7", "10", "123456789"):
            self.assertTrue(schema.is_decimal(ok), ok)
        for bad in ("", "01", "-1", "1e3", "1234567890", "1.5", "+1", " 1", "1\n", "٣", None, 3):
            self.assertFalse(schema.is_decimal(bad), repr(bad))


class Keys(unittest.TestCase):
    def test_b64u32(self):
        x = KEYS["alice.sign"]["x"]
        self.assertTrue(schema.is_b64u32(x))
        self.assertTrue(schema.is_kid(KEYS["alice.sign"]["kid"]))
        self.assertFalse(schema.is_b64u32(x[:-1]))
        self.assertFalse(schema.is_b64u32(x + "A"))
        self.assertFalse(schema.is_b64u32(mutate_last("A" * 43)))   # spare bits set
        self.assertFalse(schema.is_b64u32(None))


class Leaf(unittest.TestCase):
    def test_every_registry_type_has_a_checker(self):
        found = set()

        def walk(node):
            if type(node) is dict:
                if "type" in node and type(node["type"]) is str:
                    found.add(node["type"])
                if "of" in node and type(node["of"]) is str:
                    found.add(node["of"])
                for v in node.values():
                    walk(v)
        for method in REG.methods.values():
            walk(method.body)
        found |= set(REG.act_extra_key_types.values())
        found.discard("list")
        self.assertTrue(found)
        for name in found:
            self.assertIn(name, schema.FORMS, name)


H = encoding.EMPTY_HASH
H2 = encoding.hashstr(b"two")
H3 = encoding.hashstr(b"three")


def codes(node, value, code="body_schema"):
    try:
        schema.check(node, value, REG, code)
    except errors.Refused as err:
        return err.code
    return None


class Engine(unittest.TestCase):
    def test_closed_object_exact_keys(self):
        node = {"keys": {"a": {"type": "hashstr"}, "b": {"type": "label"}}}
        self.assertIsNone(codes(node, {"a": H, "b": "x"}))
        self.assertEqual(codes(node, {"a": H}), "body_schema")
        self.assertEqual(codes(node, {"a": H, "b": "x", "c": "y"}), "body_schema")
        self.assertEqual(codes(node, []), "body_schema")
        self.assertEqual(codes(node, None), "body_schema")

    def test_empty_closed_object_takes_only_the_empty_object(self):
        self.assertIsNone(codes({"keys": {}}, {}))
        self.assertEqual(codes({"keys": {}}, {"x": "y"}), "body_schema")

    def test_the_structure_code_is_the_callers(self):
        self.assertEqual(codes({"keys": {}}, {"x": "y"}, "schema"), "schema")

    def test_hashstr_form_is_schema_wherever_it_is(self):
        node = {"keys": {"a": {"type": "hashstr"}}}
        self.assertEqual(codes(node, {"a": "nope"}), "schema")
        self.assertEqual(codes(node, {"a": 5}), "schema")

    def test_schema_form_beats_body_schema_structure(self):
        node = {"keys": {"a": {"type": "hashstr"}, "b": {"type": "label"}}}
        self.assertEqual(codes(node, {"a": "nope", "c": "x"}), "schema")

    def test_member_id_and_time_are_schema_forms(self):
        self.assertEqual(codes({"keys": {"p": {"type": "member_id"}}}, {"p": "Bob"}), "schema")
        self.assertEqual(codes({"keys": {"t": {"type": "time"}}}, {"t": "x"}), "schema")

    def test_other_forms_take_the_container_code(self):
        node = {"keys": {"l": {"type": "label"}}}
        self.assertEqual(codes(node, {"l": 'a"b'}), "body_schema")
        self.assertEqual(codes(node, {"l": 'a"b'}, "schema"), "schema")

    def test_const(self):
        node = {"keys": {"kind": {"const": "chain"}}}
        self.assertIsNone(codes(node, {"kind": "chain"}, "schema"))
        self.assertEqual(codes(node, {"kind": "merkle"}, "schema"), "schema")

    def test_nested_node_may_set_its_own_code(self):
        node = {"keys": {"body": {"code": "body_schema", "keys": {"l": {"type": "label"}}}}}
        self.assertEqual(codes(node, {"body": {"l": ""}}, "schema"), "body_schema")
        self.assertEqual(codes(node, {}, "schema"), "schema")

    def test_list_caps_come_from_the_registry(self):
        node = {"type": "list", "of": "hashstr", "cap": "chain_resolve_caps.candidates",
                "sorted": True, "distinct": True}
        self.assertIsNone(codes(node, sorted([H, H2])))
        self.assertEqual(codes(node, [H]), "body_schema")                      # 1 < 2
        many = sorted(encoding.hashstr(bytes([i])) for i in range(18))
        self.assertEqual(codes(node, many), "body_schema")                     # 18 > 17
        self.assertIsNone(codes(node, many[:17]))

    def test_list_sorted_and_distinct(self):
        node = {"type": "list", "of": "hashstr", "cap": "chain_resolve_caps.candidates",
                "sorted": True, "distinct": True}
        a, b = sorted([H, H2])
        self.assertEqual(codes(node, [b, a]), "body_schema")
        self.assertEqual(codes(node, [a, a]), "body_schema")

    def test_list_elements_have_their_form_checked(self):
        node = {"type": "list", "of": "hashstr", "cap": "chain_resolve_caps.heads",
                "sorted": True, "distinct": True}
        self.assertEqual(codes(node, ["nope"]), "schema")
        self.assertEqual(codes(node, "notalist"), "body_schema")

    def test_list_of_objects_sorted_by_member(self):
        entry = {"keys": {"endorsements": {"type": "list", "of": "hashstr",
                                           "cap": "chain_resolve_caps.endorsements_per_override",
                                           "sorted": True, "distinct": True},
                          "resolve": {"type": "hashstr"}}}
        node = {"type": "list", "of": entry, "cap": "chain_resolve_caps.overrides",
                "sorted_by": "resolve", "distinct_by": "resolve"}
        a, b = sorted([H, H2])
        e = lambda r: {"endorsements": [H3], "resolve": r}
        self.assertIsNone(codes(node, []))
        self.assertIsNone(codes(node, [e(a), e(b)]))
        self.assertEqual(codes(node, [e(b), e(a)]), "body_schema")
        self.assertEqual(codes(node, [e(a), e(a)]), "body_schema")
        self.assertEqual(codes(node, [{"endorsements": [H3]}]), "body_schema")
        self.assertEqual(codes(node, [{"endorsements": [], "resolve": a}]), "body_schema")
        self.assertEqual(codes(node, [{"endorsements": [H3], "resolve": "nope"}]), "schema")

    def test_unknown_type_in_a_node_is_a_bug_not_a_pass(self):
        with self.assertRaises(KeyError):
            codes({"type": "no_such_type"}, "x")

    def test_defects_lists_codes_and_refuse_orders_them(self):
        node = {"keys": {"a": {"type": "hashstr"}}}
        self.assertEqual(schema.defects(node, {"a": H}, REG, "body_schema"), [])
        self.assertEqual(schema.defects(node, {"a": "x", "c": 1}, REG, "body_schema"),
                         ["body_schema", "schema"])
        with self.assertRaises(errors.Refused) as ctx:
            schema.refuse(["body_schema", "schema"])
        self.assertEqual(ctx.exception.code, "schema")
        with self.assertRaises(errors.Refused) as ctx:
            schema.refuse(["body_schema"])
        self.assertEqual(ctx.exception.code, "body_schema")
        schema.refuse([])


class Seconds(unittest.TestCase):
    def test_a_time_is_seconds_since_the_epoch_utc(self):
        self.assertEqual(schema.seconds("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(schema.seconds("1970-01-02T00:00:01Z"), 86401)
        self.assertEqual(schema.seconds("2026-11-08T12:00:00Z"), 1794139200)

    def test_leap_days_count(self):
        self.assertEqual(schema.seconds("2024-03-01T00:00:00Z") - schema.seconds("2024-02-28T00:00:00Z"), 2 * 86400)
        self.assertEqual(schema.seconds("2025-03-01T00:00:00Z") - schema.seconds("2025-02-28T00:00:00Z"), 86400)

    def test_a_value_that_is_no_time_is_a_bug_not_a_default(self):
        with self.assertRaises(ValueError):
            schema.seconds("2026-02-30T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
