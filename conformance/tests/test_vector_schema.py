import unittest

import run
import vector_schema as vs


def good(**over):
    doc = {"name": "a/b", "command": "fold", "input": {}, "anchor": "x"}
    doc.update(over)
    return doc


class ValidateTests(unittest.TestCase):
    def rejected(self, doc):
        with self.assertRaises(vs.VectorError):
            vs.validate(doc)

    def test_run_shares_the_error_class(self):
        self.assertIs(run.VectorError, vs.VectorError)

    def test_minimal_vector_is_valid(self):
        vs.validate(good())

    def test_every_input_form_is_valid(self):
        vs.validate(good())
        doc = good(input_raw="{}")
        del doc["input"]
        vs.validate(doc)
        doc = good(input_hex="c328")
        del doc["input"]
        vs.validate(doc)

    def test_null_input_is_a_real_json_input(self):
        vs.validate(good(input=None))

    def test_not_an_object(self):
        self.rejected([])

    def test_anchor_must_be_a_string(self):
        for bad in (None, {}, [], 1, True):
            self.rejected(good(anchor=bad))

    def test_empty_string_anchor_is_allowed(self):
        vs.validate(good(anchor=""))

    def test_missing_anchor(self):
        doc = good()
        del doc["anchor"]
        self.rejected(doc)

    def test_exactly_one_input_form(self):
        self.rejected(good(input_raw="{}"))
        self.rejected(good(input_hex="00"))
        doc = good(input_raw="{}", input_hex="00")
        del doc["input"]
        self.rejected(doc)
        doc = good()
        del doc["input"]
        self.rejected(doc)

    def test_input_hex_must_be_even_lowercase_hex(self):
        for bad in ("0", "zz", "C3", "c3 28", 5, None):
            doc = good(input_hex=bad)
            del doc["input"]
            self.rejected(doc)

    def test_input_hex_may_be_empty(self):
        doc = good(input_hex="")
        del doc["input"]
        vs.validate(doc)

    def test_input_raw_must_be_a_string(self):
        doc = good(input_raw=5)
        del doc["input"]
        self.rejected(doc)

    def test_input_raw_must_encode_as_utf8(self):
        doc = good(input_raw="\udcff")
        del doc["input"]
        self.rejected(doc)

    def test_name_and_command(self):
        self.rejected(good(name=""))
        self.rejected(good(command=""))
        self.rejected(good(command=None))

    def test_exit_is_an_int_in_range(self):
        vs.validate(good(exit=0))
        vs.validate(good(exit=3))
        for bad in (True, "3", 1.0, -1, 256, None):
            self.rejected(good(exit=bad))

    def test_pad_needs_input(self):
        doc = good(input_raw="{}", pad=["a"])
        del doc["input"]
        self.rejected(doc)
        doc = good(input_hex="00", pad=["a"])
        del doc["input"]
        self.rejected(doc)

    def test_pad_must_resolve_to_a_string(self):
        vs.validate(good(input={"x": {"y": ["", "s"]}}, pad=["x", "y", 1]))
        self.rejected(good(input={"n": 1}, pad=["n"]))
        self.rejected(good(input={"n": ""}, pad=["missing"]))
        self.rejected(good(input={"n": ""}, pad=[]))
        self.rejected(good(input={"n": ""}, pad="n"))
        self.rejected(good(input={"n": ""}, pad=[1.5]))
        self.rejected(good(input={"n": ""}, pad=[True]))

    def test_unknown_keys_are_refused(self):
        self.rejected(good(extra=1))

    def test_input_hex_is_sent_as_the_decoded_bytes(self):
        doc = good(input_hex="c328")
        del doc["input"]
        self.assertEqual(run.build_stdin(doc), b"\xc3\x28")

    def test_load_vector_rejects_bad_hex(self):
        import json, os, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.json")
            doc = good(input_hex="zz")
            del doc["input"]
            with open(path, "w") as fh:
                json.dump(doc, fh)
            with self.assertRaises(run.VectorError):
                run.load_vector(path)


if __name__ == "__main__":
    unittest.main()
