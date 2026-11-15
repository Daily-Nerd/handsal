"""T2.5 vector writer (CF-02, CF-07).

Format: one JSON file per vector, {name, command, input | input_raw, anchor},
anchor REQUIRED (CF-02 S1), names are `group/case`.
"""
import json
import tempfile
import unittest
from pathlib import Path

from lib import writer

import run  # noqa: E402 (writer puts the conformance dir on sys.path)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.w = writer.VectorWriter(self.dir)

    def files(self):
        return sorted(p.name for p in self.dir.iterdir())


class Writing(Base):
    def test_one_file_per_vector(self):
        self.w.add("jcs/null-where-allowed", "subset", '{"canonical":true,"reason":null}',
                   input_hex="7b2261223a6e756c6c7d")
        self.w.add("key/one", "kid", '{"kid":"k"}', input={"x": "a", "y": "b"})
        self.assertEqual(len(self.files()), 2)

    def test_file_content_has_the_four_fields_and_sorted_keys(self):
        path = self.w.add("key/one", "kid", '{"a":null,"kid":"k"}', input={"y": "b", "x": "a"})
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text)
        self.assertEqual(set(doc), {"name", "command", "input", "anchor"})
        self.assertEqual(doc["name"], "key/one")
        self.assertEqual(doc["command"], "kid")
        self.assertEqual(list(doc), sorted(doc))
        self.assertEqual(list(doc["input"]), ["x", "y"])
        self.assertEqual(doc["anchor"], '{"a":null,"kid":"k"}')
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))

    def test_input_raw_form(self):
        path = self.w.add("jcs/whitespace", "subset", '{"canonical":false,"reason":"x"}',
                          input_raw='{"a": ""}')
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("input_raw", doc)
        self.assertNotIn("input", doc)

    def test_names_lists_written_vectors_in_order(self):
        self.w.add("key/b", "kid", '{"kid":"k"}', input={"x": "1", "y": "2"})
        self.w.add("key/a", "kid", '{"kid":"k"}', input={"x": "1", "y": "2"})
        self.assertEqual(self.w.names, ["key/b", "key/a"])

    def test_bytes_are_deterministic(self):
        a = self.w.add("key/one", "kid", '{"kid":"k"}', input={"x": "1", "y": "2"})
        first = a.read_bytes()
        w2 = writer.VectorWriter(self.dir)
        w2.add("key/one", "kid", '{"kid":"k"}', input={"y": "2", "x": "1"})
        self.assertEqual(a.read_bytes(), first)

    def test_output_is_ascii(self):
        path = self.w.add("key/one", "kid", '{"kid":"k"}', input={"x": "1"})
        path.read_bytes().decode("ascii")

    def test_file_name_derived_from_name(self):
        path = self.w.add("jcs/depth-8-ok", "subset", '{"canonical":true,"reason":null}',
                          input_raw="0")
        self.assertEqual(path.name, "jcs.depth-8-ok.json")
        self.assertEqual(path.parent, self.dir)


class Refusals(Base):
    def refused(self, *args, **kw):
        with self.assertRaises(writer.VectorError):
            self.w.add(*args, **kw)
        self.assertEqual(self.files(), [])

    def test_missing_anchor(self):
        # CF-02: a vector without anchor is not a vector
        self.refused("key/one", "kid", None, input={"x": "1"})

    def test_anchor_keyword_is_required(self):
        with self.assertRaises(TypeError):
            self.w.add("key/one", "kid", input={"x": "1"})

    def test_non_string_anchor_is_refused_at_write_time(self):
        # the harness compares the exact output line, so only a string can match
        for bad in ({"kid": "k"}, [], 1, True, 1.5):
            self.refused("key/one", "kid", bad, input={"x": "1"})

    def test_empty_anchor_values_that_are_real_are_kept(self):
        # null is not an answer, but "" can be an expected output line
        self.w.add("key/one", "kid", "", input={"x": "1"})
        self.w.add("key/two", "kid", "[]", input={"x": "1"})

    def test_duplicate_name(self):
        self.w.add("key/one", "kid", '{"kid":"k"}', input={"x": "1"})
        with self.assertRaises(writer.VectorError):
            self.w.add("key/one", "kid", '{"kid":"other"}', input={"x": "2"})
        self.assertEqual(len(self.files()), 1)

    def test_unknown_group(self):
        self.refused("zzz/one", "kid", '{"kid":"k"}', input={"x": "1"})

    def test_malformed_names(self):
        for bad in ("key", "key/", "/one", "key/one/two", "Key/one", "key/on e",
                    "key/one.json", "key/../one", "key/-one", "key/one-", "key//one", ""):
            self.refused(bad, "kid", '{"kid":"k"}', input={"x": "1"})

    def test_mixed_case_case_part_is_allowed(self):
        # catalog id rnd/hash12-skips-uEi
        self.w.add("rnd/hash12-skips-uEi", "render", '{"x":null}', input={"x": "1"})

    def test_input_xor_input_raw(self):
        self.refused("key/one", "kid", '{"kid":"k"}')
        self.refused("key/one", "kid", '{"kid":"k"}', input={"x": "1"}, input_raw="00")

    def test_input_raw_must_be_a_string(self):
        self.refused("jcs/whitespace", "subset", '{"canonical":false}', input_raw=b"\x00")

    def test_command_must_be_nonempty_string(self):
        self.refused("key/one", "", '{"kid":"k"}', input={"x": "1"})
        self.refused("key/one", None, '{"kid":"k"}', input={"x": "1"})

    def test_unserializable_anchor(self):
        self.refused("key/one", "kid", object(), input={"x": "1"})

    def test_nan_refused(self):
        self.refused("key/one", "kid", float("nan"), input={"x": "1"})

    def test_known_ids_gate(self):
        w = writer.VectorWriter(self.dir, known_ids={"key/one"})
        w.add("key/one", "kid", '{"kid":"k"}', input={"x": "1"})
        with self.assertRaises(writer.VectorError):
            w.add("key/two", "kid", '{"kid":"k"}', input={"x": "1"})

    def test_failed_add_does_not_burn_the_name(self):
        with self.assertRaises(writer.VectorError):
            self.w.add("key/one", "kid", None, input={"x": "1"})
        self.w.add("key/one", "kid", '{"kid":"k"}', input={"x": "1"})


class Options(Base):
    def test_exit_and_pad_are_written(self):
        path = self.w.add("cli/over", "fold", "x", input={"note": ""}, pad=["note"], exit=2)
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["pad"], ["note"])
        self.assertEqual(doc["exit"], 2)

    def test_exit_and_pad_are_absent_when_not_given(self):
        doc = json.loads(self.w.add("key/one", "kid", "x", input={}).read_text(encoding="utf-8"))
        self.assertNotIn("pad", doc)
        self.assertNotIn("exit", doc)

    def test_exit_zero_is_written(self):
        doc = json.loads(self.w.add("key/one", "kid", "x", input={}, exit=0).read_text())
        self.assertEqual(doc["exit"], 0)

    def test_input_hex_form(self):
        doc = json.loads(self.w.add("jcs/invalid-utf8", "subset", "x", input_hex="c328").read_text())
        self.assertEqual(doc["input_hex"], "c328")
        self.assertNotIn("input", doc)

    def test_refusals(self):
        for kw in ({"exit": True}, {"exit": 256}, {"exit": "2"}, {"pad": ["missing"]},
                   {"pad": []}, {"pad": ["n"]}):
            with self.assertRaises(writer.VectorError, msg=str(kw)):
                self.w.add("key/one", "kid", "x", input={"n": 1}, **kw)
        for kw in ({"input_hex": "C3"}, {"input_hex": "c"}, {"input_raw": "\udcff"}):
            with self.assertRaises(writer.VectorError, msg=str(kw)):
                self.w.add("key/two", "kid", "x", **kw)
        with self.assertRaises(writer.VectorError):
            self.w.add("key/three", "kid", "x", input_raw="{}", pad=["a"])
        self.assertEqual(self.files(), [])


class HarnessAccepts(Base):
    """Every vector kind the writer can emit loads through run.py."""

    def test_every_kind_loads_with_zero_rejections(self):
        w = self.w
        w.add("key/plain", "kid", '{"kid":"k"}', input={"x": "1"})
        w.add("key/raw", "subset", "x", input_raw='{"a":1,"a":2}')
        w.add("jcs/invalid-utf8", "subset", "x", input_hex="c328")
        w.add("jcs/empty-hex", "subset", "x", input_hex="")
        w.add("cli/over", "fold", "x", input={"acts": [], "note": ""}, pad=["note"])
        w.add("cli/nested-pad", "fold", "x", input={"a": [{"b": "s"}]}, pad=["a", 0, "b"])
        w.add("cli/exit3", "fold", "", input={}, exit=3)
        w.add("rnd/unicode", "render", "caf\u00e9", input={"t": "\u00e9\U0001f600"})
        loaded = run.load_vectors(str(self.dir))
        self.assertEqual(len(loaded), 8)

    def test_file_name_does_not_matter_to_the_harness(self):
        path = self.w.add("key/one", "kid", "x", input={})
        path.rename(self.dir / "anything-at-all.json")
        self.assertEqual([v["name"] for v in run.load_vectors(str(self.dir))], ["key/one"])

    def test_writer_validates_with_the_harness_schema(self):
        self.assertIs(writer.VectorError, run.VectorError)


class Groups(unittest.TestCase):
    def test_group_list_matches_catalog_prefixes(self):
        expected = set(
            "add bod cas cf chg chk cli cln cls dec end enr fix fld frk frs gen idn ing inp jcs "
            "jws key lnk mem mth ok ord org pin pol quo rck rem rep rev rly rnd rsv sch sgn sig "
            "tim vrd vtn wit adm kpl".split()
        )
        self.assertEqual(set(writer.GROUPS), expected)


if __name__ == "__main__":
    unittest.main()
