"""CF-09 the store format `handsal-store/1`: one line of JCS and one LF, sorted unique acts, a null witness.

The format is pure: `encode` writes the only form a store may have and `parse` reads exactly that form, so a
byte that `sync` did not write is `store_malformed` (CF-09, invariant I1).
"""
import unittest

from handsal_check import emit, errors, ijson, store

from .checkact_world import NOW, Scenario

DROP = object()   # a member the test line leaves out
LINEAGE = [{"doc": {"name": "ORG"}, "sigs": ["s1", "s2"]}]
ACTS = ["aaa", "bbb", "ccc"]


def line(**over):
    """The store line with the members of `over` replaced; a value of `DROP` removes the member."""
    body = {"acts": ACTS, "lineage": LINEAGE, "next": "no", "synced_at": NOW, "v": "handsal-store/1", "witness": None}
    body.update(over)
    body = {k: v for k, v in body.items() if v is not DROP}
    return emit.emit_result(body) + b"\n"


def refused(raw):
    try:
        store.parse(raw)
    except errors.Refused as err:
        return err.code
    return None


class Format(unittest.TestCase):
    def test_encode_then_parse_is_the_identity(self):
        raw = store.encode(ACTS, LINEAGE, "no", NOW)
        got = store.parse(raw)
        self.assertEqual((got.acts, got.lineage, got.next, got.synced_at, got.witness, got.reason),
                         (ACTS, LINEAGE, "no", NOW, None, None))
        self.assertEqual(store.encode(got.acts, got.lineage, got.next, got.synced_at), raw)
        self.assertEqual(raw, line())   # one JCS line, keys sorted, one LF

    def test_encode_sorts_and_deduplicates_so_no_other_form_can_be_written(self):
        self.assertEqual(store.encode(["ccc", "aaa", "bbb", "aaa"], LINEAGE, "no", NOW),
                         store.encode(ACTS, LINEAGE, "no", NOW))
        self.assertEqual(store.canonical(["b", "a", "b"]), ["a", "b"])

    def test_encode_writes_the_lineage_sigs_sorted_and_unique_and_parse_refuses_any_other_form(self):   # CF-09
        loose = [{"doc": {"name": "ORG"}, "sigs": ["s2", "s1", "s2"]}]
        self.assertEqual(store.encode(ACTS, loose, "no", NOW), store.encode(ACTS, LINEAGE, "no", NOW))
        for sigs in (["s2", "s1"], ["s1", "s1", "s2"]):
            self.assertEqual(refused(line(lineage=[{"doc": {"name": "ORG"}, "sigs": sigs}])), "store_malformed", sigs)

    def test_an_empty_bag_is_a_store(self):
        got = store.parse(store.encode([], LINEAGE, "no", NOW))
        self.assertEqual(got.acts, [])

    def test_every_malformed_form_is_store_malformed(self):
        good = line()
        forms = {
            "crlf": good.replace(b"\n", b"\r\n"),
            "no lf": good[:-1],
            "second line": good + good,
            "empty": b"",
            "not json": b"{\n",
            "not an object": b"[]\n",
            "unsorted acts": line(acts=["bbb", "aaa"]),
            "duplicate acts": line(acts=["aaa", "aaa"]),
            "extra key": line(org="x"),
            "missing key": line(witness=DROP),
            "missing next": line(next=DROP),
            "next not a string": line(next=True),
            "next null": line(next=None),
            "next a number": line(next=1),
            "next in capitals": line(next="YES"),
            "next another word": line(next="maybe"),
            "next empty": line(next=""),
            "missing acts": line(acts=DROP),
            "another v": line(v="handsal-store/2"),
            "non-null witness": line(witness="a.b.c"),
            "non-string act": line(acts=["aaa", 1]),
            "acts not a list": line(acts="aaa"),
            "bad lineage entry": line(lineage=[{"doc": {}}]),
            "lineage sigs not strings": line(lineage=[{"doc": {}, "sigs": [1]}]),
            "synced_at not a time": line(synced_at="yesterday"),
            "space after a colon": good.replace(b'"v":', b'"v": '),
            "key order": b'{"v":"handsal-store/1","acts":[],"lineage":[],"next":"no","synced_at":"%s","witness":null}\n' % NOW.encode(),
            "duplicate member": b'{"acts":[],"acts":[],"lineage":[],"next":"no","synced_at":"%s","v":"handsal-store/1","witness":null}\n' % NOW.encode(),
            "over MAX_INPUT": good[:-1] + b" " * ijson.MAX_INPUT + b"\n",
        }
        for name, raw in forms.items():
            with self.subTest(form=name):
                self.assertEqual(refused(raw), "store_malformed")

    def test_the_good_line_is_not_refused(self):
        self.assertIsNone(refused(line()))

    def test_a_store_of_exactly_max_input_bytes_parses(self):
        pad = ijson.MAX_INPUT - len(line(acts=[""]))
        raw = line(acts=["a" * pad])
        self.assertEqual(len(raw), ijson.MAX_INPUT)
        self.assertEqual(store.parse(raw).acts, ["a" * pad])


class Next(unittest.TestCase):
    """CF-09: `next` is the string `"yes"` or `"no"` (the grammar of WT-02): whether the store holds a valid successor
    of the pinned document. Any other value is not a form `encode` writes."""

    def test_next_must_be_yes_or_no(self):   # CF-09 S3
        for good in ("yes", "no"):
            self.assertEqual(store.parse(store.encode(ACTS, LINEAGE, good, NOW)).next, good)
            self.assertIsNone(refused(line(next=good)))
        for bad in ("maybe", "YES", "No", "", "true", True, False, 0, 1, None, [], {}, ["yes"]):
            with self.subTest(bad=bad):
                self.assertEqual(refused(line(next=bad)), "store_malformed")
        self.assertEqual(refused(line(next=DROP)), "store_malformed")

    def test_the_writer_writes_no_other_value(self):
        for bad in ("maybe", True, None, 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):   # a bug of the writer, never a store
                store.encode(ACTS, LINEAGE, bad, NOW)

    def test_next_sits_between_lineage_and_synced_at_in_the_one_line(self):
        raw = store.encode(ACTS, LINEAGE, "yes", NOW)
        self.assertLess(raw.index(b'"lineage"'), raw.index(b'"next":"yes"'))
        self.assertLess(raw.index(b'"next":"yes"'), raw.index(b'"synced_at"'))


class Load(unittest.TestCase):
    """`load` is what a reader gets: the bag, or the reason a store cannot be read, never an exception."""

    class Port:
        def __init__(self, raw=None, code=None):
            self.raw, self.code, self.asked = raw, code, []

        def read(self, org):
            self.asked.append(org)
            if self.code:
                raise errors.Refused(self.code)
            return self.raw

    def test_a_readable_store_gives_its_view_without_a_reason(self):
        port = self.Port(store.encode(ACTS, LINEAGE, "yes", NOW))
        got = store.load(port, "org")
        self.assertEqual((got.acts, got.next, got.synced_at, got.reason, port.asked), (ACTS, "yes", NOW, None, ["org"]))

    def test_a_port_refusal_is_the_reason_and_the_view_is_empty(self):
        for code in ("store_missing", "store_owner", "store_unavailable"):
            got = store.load(self.Port(code=code), "org")
            self.assertEqual((got.reason, got.acts, got.lineage, got.next, got.synced_at, got.witness),
                             (code, [], [], None, None, None))

    def test_malformed_bytes_are_the_reason(self):
        self.assertEqual(store.load(self.Port(b"junk\n"), "org").reason, "store_malformed")

    def test_the_view_of_a_scenario_store_is_the_scenario(self):
        s = Scenario()
        got = store.load(self.Port(store.encode([], s.lineage, "no", NOW)), s.w.id)
        self.assertEqual(got.lineage, [{"doc": e["doc"], "sigs": sorted(e["sigs"])} for e in s.lineage])   # canonical


if __name__ == "__main__":
    unittest.main()
