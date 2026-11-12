"""T3.17 pin file (GP-05, GP-14) and the ordered pin checks of VR-02 step 6 (a) to (h)."""
import base64
import json
import unittest

from handsal_check import emit, encoding, errors, genesis, org, pinfile, profiles

from .genesis_fixtures import org as make_org

PROFILES = profiles.load()
DOC = make_org(PROFILES.fixture)
ORG = org.org_id(DOC)
GENESIS = genesis.doc_hash(DOC)
SPEC = PROFILES.fixture
LINE = pinfile.line(GENESIS, ORG, SPEC)


def malformed(raw):
    try:
        pinfile.parse(raw)
    except errors.Refused as err:
        return err.code
    return None


class Line(unittest.TestCase):
    def test_exact_bytes(self):
        expected = ('{"genesis":"%s","org":"%s","spec":"%s","v":"handsal-pin/1"}\n' % (GENESIS, ORG, SPEC)).encode()
        self.assertEqual(LINE, expected)

    def test_it_is_canonical_subset_and_small(self):
        self.assertEqual(emit.emit_subset(json.loads(LINE)) + b"\n", LINE)
        self.assertLessEqual(len(LINE), 512)

    def test_refuses_a_non_hashstr_member(self):
        with self.assertRaises(ValueError):
            pinfile.line("nope", ORG, SPEC)


class Parse(unittest.TestCase):
    def test_ok(self):
        pin = pinfile.parse(LINE)
        self.assertEqual((pin.genesis, pin.org, pin.spec), (GENESIS, ORG, SPEC))

    def test_every_defect_is_pin_malformed(self):
        body = LINE[:-1]
        cases = {
            "empty": b"",
            "only LF": b"\n",
            "crlf": body + b"\r\n",
            "no trailing LF": body,
            "extra line": LINE + LINE,
            "extra blank line": LINE + b"\n",
            "leading LF": b"\n" + LINE,
            "513 bytes": body[:-2] + b"," + b'"pad":"' + b"x" * (513 - len(body) - 11) + b'"}\n',
            "non-ascii": LINE.replace(b"handsal-pin/1", "handsal-pé/1".encode()),
            "wrong v": LINE.replace(b"handsal-pin/1", b"handsal-pin/2"),
            "unknown member": LINE.replace(b'"genesis"', b'"foo":"x","genesis"'),
            "reordered": b'{"genesis":"%s","spec":"%s","org":"%s","v":"handsal-pin/1"}\n' % (
                GENESIS.encode(), SPEC.encode(), ORG.encode()),
            "duplicate org": LINE.replace(b'"spec"', b'"org":"%s","spec"' % ORG.encode()),
            "missing member": b'{"genesis":"%s","org":"%s","v":"handsal-pin/1"}\n' % (GENESIS.encode(), ORG.encode()),
            "space": LINE.replace(b'"org":', b'"org": '),
            "genesis not a hashstr": LINE.replace(GENESIS.encode(), b"nope"),
            "spec not a hashstr": LINE.replace(SPEC.encode(), b"nope"),
            "org not a hashstr": LINE.replace(ORG.encode(), b"nope"),
            "a number": LINE.replace(b'"handsal-pin/1"', b"1"),
            "an array root": b"[]\n",
            "null root": b"null\n",
        }
        for label, raw in cases.items():
            self.assertEqual(malformed(raw), "pin_malformed", label)

    def test_exactly_512_bytes_is_allowed_by_size_alone(self):
        # the size limit is on the whole line; a line that fits is judged by its content only
        self.assertLessEqual(len(LINE), 512)
        self.assertIsNone(malformed(LINE))


def probe(raw=LINE, **over):
    value = {"bytes_b64": base64.b64encode(raw).decode(), "filename": org.pin_filename(ORG),
             "org": ORG, "owner_ok": True, "reason": "ok"}
    value.update(over)
    return value


NO_LINEAGE = object()


def evaluate(p, expected_org=ORG, last_hash=GENESIS, last_profile=SPEC, first_hash=ORG, allow_fixture=True):
    try:
        ends = None if last_hash is NO_LINEAGE else pinfile.Ends(first_hash, last_hash, last_profile)
        return pinfile.check(pinfile.Probe.from_json(p), expected_org, PROFILES, ends, allow_fixture)
    except errors.Refused as err:
        return err.code


class Probe(unittest.TestCase):
    def test_from_json_accepts_the_probe_object(self):
        got = pinfile.Probe.from_json(probe())
        self.assertEqual((got.raw, got.filename, got.org, got.owner_ok, got.reason),
                         (LINE, org.pin_filename(ORG), ORG, True, "ok"))

    def test_malformed_probe_objects(self):
        from handsal_check.errors import Malformed
        good = probe()
        cases = [None, [], "x", {}, {**good, "extra": 1},
                 {k: v for k, v in good.items() if k != "reason"},
                 probe(bytes_b64=5), probe(bytes_b64="@@@"), probe(bytes_b64="Zm9v\n"),
                 probe(filename=5), probe(org=5), probe(owner_ok="yes"), probe(owner_ok=1),
                 probe(reason=5), probe(owner_ok=False, reason="ok"), probe(owner_ok=False, reason="nonsense"),
                 probe(owner_ok=True, reason="pin_owner")]
        for case in cases:
            with self.assertRaises(Malformed, msg=repr(case)):
                pinfile.Probe.from_json(case)

    def test_the_four_failing_reasons_are_accepted(self):
        for reason in ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected"):
            self.assertEqual(pinfile.Probe.from_json(probe(b"", owner_ok=False, reason=reason)).reason, reason)


class Check(unittest.TestCase):
    def test_ok_returns_the_pin(self):
        pin = evaluate(probe())
        self.assertEqual((pin.genesis, pin.org, pin.spec), (GENESIS, ORG, SPEC))

    def test_a_filename_for_another_org_is_pin_org_mismatch(self):
        self.assertEqual(evaluate(probe(filename="0" * 64 + ".pin")), "pin_org_mismatch")
        self.assertEqual(evaluate(probe(filename=org.pin_filename(ORG).upper())), "pin_org_mismatch")

    def test_a_probe_of_another_org_is_pin_org_mismatch(self):
        other = org.org_id(make_org(PROFILES.fixture, name="OTHER"))
        self.assertEqual(evaluate(probe(org=other)), "pin_org_mismatch")
        self.assertEqual(evaluate(probe(), expected_org=other), "pin_org_mismatch")

    def test_owner_not_ok_returns_the_probes_reason(self):
        for reason in ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected"):
            self.assertEqual(evaluate(probe(b"", owner_ok=False, reason=reason)), reason)

    def test_the_probes_org_is_judged_before_ownership(self):
        other = org.org_id(make_org(PROFILES.fixture, name="OTHER"))
        self.assertEqual(evaluate(probe(b"", owner_ok=False, reason="pin_owner", org=other)), "pin_org_mismatch")

    def test_ownership_is_judged_before_the_bytes(self):
        self.assertEqual(evaluate(probe(b"junk", owner_ok=False, reason="pin_owner")), "pin_owner")

    def test_bytes_are_judged_before_the_pins_org(self):
        self.assertEqual(evaluate(probe(b"junk")), "pin_malformed")

    def test_a_pin_for_another_org_is_pin_org_mismatch(self):
        other = org.org_id(make_org(PROFILES.fixture, name="OTHER"))
        line = pinfile.line(GENESIS, other, SPEC)
        self.assertEqual(evaluate(probe(line)), "pin_org_mismatch")

    def test_an_unimplemented_spec_is_profile_mismatch(self):
        line = pinfile.line(GENESIS, ORG, encoding.hashstr(b"another profile"))
        self.assertEqual(evaluate(probe(line)), "profile_mismatch")

    def test_the_production_build_refuses_a_fixture_spec(self):
        self.assertEqual(evaluate(probe(), allow_fixture=False), "fixture_profile")

    def test_the_pins_genesis_must_be_the_last_document(self):
        line = pinfile.line(encoding.hashstr(b"another doc"), ORG, SPEC)
        self.assertEqual(evaluate(probe(line)), "genesis_pin_mismatch")

    def test_an_empty_lineage_is_lineage_broken_where_the_comparison_would_be(self):
        self.assertEqual(evaluate(probe(), last_hash=NO_LINEAGE), "lineage_broken")
        self.assertEqual(evaluate(probe(b"junk"), last_hash=NO_LINEAGE), "pin_malformed")
        line = pinfile.line(GENESIS, ORG, encoding.hashstr(b"another profile"))
        self.assertEqual(evaluate(probe(line), last_hash=NO_LINEAGE), "profile_mismatch")

    def test_the_pins_org_must_be_the_first_document_GP_07(self):
        self.assertEqual(evaluate(probe(), first_hash=encoding.hashstr(b"another original")), "lineage_broken")

    def test_a_first_document_with_no_hash_is_lineage_broken(self):
        self.assertEqual(evaluate(probe(), first_hash=None), "lineage_broken")

    def test_the_first_document_is_judged_before_the_last(self):
        self.assertEqual(evaluate(probe(), first_hash=encoding.hashstr(b"x"), last_hash=encoding.hashstr(b"y")),
                         "lineage_broken")

    def test_the_first_document_is_judged_after_the_pins_own_checks(self):
        line = pinfile.line(GENESIS, ORG, encoding.hashstr(b"another profile"))
        self.assertEqual(evaluate(probe(line), first_hash=encoding.hashstr(b"x")), "profile_mismatch")

    def test_ends_of_a_lineage_is_one_function_for_every_pin_reading_command(self):
        self.assertIsNone(pinfile.ends([]))
        two = [{"doc": DOC, "sigs": []}, {"doc": {"profile": SPEC, "x": "1"}, "sigs": []}]
        got = pinfile.ends(two)
        self.assertEqual((got.first, got.profile), (GENESIS, SPEC))
        self.assertEqual(got.last, genesis.doc_hash(two[1]["doc"]))
        junk = pinfile.ends([{"doc": {"b": 1, "a": 2}, "sigs": []}, {"doc": 5, "sigs": []}])
        self.assertEqual((junk.first, junk.last, junk.profile), (None, None, None))

    def test_a_last_document_with_no_hash_cannot_match(self):
        self.assertEqual(evaluate(probe(), last_hash=None), "genesis_pin_mismatch")

    def test_the_pins_spec_must_be_the_last_documents_profile(self):
        self.assertEqual(evaluate(probe(), last_profile=PROFILES.production), "pin_spec_mismatch")

    def test_profile_mismatch_before_fixture_before_genesis_before_spec(self):
        line = pinfile.line(encoding.hashstr(b"another doc"), ORG, encoding.hashstr(b"another profile"))
        self.assertEqual(evaluate(probe(line)), "profile_mismatch")
        line = pinfile.line(encoding.hashstr(b"another doc"), ORG, PROFILES.fixture)
        self.assertEqual(evaluate(probe(line), allow_fixture=False), "fixture_profile")
        self.assertEqual(evaluate(probe(line)), "genesis_pin_mismatch")
        self.assertEqual(evaluate(probe(), last_hash=GENESIS, last_profile=PROFILES.production), "pin_spec_mismatch")


if __name__ == "__main__":
    unittest.main()
