"""VR-01 input and `check-act` steps 1 to 6: the input boundary, the first five steps, and the pin and
lineage part of step 6 (the fold itself and steps 7 to 16 are in `test_checkact_pipeline`)."""
import base64
import io
import json
import unittest

from handsal_check import (checkact, conformance, emit, encoding, errors, genesis, pinfile,
                           production, profiles, registry)
from handsal_check import org as orgmod

from . import test_envelope as te
from .act_builder import FakeVitni
from .genesis_fixtures import edit as gedit, org as make_org

REG = registry.load()
PROFILES = profiles.load()
DOC = make_org(PROFILES.fixture)
ORG = orgmod.org_id(DOC)
LINE = pinfile.line(genesis.doc_hash(DOC), ORG, PROFILES.fixture)
SIG = bytes(range(64))
NOW = "2026-11-08T12:00:00Z"


def jws_of(payload, header_kid=te.KID):
    header = ('{"alg":"ES256","kid":"%s"}' % header_kid).encode()
    return ".".join(encoding.b64u_encode(part) for part in (header, emit.emit_subset(payload), SIG))


def probe():
    return {"bytes_b64": base64.b64encode(LINE).decode(), "filename": orgmod.pin_filename(ORG),
            "org": ORG, "owner_ok": True, "reason": "ok"}


def verdict_input(payload=None, **over):
    value = {
        "acts": [], "expect_method": te.APPROVE, "jws": jws_of(payload or te.verdict()),
        "lineage": [{"doc": DOC, "sigs": []}], "now": NOW, "org": ORG, "pin": probe(), "recipient": "alice",
        "relay": "r.example", "request_b64": base64.b64encode(b"deploy v2").decode(),
        "request_id": "req-00000001", "seen": [], "synced_at": NOW, "tip_statement": None}
    value.update(over)
    return value


def promote_input(**over):
    value = verdict_input(te.promote(), expect_method=te.PROMOTE)
    for key in ("recipient", "relay", "request_b64", "request_id"):
        del value[key]
    value["record_body_b64"] = base64.b64encode(b"record body v1").decode()
    value.update(over)
    return value


def malformed(value, conformance_build=True):
    try:
        checkact.parse_input(value, conformance_build)
    except errors.Malformed:
        return True
    return False


class Input(unittest.TestCase):
    def test_valid_inputs(self):
        self.assertFalse(malformed(verdict_input()))
        self.assertFalse(malformed(promote_input()))

    def test_every_required_key(self):
        for key in ("acts", "expect_method", "jws", "lineage", "now", "org", "pin", "seen", "synced_at",
                    "tip_statement"):
            value = verdict_input()
            del value[key]
            self.assertTrue(malformed(value), key)

    def test_verdict_inputs(self):
        for key in ("request_b64", "request_id", "recipient", "relay"):
            value = verdict_input()
            del value[key]
            self.assertTrue(malformed(value), key)
        self.assertTrue(malformed(verdict_input(relay=None)))

    def test_every_verdict_method_needs_them(self):
        for method in ("local:handsal.request.reject", "local:handsal.request.needs-info"):
            value = verdict_input(expect_method=method)
            del value["request_id"]
            self.assertTrue(malformed(value), method)

    def test_promote_input(self):
        value = promote_input()
        del value["record_body_b64"]
        self.assertTrue(malformed(value))

    def test_other_methods_need_none_of_them(self):
        value = verdict_input(expect_method="local:handsal.device.add")
        for key in ("request_b64", "request_id", "recipient", "relay"):
            del value[key]
        self.assertFalse(malformed(value))

    def test_types(self):
        for key, bad in (("acts", {}), ("acts", "x"), ("expect_method", 5), ("jws", None), ("jws", 5),
                         ("lineage", {}), ("seen", "x"), ("seen", ["nope"]), ("seen", [5]),
                         ("now", "2026-02-30T00:00:00Z"), ("now", 5), ("synced_at", "x"),
                         ("org", "nope"), ("org", 5), ("org", None), ("tip_statement", 5),
                         ("tip_statement", {}), ("pin", {}), ("pin", "x"), ("request_b64", 5),
                         ("request_id", 5), ("recipient", 5), ("relay", 5)):
            self.assertTrue(malformed(verdict_input(**{key: bad})), (key, bad))

    def test_tip_statement_may_be_null_or_a_string(self):
        self.assertFalse(malformed(verdict_input(tip_statement=None)))
        self.assertFalse(malformed(verdict_input(tip_statement="a.b.c")))

    def test_not_an_object(self):
        for bad in (None, [], "x", 5):
            self.assertTrue(malformed(bad), bad)

    def test_a_request_or_record_body_that_is_not_canonical_base64_is_malformed(self):
        for bad in ("@@", "Zm9v\n", "YWI"):   # "YWI" is "ab" without its padding
            self.assertTrue(malformed(verdict_input(request_b64=bad)), bad)
            self.assertTrue(malformed(promote_input(record_body_b64=bad)), bad)

    def test_every_item_of_acts_and_of_every_sigs_is_a_string(self):
        self.assertTrue(malformed(verdict_input(acts=["x", 5])))
        self.assertTrue(malformed(verdict_input(lineage=[{"doc": DOC, "sigs": ["x", 5]}])))
        self.assertTrue(malformed(verdict_input(lineage=[{"doc": DOC}])))
        self.assertTrue(malformed(verdict_input(lineage=[5])))
        self.assertTrue(malformed(verdict_input(lineage=[{"doc": DOC, "sigs": [], "extra": 1}])))
        self.assertFalse(malformed(verdict_input(acts=["junk"], lineage=[{"doc": 5, "sigs": ["junk"]}])))

    def test_the_production_build_takes_neither_pin_nor_now_nor_the_stores_four_keys(self):   # CF-08, CF-09
        full = verdict_input()
        self.assertTrue(malformed(full, conformance_build=False))     # carries all six
        supplied = ("pin", "now", "acts", "lineage", "synced_at", "tip_statement")
        production = {k: v for k, v in full.items() if k not in supplied}
        parsed = checkact.parse_input(production, conformance_build=False)
        self.assertEqual((parsed.pin, parsed.now, parsed.synced_at, parsed.tip_statement, parsed.store_reason),
                         (None, None, None, None, None))
        self.assertEqual((parsed.acts, parsed.lineage), ([], []))   # placeholders: the production `fill` replaces them
        for key in supplied:
            self.assertTrue(malformed({**production, key: full[key]}, conformance_build=False), key)

    def test_parsed_fields(self):
        parsed = checkact.parse_input(verdict_input())
        self.assertEqual(parsed.expect_method, te.APPROVE)
        self.assertEqual(parsed.org, ORG)
        self.assertEqual(parsed.pin.org, ORG)
        self.assertEqual(parsed.request_b64, base64.b64encode(b"deploy v2").decode())


def run(inp, allow_fixture=True, vitni=None):
    return checkact.run(checkact.parse_input(inp), REG, PROFILES, allow_fixture, vitni or FakeVitni())


def fails(reason, receipt=True, payload=None):
    expected = {"class": None, "reason": reason, "valid": False,
                "receipt_id": encoding.hashstr(emit.emit_subset(payload)) if receipt else None}
    return expected


class Steps(unittest.TestCase):
    def check(self, payload, reason):
        self.assertEqual(run(verdict_input(payload)), fails(reason, True, payload))

    def test_step_1_jws_shape_has_no_receipt_id(self):
        for text in ("", "a.b", "a.b.c.d", "!!!.b.c"):
            self.assertEqual(run(verdict_input(jws=text)), fails("jws_shape", False))

    def test_step_2_not_canonical_has_no_receipt_id(self):
        raw = b'{"a": 1}'
        text = ".".join(encoding.b64u_encode(p) for p in (('{"alg":"ES256","kid":"%s"}' % te.KID).encode(), raw, SIG))
        self.assertEqual(run(verdict_input(jws=text)), fails("payload_not_canonical_subset", False))

    def test_step_2_null_root(self):
        text = ".".join(encoding.b64u_encode(p) for p in (('{"alg":"ES256","kid":"%s"}' % te.KID).encode(), b"null", SIG))
        self.assertEqual(run(verdict_input(jws=text)), fails("payload_not_canonical_subset", False))

    def test_step_2_too_large(self):
        raw = b'{"a":"' + b"x" * 16384 + b'"}'
        text = ".".join(encoding.b64u_encode(p) for p in (('{"alg":"ES256","kid":"%s"}' % te.KID).encode(), raw, SIG))
        self.assertEqual(run(verdict_input(jws=text)), fails("payload_too_large", False))

    def test_step_3_schema_carries_the_receipt_id(self):
        self.check(te.edit(te.verdict(), ["status"], "FAILED"), "schema")

    def test_step_4_method_unknown(self):
        self.check(te.edit(te.verdict(), ["method"], "local:handsal.request.send"), "method_unknown")
        self.check(te.edit(te.verdict(), ["method"], "Local:Handsal.request.approve"), "method_unknown")

    def test_step_4_chain_method_for_every_non_human_method(self):
        for payload in (te.device_add(), te.endorse(), te.genesis_sign(True)):
            self.check(payload, "chain_method")
        for method in ("local:handsal.device.remove", "local:handsal.member.add", "local:handsal.chain.resolve"):
            self.check(te.edit(te.verdict(), ["method"], method), "chain_method")

    def test_step_4_comes_before_step_5(self):
        bad_act = te.edit(te.device_add(), ["ext", "dev.handsal/act", "extra"], "x")
        self.check(bad_act, "chain_method")

    def test_step_5_schema_then_body_schema(self):
        self.check(te.edit(te.verdict(), ["ext", "dev.handsal/act", "extra"], "x"), "schema")
        self.check(te.edit(te.verdict(), ["ext", "dev.handsal/act", "body"], {"x": "y"}), "body_schema")
        self.check(te.edit(te.promote(), ["ext", "dev.handsal/act", "body", "anchors"], ["a"] * 17), "body_schema")

    def test_step_5_kid_must_equal_the_header_kid(self):
        text = jws_of(te.verdict(), header_kid=te.KEYS["bob.sign"]["kid"])
        payload = te.verdict()
        self.assertEqual(run(verdict_input(jws=text)), fails("schema", True, payload))

    def test_step_6_pin_checks_then_the_documents(self):
        payload = te.verdict()
        other = orgmod.org_id(make_org(PROFILES.fixture, name="OTHER"))
        self.assertEqual(run(verdict_input(org=other)), fails("pin_org_mismatch", True, payload))
        missing = dict(probe(), bytes_b64="", owner_ok=False, reason="pin_missing")
        self.assertEqual(run(verdict_input(pin=missing)), fails("pin_missing", True, payload))
        self.assertEqual(run(verdict_input(lineage=[])), fails("lineage_broken", True, payload))
        bad_doc = gedit(DOC, ["extra"], "x")
        bad_org = genesis.doc_hash(bad_doc)   # the org id is the hash of the first document (GP-07)
        value = verdict_input(lineage=[{"doc": bad_doc, "sigs": []}], org=bad_org,
                              pin=dict(probe(), org=bad_org, filename=orgmod.pin_filename(bad_org),
                                       bytes_b64=base64.b64encode(
                                           pinfile.line(genesis.doc_hash(bad_doc), bad_org,
                                                        PROFILES.fixture)).decode()))
        value["pin"]["org"] = bad_org
        self.assertEqual(run(value), fails("genesis_schema", True, payload))

    def test_step_6_refuses_the_fixture_profile_where_the_build_does(self):
        self.assertEqual(run(verdict_input(), allow_fixture=False), fails("fixture_profile", True, te.verdict()))

    def test_step_5_is_judged_before_step_6(self):
        payload = te.edit(te.verdict(), ["status"], "FAILED")
        self.assertEqual(run(verdict_input(payload, lineage=[])), fails("schema", True, payload))

    def test_the_first_failing_step_wins(self):
        payload = te.edit(te.verdict(), ["status"], "FAILED")
        payload = te.edit(payload, ["method"], "local:handsal.request.send")
        self.check(payload, "schema")


def command(main, command_name, value):
    out = io.BytesIO()
    code = main([command_name], io.BytesIO(json.dumps(value).encode()), out)
    return code, out.getvalue()


class Command(unittest.TestCase):
    def test_conformance_build_answers_a_step_1_failure(self):
        code, out = command(conformance.main, "check-act", verdict_input(jws=""))
        self.assertEqual((code, out), (0, b'{"class":null,"reason":"jws_shape","receipt_id":null,"valid":false}\n'))

    def test_conformance_build_missing_input_is_malformed(self):
        value = verdict_input()
        del value["org"]
        self.assertEqual(command(conformance.main, "check-act", value),
                         (0, b'{"error":"malformed_input"}\n'))

    def test_the_production_build_offers_the_command_and_refuses_pin_and_now(self):
        self.assertEqual(command(production.main, "check-act", verdict_input()),
                         (0, b'{"error":"malformed_input"}\n'))


if __name__ == "__main__":
    unittest.main()
