"""A retired method is one more string outside the registry (ACT-09, S9). No implementation names it: an act
or payload of it is `method_unknown` through the path every unknown method takes, whatever extra inputs a
caller of the old method still sends."""
import json
import unittest

from handsal_check import encoding, errors, registry, render, render_attach, profiles

from .act_builder import build, head_of
from .checkact_world import EXPIRES, TS, Scenario, b64, check
from .test_recheck import rc

RETIRED = "local:handsal.record.promote"
BODY = b"record body v1"
REG = registry.load()


def retired_act(scenario):
    """An act in the shape the retired method had: body `{anchors, record_id}`, an `expires` and a `head`."""
    return build("alice", "record.promote", org=scenario.w.id, body={"anchors": ["a1"], "record_id": "rec-1"},
                 head=head_of(scenario.w.id), inputs_hash=encoding.hashstr(BODY), ts=TS, extra={"expires": EXPIRES})


class Retired(unittest.TestCase):
    def test_the_registry_does_not_know_it(self):
        self.assertIsNone(REG.wire.method(RETIRED))

    def test_a_retired_method_is_method_unknown(self):
        s = Scenario()
        act = retired_act(s)
        value = s.value(act, expect_method=RETIRED, record_body_b64=b64(BODY))
        for key in ("recipient", "request_b64", "request_id"):
            del value[key]
        got = check(value)
        self.assertFalse(got["valid"])
        self.assertEqual(got["reason"], "method_unknown")
        self.assertIsNone(got["class"])
        self.assertEqual(got["receipt_id"], act.id)

    def test_a_retired_method_needs_no_other_input(self):
        s = Scenario()
        value = s.value(retired_act(s), expect_method=RETIRED)
        self.assertEqual(check(value)["reason"], "method_unknown")

    def test_a_stored_retired_act_is_method_unknown_to_recheck_act(self):
        s = Scenario()
        act = retired_act(s)
        value = s.value(act, expect_method=RETIRED, record_body_b64=b64(BODY))
        for key in ("recipient", "request_b64", "request_id"):
            del value[key]
        got = rc(value)
        self.assertFalse(got["rechecked"])
        self.assertEqual(got["reason"], "method_unknown")
        self.assertIsNone(got["class"])
        self.assertEqual(got["receipt_id"], act.id)

    def test_a_decision_checked_with_the_retired_expect_method_is_a_context_mismatch(self):
        s = Scenario()
        got = check(s.decision_value(expect_method=RETIRED))
        self.assertEqual(got["reason"], "context_mismatch")

    def test_a_retired_payload_is_method_unknown_to_the_renderer(self):
        s = Scenario()
        act = retired_act(s)
        payload = json.loads(encoding.b64u_decode(act.jws.split(".")[1]))
        inp = render.Input({"record_body_b64": b64(BODY)}, act.kid, RETIRED, payload)
        with self.assertRaises(errors.Refused) as ctx:
            render_attach.render_payload(inp, profiles.load())
        self.assertEqual(ctx.exception.code, "method_unknown")


if __name__ == "__main__":
    unittest.main()
