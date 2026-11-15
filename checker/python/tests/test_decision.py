"""The decision act (VR-18): one generic method for a local human decision.

The rules it protects:
- what the person decides is what the signature covers: the content is attached, bound by `inputs_hash`,
  rendered under the block limits, and `action` is text under one grammar the profile owns;
- a decision signed for one consumer cannot be accepted by another: `consumer` is signed, rendered and
  compared with the consumer the verifier is (`consumer_mismatch`, step 12);
- `recheck-act` covers it through the same time-free steps as any non-chain act, with no rule copied.
"""
import json
import unittest

from handsal_check import bodies, encoding, errors, profiles, registry, render, render_attach, rules, schema
from handsal_check import recheck as recheck_module

from .act_builder import FakeVitni
from .checkact_world import CONTENT, DECISION, Scenario, b64, check, decision_outputs
from .fold_world import World, ids
from .test_recheck import NOT_PROVEN, good, rc

REG = registry.load()
PROFILES = profiles.load()
ACTION_24 = "ratify ruling and record"


def decoded(act):
    return json.loads(encoding.b64u_decode(act.jws.split(".")[1]))


class Forms(unittest.TestCase):
    def test_action_is_lowercase_words_separated_by_single_spaces_up_to_24_characters(self):
        for ok in ("ratify ruling", "forget item", "a", "x" * 24, ACTION_24, "a b c"):
            self.assertTrue(schema.is_action(ok), repr(ok))
        for bad in ("", "Ratify ruling", "ratify  ruling", " ratify", "ratify ", "ratify2", "re-open", "x" * 25,
                    "ratify\truling", "ratify\nruling", "café", "ratify_ruling", None, 7):
            self.assertFalse(schema.is_action(bad), repr(bad))

    def test_a_consumer_id_starts_with_a_letter_and_has_2_to_32_characters(self):
        for ok in ("notes", "ab", "a" * 32, "a-1"):
            self.assertTrue(schema.is_consumer_id(ok), ok)
        for bad in ("a", "a" * 33, "1ab", "-ab", "Notes", "", "no tes", None):
            self.assertFalse(schema.is_consumer_id(bad), repr(bad))

    def test_a_subject_id_has_2_to_64_characters(self):
        for ok in ("ruling-0001", "ab", "a" * 64, "0a"):
            self.assertTrue(schema.is_subject_id(ok), ok)
        for bad in ("a", "a" * 65, "-ab", "Ab", "", "ab cd", None):
            self.assertFalse(schema.is_subject_id(bad), repr(bad))

    def test_the_registry_names_these_forms_and_no_other_for_the_body(self):
        method = REG.method(DECISION)
        self.assertEqual(method.head, "always")
        self.assertEqual(method.act_extra_keys, ("expires",))
        self.assertEqual({k: v["type"] for k, v in method.body["keys"].items()},
                         {"action": "action", "consumer": "consumer_id", "subject": "subject_id"})
        self.assertEqual((method.inputs_hash, method.outputs_hash), ("raw_decision_bytes", "action_subject"))


class Body(unittest.TestCase):
    def verdict(self, **edit):
        body = {"action": "ratify ruling", "consumer": "notes", "subject": "ruling-0001"}
        body.update(edit)
        try:
            bodies.validate(DECISION, body, REG)
        except errors.Refused as err:
            return err.code
        return None

    def test_a_valid_body(self):
        self.assertIsNone(self.verdict())

    def test_a_grammar_violation_of_a_field_is_body_schema(self):
        for edit in ({"action": "Ratify"}, {"action": "ratify  ruling"}, {"action": " ratify"}, {"action": "ratify "},
                     {"action": "ratify 2"}, {"action": "x" * 25}, {"action": ""}, {"subject": "Ruling"},
                     {"subject": "a"}, {"consumer": "Notes"}, {"consumer": "n"}):
            self.assertEqual(self.verdict(**edit), "body_schema", edit)

    def test_a_missing_or_extra_key_is_body_schema(self):
        body = {"action": "ratify ruling", "consumer": "notes", "subject": "ruling-0001"}
        for broken in ({k: v for k, v in body.items() if k != "consumer"}, {**body, "recipient": "alice"}, {}):
            with self.assertRaises(errors.Refused) as caught:
                bodies.validate(DECISION, broken, REG)
            self.assertEqual(caught.exception.code, "body_schema")


class Check(unittest.TestCase):
    def setUp(self):
        self.s = Scenario()

    def test_a_valid_decision_for_the_consumer_is_valid(self):
        act = self.s.decision()
        got = check(self.s.decision_value(act))
        self.assertEqual(got, {"class": "apple-se-bio", "reason": "ok", "receipt_id": act.id, "valid": True})

    def test_the_longest_action_is_valid(self):
        act = self.s.decision(action=ACTION_24)
        self.assertTrue(check(self.s.decision_value(act, action=ACTION_24))["valid"])

    def test_another_consumer_is_consumer_mismatch(self):
        act = self.s.decision()
        got = check(self.s.decision_value(act, consumer="archive"))
        self.assertEqual((got["valid"], got["reason"], got["class"]), (False, "consumer_mismatch", "apple-se-bio"))

    def test_the_same_words_and_bytes_signed_for_another_consumer_are_not_accepted(self):
        # a decision for `archive` with the action, subject and content of the one for `notes`
        other = self.s.decision(consumer="archive")
        self.assertEqual(check(self.s.decision_value(other))["reason"], "consumer_mismatch")
        self.assertTrue(check(self.s.decision_value(other, consumer="archive"))["valid"])

    def test_an_edited_consumer_is_a_bad_signature(self):
        act = self.s.decision(edit=lambda p: p["ext"]["dev.handsal/act"]["body"].__setitem__("consumer", "archive"),
                              sig=b"\x00" * 64)
        got = check(self.s.decision_value(act, consumer="archive"))
        self.assertEqual(got["reason"], "bad_signature")

    def test_consumer_mismatch_comes_before_inputs_and_outputs(self):
        act = self.s.decision(outputs_hash=encoding.hashstr(b"other"))
        got = check(self.s.decision_value(act, consumer="archive", decision_b64=b64(b"another")))
        self.assertEqual(got["reason"], "consumer_mismatch")

    def test_the_signature_is_examined_before_the_consumer(self):
        act = self.s.decision(sig=b"\x00" * 64)
        self.assertEqual(check(self.s.decision_value(act, consumer="archive"))["reason"], "bad_signature")

    def test_other_content_is_inputs_mismatch(self):
        got = check(self.s.decision_value(decision_b64=b64(b"another content")))
        self.assertEqual(got["reason"], "inputs_mismatch")

    def test_the_right_consumer_with_another_action_or_subject_is_outputs_mismatch(self):
        act = self.s.decision()
        for change in ({"action": "forget item"}, {"subject": "ruling-0002"}):
            got = check(self.s.decision_value(act, **change))
            self.assertEqual((got["valid"], got["reason"]), (False, "outputs_mismatch"), change)

    def test_the_words_the_caller_expects_bind_the_body_and_not_only_outputs_hash(self):
        # outputs_hash is the one of the words the caller expects, but the body says other words
        act = self.s.decision(action="forget item", outputs_hash=decision_outputs("ratify ruling"))
        self.assertEqual(check(self.s.decision_value(act))["reason"], "outputs_mismatch")

    def test_outputs_of_another_action_or_subject_is_outputs_mismatch(self):
        for outputs in (decision_outputs("forget item"), decision_outputs(subject="ruling-0002"),
                        encoding.EMPTY_HASH):
            act = self.s.decision(outputs_hash=outputs)
            self.assertEqual(check(self.s.decision_value(act))["reason"], "outputs_mismatch")

    def test_expiry_and_the_time_rules_apply(self):
        act = self.s.decision(extra={"expires": "2026-01-01T00:10:00Z"})
        self.assertEqual(check(self.s.decision_value(act))["reason"], "expired")

    def test_the_grammar_of_each_field_is_body_schema_through_the_whole_pipeline(self):
        for body in ({"action": "Ratify ruling", "consumer": "notes", "subject": "ruling-0001"},
                     {"action": "ratify ruling", "consumer": "Notes", "subject": "ruling-0001"},
                     {"action": "ratify ruling", "consumer": "notes", "subject": "Ruling-0001"},
                     {"action": "ratify ruling", "consumer": "notes", "subject": "ruling-0001", "extra": "x"}):
            act = self.s.decision(body=body)
            self.assertEqual(check(self.s.decision_value(act))["reason"], "body_schema", body)

    def test_a_decision_has_no_recipient_relay_or_request_id(self):
        for key, value in (("recipient", "alice"), ("relay", "r.example"), ("request_id", "req-00000001")):
            act = self.s.decision(extra={key: value})
            self.assertEqual(check(self.s.decision_value(act))["reason"], "schema", key)

    def test_the_performer_is_the_person_of_the_signing_device(self):
        act = self.s.decision(performer="bob")
        self.assertEqual(check(self.s.decision_value(act))["reason"], "unknown_key")

    def test_a_decision_is_not_a_chain_method_and_a_chain_act_still_is(self):
        self.assertNotEqual(check(self.s.decision_value())["reason"], "chain_method")
        primary = self.s.w.device_add("alice2", ("alice", "bob")).primary
        got = check(self.s.decision_value(primary))
        self.assertEqual(got["reason"], "chain_method")


class Inputs(unittest.TestCase):
    def setUp(self):
        self.s = Scenario()

    def run_input(self, **change):
        value = self.s.decision_value()
        for key, new in change.items():
            if new is None:
                value.pop(key, None)
            else:
                value[key] = new
        try:
            return check(value)["reason"]
        except errors.Malformed:
            return "malformed_input"

    def test_the_consumer_and_the_content_are_required(self):
        self.assertEqual(self.run_input(consumer=None), "malformed_input")
        self.assertEqual(self.run_input(decision_b64=None), "malformed_input")

    def test_a_consumer_that_is_no_consumer_id_is_malformed_input_not_a_mismatch(self):
        for bad in ("Notes", "n", "", "a" * 33, "no tes", 5, None):
            self.assertEqual(self.run_input(consumer=bad) if bad is not None else "malformed_input", "malformed_input")

    def test_the_content_must_be_canonical_base64(self):
        self.assertEqual(self.run_input(decision_b64=b64(CONTENT).rstrip("=")), "malformed_input")
        self.assertEqual(self.run_input(decision_b64=7), "malformed_input")

    def test_the_expected_action_and_subject_are_required_and_have_their_forms(self):
        self.assertEqual(self.run_input(action=None), "malformed_input")
        self.assertEqual(self.run_input(subject=None), "malformed_input")
        for bad in ("Ratify", "ratify  ruling", "", "x" * 25, 5):
            self.assertEqual(self.run_input(action=bad), "malformed_input", bad)
        for bad in ("Ruling", "a", "x" * 65, 5):
            self.assertEqual(self.run_input(subject=bad), "malformed_input", bad)

    def test_a_verdict_input_does_not_need_them(self):
        self.assertTrue(check(self.s.value())["valid"])


class Recheck(unittest.TestCase):
    def setUp(self):
        self.s = Scenario()

    def test_a_stored_decision_rechecks(self):
        act = self.s.decision()
        self.assertEqual(rc(self.s.decision_value(act)), good(act.id))

    def test_another_consumer_is_consumer_mismatch(self):
        act = self.s.decision()
        got = rc(self.s.decision_value(act, consumer="archive"))
        self.assertEqual((got["rechecked"], got["reason"]), (False, "consumer_mismatch"))
        self.assertEqual(got["not_proven"], NOT_PROVEN)

    def test_other_content_is_inputs_mismatch(self):
        got = rc(self.s.decision_value(decision_b64=b64(b"another")))
        self.assertEqual(got["reason"], "inputs_mismatch")

    def test_another_action_or_subject_is_outputs_mismatch_and_both_are_required(self):
        act = self.s.decision()
        for change in ({"action": "forget item"}, {"subject": "ruling-0002"}):
            self.assertEqual(rc(self.s.decision_value(act, **change))["reason"], "outputs_mismatch", change)
        for key in ("action", "subject"):
            value = self.s.decision_value()
            del value[key]
            with self.assertRaises(errors.Malformed):
                rc(value)

    def test_the_consumer_is_required_and_a_moment_is_refused(self):
        value = self.s.decision_value()
        del value["consumer"]
        with self.assertRaises(errors.Malformed):
            rc(value)
        with self.assertRaises(errors.Malformed):
            recheck_module.parse_input({**{k: v for k, v in self.s.decision_value().items()
                                           if k not in ("next", "now", "seen", "synced_at", "tip_statement")},
                                          "now": "x"})

    def test_an_expired_decision_still_rechecks(self):
        act = self.s.decision(extra={"expires": "2026-01-01T00:10:00Z"})
        self.assertTrue(rc(self.s.decision_value(act))["rechecked"])

    def test_both_commands_share_the_consumer_step(self):
        # the consumer comparison is one of the shared time-free steps (step 12), not a copy in either command
        self.assertIn(rules.request, rules.TIME_FREE)
        self.assertEqual(rules.RECHECK_STEPS[:-1], rules.TIME_FREE)
        self.assertEqual(rules.STEPS[:len(rules.TIME_FREE)], rules.TIME_FREE)


class Render(unittest.TestCase):
    def setUp(self):
        self.s = Scenario()

    def run_render(self, act, attachments, method=None):
        payload = decoded(act)
        return render_attach.render_payload(render.Input(attachments, act.kid, method or payload["method"], payload),
                                            REG, PROFILES)

    def code(self, act, attachments):
        try:
            self.run_render(act, attachments)
        except errors.Refused as err:
            return err.code
        return None

    def test_line_1_and_the_method_lines(self):
        act = self.s.decision()
        got = self.run_render(act, {"decision_b64": b64(CONTENT)})
        h = render.hash12(decoded(act)["inputs_hash"])
        self.assertEqual(got.first_line, "notes: ratify ruling ruling-0001 (%s, %d bytes)" % (h, len(CONTENT)))
        lines = got.text.split("\n")
        self.assertEqual(lines[0], got.first_line)
        self.assertEqual(lines[1], "Method: local:handsal.decision")
        self.assertEqual(lines[4:8], ["Consumer: notes", "Action: ratify ruling", "Subject: ruling-0001",
                                      "Decision hash: " + h])
        self.assertEqual(lines[8], "----- decision (%d bytes, sha256 %s) -----" % (len(CONTENT), h))
        self.assertEqual(lines[9], "| Ruling 0001: keep the retry limit at three.")
        self.assertEqual(lines[10], "----- end -----")
        self.assertIn("Expires: 2026-01-01T01:00:00Z", lines)
        self.assertNotIn("Sender: not proven", lines)
        self.assertFalse(any(line.startswith("Parent:") for line in lines))
        self.assertTrue(got.text.endswith("\n") and not got.text.endswith("\n\n"))

    def test_line_1_is_exactly_80_bytes_at_the_longest_fields_and_never_more(self):
        full = (b"x" * 63 + b"\n") * 32   # 2048 bytes in 32 lines, the largest block
        act = self.s.decision(consumer="c" * 32, action=ACTION_24, subject="s" * 64, content=full)
        got = self.run_render(act, {"decision_b64": b64(full)})
        self.assertEqual(len(got.first_line), 80)
        self.assertTrue(got.first_line.startswith("c" * 11 + "~: " + ACTION_24 + " " + "s" * 11 + "~ ("))
        self.assertIn("Consumer: " + "c" * 32, got.text)
        self.assertIn("Subject: " + "s" * 64, got.text)

    def test_the_action_is_never_cut(self):
        act = self.s.decision(action=ACTION_24)
        self.assertIn(": " + ACTION_24 + " ", self.run_render(act, {"decision_b64": b64(CONTENT)}).first_line)

    def test_an_empty_content_has_no_content_line(self):
        act = self.s.decision(content=b"")
        got = self.run_render(act, {"decision_b64": ""})
        self.assertIn("0 bytes)", got.first_line)
        self.assertIn("----- decision (0 bytes, sha256 ", got.text)
        self.assertEqual(got.text.split("\n")[8:10][1], "----- end -----")

    def test_a_line_that_looks_like_the_end_does_not_end_the_block(self):
        raw = b"----- end -----\n"
        act = self.s.decision(content=raw)
        self.assertIn("| ----- end -----", self.run_render(act, {"decision_b64": b64(raw)}).text)

    def test_other_content_attached_is_attachment_mismatch_and_none_is_missing(self):
        act = self.s.decision()
        self.assertEqual(self.code(act, {"decision_b64": b64(b"another")}), "attachment_mismatch")
        self.assertEqual(self.code(act, {}), "attachment_missing")
        self.assertEqual(self.code(act, {"request_b64": b64(CONTENT)}), "attachment_missing")

    def test_a_decision_attachment_that_is_not_canonical_base64_is_malformed(self):
        act = self.s.decision()
        with self.assertRaises(errors.Malformed):
            self.run_render(act, {"decision_b64": "not base64!"})
        with self.assertRaises(errors.Malformed):
            self.run_render(act, {"decision_b64": 5})

    def test_the_block_limits_are_the_request_limits(self):
        for raw, wanted in ((b"a" * 2048, None), (b"a" * 2049, "render_refused"), (b"a\n" * 32, None),
                            (b"a\n" * 33, "render_refused")):
            act = self.s.decision(content=raw)
            self.assertEqual(self.code(act, {"decision_b64": b64(raw)}), wanted, len(raw))

    def test_a_payload_whose_action_is_outside_the_grammar_is_body_schema(self):
        act = self.s.decision(action="Ratify ruling")
        self.assertEqual(self.code(act, {"decision_b64": b64(CONTENT)}), "body_schema")

    def test_the_render_command_wire_form(self):
        act = self.s.decision()
        out = render_attach.command({"attachments": {"decision_b64": b64(CONTENT)}, "kid": act.kid,
                                     "method": DECISION, "payload": decoded(act)}, REG, PROFILES)
        self.assertEqual(sorted(out), ["first_line", "text"])


class Fold(unittest.TestCase):
    def test_a_decision_is_never_on_the_chain(self):
        w = World()
        act = Scenario(w).decision()
        vitni = FakeVitni()
        e = w.epoch(act, vitni=vitni)
        self.assertEqual(ids(e), {w.id})
        self.assertEqual(vitni.calls, [])


if __name__ == "__main__":
    unittest.main()
