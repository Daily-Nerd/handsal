"""Vectors dec/*: the decision act through `check-act` (VR-18). Each row is stated from the spec, not from a checker."""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

REASON = {
    "dec/other-action": "outputs_mismatch", "dec/other-subject": "outputs_mismatch",
    "dec/other-consumer": "consumer_mismatch", "dec/replay-same-decision-other-consumer": "consumer_mismatch",
    "dec/consumer-swapped": "bad_signature", "dec/inputs-mismatch": "inputs_mismatch",
    "dec/outputs-mismatch": "outputs_mismatch", "dec/expired": "expired",
    "dec/action-uppercase-body-schema": "body_schema", "dec/action-double-space-body-schema": "body_schema",
    "dec/action-leading-space-body-schema": "body_schema", "dec/action-trailing-space-body-schema": "body_schema",
    "dec/action-digit-body-schema": "body_schema", "dec/action-25-bytes-body-schema": "body_schema",
    "dec/action-empty-body-schema": "body_schema", "dec/subject-uppercase-body-schema": "body_schema",
    "dec/consumer-uppercase-body-schema": "body_schema", "dec/body-extra-key-body-schema": "body_schema",
    "dec/recipient-key-schema": "schema"}
MALFORMED = {"dec/consumer-input-missing", "dec/consumer-input-form-malformed", "dec/decision-input-missing",
             "dec/action-input-missing", "dec/subject-input-missing", "dec/action-input-form-malformed",
             "dec/subject-input-form-malformed"}
GRAMMAR = {"dec/action-uppercase-body-schema", "dec/action-double-space-body-schema",
           "dec/action-leading-space-body-schema", "dec/action-trailing-space-body-schema",
           "dec/action-digit-body-schema", "dec/action-25-bytes-body-schema", "dec/action-empty-body-schema"}


def payload(jws):
    return json.loads(forge.parts(jws)[1])


def act(jws):
    return payload(jws)["ext"]["dev.handsal/act"]


class DecisionRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(("dec",), ("dec",))
        cls.ok = catalog.generate_modules(("ok",), ("ok",))

    def test_rows_are_the_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("dec/")})
        self.assertEqual(set(self.v), set(REASON) | MALFORMED)

    def test_every_row_is_a_check_act_for_the_decision_method(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act", name)
            self.assertEqual(v["input"]["expect_method"], inputs.DECISION, name)

    def test_the_reasons_are_the_catalog_codes(self):
        for name, v in self.v.items():
            self.assertEqual(catalog.anchor_code(v), catalog.catalog_code(name), name)
            if name in REASON:
                self.assertEqual(catalog.anchor_code(v), REASON[name], name)

    def test_the_input_names_the_consumer_the_verifier_is_and_the_content(self):
        for name, v in self.v.items():
            if name in MALFORMED:
                continue
            inp = v["input"]
            self.assertIn("consumer", inp, name)
            self.assertIn("decision_b64", inp, name)
            self.assertIn("action", inp, name)
            self.assertIn("subject", inp, name)
            for key in ("recipient", "relay", "request_b64", "request_id"):
                self.assertNotIn(key, inp, name)

    def test_the_malformed_rows_each_drop_or_break_one_input(self):
        self.assertNotIn("consumer", self.v["dec/consumer-input-missing"]["input"])
        self.assertEqual(self.v["dec/consumer-input-form-malformed"]["input"]["consumer"], "Notes")
        self.assertNotIn("decision_b64", self.v["dec/decision-input-missing"]["input"])
        for name in MALFORMED:
            self.assertEqual(json.loads(self.v[name]["anchor"]), {"error": "malformed_input"}, name)

    def test_the_word_rows_have_the_right_consumer_and_one_other_word(self):
        good = self.ok["ok/decision"]["input"]
        for name, key, value in (("dec/other-action", "action", "forget item"),
                                 ("dec/other-subject", "subject", "ruling-0002")):
            inp = self.v[name]["input"]
            self.assertEqual({k: v for k, v in inp.items() if k != key}, {k: v for k, v in good.items() if k != key})
            self.assertEqual(inp[key], value)
        for name, key, value in (("dec/action-input-missing", "action", None), ("dec/subject-input-missing", "subject", None),
                                 ("dec/action-input-form-malformed", "action", "Ratify ruling"),
                                 ("dec/subject-input-form-malformed", "subject", "Ruling")):
            inp = self.v[name]["input"]
            self.assertEqual(inp.get(key), value, name)
            self.assertEqual({k: v for k, v in inp.items() if k != key}, {k: v for k, v in good.items() if k != key}, name)

    def test_the_consumer_rows_differ_from_the_good_row_in_the_consumer_alone(self):
        other = self.v["dec/other-consumer"]["input"]
        self.assertEqual(other["consumer"], "archive")
        self.assertEqual(act(other["jws"])["body"]["consumer"], base.DECISION_CONSUMER)
        replay = self.v["dec/replay-same-decision-other-consumer"]["input"]
        self.assertEqual(replay["consumer"], base.DECISION_CONSUMER)
        body = act(replay["jws"])["body"]
        self.assertEqual(body, {"action": base.DECISION_ACTION, "consumer": "archive",
                                "subject": base.DECISION_SUBJECT})
        control = self.ok["ok/decision-other-consumer"]["input"]
        self.assertEqual(act(control["jws"])["body"], body)
        self.assertEqual(control["consumer"], "archive")

    def test_the_swapped_consumer_row_names_the_new_consumer_in_the_payload_and_in_the_input(self):
        inp = self.v["dec/consumer-swapped"]["input"]
        self.assertEqual((act(inp["jws"])["body"]["consumer"], inp["consumer"]), ("archive", "archive"))

    def test_each_grammar_row_has_the_one_action_defect(self):
        for name in GRAMMAR:
            body = act(self.v[name]["input"]["jws"])["body"]
            self.assertEqual(set(body), {"action", "consumer", "subject"}, name)
            self.assertEqual((body["consumer"], body["subject"]), (base.DECISION_CONSUMER, base.DECISION_SUBJECT), name)
        actions = {n: act(self.v[n]["input"]["jws"])["body"]["action"] for n in GRAMMAR}
        self.assertEqual(len(actions["dec/action-25-bytes-body-schema"]), 25)
        self.assertEqual(actions["dec/action-empty-body-schema"], "")
        self.assertTrue(actions["dec/action-leading-space-body-schema"].startswith(" "))
        self.assertTrue(actions["dec/action-trailing-space-body-schema"].endswith(" "))
        self.assertIn("  ", actions["dec/action-double-space-body-schema"])

    def test_the_longest_action_is_24_and_the_row_that_proves_it_valid_is_in_ok(self):
        self.assertEqual(len(base.DECISION_ACTION_24), 24)
        row = self.ok["ok/decision-action-24"]
        self.assertEqual(act(row["input"]["jws"])["body"]["action"], base.DECISION_ACTION_24)
        self.assertEqual(json.loads(row["anchor"])["reason"], "ok")

    def test_the_outputs_row_has_other_words_in_outputs_hash_and_nothing_else_wrong(self):
        p = payload(self.v["dec/outputs-mismatch"]["input"]["jws"])
        self.assertNotEqual(p["outputs_hash"], base.hashstr(forge.jcs.emit(
            {"action": base.DECISION_ACTION, "subject": base.DECISION_SUBJECT})))
        self.assertEqual(p["inputs_hash"], base.hashstr(base.DECISION_BODY))

    def test_the_outputs_hash_of_a_good_decision_is_the_hash_of_action_and_subject(self):
        p = payload(self.ok["ok/decision"]["input"]["jws"])
        self.assertEqual(p["outputs_hash"], base.hashstr(forge.jcs.emit(
            {"action": base.DECISION_ACTION, "subject": base.DECISION_SUBJECT})))
        self.assertEqual(p["inputs_hash"], base.hashstr(base.DECISION_BODY))
        self.assertEqual(p["parent_receipt_hash"], None)
        self.assertEqual(set(act(self.ok["ok/decision"]["input"]["jws"])), {"body", "expires", "head", "kid", "org"})

    def test_the_expired_row_is_expired_at_the_fixture_time(self):
        a = act(self.v["dec/expired"]["input"]["jws"])
        self.assertLessEqual(a["expires"], base.NOW)

    def test_the_recipient_row_carries_a_recipient_in_the_act_object(self):
        self.assertEqual(act(self.v["dec/recipient-key-schema"]["input"]["jws"])["recipient"], "alice")

    def test_a_row_that_passes_step_9_is_a_positive_for_the_vitni_cross_check(self):
        import groups.dec as module
        import tempfile

        import generate
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(d, registry=[module], known_ids=generate.shipping_ids(), stats=stats)
        # four distinct acts get past the signature (the good one, the one for `archive`, the one with other
        # outputs and the expired one) and are positives; dec/consumer-swapped is the one negative
        self.assertEqual(stats["positives"], 4)
        self.assertEqual(stats["negatives"], 1)


if __name__ == "__main__":
    unittest.main()
