"""Vectors rck/*: the stored-act re-check (VR-17). Each row is stated from the spec, not from a checker."""
import json
import unittest

from lib import base, forge, inputs
from tests import catalog

NOT_PROVEN = ["expiry", "freshness", "order_of_arrival", "replay", "revocation_after_head"]
TIMED = ("now", "seen", "synced_at", "tip_statement")
REASON = {
    "rck/ok": "ok", "rck/ok-expired-act": "ok", "rck/ok-fork-after-head": "ok",
    "rck/removed-key-names-old-head-accepted": "ok", "rck/bad-signature": "bad_signature",
    "rck/key-not-active-at-head": "unknown_key", "rck/inputs-mismatch": "inputs_mismatch",
    "rck/chain-method-refused": "chain_method", "rck/head-unknown": "stale_view",
    "rck/ok-act-of-earlier-epoch": "ok", "rck/head-past-change-stale-view": "stale_view",
    "rck/ok-decision": "ok", "rck/decision-other-consumer": "consumer_mismatch",
    "rck/decision-inputs-mismatch": "inputs_mismatch", "rck/decision-other-action": "outputs_mismatch",
    "rck/decision-other-subject": "outputs_mismatch"}
MALFORMED = {"rck/now-input-malformed": "now", "rck/synced-at-input-malformed": "synced_at",
             "rck/seen-input-malformed": "seen", "rck/tip-statement-input-malformed": "tip_statement"}
CONTROL = "rck/key-added-after-head-check-act-ok"
DECISION_MALFORMED = ("rck/decision-consumer-input-missing", "rck/decision-action-input-missing")   # VR-18


def payload(jws):
    return json.loads(forge.parts(jws)[1])


def head_id(jws):
    return payload(jws)["ext"]["dev.handsal/act"]["head"]["id"]


class RecheckRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(("rck",), ("rck",))

    def test_rows_are_the_catalog_ids(self):
        self.assertEqual(set(self.v), {k for k in catalog.ROWS if k.startswith("rck/")})

    def test_every_row_is_a_recheck_act_but_the_control(self):
        for name, v in self.v.items():
            self.assertEqual(v["command"], "check-act" if name == CONTROL else "recheck-act", name)

    def test_the_answer_has_five_keys_never_valid_and_rechecked_is_ok(self):
        for name, v in self.v.items():
            if name in MALFORMED or name == CONTROL or name in DECISION_MALFORMED:
                continue
            got = json.loads(v["anchor"])
            self.assertEqual(set(got), {"class", "not_proven", "reason", "receipt_id", "rechecked"}, name)
            self.assertEqual(got["not_proven"], NOT_PROVEN, name)
            self.assertEqual(got["reason"], REASON[name], name)
            self.assertEqual(got["rechecked"], got["reason"] == "ok", name)

    def test_the_class_is_null_before_the_state_and_after_a_head_that_names_no_device(self):
        for name in ("rck/chain-method-refused", "rck/head-unknown", "rck/key-not-active-at-head",
                     "rck/head-past-change-stale-view"):
            self.assertIsNone(json.loads(self.v[name]["anchor"])["class"], name)
        for name in ("rck/ok", "rck/bad-signature", "rck/inputs-mismatch"):
            self.assertEqual(json.loads(self.v[name]["anchor"])["class"], base.CLASS, name)

    def test_no_input_carries_a_key_that_names_a_moment_except_the_four_that_must_be_refused(self):
        for name, v in self.v.items():
            if name == CONTROL:
                continue
            carried = [k for k in TIMED if k in v["input"]]
            self.assertEqual(carried, [MALFORMED[name]] if name in MALFORMED else [], name)

    def test_a_refused_input_is_otherwise_the_input_of_rck_ok(self):
        ok = self.v["rck/ok"]["input"]
        for name, key in MALFORMED.items():
            got = self.v[name]
            self.assertEqual(got["anchor"], '{"error":"malformed_input"}', name)
            self.assertEqual({k: v for k, v in got["input"].items() if k != key}, ok, name)

    def test_the_decision_rows_differ_from_the_good_one_in_one_input_only(self):
        ok = self.v["rck/ok-decision"]["input"]
        self.assertEqual(ok["expect_method"], inputs.DECISION)
        self.assertEqual((ok["consumer"], ok["decision_b64"] != ""), (base.DECISION_CONSUMER, True))
        for key in TIMED:
            self.assertNotIn(key, ok)
        other = self.v["rck/decision-other-consumer"]["input"]
        self.assertEqual({k: v for k, v in other.items() if k != "consumer"},
                         {k: v for k, v in ok.items() if k != "consumer"})
        self.assertEqual(other["consumer"], "archive")
        for name, key in zip(DECISION_MALFORMED, ("consumer", "action")):
            missing = self.v[name]
            self.assertEqual(missing["anchor"], '{"error":"malformed_input"}')
            self.assertEqual(missing["input"], {k: v for k, v in ok.items() if k != key})
        for name, key, value in (("rck/decision-other-action", "action", "forget item"),
                                 ("rck/decision-other-subject", "subject", "ruling-0002")):
            inp = self.v[name]["input"]
            self.assertEqual(inp[key], value)
            self.assertEqual({k: v for k, v in inp.items() if k != key}, {k: v for k, v in ok.items() if k != key})
        mismatch = self.v["rck/decision-inputs-mismatch"]["input"]
        self.assertNotEqual(mismatch["decision_b64"], ok["decision_b64"])
        self.assertEqual(mismatch["jws"], ok["jws"])

    def test_the_expired_act_is_expired_at_the_fixture_time(self):
        act = payload(self.v["rck/ok-expired-act"]["input"]["jws"])["ext"]["dev.handsal/act"]
        self.assertLess(act["expires"], base.NOW)

    def test_the_two_acts_that_are_judged_by_an_old_head_name_a_position_before_the_tip(self):
        removed = self.v["rck/removed-key-names-old-head-accepted"]["input"]
        ids = {inputs.receipt_id(j) for j in removed["acts"]}
        self.assertIn(head_id(removed["jws"]), ids)
        self.assertTrue(any('"method":"local:handsal.device.remove"' in
                            forge.parts(j)[1].decode("utf-8") for j in removed["acts"]))
        root = inputs.doc_id(base.Fixtures(base.fixture_profile()).org)
        self.assertEqual(head_id(self.v["rck/key-not-active-at-head"]["input"]["jws"]), root)

    def test_the_control_is_the_same_act_with_its_add_in_the_bag_and_is_valid_at_the_tip(self):
        control, row = self.v[CONTROL], self.v["rck/key-not-active-at-head"]
        self.assertEqual(control["input"]["jws"], row["input"]["jws"])
        self.assertEqual(control["input"]["acts"], row["input"]["acts"])
        self.assertEqual(json.loads(control["anchor"])["valid"], True)

    def test_a_head_that_names_no_node_is_in_no_act_of_the_bag(self):
        v = self.v["rck/head-unknown"]["input"]
        self.assertNotIn(head_id(v["jws"]), {inputs.receipt_id(j) for j in v["acts"]})

    def test_the_epoch_rows_pin_the_change_and_not_the_original(self):
        for name in ("rck/ok-act-of-earlier-epoch", "rck/head-past-change-stale-view"):
            v = self.v[name]["input"]
            self.assertEqual(len(v["lineage"]), 2, name)
            last = inputs.doc_id(v["lineage"][-1]["doc"])
            line = json.loads(__import__("base64").b64decode(v["pin"]["bytes_b64"]))
            self.assertEqual(line["genesis"], last, name)
            self.assertEqual(v["org"], inputs.doc_id(v["lineage"][0]["doc"]), name)
        ok = self.v["rck/ok-act-of-earlier-epoch"]["input"]
        self.assertEqual(head_id(ok["jws"]), inputs.doc_id(ok["lineage"][0]["doc"]))   # a position of the first epoch
        past = self.v["rck/head-past-change-stale-view"]["input"]
        self.assertEqual(past["lineage"][-1]["doc"]["head"], inputs.doc_id(past["lineage"][0]["doc"]))
        self.assertNotEqual(head_id(past["jws"]), past["lineage"][-1]["doc"]["head"])

    def test_the_fork_row_has_two_children_of_the_head(self):
        v = self.v["rck/ok-fork-after-head"]["input"]
        parents = {payload(j)["parent_receipt_hash"] for j in v["acts"]
                   if payload(j)["method"] == "local:handsal.device.add"}
        self.assertEqual(parents, {head_id(v["jws"])})
        self.assertGreaterEqual(len(v["acts"]), 2)


if __name__ == "__main__":
    unittest.main()
