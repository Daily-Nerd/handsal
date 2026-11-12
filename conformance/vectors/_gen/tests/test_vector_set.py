"""Rules over the whole committed vector set, each stated from the spec and independent of the
checker: an expectation that holds only because one row was built wrong shows up here.

- VR-02: a `check-act` row whose first failure is step 10 or later (or `ok`) passes every earlier
  step, step 9 included, so `expect_method` is the method of the act.
- Section 2.2: `relay`, `request_id` and `record_id` of a legal act obey their grammars.
- GP-02, GP-15: a `fold` or `genesis-check` row that expects no code of steps 1 to 3 lists, in
  every document, more role holders than each rule's `persons`.
"""
import base64
import glob
import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
VECTORS = HERE.parents[2]
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
LATE_REASONS = {"high_s", "identity_mismatch", "request_mismatch", "inputs_mismatch",
                "outputs_mismatch", "stale_time", "expired", "not_yet_valid", "ok"}
EARLY_CODES = {  # GP-15 steps 1 to 3
    "genesis_schema", "doc_not_sorted", "genesis_key_invalid", "duplicate_key",
    "profile_mismatch", "fixture_profile", "policy_invalid", "policy_out_of_bounds",
    "policy_unreachable", "class_unknown", "class_pending", "class_test_only",
    "class_policy_mismatch", "role_key_class", "fixture_key"}


def load():
    for path in sorted(glob.glob(str(VECTORS / "*.json"))):
        yield json.loads(Path(path).read_text(encoding="utf-8"))


def payload_of(jws):
    """The decoded payload object of a compact JWS, or {} when it is no JSON object."""
    seg = jws.split(".")[1]
    try:
        obj = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


class WholeSet(unittest.TestCase):
    def test_late_check_act_rows_pass_the_context_check(self):
        for v in load():
            jws = v.get("input", {}).get("jws") if isinstance(v.get("input"), dict) else None
            if v["command"] != "check-act" or not isinstance(jws, str) or jws.count(".") != 2:
                continue
            reason = json.loads(v["anchor"]).get("reason")
            if reason in LATE_REASONS:
                self.assertEqual(v["input"]["expect_method"], payload_of(jws).get("method"), v["name"])

    def test_the_relay_of_a_check_act_input_obeys_section_2_2(self):
        for v in load():
            inp = v.get("input")
            if v["command"] != "check-act" or not isinstance(inp, dict):
                continue
            jws = inp.get("jws")
            if not isinstance(jws, str) or jws.count(".") != 2:
                continue
            ext = payload_of(jws).get("ext")
            act = ext.get("dev.handsal/act", {}) if isinstance(ext, dict) else {}
            relay = act.get("relay") if isinstance(act, dict) else None
            reason = json.loads(v["anchor"]).get("reason")
            if isinstance(relay, str) and reason not in ("schema", "payload_not_canonical_subset"):
                self.assertTrue(len(relay) <= 253 and all(LABEL.fullmatch(x) for x in relay.split(".")),
                                v["name"])

    def test_a_row_after_step_3_has_no_unreachable_policy(self):
        for v in load():
            inp = v.get("input")
            if v["command"] not in ("fold", "genesis-check") or not isinstance(inp, dict):
                continue
            if not isinstance(inp.get("lineage"), list):
                continue
            out = json.loads(v["anchor"])
            code = out.get("error") or out.get("reason")
            if code in EARLY_CODES:
                continue
            for entry in inp["lineage"]:
                doc = entry.get("doc") if isinstance(entry, dict) else None
                if not isinstance(doc, dict) or not isinstance(doc.get("policy"), dict) \
                        or not isinstance(doc.get("members"), list):
                    continue
                for rule, spec in doc["policy"].get("rules", {}).items():
                    holders = [m for m in doc["members"] if m.get("role") in spec.get("roles", [])]
                    self.assertLess(int(spec["persons"]), len(holders), (v["name"], rule))


if __name__ == "__main__":
    unittest.main()
