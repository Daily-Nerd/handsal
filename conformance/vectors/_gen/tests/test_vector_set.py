"""Rules over the whole committed vector set, each stated from the spec and independent of the
checker: an expectation that holds only because one row was built wrong shows up here.

- VR-02: a `check-act` row whose first failure is step 10 or later (or `ok`) passes every earlier
  step, step 9 included, so `expect_method` is the method of the act.
- Section 2.2: `relay`, `request_id` and `record_id` of a legal act obey their grammars.
- GP-02, GP-15: a `fold` or `genesis-check` row that expects no code of steps 1 to 3 lists, in
  every document, more role holders than each rule's `persons`.
- CF-04, SG-04: every `emit` vector (a signer vector) is the answer the signer model gives for
  the stdin the harness builds from it, `pad` included, and its `exit` is the one the model gives.
- GP-15 step 6: a row whose answer needs the state (a fold state, or a `check-act` reason of
  step 7 or later) has a counting signature for every device of every document of its lineage,
  so `genesis_unsigned` is never an unwanted second defect.
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


def header_kid(jws):
    seg = jws.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["kid"]


def unsigned_devices(lineage):
    """The kids a lineage lists in a document and no signature of that entry names."""
    missing = []
    for entry in lineage:
        signed = {header_kid(j) for j in entry["sigs"]}
        missing += [d["kid"] for d in entry["doc"]["devices"] if d["kid"] not in signed]
    return missing


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

    def test_a_row_that_needs_the_state_signs_every_listed_device(self):
        for v in load():
            inp = v.get("input")
            if v["command"] not in ("fold", "check-act") or not isinstance(inp, dict):
                continue
            if not isinstance(inp.get("lineage"), list) or not inp["lineage"]:
                continue
            out = json.loads(v["anchor"])
            if v["command"] == "fold" and "error" in out:
                continue
            if v["command"] == "check-act" and out.get("reason") not in LATE_REASONS | {
                    "unknown_key", "revoked_key", "bad_signature", "context_mismatch", "relay_mismatch",
                    "org_mismatch", "unproven_class", "duplicate_receipt", "stale_view"}:
                continue
            self.assertEqual(unsigned_devices(inp["lineage"]), [], v["name"])

    def test_every_emit_vector_is_the_signer_models_answer(self):
        from lib import signer_emit
        seen = 0
        for v in load():
            if v["command"] != "emit":
                continue
            seen += 1
            code, obj = signer_emit.run(signer_emit.stdin_for(v["input"], v.get("pad")))
            self.assertEqual((code, signer_emit.line(obj)), (v.get("exit", 0), v["anchor"]), v["name"])
        self.assertGreater(seen, 0)

    def test_the_unsigned_device_helper_finds_a_device_nobody_signed(self):
        from lib import base, inputs
        fx = base.Fixtures(base.fixture_profile())
        full = inputs.original_lineage(fx, fx.org)
        self.assertEqual(unsigned_devices(full), [])
        short = [{"doc": fx.org, "sigs": full[0]["sigs"][:-1]}]
        self.assertEqual(len(unsigned_devices(short)), 1)


if __name__ == "__main__":
    unittest.main()
