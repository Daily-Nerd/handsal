"""The generator's model of the signer `emit` command (CF-04, SG-01, SG-04, SG-13, ACT-05).

`lib/signer_emit.py` is written from the spec alone. Its payload for a draft must equal the
payload the base builders sign for the same act (two derivations of one fact), and every refusal
the vectors state must be one the model gives for exactly that defect.
"""
import base64
import copy
import json
import unittest

from lib import base, emitrows, forge, jcs, signer_emit

FX = base.Fixtures(base.fixture_profile())
MAX_INPUT = 16777216


def stdin_of(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def payload_of(jws):
    return forge.parts(jws)[1]


def fixed_of(jws):
    payload = json.loads(payload_of(jws))
    return {"kid": json.loads(forge.parts(jws)[0])["kid"], "nonce": payload["nonce"],
            "performer": payload["performer_id"], "ts": payload["ts"]}


def approve_input(kind="approve"):
    jws = FX.verdict(kind)
    return {
        "attachments": {"request_b64": FX.request_b64()},
        "draft": {"body": {}, "expires_in_s": "3600", "head": {"id": FX.org_id, "kind": "chain"},
                  "method": "local:handsal.request.%s" % kind, "org": FX.org_id,
                  "recipient": "alice", "relay": base.RELAY_HOST, "request_id": base.REQUEST_ID},
        "fixed": fixed_of(jws)}, jws


def add_input(label=None):
    first = FX.device_add("alice2", ("alice", "bob"))
    second = FX.device_add("bob2", ("bob", "carol"), parent=first, label=label)
    entry = FX.device_entry("bob2")
    body = {"agree": entry["agree"], "class": entry["class"], "kid": entry["kid"],
            "label": label or entry["label"],
            "link_code_hash": base.hashstr(b"link-code/bob2"), "person": "bob",
            "sign": entry["sign"]}
    return {
        "attachments": {},
        "draft": {"body": body, "method": "local:handsal.device.add", "org": FX.org_id,
                  "parent": {"id": first.id, "performer": "alice"}},
        "fixed": fixed_of(second.acts[0])}, second.acts[0]


def run(value):
    code, obj = signer_emit.run(stdin_of(value))
    return code, obj


def edit(value, mutate):
    out = copy.deepcopy(value)
    mutate(out)
    return out


class Payload(unittest.TestCase):
    def test_a_verdict_draft_emits_the_payload_the_base_builder_signs(self):
        for kind in ("approve", "reject", "needs-info"):
            inp, jws = approve_input(kind)
            self.assertEqual(run(inp), (0, {"payload_hex": payload_of(jws).hex()}), kind)

    def test_a_device_add_draft_emits_the_payload_the_base_builder_signs(self):
        inp, jws = add_input()
        self.assertEqual(run(inp), (0, {"payload_hex": payload_of(jws).hex()}))

    def test_a_slash_is_written_raw(self):
        inp, jws = add_input("a/b")
        code, out = run(inp)
        self.assertEqual(code, 0)
        self.assertIn(b'"label":"a/b"', bytes.fromhex(out["payload_hex"]))
        self.assertEqual(bytes.fromhex(out["payload_hex"]), payload_of(jws))

    def test_the_emitted_bytes_are_canonical_and_the_act_object_names_fixed_kid(self):
        inp, _jws = approve_input()
        raw = bytes.fromhex(run(inp)[1]["payload_hex"])
        self.assertEqual(jcs.recognize(raw), (True, None))
        act = json.loads(raw)["ext"]["dev.handsal/act"]
        self.assertEqual(act["kid"], inp["fixed"]["kid"])

    def test_expires_is_ts_plus_expires_in_s(self):
        inp, _jws = approve_input()
        inp["draft"]["expires_in_s"] = "60"
        act = json.loads(bytes.fromhex(run(inp)[1]["payload_hex"]))["ext"]["dev.handsal/act"]
        self.assertEqual(act["expires"], base.shift(inp["fixed"]["ts"], 60))

    def test_the_largest_allowed_expiry_is_accepted(self):
        inp, _jws = approve_input()
        inp["draft"]["expires_in_s"] = "2592000"
        self.assertEqual(run(inp)[0], 0)


REFUSED = (2, {"error": "schema_refused"})


class Framing(unittest.TestCase):
    def test_one_trailing_lf_is_framing_and_two_are_refused(self):
        inp, _jws = approve_input()
        compact = stdin_of(inp)
        self.assertEqual(signer_emit.run(compact[:-1])[0], 0)
        self.assertEqual(signer_emit.run(compact)[0], 0)
        self.assertEqual(signer_emit.run(compact + b"\n"), REFUSED)

    def test_a_number_a_space_or_unsorted_keys_are_refused(self):
        inp, _jws = approve_input()
        self.assertEqual(run(edit(inp, lambda v: v["draft"].__setitem__("expires_in_s", 3600))), REFUSED)
        text = json.dumps(inp, separators=(",", ": ")).encode() + b"\n"
        self.assertEqual(signer_emit.run(text), REFUSED)
        unsorted = b'{"fixed":' + json.dumps(inp["fixed"], separators=(",", ":")).encode() + b',"draft":{}}'
        self.assertEqual(signer_emit.run(unsorted), REFUSED)

    def test_input_over_max_input_is_refused_before_it_is_read(self):
        self.assertEqual(signer_emit.run(b"x" * (MAX_INPUT + 1)), REFUSED)

    def test_the_top_level_keys_are_exactly_attachments_draft_fixed(self):
        inp, _jws = approve_input()
        for mutate in (lambda v: v.pop("fixed"), lambda v: v.pop("attachments"),
                       lambda v: v.__setitem__("extra", {})):
            self.assertEqual(run(edit(inp, mutate)), REFUSED)


class Draft(unittest.TestCase):
    def refused_with(self, inp, mutate, want=REFUSED):
        self.assertEqual(run(edit(inp, mutate)), want)

    def test_a_key_outside_the_draft_set_is_refused(self):
        inp, _jws = approve_input()
        for key in ("ts", "nonce", "prompt", "auth_context", "inputs_hash", "outputs_hash"):
            self.refused_with(inp, lambda v, key=key: v["draft"].__setitem__(key, "x"))

    def test_a_missing_key_is_refused(self):
        inp, _jws = approve_input()
        for key in ("relay", "recipient", "request_id", "expires_in_s", "head", "org", "body"):
            self.refused_with(inp, lambda v, key=key: v["draft"].pop(key))

    def test_a_body_with_an_extra_key_is_refused(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"]["body"].__setitem__("x", "y"))

    def test_a_method_outside_the_registry_is_unsupported_method(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"].__setitem__("method", "local:handsal.request.send"),
                          (2, {"error": "unsupported_method"}))

    def test_a_chain_draft_with_recipient_expires_or_head_is_refused(self):
        inp, _jws = add_input()
        self.assertEqual(run(inp)[0], 0)
        self.refused_with(inp, lambda v: v["draft"].__setitem__("recipient", "alice"))
        self.refused_with(inp, lambda v: v["draft"].__setitem__("expires_in_s", "3600"))
        self.refused_with(inp, lambda v: v["draft"].__setitem__("head", {"id": FX.org_id, "kind": "chain"}))

    def test_a_parent_needs_exactly_id_and_performer(self):
        inp, _jws = add_input()
        self.refused_with(inp, lambda v: v["draft"]["parent"].pop("performer"))
        self.refused_with(inp, lambda v: v["draft"]["parent"].pop("id"))
        self.refused_with(inp, lambda v: v["draft"].pop("parent"))
        self.refused_with(inp, lambda v: v["draft"]["parent"].__setitem__("extra", "x"))

    def test_expires_in_s_is_a_decimal_string_from_1_to_max(self):
        inp, _jws = approve_input()
        for bad in ("0", "2592001", "01", "+1", "-1", "1.0", "", "1e3", " 1"):
            self.refused_with(inp, lambda v, bad=bad: v["draft"].__setitem__("expires_in_s", bad))
        for good in ("1", "2592000"):
            self.assertEqual(run(edit(inp, lambda v, good=good: v["draft"].__setitem__("expires_in_s", good)))[0], 0)

    def test_the_forms_of_the_draft_values_are_checked(self):
        inp, _jws = approve_input()
        for key, bad in (("org", "not a hashstr"), ("recipient", "Alice"), ("relay", "R.example"),
                         ("relay", "a..b"), ("relay", "-a.example"), ("request_id", "short"),
                         ("head", {"id": "x", "kind": "chain"}),
                         ("head", {"id": FX.org_id, "kind": "merkle"})):
            self.refused_with(inp, lambda v, key=key, bad=bad: v["draft"].__setitem__(key, bad))

    def test_a_recipient_that_is_not_the_performer_is_identity_mismatch(self):
        inp, _jws = approve_input()
        self.refused_with(inp, lambda v: v["draft"].__setitem__("recipient", "bob"),
                          (2, {"error": "identity_mismatch"}))
        self.refused_with(inp, lambda v: v["fixed"].__setitem__("performer", "bob"),
                          (2, {"error": "identity_mismatch"}))

    def test_a_schema_defect_is_reported_before_the_identity_one(self):
        inp, _jws = approve_input()

        def both(v):
            v["draft"]["recipient"] = "bob"
            v["draft"].pop("relay")
        self.refused_with(inp, both)


def genesis_input(org):
    return {"attachments": {"document": FX.org},
            "draft": {"body": {}, "method": "local:handsal.genesis.sign", "org": org},
            "fixed": {"kid": FX.key("alice").kid, "nonce": base.hashstr(b"n"), "performer": "alice",
                      "ts": base.NOW}}


class Genesis(unittest.TestCase):
    def test_an_original_whose_org_is_not_the_document_hash_is_attachment_mismatch(self):
        self.assertEqual(run(genesis_input(base.hashstr(b"another"))),
                         (2, {"error": "attachment_mismatch"}))

    def test_an_original_draft_has_no_head(self):
        inp = genesis_input(base.hashstr(b"another"))
        inp["draft"]["head"] = {"id": FX.org_id, "kind": "chain"}
        self.assertEqual(run(inp), REFUSED)

    def test_a_document_that_is_not_an_object_is_one_the_method_cannot_read(self):
        # SG-08 step 3: unreadable is attachment_mismatch
        inp = genesis_input(FX.org_id)
        inp["attachments"]["document"] = "x"
        self.assertEqual(run(inp), (2, {"error": "attachment_mismatch"}))


class OrderInsideStepOne(unittest.TestCase):
    """SG-08 step 1 and 3: the order of defects that one draft can hold together."""

    def test_an_absent_document_is_missing_whatever_the_head_says(self):
        for head in (None, {"id": FX.org_id, "kind": "chain"}):
            inp = genesis_input(FX.org_id)
            del inp["attachments"]["document"]
            if head:
                inp["draft"]["head"] = head
            self.assertEqual(run(inp), (2, {"error": "attachment_missing"}), head)

    def test_an_unsupported_method_comes_before_a_malformed_fixed_value(self):
        inp, _jws = approve_input()
        inp["draft"]["method"] = "local:handsal.request.send"
        inp["fixed"]["nonce"] = "not a hashstr"
        self.assertEqual(run(inp), (2, {"error": "unsupported_method"}))

    def test_the_shape_of_fixed_comes_before_the_method(self):
        inp, _jws = approve_input()
        inp["draft"]["method"] = "local:handsal.request.send"
        del inp["fixed"]["ts"]
        self.assertEqual(run(inp), REFUSED)

    def test_a_change_without_a_head_is_schema_refused_before_its_previous_is_read(self):
        inp, _jws = emitrows.genesis_change_input(FX)
        del inp["draft"]["head"]
        del inp["attachments"]["previous"]
        self.assertEqual(run(inp), REFUSED)

    def test_the_org_of_a_change_is_compared_before_its_previous_is_read(self):
        inp, _jws = emitrows.genesis_change_input(FX)
        inp["draft"]["org"] = base.hashstr(b"x")
        del inp["attachments"]["previous"]
        self.assertEqual(run(inp), (2, {"error": "attachment_mismatch"}))


class StdinMatchesTheFile(unittest.TestCase):
    def test_stdin_is_built_from_the_input_as_the_writer_stores_it_with_sorted_keys(self):
        # the writer sorts keys on disk and the harness sends what is on disk, so a row built
        # with keys in another order must be judged by the model on the sorted bytes
        inp, _jws = approve_input()
        shuffled = {key: inp[key] for key in ("fixed", "draft", "attachments")}
        self.assertEqual(signer_emit.stdin_for(shuffled), signer_emit.stdin_for(inp))
        self.assertEqual(signer_emit.run(signer_emit.stdin_for(shuffled))[0], 0)


class Padding(unittest.TestCase):
    def test_a_row_padded_to_max_input_plus_one_is_refused(self):
        inp, _jws = approve_input()
        stdin = signer_emit.padded_stdin(inp, ["attachments", "request_b64"])
        self.assertEqual(len(stdin), MAX_INPUT + 1)
        self.assertEqual(signer_emit.run(stdin), REFUSED)
        self.assertTrue(base64.b64decode(inp["attachments"]["request_b64"]))


def edit_fixed(inp, key, value):
    return edit(inp, lambda v: v["fixed"].__setitem__(key, value))


class Fixed(unittest.TestCase):
    """SG-04: `emit` checks the forms of the four `fixed` values (ACT-07)."""

    def test_a_malformed_value_of_each_key_is_schema_refused(self):
        inp, _jws = approve_input()
        for key, value in (("nonce", "a plain string"), ("nonce", FX.org_id[:-1] + "B"),
                           ("kid", FX.key("alice").kid[:-1]), ("kid", "x" * 43 + "="),
                           ("performer", "Alice"), ("performer", "a"),
                           ("ts", "2026-11-12 10:00:00"), ("ts", "2026-13-01T00:00:00Z")):
            self.assertEqual(run(edit_fixed(inp, key, value)), REFUSED, (key, value))

    def test_a_missing_or_extra_key_is_schema_refused(self):
        inp, _jws = approve_input()
        self.assertEqual(run(edit(inp, lambda v: v["fixed"].pop("ts"))), REFUSED)
        self.assertEqual(run(edit_fixed(inp, "extra", "x")), REFUSED)

    def test_a_form_defect_is_reported_before_the_identity_one(self):
        inp, _jws = approve_input()
        inp["draft"]["recipient"] = "bob"
        self.assertEqual(run(edit_fixed(inp, "nonce", "x")), REFUSED)


class EveryMethod(unittest.TestCase):
    """ACT-05 S1: each method's draft emits the payload the base builders sign."""

    def same(self, inp, jws):
        self.assertEqual(run(inp), (0, {"payload_hex": payload_of(jws).hex()}))

    def test_device_remove(self):
        self.same(*emitrows.device_remove_input(FX))

    def test_member_add(self):
        self.same(*emitrows.member_add_input(FX))

    def test_chain_resolve(self):
        self.same(*emitrows.chain_resolve_input(FX))

    def test_endorse(self):
        self.same(*emitrows.endorse_input(FX))

    def test_record_promote(self):
        self.same(*emitrows.record_promote_input(FX))

    def test_reject_and_needs_info(self):
        for kind in ("reject", "needs-info"):
            self.same(*emitrows.verdict_input(FX, kind))

    def test_genesis_original(self):
        self.same(*emitrows.genesis_original_input(FX))

    def test_genesis_change(self):
        self.same(*emitrows.genesis_change_input(FX))

    def test_a_resolve_lists_are_written_in_the_order_given(self):
        inp, jws = emitrows.chain_resolve_input(FX)
        body = json.loads(payload_of(jws))["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["candidates"], sorted(body["candidates"]))
        self.assertEqual(body["candidates"], inp["draft"]["body"]["candidates"])


class Attachments(unittest.TestCase):
    """SG-13, RN-09, SG-08: what the signer checks against the attachments."""

    def code(self, inp):
        return run(inp)

    def test_a_missing_attachment_is_attachment_missing(self):
        for build, name in ((approve_input, "request_b64"),
                            (lambda: emitrows.record_promote_input(FX), "record_body_b64"),
                            (lambda: emitrows.endorse_input(FX), "act"),
                            (lambda: emitrows.chain_resolve_input(FX), "candidates"),
                            (lambda: emitrows.chain_resolve_input(FX), "heads"),
                            (lambda: emitrows.genesis_change_input(FX), "previous")):
            inp, _jws = build()
            del inp["attachments"][name]
            self.assertEqual(self.code(inp), (2, {"error": "attachment_missing"}), name)

    def test_an_endorse_draft_that_differs_from_its_attached_act_is_mismatch(self):
        mismatch = (2, {"error": "attachment_mismatch"})
        other = base.hashstr(b"another act")
        for mutate in (lambda d: d["body"].__setitem__("act", other),
                       lambda d: d["parent"].__setitem__("id", other),
                       lambda d: d["parent"].__setitem__("performer", "dave"),
                       lambda d: d["head"].__setitem__("id", other)):
            inp, _jws = emitrows.endorse_input(FX)
            mutate(inp["draft"])
            self.assertEqual(self.code(inp), mismatch)

    def test_a_resolve_whose_attached_lists_do_not_bind_is_mismatch(self):
        mismatch = (2, {"error": "attachment_mismatch"})
        inp, _jws = emitrows.chain_resolve_input(FX)
        inp["attachments"]["heads"] = [j for j in inp["attachments"]["candidates"]
                                       if j not in inp["attachments"]["heads"]]
        self.assertEqual(self.code(inp), mismatch)
        inp, _jws = emitrows.chain_resolve_input(FX)
        inp["attachments"]["candidates"] = inp["attachments"]["candidates"] * 2
        self.assertEqual(self.code(inp), mismatch)

    def test_a_genesis_change_that_does_not_bind_its_document_is_mismatch(self):
        mismatch = (2, {"error": "attachment_mismatch"})
        for mutate in (lambda i: i["draft"].__setitem__("org", base.hashstr(b"x")),
                       lambda i: i["draft"]["head"].__setitem__("id", base.hashstr(b"x")),
                       lambda i: i["attachments"].__setitem__("previous", dict(FX.org, name="x"))):
            inp, _jws = emitrows.genesis_change_input(FX)
            mutate(inp)
            self.assertEqual(self.code(inp), mismatch)

    def test_head_presence_is_decided_before_org_against_the_document(self):
        # SG-08: an original that carries a head is schema_refused, whatever its org is
        inp = emitrows.genesis_original_input(FX)[0]
        inp["draft"]["head"] = {"id": FX.org_id, "kind": "chain"}
        inp["draft"]["org"] = base.hashstr(b"another")
        self.assertEqual(self.code(inp), REFUSED)

    def test_identity_is_decided_before_any_attachment_is_read(self):
        inp, _jws = approve_input()
        inp["draft"]["recipient"] = "bob"
        del inp["attachments"]["request_b64"]
        self.assertEqual(self.code(inp), (2, {"error": "identity_mismatch"}))


if __name__ == "__main__":
    unittest.main()
