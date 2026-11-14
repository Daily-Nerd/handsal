"""Vectors sgn/*: the signer `emit` rows (CF-04, SG-01, SG-04, SG-13, ACT-14).

CF-04 gives a signer the `render` and `emit` vectors only, through `handsal-sign-conformance`.
The other `sgn` ids of the first catalog (key, prompt, display, ceremony, pin helper, installer)
are implementation tests (CF-07) and are not vectors. Every row here is an `emit` input
`{attachments, draft, fixed}`: an approve, device.add, device.remove or genesis.sign draft that is
good except for the one thing the id names. Each outcome is stated here and the signer model
(`lib/signer_emit.py`) must agree before the row is written.
"""
from lib import base, emitrows
from lib.emitrows import device_add_input, device_remove_input, genesis_input, verdict_input


def _approve(fx, mutate):
    inp, _jws = verdict_input(fx)
    mutate(inp)
    return inp


def _draft(key, value):
    return lambda inp: inp["draft"].__setitem__(key, value)


def generate(ctx):
    fx = ctx.fixtures
    def refuse(name, inp, code="schema_refused", **kwargs):
        emitrows.refused(ctx, name, inp, code, **kwargs)

    # the act object carries `kid` (ACT-14): bob's key, a request id that is not alice's row's
    inp, jws = verdict_input(fx, signer="bob", request_id="req-00000002")
    emitrows.ok(ctx, "sgn/emit-act-kid-filled", inp, jws)

    # a draft carries facts, never derived values or words (SG-04)
    for name, key, value in (("sgn/refuse-ts-input", "ts", base.NOW),
                             ("sgn/refuse-nonce-input", "nonce", base.hashstr(b"a nonce")),
                             ("sgn/refuse-display-text", "prompt", "Approve the deploy"),
                             ("sgn/refuse-auth-handle", "auth_context", "ctx-0001")):
        refuse(name, _approve(fx, _draft(key, value)))
    refuse("sgn/refuse-schema-violation",
           _approve(fx, lambda inp: inp["draft"]["body"].__setitem__("x", "y")))
    refuse("sgn/refuse-unknown-method",
           _approve(fx, _draft("method", "local:handsal.request.send")), "unsupported_method")

    # expires_in_s: a decimal string from 1 to MAX_EXPIRES_IN_S, on the methods that carry expires
    refuse("sgn/expires-in-s-zero-refused", _approve(fx, _draft("expires_in_s", "0")))
    refuse("sgn/expires-over-30d", _approve(fx, _draft("expires_in_s", "2592001")))
    inp, _jws = device_add_input(fx)
    inp["draft"]["expires_in_s"] = "3600"
    refuse("sgn/expires-in-s-refused-for-chain-method", inp)

    # the keys of a draft are exactly the keys of its method (SG-04)
    inp, _jws = device_add_input(fx)
    del inp["draft"]["parent"]["performer"]
    refuse("sgn/parent-performer-required", inp)
    inp, _jws = device_remove_input(fx)
    inp["draft"]["recipient"] = "alice"
    refuse("sgn/chain-draft-recipient-refused", inp)
    refuse("sgn/verdict-draft-missing-relay-refused", _approve(fx, lambda inp: inp["draft"].pop("relay")))

    # a decision draft: its body has the three forms (VR-18), it has no recipient, and its content is attached
    inp, _jws = emitrows.decision_input(fx)
    inp["draft"]["body"]["action"] = "Ratify ruling"
    refuse("sgn/decision-action-grammar-refused", inp)
    inp, _jws = emitrows.decision_input(fx)
    inp["draft"]["recipient"] = "alice"
    refuse("sgn/decision-draft-recipient-refused", inp)
    inp, _jws = emitrows.decision_input(fx)
    del inp["attachments"]["decision_b64"]
    refuse("sgn/decision-attachment-missing-refused", inp, "attachment_missing")

    # a verdict is addressed to the person bound to the key (SG-04, ACT-13, VR-05)
    inp, _jws = verdict_input(fx)
    inp["draft"]["recipient"] = "bob"
    refuse("sgn/verdict-recipient-not-performer-refused", inp, "identity_mismatch")

    # SG-08: the person is decided before any attachment is read, so a missing attachment never
    # shows
    inp, _jws = verdict_input(fx)
    inp["draft"]["recipient"] = "bob"
    del inp["attachments"]["request_b64"]
    refuse("sgn/identity-before-attachment-refused", inp, "identity_mismatch")

    # SG-13: org is derived from the attached document, never copied from the draft
    refuse("sgn/genesis-org-not-document-hash-refused",
           genesis_input(fx, base.hashstr(b"another organization")), "attachment_mismatch")

    # SG-08: head presence is shape and is decided before org against the document
    inp = genesis_input(fx, base.hashstr(b"another organization"))
    inp["draft"]["head"] = {"id": fx.org_id, "kind": "chain"}
    refuse("sgn/genesis-head-before-org-refused", inp)

    # SG-08 step 3: an absent document is missing, whatever the draft's head says (head presence
    # needs `prev` of the document)
    inp = genesis_input(fx, fx.org_id)
    inp["draft"]["head"] = {"id": fx.org_id, "kind": "chain"}
    del inp["attachments"]["document"]
    refuse("sgn/genesis-document-missing-before-head-refused", inp, "attachment_missing")

    # SG-08 step 1: the method is decided before the forms of `fixed`
    inp = _approve(fx, _draft("method", "local:handsal.request.send"))
    inp["fixed"]["nonce"] = "not a hashstr"
    refuse("sgn/unsupported-method-before-bad-fixed-refused", inp, "unsupported_method")

    # SG-01: the stdin bound is MAX_INPUT, and the harness pads inside one string to exceed it
    inp, _jws = verdict_input(fx)
    refuse("sgn/signer-stdin-over-max-input-refused", inp, pad=["attachments", "request_b64"])
