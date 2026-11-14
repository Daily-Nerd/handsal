"""Vectors ord/*: the order of the VR-02 pipeline, one row per adjacent pair (CF-07).

Each row is an act with two defects, the earlier step's and the later step's, so the
expected reason is the earlier one and a checker that reads them in the wrong order gives
the other. `receipt_id` and `class` follow VR-01 (lib/inputs.py): null before the point
they are known, alice's class from step 7 on. Rows that fail before the signature is read
carry no vitni record; a row whose reason is a signature fact records vitni's own verdict.

Pairs written elsewhere: wit/ord-* (the witness steps), gen/order-* (GP-15). The pair
`role_key_class` before `fixture_key` has no vector (CF-07).
"""
from lib import base, chain, checkrows, forge, inputs

AB = ("alice", "bob")
PIN_CLASS = "fixture-pin"
APPROVE = inputs.APPROVE
NOW = base.NOW
OTHER_BYTES = base.Fixtures.request_b64(None, b"another request")


def _flip_s(jws):
    head, payload, sig = forge.parts(jws)
    return forge.join(head, payload, sig[:32] + bytes([sig[32] ^ 1]) + sig[33:])


def _number(raw):
    return raw.replace(b'"tokens":"0"', b'"tokens":0')


def _act_edit(**fields):
    return forge.act_edit(lambda a: a.update(fields))


def _expired(fx, **kwargs):
    return fx.approve(ts=base.shift(NOW, -7200), expires=base.shift(NOW, -60), **kwargs)


def _fork(fx):
    one, two = fx.device_add("alice2", AB), fx.device_add("alice3", AB)
    return one.acts + two.acts


def _pin(fx, **fields):
    return dict(fx.pin_ok(), **fields)


def _probe_bytes(fx, org_in_text, genesis=None):
    return inputs.pin_line(org_in_text, genesis or fx.org_id, fx.profile)


def _steps_one_to_five(ctx):
    fx = ctx.fixtures
    row, ok = checkrows.row, fx.approve()
    number = forge.resign(fx, ok, raw_edit=_number)
    segments = number.split(".")
    segments[1] += "="
    row(ctx, "ord/jws-before-canonical", ".".join(segments), "jws_shape")
    both = forge.resign(fx, ok, lambda p: p.__setitem__("seq", "1"), raw_edit=_number)
    row(ctx, "ord/canonical-before-schema", both, "payload_not_canonical_subset")

    def unknown_method(p):
        p["method"] = "local:handsal.request.send"
    row(ctx, "ord/schema-before-method",
        forge.resign(fx, ok, lambda p: (p.__setitem__("seq", "1"), unknown_method(p))), "schema")
    both = forge.resign(fx, ok, lambda p: (unknown_method(p), p["ext"]["dev.handsal/act"]
                                          .__setitem__("seq", "1")))
    row(ctx, "ord/method-before-act-object", both, "method_unknown")
    bodied = fx.device_add("alice2", AB, body_edit=lambda b: b.__setitem__("x", "y"))
    row(ctx, "ord/chain-method-before-body", bodied.acts[0], "chain_method")
    both = forge.resign(fx, ok, forge.act_edit(lambda a: (a.__setitem__("x", "y"),
                                                          a["body"].__setitem__("x", "y"))))
    row(ctx, "ord/act-object-before-body", both, "schema")
    extra_body = forge.resign(fx, ok, forge.act_edit(lambda a: a["body"].__setitem__("x", "y")))
    missing = _pin(fx, owner_ok=False, reason="pin_missing")
    row(ctx, "ord/body-before-fold", extra_body, "body_schema", pin=missing)


def _step_six(ctx):
    fx = ctx.fixtures
    row, ok = checkrows.row, fx.approve()
    other = fx.wit_org_id
    row(ctx, "ord/probe-org-before-owner", ok, "pin_org_mismatch",
        pin=_pin(fx, org=other, owner_ok=False, reason="pin_owner"))
    row(ctx, "ord/owner-before-pin-parse", ok, "pin_owner",
        pin=inputs.probe(fx.org_id, b"not a pin", owner_ok=False, reason="pin_owner"))
    row(ctx, "ord/pin-parse-before-pin-org", ok, "pin_malformed",
        pin=inputs.probe(fx.org_id, _probe_bytes(fx, other)[:-1]))
    row(ctx, "ord/pin-org-before-fold", ok, "pin_org_mismatch",
        pin=inputs.probe(fx.org_id, _probe_bytes(fx, other)), acts=_fork(fx))
    wrong_org = forge.resign(fx, ok, _act_edit(org=other))
    row(ctx, "ord/fold-before-org", wrong_org, "pin_missing",
        pin=_pin(fx, owner_ok=False, reason="pin_missing"))


def _steps_seven_to_ten(ctx):
    fx = ctx.fixtures
    row, ok = checkrows.row, fx.approve()
    wrong_org = forge.resign(fx, ok, _act_edit(org=fx.wit_org_id))
    row(ctx, "ord/org-before-relay", wrong_org, "org_mismatch", relay="b.example")
    row(ctx, "ord/org-before-vitni", _flip_s(wrong_org), "org_mismatch")
    row(ctx, "ord/relay-before-signature", _flip_s(ok), "relay_mismatch", relay="b.example")
    row(ctx, "ord/fork-before-vitni", _flip_s(ok), "fork", acts=_fork(fx))
    removal = chain.Chain(fx, ctx=ctx)
    removal.device_remove("alice", ("bob", "carol"))
    high = forge.resign(fx, ok, high_s=True)
    row(ctx, "ord/signature-before-high-s", high, "revoked_key", acts=removal.acts,
        bad=(["alice"], "revoked_key", ["alice"]))
    row(ctx, "ord/sig-before-time", _flip_s(_expired(fx)), "bad_signature",
        bad=(["alice"], "bad_signature"))


def _steps_ten_to_sixteen(ctx):
    fx = ctx.fixtures
    row, ok = checkrows.row, fx.approve()
    to_bob = forge.resign(fx, ok, _act_edit(recipient="bob"))
    row(ctx, "ord/high-s-before-identity", forge.resign(fx, to_bob, high_s=True), "high_s",
        bad=(["alice"], "ok"))
    row(ctx, "ord/identity-before-inputs", to_bob, "identity_mismatch", signers=["alice"],
        recipient="bob", request_b64=OTHER_BYTES)
    row(ctx, "ord/request-before-inputs", ok, "request_mismatch", signers=["alice"],
        request_id="req-00000002", request_b64=OTHER_BYTES)
    row(ctx, "ord/consumer-before-inputs", fx.decision(), "consumer_mismatch", signers=["alice"],
        method=inputs.DECISION, consumer="archive", decision_b64=OTHER_BYTES)
    row(ctx, "ord/inputs-before-time", _expired(fx), "inputs_mismatch", signers=["alice"],
        request_b64=OTHER_BYTES)
    stale = base.shift(NOW, -86401)
    row(ctx, "ord/time-before-view", _expired(fx), "expired", signers=["alice"], synced_at=stale)
    row(ctx, "ord/view-before-dup", ok, "stale_view", signers=["alice"], synced_at=stale,
        seen=[inputs.receipt_id(ok)])

    c = chain.Chain(fx, ctx=ctx)
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=PIN_CLASS)
    unproven = fx.verdict("approve", "dave2", recipient="dave")
    row(ctx, "ord/dup-before-class", unproven, "duplicate_receipt", signers=["dave2"],
        cls=PIN_CLASS, acts=c.acts, recipient="dave", seen=[inputs.receipt_id(unproven)])


def generate(ctx):
    ok = ctx.fixtures.approve()
    ctx.positive(ok, APPROVE, ["alice"])
    _steps_one_to_five(ctx)
    _step_six(ctx)
    _steps_seven_to_ten(ctx)
    _steps_ten_to_sixteen(ctx)
