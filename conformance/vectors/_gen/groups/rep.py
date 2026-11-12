"""Vectors rep/*: replay, swapped fields and duplicate receipts (VR-09, VR-10, VR-15, ACT-12).

A swapped field row keeps the signature of the original act, so the edited payload no longer
verifies: `bad_signature` at step 9 (VR-10). `rep/org-swapped` swaps the org of an act signed
for another org back to the consumer's, since a payload naming another org is `org_mismatch`
at step 7 before any signature is read. `rep/same-payload-two-sigs` is the high-S form of
the payload of `ok/approve` (its low form is `sig/low-s-ok`): same receipt id, `high_s`.
`rep/invalid-twin-not-in-seen` is the valid act with an empty `seen`; the garbage twin the
consumer refused is the consumer's own record.
"""
from lib import base, checkrows, forge, inputs

NOTHING = []


def _set_act(key, value):
    return lambda p: p["ext"]["dev.handsal/act"].__setitem__(key, value)


def generate(ctx):
    fx = ctx.fixtures
    ok = fx.approve()
    ctx.positive(ok, inputs.APPROVE, ["alice"])
    row = checkrows.row

    row(ctx, "rep/same-receipt-twice", ok, "duplicate_receipt", seen=[inputs.receipt_id(ok)])
    later = fx.approve(ts=base.shift(base.NOW, -30))
    row(ctx, "rep/different-receipt-same-request-ok", later, "ok", signers=["alice"],
        seen=[inputs.receipt_id(ok)])
    row(ctx, "rep/invalid-twin-not-in-seen", ok, "ok", seen=[])
    row(ctx, "rep/recipient-input-mismatch", ok, "request_mismatch", recipient="bob")
    row(ctx, "rep/request-id-input-mismatch", ok, "request_mismatch", request_id="req-00000002")

    high = forge.resign(fx, ok, high_s=True)
    row(ctx, "rep/same-payload-two-sigs", high, "high_s", bad=(["alice"], "ok"))

    # the low-S form is the ordinary valid act, and it has the receipt id of the high-S form
    row(ctx, "rep/same-payload-low-s-same-receipt-id", ok, "ok", signers=["alice"])

    tampered = {
        "rep/inputs-hash-swapped": forge.tamper(ok, lambda p: p.__setitem__(
            "inputs_hash", base.hashstr(b"another request"))),
        "rep/request-id-swapped": forge.tamper(ok, _set_both("request_id", "req-00000002")),
        "rep/org-swapped": forge.tamper(fx.approve(org=fx.wit_org_id), _set_both("org", fx.org_id)),
    }
    for name, jws in tampered.items():
        row(ctx, name, jws, "bad_signature", bad=(["alice"], "bad_signature"))


def _set_both(key, value):
    return lambda p: p["ext"]["dev.handsal/act"].__setitem__(key, value)
