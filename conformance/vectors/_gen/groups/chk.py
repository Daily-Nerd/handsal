"""Vectors chk/*: check-act input and the pinned state (VR-01, VR-02 step 6, GP-14).

Each row is APPROVE with one input defect. A fold or pin failure is step 6, so
`receipt_id` is the payload id and `class` is null (VR-01).
"""
from lib import inputs


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    jws = fx.approve()
    ctx.positive(jws, inputs.APPROVE, ["alice"])

    unsigned = [{"doc": fx.org, "sigs": []}]
    w.add("chk/lineage-invalid", "check-act", inputs.check_anchor(jws, "genesis_unsigned"),
          input=inputs.check_input(fx, jws, lineage=unsigned))
    for name, reason in (("chk/pin-owner-false", "pin_owner"), ("chk/state-is-error", "pin_missing")):
        pin = dict(fx.pin_ok(), owner_ok=False, reason=reason)
        w.add(name, "check-act", inputs.check_anchor(jws, reason),
              input=inputs.check_input(fx, jws, pin=pin))
    w.add("chk/request-id-input-missing", "check-act", inputs.error_anchor("malformed_input"),
          input=inputs.check_input(fx, jws, request_id=inputs.DROP))
