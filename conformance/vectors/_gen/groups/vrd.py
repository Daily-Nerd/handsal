"""Vectors vrd/*: the outputs check (ACT-09, VR-07).

An approve whose `outputs_hash` was computed for the verdict `reject` is
otherwise perfect: signed, fresh, for the right org, relay, request and
recipient. The first failure is step 12, `outputs_mismatch`. A `record.promote` whose
`outputs_hash` is the hash of any bytes but the empty string is refused the same way, and
for the same reason: VR-07 owns the one value each method must carry.
"""
from lib import base, inputs


def generate(ctx):
    fx = ctx.fixtures
    jws = fx.verdict("approve", verdict="reject")
    ctx.writer.add("vrd/outputs-verdict-swapped", "check-act",
                   inputs.check_anchor(jws, "outputs_mismatch"),
                   input=inputs.check_input(fx, jws))
    record = fx.record_promote(outputs_hash=base.hashstr(b"not the empty string"))
    ctx.writer.add("vrd/record-outputs-not-empty", "check-act",
                   inputs.check_anchor(record, "outputs_mismatch"),
                   input=inputs.check_input(fx, record, method=inputs.RECORD_PROMOTE))
