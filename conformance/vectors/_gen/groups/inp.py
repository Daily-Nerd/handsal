"""Vectors inp/*: the bytes the consumer holds are the bytes that were signed (VR-06, VR-01)."""
from lib import checkrows, inputs


def generate(ctx):
    fx = ctx.fixtures
    other = fx.request_b64(b"another request")
    jws = fx.approve()
    checkrows.row(ctx, "inp/other-request", jws, "inputs_mismatch", signers=["alice"],
                  request_b64=other)
    checkrows.row(ctx, "inp/not-supplied-flag", jws, None, error="malformed_input",
                  request_b64=inputs.DROP)
    empty = fx.approve(request=b"")
    checkrows.row(ctx, "inp/empty-bytes", empty, "ok", signers=["alice"],
                  request_b64=fx.request_b64(b""))
    record = fx.record_promote()
    checkrows.row(ctx, "inp/record-body-mismatch", record, "inputs_mismatch",
                  method=inputs.RECORD_PROMOTE, signers=["alice"],
                  record_body_b64=fx.request_b64(b"another record body"))
