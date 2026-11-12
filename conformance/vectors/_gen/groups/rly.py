"""Vectors rly/*: the relay a verdict names (VR-08, ACT-09 field types).

The act names `r.example`, the relay the consumer is configured with, unless a row
says otherwise. A relay that is not configured is a missing input, never a skipped check.
"""
from lib import checkrows, forge


def generate(ctx):
    fx = ctx.fixtures
    jws = fx.approve()
    checkrows.row(ctx, "rly/not-configured-flag", jws, None, error="malformed_input", relay=None)
    checkrows.row(ctx, "rly/other-relay", jws, "relay_mismatch", signers=["alice"],
                  relay="b.example")
    upper = forge.resign(fx, jws, forge.act_edit(lambda a: a.__setitem__("relay", "R.example")))
    checkrows.row(ctx, "rly/uppercase-relay-schema", upper, "schema")  # an act-object key: ACT-10
