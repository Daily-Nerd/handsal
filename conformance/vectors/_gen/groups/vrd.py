"""Vectors vrd/*: the outputs check (ACT-09, VR-07).

An approve whose `outputs_hash` was computed for the verdict `reject` is
otherwise perfect: signed, fresh, for the right org, relay, request and
recipient. The first failure is step 12, `outputs_mismatch`: VR-07 owns the one value each
method must carry (a decision's twin is `dec/outputs-mismatch`).
"""
from lib import inputs


def generate(ctx):
    fx = ctx.fixtures
    jws = fx.verdict("approve", verdict="reject")
    ctx.writer.add("vrd/outputs-verdict-swapped", "check-act",
                   inputs.check_anchor(jws, "outputs_mismatch"),
                   input=inputs.check_input(fx, jws))
