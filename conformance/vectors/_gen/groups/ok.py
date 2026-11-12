"""Vectors ok/*: valid acts through `check-act` (ACT-01, ACT-09, VR-01).

One row per non-chain method. Each is a complete, fresh, unseen act by alice
under ORG, so every step of VR-02 passes and the result is `ok` with alice's
class. Every act is a positive: both vitni binaries must say `ok` for it.
"""
from lib import inputs


def generate(ctx):
    fx = ctx.fixtures
    rows = (
        ("ok/approve", inputs.APPROVE, fx.verdict("approve")),
        ("ok/reject", inputs.REJECT, fx.verdict("reject")),
        ("ok/needs-info", inputs.NEEDS_INFO, fx.verdict("needs-info")),
        ("ok/record-promote", inputs.RECORD_PROMOTE, fx.record_promote()),
    )
    for name, method, jws in rows:
        ctx.positive(jws, method, ["alice"])
        ctx.writer.add(name, "check-act", inputs.check_anchor(jws, "ok"),
                       input=inputs.check_input(fx, jws, method=method))
