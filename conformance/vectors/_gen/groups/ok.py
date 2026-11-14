"""Vectors ok/*: valid acts through `check-act` (ACT-01, ACT-09, VR-01).

One row per non-chain method. Each is a complete, fresh, unseen act by alice
under ORG, so every step of VR-02 passes and the result is `ok` with alice's
class. Every act is a positive: both vitni binaries must say `ok` for it.
"""
from lib import base, inputs


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

    # VR-18: a decision for consumer `notes`, the longest action, and the same decision signed for `archive`
    # (checked by `archive`: the control of `dec/replay-same-decision-other-consumer`)
    for name, jws, override in (
            ("ok/decision", fx.decision(), {}),
            ("ok/decision-action-24", fx.decision(action=base.DECISION_ACTION_24), {"action": base.DECISION_ACTION_24}),
            ("ok/decision-other-consumer", fx.decision(consumer="archive"), {"consumer": "archive"})):
        ctx.positive(jws, inputs.DECISION, ["alice"])
        ctx.writer.add(name, "check-act", inputs.check_anchor(jws, "ok"),
                       input=inputs.check_input(fx, jws, method=inputs.DECISION, **override))
