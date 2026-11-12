"""Vectors idn/*: the performer is the recipient (VR-05, VR-03)."""
from lib import checkrows, forge, inputs


def generate(ctx):
    fx = ctx.fixtures
    swapped = forge.resign(fx, fx.approve(), forge.act_edit(
        lambda a: a.__setitem__("recipient", "bob")))
    checkrows.row(ctx, "idn/recipient-not-performer", swapped, "identity_mismatch",
                  signers=["alice"], recipient="bob")
    # a record promoted by a member the pinned state does not hold: vitni has no key for it
    unknown = fx.record_promote("dave")
    checkrows.row(ctx, "idn/record-performer-unknown-member", unknown, "unknown_key", cls=None,
                  method=inputs.RECORD_PROMOTE, bad=(["alice", "bob", "carol"], "unknown_key"))
