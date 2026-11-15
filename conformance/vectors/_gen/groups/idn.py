"""Vectors idn/*: the performer is the recipient (VR-05, VR-03)."""
from lib import checkrows, forge, inputs


def generate(ctx):
    fx = ctx.fixtures
    swapped = forge.resign(fx, fx.approve(), forge.act_edit(
        lambda a: a.__setitem__("recipient", "bob")))
    checkrows.row(ctx, "idn/recipient-not-performer", swapped, "identity_mismatch",
                  signers=["alice"], recipient="bob")
    # VR-03 S4, ACT-13: a decision whose performer is not the person of the signing key. Alice's key signs it
    # again with `performer_id` bob, so vitni has no such key under bob (the kid is in the state: alice's class)
    other = forge.resign(fx, fx.decision(), lambda p: p.__setitem__("performer_id", "bob"))
    checkrows.row(ctx, "idn/decision-performer-not-signer", other, "unknown_key", method=inputs.DECISION,
                  bad=(["alice", "bob", "carol"], "unknown_key"))
