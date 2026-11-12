"""Vectors frs/*: the consumer's view is fresh and contains the act's head (VR-12).

An approve by alice whose head or whose `synced_at` is the point of the row. `synced_at`
within `max_view_age_s` (86400 s) of NOW is valid, one second older is `stale_view`, and a
`synced_at` more than `clock_skew_s` (300 s) after NOW is `view_in_future`. A head is valid
when it is a position of the accepted chain, however old; a position the consumer's bag
lacks, a losing candidate, and an id that names nothing are `stale_view`.
`frs/offline-historical-verify-unaffected` is a `fold`: freshness is a rule of `check-act`
and `enrolled` only, so a fold input carries no `synced_at`.
"""
from lib import base, chain, checkrows, inputs, scenes

AB = ("alice", "bob")
NOW = base.NOW
DEVICES = ("alice2", "alice3", "alice4", "X1", "X2", "bob2", "bob3")


def _chain(ctx, count):
    c = chain.Chain(ctx.fixtures, ctx=ctx)
    built = [c.device_add(name, AB) for name in DEVICES[:count]]
    return c, [b.id for b in built]


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    row = checkrows.row
    jws = fx.approve()
    for name, reason, gap in (("frs/age-exactly-max-ok", "ok", -86400),
                              ("frs/age-max-plus-1", "stale_view", -86401),
                              ("frs/as-of-future", "view_in_future", 301),
                              ("frs/local-sync-stale", "stale_view", -90000)):
        row(ctx, name, jws, reason, signers=["alice"], synced_at=base.shift(NOW, gap))
    row(ctx, "frs/no-view-supplied", jws, None, error="malformed_input", synced_at=inputs.DROP)

    seven, ids = _chain(ctx, 7)
    old = fx.approve(tip=ids[2])
    row(ctx, "frs/head-older-than-tip-ok", old, "ok", signers=["alice"], acts=seven.acts)

    # a head the consumer's bag lacks: its view is behind the signer's
    behind, _ = _chain(ctx, 3)
    ahead = fx.device_add("bob2", AB, parent=behind.tip)
    row(ctx, "frs/head-ahead-of-tip", fx.approve(tip=ahead.id), "stale_view", signers=["alice"],
        acts=behind.acts)
    row(ctx, "frs/head-unknown-id", fx.approve(tip=base.hashstr(b"junk head")), "stale_view",
        signers=["alice"])

    scene = scenes.losing_branch(fx, ctx=ctx)
    row(ctx, "frs/head-other-branch", fx.approve(tip=scene.lost.id), "stale_view",
        signers=["alice"], acts=scene.bag)

    # head at position 3, alice's key removed at position 5 (VR-12: the key must be active at the tip)
    five = chain.Chain(fx, ctx=ctx)
    built = [five.device_add(n, AB) for n in ("alice2", "bob2", "alice3", "bob3")]
    five.device_remove("alice", ("bob", "carol"))
    revoked = fx.approve(tip=built[2].id)
    row(ctx, "frs/head-older-key-revoked-at-tip", revoked, "revoked_key",
        bad=(["alice"], "revoked_key", ["alice"]), acts=five.acts)

    c, _ = _chain(ctx, 3)
    w.add("frs/offline-historical-verify-unaffected", "fold", c.expect(), input=c.fold_input())
