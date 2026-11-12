"""Vectors ing/*: an approve is checked at the tip it is presented at (VR-14).

ing/revoked-after-ingestion-recheck-fails: alice's key is removed after the approve was
ingested, so `check-act` at the new tip says `revoked_key`. The consumer's recorded decision
is its own store; the two consumer-store cases (an invalid twin never recorded against a receipt
id, and the recorded `tip_id_at_ingestion`) are implementation tests (CF-07), not vector ids.
"""
from lib import chain, checkrows

BC = ("bob", "carol")


def generate(ctx):
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", ("alice", "bob"))
    c.device_remove("alice", BC)
    jws = fx.approve()
    checkrows.row(ctx, "ing/revoked-after-ingestion-recheck-fails", jws, "revoked_key",
                  bad=(["alice"], "revoked_key", ["alice"]), acts=c.acts)
