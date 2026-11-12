"""Vectors rev/*: revocation is positional (FO-05).

carol's device is removed at position 1. A primary signed by carol's key at parent 1
is not on the chain; one signed by it at position 0 stays applied.
"""
from lib import chain

PAIR = ("alice", "bob")


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    c = chain.Chain(fx, ctx=ctx)
    c.device_remove("carol", PAIR)
    c.device_add("carol2", ("carol", "bob"), ok=False)
    w.add("rev/act-after-revocation-ignored", "fold", c.expect(), input=c.fold_input())

    c = chain.Chain(fx, ctx=ctx)
    c.device_add("carol2", ("carol", "bob"))
    c.device_remove("carol", PAIR)
    w.add("rev/act-before-revocation-kept", "fold", c.expect(), input=c.fold_input())
