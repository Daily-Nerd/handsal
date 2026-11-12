"""Vectors lnk/*: the link code hash of a device add (SG-09, ACT-09).

A code is a `link_code_hash` hashstr and a device enrolls once per code: a second
`device.add` with the same code is ignored (`link_code_reused`, an internal ignore reason).
"""
from lib import base, chain

PAIR = ("alice", "bob")


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", PAIR)
    w.add("lnk/ok", "fold", c.expect(), input=c.fold_input())

    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", PAIR, ok=False,
                 body_edit=lambda b: b.__setitem__("link_code_hash", "not-a-hash"))
    w.add("lnk/code-hash-format", "fold", c.expect(), input=c.fold_input())

    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", PAIR)
    first = base.hashstr(b"link-code/alice2")
    c.device_add("bob2", ("bob", "carol"), ok=False,
                 body_edit=lambda b: b.__setitem__("link_code_hash", first))
    w.add("lnk/reused-code", "fold", c.expect(), input=c.fold_input())
