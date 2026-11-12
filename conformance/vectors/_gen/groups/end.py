"""Vectors end/*: endorsement rules (FO-08, FO-23).

Each defective row is a two-person `device.add` of alice2 whose counted endorsement
(bob's) has one defect, so only alice counts and the act is not on the chain: the
state stays the genesis state. end/same-person-twice is a removal signed by two
devices of alice: one person, one vote.
"""
from lib import base, chain, forge

PAIR = ("alice", "bob")


def _act(edit):
    return forge.act_edit(edit)


def _endorse_row(ctx, name, mutate):
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    built = c.device_add("alice2", PAIR, ok=False)
    c.edit_act(built, 1, forge.resign(fx, built.acts[1], mutate(built)))
    ctx.writer.add(name, "fold", c.expect(), input=c.fold_input())


def _retarget(act_id):
    def mutate(p):
        p["parent_receipt_hash"] = act_id
        p["parent_performer_id"] = "alice"
        p["ext"]["dev.handsal/act"]["body"]["act"] = act_id
    return mutate


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    other = base.hashstr(b"another act")
    _endorse_row(ctx, "end/body-act-mismatch",
                 lambda built: _act(lambda a: a["body"].__setitem__("act", other)))
    _endorse_row(ctx, "end/endorse-endorsement",
                 lambda built: _retarget(base.hashstr(forge.parts(built.acts[2])[1])))
    _endorse_row(ctx, "end/endorse-unknown-id",
                 lambda built: _retarget(base.hashstr(b"unknown act")))
    _endorse_row(ctx, "end/head-binding",
                 lambda built: _act(lambda a: a["head"].__setitem__("id", other)))
    _endorse_row(ctx, "end/parent-performer-mismatch",
                 lambda built: (lambda p: p.__setitem__("parent_performer_id", "carol")))

    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", PAIR)
    c.device_remove("carol", ("alice", "alice2"), short=True, ok=False)
    w.add("end/same-person-twice", "fold", c.expect(), input=c.fold_input())
