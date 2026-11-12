"""Vectors on ORG4: a rule at `persons "3"` is not met by two persons (FO-11, FO-22, GP-02).

ORG4 has four maintainers, so `persons "3"` keeps a spare (GP-02). Each row is a two-person
act, alice and bob, under a rule that asks for three: the act is not on the chain and the
state is ORG4's own. Only `device.remove` is raised in `quo/raised-floor-3-two-rejected`;
`quo/raised-floor-3-three-applied` is the same bag with carol's endorsement added, which
makes three persons, so the removal is applied.
"""
from lib import epochs

AB = ("alice", "bob")


def _only_remove(doc):
    doc["policy"]["rules"]["device.remove"]["persons"] = "3"


def _row(ctx, name, doc, act):
    c = epochs.original_chain(ctx.fixtures, doc, ctx=ctx)
    act(c)
    ctx.writer.add(name, "fold", c.expect(), input=c.fold_input())


def generate(ctx):
    fx = ctx.fixtures
    removal = lambda c: c.device_remove("carol", AB, ok=False)
    _row(ctx, "rem/second-person-quorum-unmet", epochs.org4(fx), removal)
    _row(ctx, "quo/policy-swap-2-vs-3", epochs.org4(fx),
         lambda c: c.device_add("alice2", AB, ok=False))
    raised = epochs.org4(fx, persons="2", edit=_only_remove)
    _row(ctx, "quo/raised-floor-3-two-rejected", raised, removal)
    # carol's own endorsement is the third person (FO-22: the target counts like anyone)
    _row(ctx, "quo/raised-floor-3-three-applied", raised,
         lambda c: c.device_remove("carol", ("alice", "bob", "carol")))
