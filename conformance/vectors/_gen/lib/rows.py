"""Table-driven fold rows: a function builds the bag on a fresh `Chain`, the chain is the anchor."""
from . import chain


def add_rows(ctx, rows):
    """Write one `fold` vector per `(name, build)`: `build(chain)` makes the acts of the row."""
    for name, build in rows:
        c = chain.Chain(ctx.fixtures, ctx=ctx)
        build(c)
        ctx.writer.add(name, "fold", c.expect(), input=c.fold_input())


AB = ("alice", "bob")
BC = ("bob", "carol")
PIN = "fixture-pin"


def with_dave(c):
    """dave (role member) joins with an accepted device and a fixture-pin device."""
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=PIN)
