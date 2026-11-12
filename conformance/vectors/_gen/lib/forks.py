"""Helpers for fork, resolve and cleanliness rows (FO-24 to FO-26).

A row builds its bag on a `Chain`: the branch the walk ends on is built as the applied one
(`applied=True`, at the tip), every other child with `ok=False, valid=True` at its parent
(a valid act that is not on the accepted chain). The expected output is the author's
statement of the walk: the state at the tip, or the fork result (FO-01, FO-24).
"""
from . import chain, inputs, state

AB, BC, AC = ("alice", "bob"), ("bob", "carol"), ("alice", "carol")


def new(ctx):
    return chain.Chain(ctx.fixtures, ctx=ctx)


def child(c, name, signers, parent, *, applied=False, **hooks):
    """A device.add of `name` at `parent` (a built act, None for the root).

    `applied=True` builds it at the tip, which must be `parent`; otherwise it is a valid act
    beside the accepted chain.
    """
    if applied:
        return c.device_add(name, signers, **hooks)
    return c.device_add(name, signers, parent=parent, ok=False, valid=True, **hooks)


def removal(c, name, signers, parent, *, applied=False, **hooks):
    """A device.remove of `name`, placed like `child`."""
    if applied:
        return c.device_remove(name, signers, **hooks)
    return c.device_remove(name, signers, parent=parent, ok=False, valid=True, **hooks)


def parent_id(c, parent):
    return c.root if parent is None else parent.id


def fork_row(ctx, name, c, parent, *children):
    """Write the `fold` row whose output is the fork at `parent` with these candidates."""
    ids = [b if isinstance(b, str) else b.id for b in children]
    ctx.writer.add(name, "fold", state.fork_anchor(parent_id(c, parent), ids),
                   input=c.fold_input())


def state_row(ctx, name, c):
    """Write the `fold` row whose output is the state at the chain's tip."""
    ctx.writer.add(name, "fold", c.expect(), input=c.fold_input())


def evidence(built, index):
    """The receipt id of act `index` of a built chain act (an endorsement's id)."""
    return inputs.receipt_id(built.acts[index])
