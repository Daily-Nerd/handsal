"""Vectors cas/*: a removed kid never returns (FO-07 S2).

alice2 is added and removed, then added again by the same two persons: the re-add is not
on the chain, so alice2 stays removed.
"""
from lib import rows
from lib.rows import AB


def _never_returns(c):
    c.device_add("alice2", AB)
    c.device_remove("alice2", ("alice", "bob"))
    c.device_add("alice2", AB, ok=False)


def generate(ctx):
    rows.add_rows(ctx, (("cas/removed-never-returns", _never_returns),))
