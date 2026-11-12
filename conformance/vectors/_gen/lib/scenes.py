"""Multi-act setups several vector groups reuse; each is built in one place.

A scene records its valid acts for the vitni cross-check through `ctx` (None in unit
tests). Nothing here judges an act: the author states what is valid (CF-06).
"""
from collections import namedtuple

from . import chain

AB = ("alice", "bob")
LosingBranch = namedtuple("LosingBranch", "chain first kept lost resolve bag")


def losing_branch(fx, *, wit=False, ctx=None):
    """A fork at T1 and the resolve that lifts it.

    T1 (alice2) has two valid children, `kept` (alice3) and `lost` (bob3), each added by
    alice and bob. A resolve at T1 by alice and bob chooses `kept` with heads [`lost`], so it
    is current (FO-25) and the accepted chain is T1, kept. `lost` is no position of it.
    `chain` holds T1 and kept applied; `bag` is every act, `chain.expect()` the fold output.
    """
    c = chain.Chain(fx, wit=wit, ctx=ctx)
    first = c.device_add("alice2", AB)
    kept = c.device_add("alice3", AB)
    lost = c.device_add("bob3", AB, ok=False, valid=True, parent=first)
    resolve = fx.chain_resolve(AB, candidates=[kept.id, lost.id], choose=kept.id,
                               heads=[lost.id], parent=first, org=c._org())
    if ctx is not None:
        ctx.positive(resolve.acts[0], chain.RESOLVE, ["alice"])
        ctx.positive(resolve.acts[1], chain.ENDORSE, ["bob"])
    return LosingBranch(c, first, kept, lost, resolve, c.acts + resolve.acts)
