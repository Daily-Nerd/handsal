"""Vectors aid/*: `genesis-aids`, what the ceremony shows about the previous epoch of a change (CF-03, SG-12 steps 6, 7).

Input `{acts, lineage}` like `genesis-check`; output `{aids, reason}`. A row's expectation is the author's statement
of the facts, not a checker's answer (CF-06): where the accepted chain of the previous epoch ends, where H lies
against it, and which kids a valid `device.remove` removes anywhere in the previous epoch's act tree, among those that
the change carries or whose key signed it.

A change names H, a node of the previous epoch, and carries the devices that are active there. Epoch 0 is built on a
`Chain` step by step; a branch beside the accepted chain is a valid act off the tip (`lib/forks.py`), and a
`chain.resolve` chooses one branch and examines the heads of the others.
"""
from lib import epochs, inputs, result
from lib.changes import AB, AC, BC, E0, add, record_sigs, remove
from lib.forks import child, removal

ALL = ("alice", "bob", "carol")


def _tip(at, tip):
    return {"at": "tip", "place": at, "tip": tip}


def _fork(parent, candidates, place, candidate=None):
    return {"at": "fork", "candidate": candidate, "candidates": sorted(candidates), "parent": parent, "place": place}


def _row(ctx, name, e0, doc, sigs, *, head, removed=()):
    """The `genesis-aids` row for the lineage E0 followed by the change `doc` with `sigs`."""
    lineage = epochs.lineage_with(e0.lineage, doc, sigs)
    record_sigs(ctx, lineage[1]["sigs"])
    answer = {"aids": {"head": head, "removed": sorted(removed)}, "reason": "ok"}
    ctx.writer.add(name, "genesis-aids", result.line(answer), input={"acts": list(e0.c.acts), "lineage": lineage})


def _change(ctx, name, e0, n, *, head, removed=(), carry=ALL, new=(), at=None, also=()):
    doc = e0.change(n, carry=carry, new=new, head=at)
    _row(ctx, name, e0, doc, epochs.sign_change(ctx.fixtures, doc, also=also), head=head, removed=removed)


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    kid = lambda name: fx.key(name).kid

    lineage = inputs.original_lineage(fx, fx.org)
    record_sigs(ctx, lineage[0]["sigs"])
    w.add("aid/original-has-no-aids", "genesis-aids", result.line({"aids": None, "reason": "ok"}),
          input={"acts": [], "lineage": lineage})

    # the accepted chain ends at a tip
    e0 = E0(ctx, [add("alice2")])
    _change(ctx, "aid/head-is-tip", e0, 1, head=_tip("tip", e0.ids[1]))
    e0 = E0(ctx, [add("alice2"), add("bob2")])
    _change(ctx, "aid/head-not-tip", e0, 1, head=_tip("not_tip", e0.ids[2]))

    # a fork at the root: two valid children
    e0 = E0(ctx)
    c1, c2 = child(e0.c, "alice2", AB, None), child(e0.c, "bob2", BC, None)
    below = child(e0.c, "alice3", AB, c1)
    fork = lambda place, candidate=None: _fork(e0.ids[0], [c1.id, c2.id], place, candidate)
    _change(ctx, "aid/fork-head-is-parent", e0, 0, head=fork("parent"))
    _change(ctx, "aid/fork-head-below-candidate", e0, 0, head=fork("below", c1.id), at=below.id)
    _change(ctx, "aid/fork-head-is-candidate", e0, 0, head=fork("below", c2.id), at=c2.id)

    # a fork above H: H is on the accepted chain before the fork
    e0 = E0(ctx, [add("alice2")])
    top = e0.built[1]
    d1, d2 = child(e0.c, "alice3", AB, top), child(e0.c, "bob2", BC, top)
    _change(ctx, "aid/fork-head-not-below", e0, 0, head=_fork(top.id, [d1.id, d2.id], "not_below"), at=e0.ids[0])

    # removed keys
    e0 = E0(ctx, [add("bob2"), remove("bob2", AC)])   # bob2 is removed after H, and the change carries it
    _change(ctx, "aid/removed-key-carried", e0, 1, head=_tip("not_tip", e0.ids[2]), carry=("alice", "bob"), new=("grace",),
            removed=[kid("bob2")])
    e0 = E0(ctx, [add("bob2"), remove("alice", BC)])   # alice signs the change at H, before her removal, and is not listed
    _change(ctx, "aid/removed-key-signed", e0, 1, head=_tip("not_tip", e0.ids[2]), carry=("bob", "carol"), new=("grace",),
            also=["alice"], removed=[kid("alice")])
    e0 = E0(ctx, [add("alice2")])   # carol's removal is on a branch the resolve discarded, and still counts
    first = e0.built[1]
    gone = removal(e0.c, "carol", AB, None)
    e0.c.resolve(AB, candidates=[first.id, gone.id], choose=first.id, heads=[gone.id], parent=None)
    _change(ctx, "aid/removed-key-on-discarded-branch", e0, 1, head=_tip("tip", first.id), removed=[kid("carol")])
    e0 = E0(ctx, [add("alice2")])   # a fork inside the chosen branch is shown, and carol's removal beside it still counts
    first = e0.built[1]
    gone = removal(e0.c, "carol", AB, None)
    n1, n2 = child(e0.c, "alice3", AB, first), child(e0.c, "bob2", BC, first)
    e0.c.resolve(AB, candidates=[first.id, gone.id], choose=first.id, heads=[gone.id], parent=None)
    _change(ctx, "aid/nested-fork-shown", e0, 0, head=_fork(first.id, [n1.id, n2.id], "not_below"), removed=[kid("carol")])

    # a refused lineage gives the code of `genesis-check`, and no aids
    e0 = E0(ctx)
    forged = e0.change(0, carry=("alice",))
    later = epochs.make_change(fx, forged, inputs.doc_id(forged), carry=("frank", "grace"), new=("heidi",))
    three = epochs.lineage_with(epochs.lineage_with(e0.lineage, forged, epochs.sign_change(fx, forged)), later,
                                epochs.sign_change(fx, later))
    for entry in three[1:]:
        record_sigs(ctx, entry["sigs"])
    w.add("aid/refused-lineage-has-no-aids", "genesis-aids",
          result.line({"aids": None, "reason": "genesis_change_unauthorized"}), input={"acts": [], "lineage": three})
