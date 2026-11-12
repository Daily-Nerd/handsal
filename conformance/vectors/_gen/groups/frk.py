"""Vectors frk/*: forks and the acts that cannot make one (FO-08, FO-14, FO-22, FO-24, FO-25).

A fork row is two or more valid children of one parent; the output is the fork with its
sorted candidates and no `keys`. A state row is a bag whose extra acts are not valid (one
signer, one person, an endorsement with the wrong head) so the walk takes the one valid
child. Persons are alice, bob and carol (Q = 2); alice2 is `K`, the key the removal rows
revoke.

Not written here: the rows that state several stages of one scenario under one id (an input
per stage), `frk/bc1-*`, `frk/a-c1-self-removal-variant-rejected`, `frk/finality-*` and the
two rows that need a genesis change.
"""
from lib import base, forge, inputs
from lib.forks import AB, BC, child, fork_row, new, removal, state_row

NOW = base.NOW
SIX = ("alice2", "alice3", "alice4", "bob2", "bob3")


def _six(ctx):
    """T1 to T5 are device adds, T6 removes alice2 (K) by bob and carol."""
    c = new(ctx)
    built = [c.device_add(n, AB) for n in SIX]
    built.append(c.device_remove("alice2", BC))
    return c, built


def _equivocation(ctx, name):
    c = new(ctx)
    c1 = child(c, "alice2", AB, None)
    c2 = child(c, "bob2", BC, None)
    return c, c1, c2


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    c, c1, c2 = _equivocation(ctx, "frk/quorum-equivocation-freeze")
    child(c, "alice3", AB, c1)  # each branch is built upon
    child(c, "bob3", BC, c2)
    fork_row(ctx, "frk/quorum-equivocation-freeze", c, None, c1, c2)

    c = new(ctx)
    r1 = removal(c, "carol", AB, None, ts=base.shift(NOW, -3600))
    r2 = removal(c, "carol", AB, None, ts=base.shift(NOW, -3500))
    fork_row(ctx, "frk/two-identical-bodies-fork", c, None, r1, r2)

    c = new(ctx)
    c.member_add("dave", AB, role="member")
    top = c.device_add("dave2", ("alice", "dave", "bob"))
    r1 = removal(c, "dave", AB, top)
    r2 = removal(c, "dave2", BC, top)
    fork_row(ctx, "frk/two-valid-removals", c, top, r1, r2)

    c = new(ctx)
    r1 = removal(c, "carol", AB, None)  # drops a key bob and carol's branch counts
    r2 = removal(c, "alice", BC, None)  # drops a key alice and bob's branch counts
    fork_row(ctx, "frk/mutual-disqualification", c, None, r1, r2)

    c = new(ctx)
    first = child(c, "alice2", AB, None, applied=True)
    late = child(c, "alice3", AB, None)  # alice's old proposal, completed late by bob
    fork_row(ctx, "frk/late-endorsement-stale-head-fork", c, None, first, late)

    # K removed at 6; K and carol sign a child at parent 3: valid against S_3
    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    fork_row(ctx, "frk/revoked-key-old-parent-freeze", c, built[2], built[3], x)

    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    c.resolve(BC, candidates=[built[3].id, x.id], choose=built[3].id, heads=[x.id],
              parent=built[2])
    state_row(ctx, "frk/revoked-key-old-parent-lifted", c)

    # a resolve signed by K must count K, but the examined path holds K's removal
    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    c.resolve(("alice2", "bob"), candidates=[built[3].id, x.id], choose=x.id,
              heads=[built[5].id], parent=built[2])
    fork_row(ctx, "frk/revoked-key-cannot-resolve", c, built[2], built[3], x)

    c, c1, c2 = _equivocation(ctx, "frk/equivocators-conflicting-resolves-freeze")
    c.resolve(AB, candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
    c.resolve(BC, candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id], parent=None)
    fork_row(ctx, "frk/equivocators-conflicting-resolves-freeze", c, None, c1, c2)

    # acts that are not valid children, beside one valid act
    c = new(ctx)
    c.device_add("alice2", AB)
    c.device_add("alice3", ("bob",), short=True, ok=False, parent=None)  # bob alone is no act
    c.device_add("alice4", ("frank", "bob"), ok=False, parent=None)  # frank's key is not in S_P
    state_row(ctx, "frk/single-touch-cannot-fork", c)

    c = new(ctx)
    c.device_add("alice2", AB)
    for stamp in (-3600, -3500):  # two self-removals of K: one signature is no act
        c.device_remove("alice2", ("alice2",), short=True, ok=False,
                        ts=base.shift(NOW, stamp))
    state_row(ctx, "frk/two-self-removals-no-fork", c)

    c = new(ctx)
    for name in ("alice2", "alice3"):  # K alone signs two adds: neither is an act
        c.device_add(name, ("alice",), short=True, ok=False)
    state_row(ctx, "frk/two-adds-one-key", c)

    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    c.device_remove("alice2", BC)
    c.device_add("X1", ("alice2",), short=True, ok=False, parent=t1)  # K alone adds a key
    state_row(ctx, "frk/revocation-race", c)

    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    c.device_remove("alice2", BC)
    c.device_add("X1", ("alice2", "alice"), short=True, ok=False, parent=t1)  # one person
    state_row(ctx, "frk/own-revocation-not-counted", c)

    c = new(ctx)
    c.device_add("alice2", AB)
    state_row(ctx, "frk/stale-proposal-at-tip-applies", c)

    c = new(ctx)
    first = c.device_add("alice2", AB)
    late = c.device_add("alice3", AB, ok=False, parent=None)
    c.edit_act(late, 1, forge.resign(fx, late.acts[1], forge.act_edit(
        lambda a: a["head"].__setitem__("id", first.id))))  # the late endorsement names a later head
    state_row(ctx, "frk/late-endorsement-new-head-no-fork", c)

    c = new(ctx)
    c.device_add("alice2", ("alice", "bob", "carol"))  # two endorsement sets, one primary
    state_row(ctx, "frk/two-endorsement-sets-one-primary-no-fork", c)

    c = new(ctx)
    c.device_add("alice2", AB)
    c.device_add("alice3", ("alice",), short=True, ok=False, parent=None)  # under-endorsed
    state_row(ctx, "frk/pending-superseded-no-fork", c)

    c = new(ctx)
    t1 = c.device_add("bob2", AB)
    c.device_remove("bob2", ("bob2",), short=True, ok=False)  # one signature: not an act
    c.member_add("dave", AB, role="member")
    state_row(ctx, "frk/single-grade-withdrawn-vs-two-signer", c)

    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    c.device_remove("alice2", ("alice2",), short=True, ok=False, parent=t1)
    c.device_remove("alice2", BC)
    state_row(ctx, "frk/equal-effect-merged", c)

    # old parents: signatures that are no act, however old the parent
    c, built = _six(ctx)
    for parent in built[:5]:
        c.device_add("X1", ("alice2", "alice"), short=True, ok=False, parent=parent)
    state_row(ctx, "frk/revoked-key-cannot-freeze-at-old-parent", c)

    c, built = _six(ctx)
    for parent in built[:5]:
        c.device_remove("alice2", ("alice2",), short=True, ok=False, parent=parent)
    state_row(ctx, "frk/revoked-key-single-self-removals-old-parents", c)

    c, built = _six(ctx)
    c.device_add("X1", ("alice2",), short=True, ok=False, parent=built[2])
    state_row(ctx, "frk/retroactive-candidate-by-revoked-key", c)

    # a resolve chosen before alice's key a1 is removed on the chosen branch stays
    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    kept = child(c, "bob2", AB, t1, applied=True)
    lost = child(c, "bob3", BC, t1)
    c.device_remove("alice", ("alice2", "carol"))
    c.resolve(AB, candidates=[kept.id, lost.id], choose=kept.id, heads=[lost.id], parent=t1)
    state_row(ctx, "frk/resolve-not-voided-by-later-acts", c)

    # the frozen bag, through check-act and enrolled
    c, c1, c2 = _equivocation(ctx, "frk/check-act-refuses")
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    w.add("frk/check-act-refuses", "check-act", inputs.check_anchor(approve, "fork"),
          input=inputs.check_input(fx, approve, acts=list(c.acts)))
    w.add("frk/enrolled-false", "enrolled", inputs.enrolled_anchor(False, "fork"),
          input=inputs.enrolled_input(fx, acts=list(c.acts)))
