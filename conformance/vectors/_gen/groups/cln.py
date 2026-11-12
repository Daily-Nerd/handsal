"""Vectors cln/*: which removals count against a key (FO-18, FO-25, FO-26).

A removal counts against its key in the acts whose past cone contains it and in a resolve
that discards its branch, and nowhere else. A removal that is not an act (one person signed
it) counts nowhere.

Not written: `cln/active-everywhere-ok` and `cln/unaccepted-never-clean` (no command output
shows a key as clean or not apart from the rows that use it).
"""
from lib.forks import AB, AC, BC, child, fork_row, new, removal, state_row


def generate(ctx):
    # K = alice2 is removed below candidate d, and K signs the resolve that discards d
    c = new(ctx)
    top = c.device_add("alice2", AB)
    d = removal(c, "alice2", BC, top)
    other = child(c, "bob2", AB, top)
    c.resolve(("alice2", "bob"), candidates=sorted([d.id, other.id]), choose=other.id,
              heads=[d.id], parent=top)
    fork_row(ctx, "cln/tainted-on-one-branch", c, top, d, other)

    # a nested fork below c1 (q1, q2): q2 removes alice2, which is on an examined path
    c = new(ctx)
    top = c.device_add("alice2", AB)
    c1 = child(c, "bob2", AB, top)
    q1 = child(c, "alice3", AB, c1)
    q2 = removal(c, "alice2", BC, c1)
    c2 = child(c, "bob3", BC, top)
    c.resolve(("alice2", "bob"), candidates=sorted([c1.id, c2.id]), choose=c2.id,
              heads=sorted([q1.id, q2.id]), parent=top)
    fork_row(ctx, "cln/nested-resolved-fork-all-branches", c, top, c1, c2)

    # c2 removes bob, but c2 sits on no examined path of the resolve at P1 (it lost at P)
    c = new(ctx)
    p = c.device_add("alice2", AB)
    c1 = child(c, "bob2", AB, p, applied=True)
    c2 = removal(c, "bob", ("alice2", "carol"), p)
    c.resolve(AC, candidates=sorted([c1.id, c2.id]), choose=c1.id, heads=[c2.id], parent=p)
    d1 = child(c, "carol2", AC, c1, applied=True)
    d2 = child(c, "alice3", AB, c1)
    c.resolve(BC, candidates=sorted([d1.id, d2.id]), choose=d1.id, heads=[d2.id], parent=c1)
    state_row(ctx, "cln/losing-branch-no-effect", c)

    # alice and alice2 are one person: their removal of bob is no act, so bob still counts
    c = new(ctx)
    p = c.device_add("alice2", AB)
    c.device_remove("bob", ("alice", "alice2"), short=True, ok=False)
    d1 = child(c, "carol2", AC, p, applied=True)
    d2 = child(c, "alice3", AB, p)
    c.resolve(BC, candidates=sorted([d1.id, d2.id]), choose=d1.id, heads=[d2.id], parent=p)
    state_row(ctx, "cln/invalid-act-removal-no-effect", c)
