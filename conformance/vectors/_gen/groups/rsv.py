"""Vectors rsv/* and sch/resolve-with-head: `chain.resolve` (FO-24, FO-25, ACT-08, ACT-09).

A resolve joins the bag and takes no position. Where it lifts the fork the row builds the
chosen branch as the applied one, so the expected output is the state through that branch; where
it is ignored or not current the output is the fork at its parent. A resolve that fails the
schema is ignored by the fold (ACT-09), so it never lifts anything.

The five `rsv/{candidate,choose,head,override-entry,override-resolve}-non-canonical-hashstr`
rows are `fold` rows (ACT-07 S2): VR-02 stops a resolve at step 4 (`chain_method`), so
`check-act` never reads one. Each is the bag of `rsv/lifts-fork` whose resolve has one hashstr
written with nonzero trailing bits (the same 32 bytes), so a reader that compared decoded bytes
would lift the fork; a strict one ignores the resolve and the fork stays. The staged and long
scenarios are in groups/frk_stage.py.
`rsv/override-entry-shape-schema` is the case with `endorsements` empty; the bare hashstr
entry, the 16 endorsements and the non-canonical endorsement have their own ids.
`rsv/override-with-completion-evidence-current` is the last stage (after S).
"""
from lib import base, forge
from lib.forks import AB, AC, BC, child, evidence, fork_row, new, removal, state_row

UNKNOWN = base.hashstr(b"no such act")


def _pair(ctx, *, keep_first=True):
    """Two children of the root, c1 (alice2, alice and bob) and c2 (bob2, bob and carol).

    c1 is the applied one when `keep_first`; c2 never is."""
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=keep_first)
    c2 = child(c, "bob2", BC, None)
    return c, c1, c2


def _lift(c, c1, c2, signers=BC, parent=None, **hooks):
    return c.resolve(signers, candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id],
                     parent=parent, **hooks)


def generate(ctx):
    fx = ctx.fixtures

    c, c1, c2 = _pair(ctx)
    _lift(c, c1, c2)
    state_row(ctx, "rsv/lifts-fork", c)

    c, c1, c2 = _pair(ctx)
    _lift(c, c1, c2, BC)
    _lift(c, c1, c2, AC)
    state_row(ctx, "rsv/same-choice-two-resolves-ok", c)

    c = new(ctx)
    only = child(c, "alice2", AB, None, applied=True)
    c.resolve(BC, candidates=sorted([only.id, UNKNOWN]), choose=only.id, heads=[UNKNOWN],
              parent=None)
    state_row(ctx, "rsv/no-fork-ignored", c)

    # ignored resolves: the fork between c1 and c2 stays
    def stays_a_fork(name, resolve, *, setup=None):
        c = new(ctx)
        top = setup(c) if setup else None
        c1 = child(c, "alice3" if setup else "alice2", AB, top)
        c2 = child(c, "bob3" if setup else "bob2", BC, top)
        resolve(c, c1, c2, top)
        fork_row(ctx, name, c, top, c1, c2)
        return c, c1, c2

    stays_a_fork("rsv/candidate-not-at-parent", lambda c, c1, c2, top: c.resolve(
        BC, candidates=sorted([c1.id, UNKNOWN]), choose=c1.id, heads=[c2.id], parent=top))
    stays_a_fork("rsv/choose-not-in-candidates", lambda c, c1, c2, top: c.resolve(
        BC, candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=top,
        body_edit=lambda b: b.__setitem__("choose", UNKNOWN)))
    stays_a_fork("rsv/choose-not-candidate-ignored", lambda c, c1, c2, top: c.resolve(
        BC, candidates=sorted([c1.id, UNKNOWN]), choose=UNKNOWN, heads=[c2.id], parent=top))
    stays_a_fork("rsv/quorum-unmet-ignored", lambda c, c1, c2, top: _lift(
        c, c1, c2, ("alice",), top, short=True))
    stays_a_fork("rsv/single-person-two-devices", lambda c, c1, c2, top: _lift(
        c, c1, c2, ("alice", "alice2"), top, short=True),
        setup=lambda c: c.device_add("alice2", AB))
    stays_a_fork("rsv/head-outside-losing-subtree-ignored", lambda c, c1, c2, top: c.resolve(
        BC, candidates=[c1.id, c2.id], choose=c1.id, heads=[c1.id], parent=top))
    stays_a_fork("rsv/single-candidate-schema", lambda c, c1, c2, top: c.resolve(
        BC, candidates=[c1.id], choose=c1.id, heads=[c2.id], parent=top))
    stays_a_fork("rsv/overrides-missing-schema", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.pop("overrides")))
    stays_a_fork("rsv/override-entry-shape-schema", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__(
            "overrides", [{"endorsements": [], "resolve": UNKNOWN}])))
    # the other cases of an override entry that is no entry: a bare hashstr, 16 endorsements,
    # and an endorsement hashstr with nonzero trailing bits (ACT-07 owns the form: ignored)
    sixteen = sorted(base.hashstr(b"rsv-16/%02d" % n) for n in range(16))
    noncanonical = lambda h: "u" + forge.flip_spare_bits(h[1:])
    entry = {"endorsements": [noncanonical(UNKNOWN)], "resolve": UNKNOWN}
    stays_a_fork("rsv/override-entry-bare-hashstr-schema", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__("overrides", [UNKNOWN])))
    stays_a_fork("rsv/override-entry-sixteen-endorsements-schema", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__(
            "overrides", [{"endorsements": sixteen, "resolve": UNKNOWN}])))
    stays_a_fork("rsv/override-entry-non-canonical-hashstr", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__("overrides", [entry])))
    stays_a_fork("rsv/override-resolve-non-canonical-hashstr", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__("overrides", [
            {"endorsements": [base.hashstr(b"no such endorsement")],
             "resolve": noncanonical(UNKNOWN)}])))
    stays_a_fork("rsv/candidate-non-canonical-hashstr", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__(
            "candidates", sorted([noncanonical(c1.id), c2.id]))))
    stays_a_fork("rsv/head-non-canonical-hashstr", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__("heads", [noncanonical(c2.id)])))
    stays_a_fork("rsv/choose-non-canonical-hashstr", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, body_edit=lambda b: b.__setitem__("choose", noncanonical(c1.id))))
    stays_a_fork("sch/resolve-with-head", lambda c, c1, c2, top: _lift(
        c, c1, c2, BC, top, primary_head={"id": c.root, "kind": "chain"}))

    c = new(ctx)
    c1, c2 = child(c, "alice2", AB, None), child(c, "bob2", BC, None)
    below = child(c, "alice3", AB, c2)
    c.resolve(BC, candidates=[c1.id, c2.id], choose=c1.id, heads=sorted([c2.id, below.id]),
              parent=None)
    fork_row(ctx, "rsv/heads-ancestor-pair-ignored", c, None, c1, c2)

    # 18 children: one over the cap of 17 candidates, so the resolve fails its schema
    c = new(ctx)
    kids = []
    for n in range(10, 28):
        name = "alice%d" % n
        fx.register_device(name, "rsv-18/%s/sign" % name, "rsv-18/%s/agree" % name)
        kids.append(child(c, name, AB, None))
    ids = sorted(k.id for k in kids)
    c.resolve(BC, candidates=ids, choose=ids[0], heads=ids[1:17], parent=None)
    fork_row(ctx, "rsv/candidates-over-17-schema", c, None, *kids)

    # the completing endorsement names a head that is not the resolve's parent: not counted
    c, c1, c2 = _pair(ctx, keep_first=False)
    res = _lift(c, c1, c2, BC)
    c.edit_act(res, 1, forge.resign(fx, res.acts[1], forge.act_edit(
        lambda a: a["head"].__setitem__("id", c1.id))))
    fork_row(ctx, "rsv/endorsement-head-must-be-parent", c, None, c1, c2)

    # K (alice2) is removed on the examined path, so a resolve signed by K counts bob only
    def with_k(c):
        return c.device_add("alice2", AB)
    c = new(ctx)
    top = with_k(c)
    gone = removal(c, "alice2", BC, top)
    c2 = child(c, "bob2", AB, top)
    c.resolve(("alice2", "bob"), candidates=[gone.id, c2.id], choose=c2.id, heads=[gone.id],
              parent=top)
    fork_row(ctx, "rsv/revoked-on-branch-not-counted", c, top, gone, c2)

    c = new(ctx)
    top = with_k(c)
    c1 = child(c, "bob2", AB, top)
    q = removal(c, "alice2", BC, c1)
    c2 = child(c, "bob3", BC, top)
    c.resolve(("alice2", "bob"), candidates=[c1.id, c2.id], choose=c2.id, heads=[q.id],
              parent=top)
    fork_row(ctx, "rsv/clean-on-examined-paths-required", c, top, c1, c2)

    c = new(ctx)
    c1, c2 = child(c, "alice2", AB, None), child(c, "bob2", BC, None)
    child(c, "X1", AB, c1)  # X1 is added under c1 after P, so it is no key of S_P
    c.resolve(("X1", "bob"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
    fork_row(ctx, "rsv/fresh-key-on-chosen-branch-not-counted", c, None, c1, c2)

    c, c1, c2 = _pair(ctx, keep_first=False)
    c.resolve(("alice", "bob"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id],
              parent=None)
    c.resolve(("carol", "alice"), candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id],
                   parent=None)
    fork_row(ctx, "rsv/conflicting-resolves-freeze", c, None, c1, c2)

    c = new(ctx)
    c1, c2 = child(c, "alice2", AB, None), child(c, "bob2", BC, None)
    c3 = child(c, "alice3", AC, None)  # a child of P the resolve does not list
    _lift(c, c1, c2)
    fork_row(ctx, "rsv/unlisted-leaf-dropped", c, None, c1, c2, c3)

    # R1 chose c1; S names, as its overridden resolve, an id that is a primary
    c, c1, c2 = _pair(ctx, keep_first=False)
    r1 = c.resolve(BC, candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
    c.resolve(AB, candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id], parent=None,
              overrides=[{"endorsements": [evidence(r1, 1)], "resolve": c1.id}])
    fork_row(ctx, "rsv/override-wrong-id-not-current", c, None, c1, c2)

    # R1 = bob + carol; the entry names bob2's endorsement, one person with R1's primary
    c = new(ctx)
    top = c.device_add("bob2", AB)
    c1, c2 = child(c, "alice2", AB, top), child(c, "alice3", AC, top)
    r1 = c.resolve(("bob", "carol", "bob2"), candidates=[c1.id, c2.id], choose=c1.id,
                   heads=[c2.id], parent=top)
    c.resolve(AB, candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id], parent=top,
              overrides=[{"endorsements": [evidence(r1, 2)], "resolve": r1.id}])
    fork_row(ctx, "rsv/override-evidence-insufficient-not-current", c, top, c1, c2)

    # an overriding resolve that carries the completing endorsement of the applied one
    for name, signers in (("rsv/overriding-resolve-lifts-conflict", AC),
                          ("rsv/override-with-completion-evidence-current", AB)):
        c = new(ctx)
        c2 = child(c, "bob2", BC, None, applied=True)
        c1 = child(c, "alice2", AB, None)
        r1 = c.resolve(BC, candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
        c.resolve(signers, candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id], parent=None,
                  overrides=[{"endorsements": [evidence(r1, 1)], "resolve": r1.id}])
        state_row(ctx, name, c)

    # the walk continues below a chosen candidate; a parent that is the resolve's id is no node
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    res = _lift(c, c1, c2)
    c.device_add("alice3", AB)
    c.device_add("bob3", AB, ok=False, parent=res)
    state_row(ctx, "rsv/takes-no-position", c)

    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    d1, d2 = child(c, "alice3", AB, c2), child(c, "bob3", BC, c2)
    c.resolve(AC, candidates=[c1.id, c2.id], choose=c1.id, heads=sorted([d1.id, d2.id]),
              parent=None)
    state_row(ctx, "rsv/two-heads-one-losing-candidate-current", c)

    # h applies; x (K and alice: one person) is no child, so the resolve listing it is ignored
    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    h = c.device_remove("alice2", BC)
    x = c.device_add("X1", ("alice2", "alice"), short=True, ok=False, parent=t1)
    c.resolve(BC, candidates=sorted([h.id, x.id]), choose=h.id, heads=[x.id], parent=t1)
    state_row(ctx, "rsv/lifts-revocation-race", c)

    c = new(ctx)
    t1 = c.device_add("alice2", AB)
    selfs = [c.device_remove("alice2", ("alice2",), short=True, ok=False,
                             ts=base.shift(base.NOW, s)) for s in (-3600, -3500)]
    c.resolve(BC, candidates=sorted(s.id for s in selfs), choose=selfs[0].id,
              heads=[selfs[1].id], parent=t1)
    state_row(ctx, "rsv/lifts-two-self-removals", c)

    # the equivocators sign both children, and one of them signs the resolve
    c = new(ctx)
    c2 = child(c, "bob2", BC, None, applied=True)
    c1 = child(c, "alice2", AB, None)
    c.resolve(("bob", "alice"), candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id],
              parent=None)
    state_row(ctx, "rsv/equivocator-counts", c)

    # disqualified and chosen: c2 holds alice2's key, removed on the losing branch d
    c = new(ctx)
    top = c.device_add("alice2", AB)
    c2 = child(c, "alice3", ("alice2", "bob"), top, applied=True)
    c1 = child(c, "bob2", AB, top)
    d = removal(c, "alice2", BC, c1)
    c.resolve(BC, candidates=[c1.id, c2.id], choose=c2.id, heads=[d.id], parent=top)
    state_row(ctx, "rsv/choose-disqualified-ok", c)

    # the chosen branch is never read: alice2's removal below c1 does not void the resolve
    c = new(ctx)
    top = c.device_add("alice2", AB)
    c1 = child(c, "bob2", AB, top, applied=True)
    c.device_remove("alice2", BC)
    c2 = child(c, "bob3", BC, top)
    c.resolve(("alice2", "bob"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id],
              parent=top)
    state_row(ctx, "rsv/chosen-branch-removal-not-read", c)
