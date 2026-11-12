"""Vectors frk/* and rsv/*, part 2: the stages of the long fork and resolve scenarios (FO-24, FO-25).

Each scenario is one bag that grows; each stage is a vector over the bag as it is at that point,
so a row's input holds exactly the acts its id names. The chain a stage ends on is built as the
applied one (at the tip) and every other branch as a valid act beside it (lib/chain.py). A
resolve that is pending (one person signed it) is built with `short=True`; completing it is the
same primary plus an endorsement, so the stage that completes it rebuilds the scenario with the
full signer list, which gives the same primary bytes.

Persons are alice, bob and carol (Q = 2). Names follow the catalog: P is the fork parent, c1 and
c2 its children, R the resolves, e the endorsements the overrides name as evidence.
"""
from lib import base, epochs, forge, inputs
from lib.changes import fold_row
from lib.forks import AB, AC, BC, child, evidence, fork_row, new, removal, state_row

NOW = base.NOW
SIX = ("alice2", "alice3", "alice4", "bob2", "bob3")


def _ids(*built):
    return sorted(b.id for b in built)


def _six(ctx):
    """T1 to T5 are device adds, T6 removes alice2 (K) by bob and carol."""
    c = new(ctx)
    built = [c.device_add(n, AB) for n in SIX]
    built.append(c.device_remove("alice2", BC))
    return c, built


def _stale_proposal(ctx):
    """FO-24 S3: a stale proposal completed late, then a second one (refreeze)."""
    c = new(ctx)
    first = child(c, "alice2", AB, None, applied=True)
    s1 = child(c, "alice3", AB, None)
    c.resolve(BC, candidates=_ids(first, s1), choose=first.id, heads=[s1.id], parent=None)
    state_row(ctx, "frk/stale-proposal-first-resolve-lifts", c)
    s2 = child(c, "alice4", AB, None)
    fork_row(ctx, "frk/stale-proposal-second-stale-refreezes", c, None, first, s1, s2)
    c.resolve(BC, candidates=_ids(first, s1, s2), choose=first.id, heads=_ids(s1, s2), parent=None)
    state_row(ctx, "frk/stale-proposal-refreeze-lifted-again", c)


def _extension(ctx):
    """FO-24 S4: a new primary under the losing branch, or a new child of P, refreezes."""
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    c.resolve(AC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    d = child(c, "bob3", BC, c2)
    fork_row(ctx, "frk/losing-branch-extension-refreezes", c, None, c1, c2)
    c.resolve(AC, candidates=_ids(c1, c2), choose=c1.id, heads=[d.id], parent=None)
    state_row(ctx, "frk/losing-branch-extension-lifted", c)

    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    c.resolve(AB, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    c3 = child(c, "bob3", BC, None)
    fork_row(ctx, "frk/resolve-new-child-refreezes", c, None, c1, c2, c3)
    c.resolve(AB, candidates=_ids(c1, c2, c3), choose=c1.id, heads=_ids(c2, c3), parent=None)
    state_row(ctx, "frk/resolve-new-child-lifted", c)


def _stale_resolve(ctx):
    """FO-25 S4: a stale resolve completed by one touch conflicts with the applied one."""
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    r2 = c.resolve(AB, candidates=_ids(c1, c2), choose=c2.id, heads=[c1.id], parent=None)
    fork_row(ctx, "frk/stale-resolve-completed-forks", c, None, c1, c2)
    child(c, "alice3", AC, c1, applied=True)  # e: a later primary under c1
    fork_row(ctx, "frk/stale-resolve-late-endorsement-still-forks", c, None, c1, c2)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None,
              overrides=[{"endorsements": [evidence(r2, 1)], "resolve": r2.id}])
    state_row(ctx, "frk/stale-resolve-lifted-by-override", c)


def _two_stale_artifacts(ctx):
    """FO-25 S6: a stale primary under c2 and a stale resolve choosing c2 never replace c1."""
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    state_row(ctx, "frk/two-stale-artifacts-winner-applied", c)
    s = child(c, "X1", AB, c2)  # device.add of X1 for alice: one proposal and one touch
    fork_row(ctx, "frk/two-stale-artifacts-stale-primary-forks", c, None, c1, c2)
    r_s = c.resolve(AC, candidates=_ids(c1, c2), choose=c2.id, heads=[c1.id], parent=None)
    fork_row(ctx, "frk/two-stale-artifacts-cannot-replace-winner", c, None, c1, c2)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[s.id], parent=None,
              overrides=[{"endorsements": [evidence(r_s, 1)], "resolve": r_s.id}])
    state_row(ctx, "frk/two-stale-artifacts-override-lifts", c)


def _pending_name(ctx):
    """FO-25 S8: bob2's endorsement is the same person as bob, so R1 stays pending until carol."""
    c = new(ctx)
    top = c.device_add("bob2", AB)
    c1 = child(c, "alice2", AB, top, applied=True)
    c2 = child(c, "alice3", AC, top)
    cands = _ids(c1, c2)
    r1 = c.resolve(("bob", "bob2", "carol"), candidates=cands, choose=c1.id, heads=[c2.id],
                   parent=top)
    state_row(ctx, "frk/pending-name-override-first-resolve-applies", c)
    s = c.resolve(AB, candidates=cands, choose=c2.id, heads=[c1.id], parent=top,
                  overrides=[{"endorsements": [evidence(r1, 1)], "resolve": r1.id}])
    fork_row(ctx, "frk/pending-name-override-cannot-replace", c, top, c1, c2)
    c.resolve(BC, candidates=cands, choose=c1.id, heads=[c2.id], parent=top,
              overrides=[{"endorsements": [evidence(s, 1)], "resolve": s.id}])
    state_row(ctx, "frk/pending-name-override-lifted", c)


def _ancestor(ctx, x_signers, *, applied_c2=False, **x_hooks):
    """G has c1 and c2; under c1, d1 and d2. R_G at G chooses c1, R_P at c1 chooses d1, and R_x
    at G chooses c2 naming R_G (and R_P when asked) by the evidence of their completions."""
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=not applied_c2)
    c2 = child(c, "bob2", BC, None, applied=applied_c2)
    d1 = child(c, "alice3", AB, c1, applied=not applied_c2)
    d2 = child(c, "bob3", BC, c1)
    r_g = c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    r_p = c.resolve(BC, candidates=_ids(d1, d2), choose=d1.id, heads=[d2.id], parent=c1)
    entries = [{"endorsements": [evidence(r_g, 1)], "resolve": r_g.id}]
    if applied_c2:
        entries.append({"endorsements": [evidence(r_p, 1)], "resolve": r_p.id})
    r_x = c.resolve(x_signers, candidates=_ids(c1, c2), choose=c2.id, heads=_ids(d1, d2),
                    parent=None, overrides=sorted(entries, key=lambda e: e["resolve"]), **x_hooks)
    return c, (c1, c2), r_x


def _ancestor_rows(ctx):
    c, _pair, _r_x = _ancestor(ctx, ("alice",), short=True)  # R_x is signed and still pending
    state_row(ctx, "frk/ancestor-override-before-completion-applies", c)
    c, (c1, c2), r_x = _ancestor(ctx, AB)  # bob completes it: R_P is not named
    fork_row(ctx, "frk/ancestor-override-cannot-discard-unseen-resolve", c, None, c1, c2)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None,
              overrides=[{"endorsements": [evidence(r_x, 1)], "resolve": r_x.id}])
    state_row(ctx, "frk/ancestor-override-lifted", c)
    c, _pair, _r_x = _ancestor(ctx, AB, applied_c2=True)  # R_x names R_G and R_P, then bob
    state_row(ctx, "rsv/override-names-discarded-subtree-resolve-current", c)


def _override_evidence(ctx):
    # R1 by bob and carol (carol's e1) chooses c1: the first stage, c1 is the next node
    c = new(ctx)
    c1 = child(c, "alice2", AB, None, applied=True)
    c2 = child(c, "bob2", BC, None)
    c.resolve(BC, candidates=_ids(c1, c2), choose=c1.id, heads=[c2.id], parent=None)
    state_row(ctx, "rsv/override-completion-evidence-first-resolve-applies", c)

    # an endorsement of R1 whose only copy fails its signature is no evidence (FO-25 condition 2)
    c = new(ctx)
    c2 = child(c, "bob2", BC, None, applied=True)
    c1 = child(c, "alice2", AB, None)
    r1 = c.resolve(("bob", "carol", "alice"), candidates=_ids(c1, c2), choose=c1.id,
                   heads=[c2.id], parent=None)
    bad = forge.tamper(r1.acts[2], lambda p: p.__setitem__("ts", base.shift(p["ts"], 1)))
    c.edit_act(r1, 2, bad)
    named = sorted([evidence(r1, 1), inputs.receipt_id(bad)])
    c.resolve(AB, candidates=_ids(c1, c2), choose=c2.id, heads=[c1.id], parent=None,
              overrides=[{"endorsements": named, "resolve": r1.id}])
    fork_row(ctx, "rsv/override-evidence-bad-signature-not-effective", c, None, c1, c2)

    # the evidence key is added below P (on c1's branch) and counts in the state at R_P's parent
    c = new(ctx)
    c2 = child(c, "alice3", AC, None, applied=True)
    c1 = child(c, "alice2", AB, None)
    a = child(c, "bob2", AB, c1)
    d1 = child(c, "carol2", AC, a)
    d2 = child(c, "bob3", BC, a)
    r_p = c.resolve(("alice", "bob2"), candidates=_ids(d1, d2), choose=d1.id, heads=[d2.id],
                    parent=a)
    c.resolve(AC, candidates=_ids(c1, c2), choose=c2.id, heads=_ids(d1, d2), parent=None,
              overrides=[{"endorsements": [evidence(r_p, 1)], "resolve": r_p.id}])
    state_row(ctx, "rsv/override-evidence-key-added-below-p-counts", c)


def _heads_and_poison(ctx):
    # the heads stop at 5 and leave K's removal at 6 off the examined path: not current
    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    c.resolve(("alice2", "carol"), candidates=_ids(built[3], x), choose=x.id,
              heads=[built[4].id], parent=built[2])
    fork_row(ctx, "rsv/stale-head-not-current", c, built[2], built[3], x)

    # FO-25 S1, second case: heads [6] cover K's removal on the examined path, so only carol
    # counts and the resolve is not applicable (a row of its own, one case per id)
    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    c.resolve(("alice2", "carol"), candidates=_ids(built[3], x), choose=x.id,
              heads=[built[5].id], parent=built[2])
    fork_row(ctx, "rsv/stale-head-covers-removal-ignored", c, built[2], built[3], x)

    # the attacker removes carol, alice and alice2 in turn; carol is removed on the examined path
    c = new(ctx)
    p = None
    for name in ("alice2", "bob2", "alice3"):
        p = c.device_add(name, AB)
    h4 = c.device_add("bob3", AB)
    c.device_add("alice4", AB)
    c.device_remove("bob2", AC)
    x1 = c.device_remove("carol", ("bob2", "carol"), ok=False, valid=True, parent=p)
    x2 = c.device_remove("alice", ("bob2", "alice"), ok=False, valid=True, parent=x1)
    x3 = c.device_remove("alice2", ("bob2", "alice2"), ok=False, valid=True, parent=x2)
    c.resolve(BC, candidates=_ids(h4, x1), choose=h4.id, heads=[x3.id], parent=p)
    fork_row(ctx, "rsv/poisoned-unliftable", c, p, h4, x1)


def minted_person_bag(ctx):
    """The R11 bag, before any resolve: K (alice's own device a1) and bob, one tricked touch, add
    frank at node 3 (`m`); frank and K then remove bob (`x1`) and carol (`x2`). The honest chain
    4, 5, 6 runs below node 3 and node 6 removes K. Returns (chain, node 3, node 4, node 6, m,
    x1, x2); every device of alice but K is added at nodes 1 to 3, so bob and carol hold one
    device each at node 3.
    """
    c = new(ctx)
    for name in ("alice2", "alice3", "alice4"):
        p = c.device_add(name, AB)
    honest4 = c.device_add("bob2", AB)
    c.device_add("carol2", BC)
    honest6 = c.device_remove("alice", BC)
    m = c.member_add("frank", AB, role="maintainer", ok=False, valid=True, parent=p)
    x1 = c.device_remove("bob", ("alice", "frank"), ok=False, valid=True, parent=m)
    x2 = c.device_remove("carol", ("alice", "frank"), ok=False, valid=True, parent=x1)
    return c, p, honest4, honest6, m, x1, x2


def _r11(ctx):
    # K = alice2 is removed at 6; c2 at 3 is signed by K and carol
    c, built = _six(ctx)
    x = child(c, "X1", ("alice2", "carol"), built[2])
    cands = _ids(built[3], x)
    c.resolve(BC, candidates=cands, choose=built[3].id, heads=[x.id], parent=built[2])
    state_row(ctx, "frk/r11-honest-resolve-applies", c)
    r_k = c.resolve(("alice2", "carol"), candidates=cands, choose=x.id, heads=[built[4].id],
                    parent=built[2])
    fork_row(ctx, "frk/r11-resolve-above-removal-costs-override", c, built[2], built[3], x)
    c.resolve(BC, candidates=cands, choose=built[3].id, heads=[x.id], parent=built[2],
              overrides=[{"endorsements": [evidence(r_k, 1)], "resolve": r_k.id}])
    state_row(ctx, "frk/r11-override-lifts", c)

    fx = ctx.fixtures
    c, p, honest4, honest6, m, _x1, x2 = minted_person_bag(ctx)
    c.resolve(BC, candidates=_ids(honest4, m), choose=honest4.id, heads=[x2.id], parent=p)
    fork_row(ctx, "frk/r11-minted-person-branch-freezes", c, p, honest4, m)

    # an honest change at H = node 6 lists alice2, bob and carol; every listed device signs
    doc = epochs.make_change(fx, fx.org, honest6.id, carry=("alice", "bob", "carol"), new=(),
                             st=c.history[6])
    lineage = epochs.lineage_with(c.lineage, doc, epochs.sign_change(fx, doc))
    fold_row(ctx, "frk/r11-minted-person-change-recovers", lineage, c.acts)


def _finality(ctx):
    """FO-24 S6: bag B has c built upon at P; one more leaf or branch at P freezes P."""
    def bag(ctx):
        c = new(ctx)
        p = c.device_add("alice3", AB)
        base_c = child(c, "alice2", AB, p, applied=True)
        c.device_add("bob2", AB)
        return c, p, base_c

    c, p, cc = bag(ctx)
    state_row(ctx, "frk/finality-base-bag-applies", c)
    leaf = child(c, "X1", ("alice3", "carol"), p)
    fork_row(ctx, "frk/finality-added-leaf-only-forks", c, p, cc, leaf)

    c, p, cc = bag(ctx)
    b1 = child(c, "X1", ("alice3", "carol"), p)
    child(c, "X2", ("alice3", "carol"), b1)
    fork_row(ctx, "frk/finality-added-branch-only-forks", c, p, cc, b1)


def _bc1(ctx):
    """FO-22 S2: one person's two keys sign a removal and a competing act at one parent."""
    def bag(ctx, y_signers, *, short):
        c = new(ctx)
        c.device_add("alice2", AB)
        p = c.device_add("alice3", AB)
        h = c.device_remove("alice3", ("bob", "carol", "alice2"))
        hooks = {"short": True} if short else {}
        y = c.device_add("X1", y_signers, ok=False, valid=not short, parent=p, **hooks)
        return c, p, h, y

    c, p, h, y = bag(ctx, ("alice3", "alice2"), short=True)
    c.device_remove("alice2", ("alice2",), short=True, ok=False, parent=y)  # y2: one signature
    state_row(ctx, "frk/bc1-sequence-rejected", c)

    c, p, h, y = bag(ctx, ("alice2", "carol"), short=False)
    y2 = c.device_remove("bob", ("alice2", "carol"), ok=False, valid=True, parent=y)
    fork_row(ctx, "frk/bc1-two-person-variant-forks", c, p, h, y)
    c.resolve(AC, candidates=_ids(h, y), choose=h.id, heads=[y2.id], parent=p)
    state_row(ctx, "frk/bc1-two-person-variant-lifted", c)


def generate(ctx):
    _stale_proposal(ctx)
    _extension(ctx)
    _stale_resolve(ctx)
    _two_stale_artifacts(ctx)
    _pending_name(ctx)
    _ancestor_rows(ctx)
    _override_evidence(ctx)
    _heads_and_poison(ctx)
    _r11(ctx)
    _finality(ctx)
    _bc1(ctx)
