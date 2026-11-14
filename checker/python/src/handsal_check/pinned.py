"""The pinned fold (VR-02 step 6, GP-13 steps 1 to 4): the one place `check-act`, `recheck-act` and `enrolled` get
the state.

`folded` runs the pin checks and folds the lineage; `tip` and `head` pick the node whose state is judged: the tip
for `check-act` and `enrolled`, the act's own head for `recheck-act`. `fold` is `folded` and then `tip`: it runs
the pin checks (a) to (h) (`pinfile.check`), folds the lineage (`epoch.fold_lineage`) and reads the state at the
tip (`fold_out.view`). It returns `(pin, epochs, tip node)`, or raises Refused with the first failing code, a
fold error and `fork` included. A verifier that cannot answer raises
`VerifierUnavailable`, never a pass. It reads no input object: the caller hands it the probe, the org, the
lineage and the acts, so both commands decide the same thing from the same code.
"""
from . import epoch, errors, fold_out, pinfile, tree


def folded(probe, org, lineage, acts, reg, profiles, allow_fixture, vitni, render_size, store_reason=None):
    """`(pin, epochs)`: the pin checks (a) to (h) and the fold of the lineage, before any node is chosen.
    `recheck-act` reads the state at the act's own head, so it stops here and picks the node itself.
    `store_reason` is the production build's store failure, judged at (f) (CF-09, SS11): the one place all three
    commands get the state is also the one place a missing or unreadable store stops them."""
    pin = pinfile.check(probe, org, profiles, pinfile.ends(lineage), allow_fixture, store_reason)
    return pin, epoch.fold_lineage(lineage, acts, reg, profiles, allow_fixture, vitni, render_size)


def tip(epochs):
    """`(last epoch, tip node)`, or Refused with the fold error (`fork` for a frozen bag)."""
    found = fold_out.view(epochs, None)
    if found.error is not None:
        raise errors.Refused(found.error)
    return epochs[-1], found.node


def head(epochs, node_id):
    """`(epoch, node)` of the position an act names as its `head` (ACT-08), or Refused `stale_view`.

    A head is a position in its own epoch, and the lineage proves which epoch that is. In the last epoch it is
    a node of the accepted chain (a fork or later acts beyond it do not change its state, FO-16). In an earlier
    epoch it is a node on the path to the head H of the change that follows, the only part of that epoch the
    lineage continues from (GP-19). Any other id is no position the evidence proves: unknown, on a branch a
    resolve discarded, past a fork parent or past H."""
    node = fold_out.node_by_id(epochs, node_id)
    if node is not None:
        return epochs[-1], node
    for earlier, following in zip(epochs, epochs[1:]):
        earlier.build()
        closing = earlier.nodes.get(following.doc["head"])
        for item in tree.path_from_root(closing):
            if item.id == node_id:
                return earlier, item
    raise errors.Refused("stale_view")


def fold(probe, org, lineage, acts, reg, profiles, allow_fixture, vitni, render_size, store_reason=None):
    """`(pin, epochs, tip node)` for `probe` against the input `org` and `lineage`, or Refused."""
    pin, epochs = folded(probe, org, lineage, acts, reg, profiles, allow_fixture, vitni, render_size, store_reason)
    return pin, epochs, tip(epochs)[1]
