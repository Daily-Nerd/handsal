"""The pinned fold (VR-02 step 6, GP-13 steps 1 to 4): the one place `check-act` and `enrolled` get the state.

`fold` runs the pin checks (a) to (h) (`pinfile.check`), then folds the lineage (`epoch.fold_lineage`) and
reads the state at the tip (`fold_out.view`). It returns `(pin, epochs, tip node)`, or raises Refused with
the first failing code, a fold error and `fork` included. A verifier that cannot answer raises
`VerifierUnavailable`, never a pass. It reads no input object: the caller hands it the probe, the org, the
lineage and the acts, so both commands decide the same thing from the same code.
"""
from . import epoch, errors, fold_out, pinfile


def fold(probe, org, lineage, acts, reg, profiles, allow_fixture, vitni, render_size):
    """`(pin, epochs, tip node)` for `probe` against the input `org` and `lineage`, or Refused."""
    pin = pinfile.check(probe, org, profiles, pinfile.ends(lineage), allow_fixture)
    epochs = epoch.fold_lineage(lineage, acts, reg, profiles, allow_fixture, vitni, render_size)
    found = fold_out.view(epochs, None)
    if found.error is not None:
        raise errors.Refused(found.error)
    return pin, epochs, found.node
