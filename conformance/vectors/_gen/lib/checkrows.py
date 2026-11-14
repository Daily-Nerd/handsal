"""One `check-act` vector row, and the vitni cross-check record that goes with it (CF-06)."""
from . import inputs

UNSET = inputs.UNSET


def row(ctx, name, jws, reason, *, cls=UNSET, method=inputs.APPROVE, signers=None, bad=None,
        error=None, **override):
    """Write the `check-act` row `name` for `jws`, expecting `reason`.

    `error`: the row expects `{"error": error}` (a required input missing) and `reason` is
    ignored. `signers`: device names whose keys vitni must accept `jws` under (a positive act).
    `bad=(signers, vitni_reason[, revoked])`: vitni's verdict on a signature the checker
    refuses. Neither: vitni is not asked (the act fails before step 9, or its signature is not
    what the row is about).
    """
    if signers:
        ctx.positive(jws, method, signers)
    if bad:
        who, vitni_reason, *rest = bad
        ctx.negative(jws, method, who, vitni_reason, revoked=rest[0] if rest else ())
    anchor = (inputs.error_anchor(error) if error is not None
              else inputs.check_anchor(jws, reason, cls))
    ctx.writer.add(name, "check-act", anchor,
                   input=inputs.check_input(ctx.fixtures, jws, method=method, **override))


def recheck_row(ctx, name, jws, reason, *, cls=UNSET, method=inputs.APPROVE, signers=None, bad=None,
                error=None, **override):
    """Write the `recheck-act` row `name` for `jws`, expecting `reason` (VR-17); the arguments are those of
    `row`. `override` may carry a key that names a moment, which makes the row expect `error`."""
    if signers:
        ctx.positive(jws, method, signers)
    if bad:
        who, vitni_reason, *rest = bad
        ctx.negative(jws, method, who, vitni_reason, revoked=rest[0] if rest else ())
    anchor = (inputs.error_anchor(error) if error is not None
              else inputs.recheck_anchor(jws, reason, cls))
    ctx.writer.add(name, "recheck-act", anchor,
                   input=inputs.recheck_input(ctx.fixtures, jws, method=method, **override))
