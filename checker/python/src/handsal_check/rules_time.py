"""Time rules and view rules (VR-11, VR-12) and the witness step (WT-04, WT-05): VR-02 steps 13 and 14.

All values come from the policy of the current epoch (`freshness`). `now` is the verifier's clock and
`synced_at` the time the consumer last folded its bag. Exactly on a bound is valid in every rule.

time:  `ts_in_future` (ts later than now + clock_skew_s), `bad_expiry` (expires not after ts),
       `validity_too_long` (expires - ts above max_validity_s), `expired` (now >= expires).
view:  `epoch_superseded` first (`next` is "yes": the store holds a valid successor of the pin, whatever the age
       of the view), then `view_in_future` (synced_at later than now + clock_skew_s), `stale_view` (now - synced_at
       above max_view_age_s, or the act's head is not a position of the accepted chain: one rule for a verifier
       that is behind, another branch, another epoch and junk). A head older than the tip is valid.
witness: `witness.check` after the view rules, in every mode: in mode `relay` the view rules still
       run (WT-07).
"""
from . import errors, schema, tree
from .witness import Context, check as check_statement


def _freshness(ctx):
    return ctx.epoch.policy["freshness"]


def _refuse(code):
    return errors.Refused(code)


def time(ctx):
    """Step 13."""
    freshness = _freshness(ctx)
    now, ts = schema.seconds(ctx.inp.now), schema.seconds(ctx.payload["ts"])
    if ts > now + int(freshness["clock_skew_s"]):
        raise _refuse("ts_in_future")
    expires = ctx.act["expires"]
    if schema.seconds(expires) <= ts:
        raise _refuse("bad_expiry")
    if schema.seconds(expires) - ts > int(freshness["max_validity_s"]):
        raise _refuse("validity_too_long")
    if now >= schema.seconds(expires):
        raise _refuse("expired")


def fresh_view(epoch, now, synced_at, next_):
    """The view rules of VR-12 that need no act, shared by `check-act` step 14 and `act_free_view`, in order:
    `epoch_superseded` when `next_` is "yes", then `view_in_future` and `stale_view` for the view synced at
    `synced_at` against the epoch's `freshness` and the clock `now`."""
    if next_ == "yes":
        raise _refuse("epoch_superseded")
    freshness = epoch.policy["freshness"]
    now, synced = schema.seconds(now), schema.seconds(synced_at)
    if synced > now + int(freshness["clock_skew_s"]):
        raise _refuse("view_in_future")
    if now - synced > int(freshness["max_view_age_s"]):
        raise _refuse("stale_view")


def act_free_view(epoch, pin, node, inp, vitni):
    """The view of the state at `node` when no act is judged: `fresh_view`, then the witness of the epoch's mode
    (WT-04, WT-05, WT-10). The one owner of that order (WT-07) for the two callers that hold no act, `enrolled`
    step 6 and `head` step 5. `inp` holds `now`, `synced_at`, `next` and `tip_statement`. `check-act` step 14 keeps
    its own steps (`view`, `witness`), because the act's head sits between the age and the witness there."""
    fresh_view(epoch, inp.now, inp.synced_at, inp.next)
    check_statement(inp.tip_statement, Context(epoch, pin.org, pin.genesis, inp.now, tree.positions(node)), vitni)


def view(ctx):
    """Step 14, the view rules: the age, then the act's head must be a position of the accepted chain."""
    fresh_view(ctx.epoch, ctx.inp.now, ctx.inp.synced_at, ctx.inp.next)
    if ctx.act["head"]["id"] not in ctx.positions:
        raise _refuse("stale_view")


def witness(ctx):
    """Step 14, the witness rules."""
    check_statement(ctx.inp.tip_statement,
                    Context(ctx.epoch, ctx.pin.org, ctx.pin.genesis, ctx.inp.now, ctx.positions), ctx.vitni)
