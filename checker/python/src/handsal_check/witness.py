"""The freshness witness (WT-03 to WT-10): the check `check-act` step 14 and `enrolled` step 6 run
after the VR-12 view rules.

`check` takes the statement text (or None) and a `Context`: the epoch whose policy names the mode,
the pin's `org` and `genesis`, the verifier's `now`, and the position ids of the current epoch's
chain as the consumer folded it. It returns None or raises Refused; it never returns an acceptance,
because a statement can only add a refusal (WT-06). The witness is read from the epoch's own policy
only: no flag and no input switches the mode (WT-08), and no mode is ever read as `none` by default
(WT-07).

Mode `none` (WT-04): `tip_statement` must be null; any text at all is `witness_unexpected`, whatever it
holds, and is not parsed.

Mode `relay` (WT-05), first failure wins:
  1  null                                      `witness_missing`
  2  the shape of WT-02                        `witness_malformed`
  3  header kid is not the policy's relay kid  `witness_key_mismatch`
  4  vitni verify against the one relay key; S above n/2   `witness_bad_signature`
  5  statement org is not the pin's org        `witness_org_mismatch`
  6  statement epoch is not the pin's genesis  `witness_epoch_mismatch`
  6a `next` is "yes"                           `witness_superseded` (WT-10; no bag is read)
  7  ts later than now + clock_skew_s          `witness_in_future`
  8  now - ts above max_tip_age_s              `stale_witness`
  9  tip is no position of the epoch's chain   `behind_witness`
Signature before content: apart from the header kid that selects the key, nothing in an
unauthenticated statement decides anything. A verifier that cannot answer raises
`VerifierUnavailable`, never a pass.
"""
from collections import namedtuple

from . import errors, schema, verifier, witness_stmt

Context = namedtuple("Context", "epoch org genesis now positions")


def _refuse(code):
    return errors.Refused(code)


def _signature(stmt, epoch, vitni):
    """Step 4: vitni verify with the one-entry map of the relay key, and low S."""
    _, (x, y) = epoch.relay
    keys = {witness_stmt.PERFORMER: {stmt.kid: verifier.key_entry({"x": x, "y": y}, "active")}}
    if vitni.verify(stmt.jws, keys, witness_stmt.METHOD) != "ok" or not verifier.is_low_s(stmt.signature):
        raise _refuse("witness_bad_signature")


def _content(stmt, ctx):
    """Steps 5 to 6a: the statement says what the pin says, and its epoch has no known successor."""
    if stmt.org != ctx.org:
        raise _refuse("witness_org_mismatch")
    if stmt.epoch != ctx.genesis:
        raise _refuse("witness_epoch_mismatch")
    if stmt.next == "yes":
        raise _refuse("witness_superseded")


def _freshness(stmt, ctx):
    """Steps 7 and 8: not from the future beyond the skew, not older than the policy's tip age. Exactly
    on either bound is valid."""
    policy = ctx.epoch.policy
    now, ts = schema.seconds(ctx.now), schema.seconds(stmt.ts)
    if ts > now + int(policy["freshness"]["clock_skew_s"]):
        raise _refuse("witness_in_future")
    if now - ts > int(policy["witness"]["max_tip_age_s"]):
        raise _refuse("stale_witness")


def check(text, ctx, vitni):
    """Raise Refused unless the witness of the epoch in `ctx` is satisfied by the statement `text`."""
    if ctx.epoch.relay is None:
        if text is not None:
            raise _refuse("witness_unexpected")
        return
    if text is None:
        raise _refuse("witness_missing")
    stmt = witness_stmt.parse(text)
    if stmt.kid != ctx.epoch.relay[0]:
        raise _refuse("witness_key_mismatch")
    _signature(stmt, ctx.epoch, vitni)
    _content(stmt, ctx)
    _freshness(stmt, ctx)
    if stmt.tip not in ctx.positions:   # a tip older than the consumer's own is valid: any position counts
        raise _refuse("behind_witness")
