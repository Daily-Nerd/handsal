"""Vectors hed/*: the head a signer names (VR-19, CF-03, ACT-08, VR-12).

Every row is a conformance `head` input `{acts, lineage, next, now, org, pin, synced_at, tip_statement}` (the
`enrolled` input without `device_kid`) and its answer `{"head":{"id":T,"kind":"chain"},"reason":"ok"}` or
`{"head":null,"reason":R}`. The common world is ORG at the pinned epoch, `synced_at` = NOW, `next` `"no"`, mode
`none` and `tip_statement` null; a row changes the one thing its name says.

T is stated here from the bag the row builds (the last primary it applied, or the root), and the whole-set guard of
SH6 (`lib/checkact_model.py`) asks the generator's own model of `check-act` about every row before it is written:
a decision signed at T must pass steps 6 and 14, T must be the tip of the model's fold, and a refusal must be the
code the model gives. A row the model contradicts stops generation, so the equality of VR-19 cannot drift between
the rows and the spec.

Reused, not copied: the bag of `enr/fork` (two valid children of the root, one applied), the lifted fork of
`ord/fork-before-vitni` plus a `chain.resolve`, the two epochs of `fld/epochs-in-one-bag`, and the view numbers of
`frs/*` (VR-12). The witness rows sign the statement for their own tip: a statement for another tip would be
`behind_witness` (WT-05 step 9), a row of `wit/*`.
"""
from lib import base, chain, checkact_model, epochs, inputs
from lib.changes import E0, add, record_sigs
from lib.forks import AB, BC, child

NOW = base.NOW


def _three(ctx, *, wit=False):
    """A chain of three valid primaries of ORG (or WIT_ORG): the third is the tip."""
    c = chain.Chain(ctx.fixtures, wit=wit, ctx=ctx)
    built = [c.device_add(name, AB) for name in ("alice2", "bob2", "alice3")]
    return c, built[-1].id


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    def put(name, data, anchor):
        """The guard first, then the file: a row the model of `check-act` contradicts stops generation."""
        checkact_model.agree(fx, data, anchor)
        w.add(name, "head", anchor, input=data)

    def row(name, head, reason="ok", *, wit=False, **override):
        put(name, inputs.head_input(fx, wit=wit, **override), inputs.head_anchor(head, reason))

    def missing(name, key, acts):
        data = inputs.head_input(fx, acts=acts)
        del data[key]
        put(name, data, inputs.error_anchor("malformed_input"))

    c, tip = _three(ctx)
    acts = list(c.acts)
    stale, future = base.shift(NOW, -86401), base.shift(NOW, 301)

    # the ok rows (S1, S6): the tip, the root, the chosen branch, the last epoch
    row("hed/ok-tip", tip, acts=acts)
    row("hed/ok-root", fx.org_id)

    lifted = chain.Chain(fx, ctx=ctx)
    first = child(lifted, "alice2", AB, None, applied=True)
    side = child(lifted, "alice3", AB, None)
    lifted.resolve(BC, candidates=sorted((first.id, side.id)), choose=first.id, heads=[side.id], parent=None)
    row("hed/ok-after-resolve", first.id, acts=list(lifted.acts))

    e0 = E0(ctx, [add("alice2")])
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    lineage = epochs.lineage_with(e0.lineage, doc, epochs.sign_change(fx, doc))
    record_sigs(ctx, lineage[1]["sigs"])
    c1 = chain.Chain(fx, doc=doc, lineage=lineage, ctx=ctx)
    last = c1.device_add("alice3", AB)
    row("hed/ok-two-epochs", last.id, acts=e0.c.acts + c1.acts, lineage=lineage, pin=inputs.probe_for(lineage))

    # the fold and the epoch (S2): a fork has no head, and a successor makes it epoch_superseded
    forked = chain.Chain(fx, ctx=ctx)
    child(forked, "alice2", AB, None, applied=True)
    child(forked, "bob2", BC, None)
    row("hed/fork", None, "fork", acts=list(forked.acts))
    row("hed/epoch-superseded", None, "epoch_superseded", acts=acts, next="yes")
    row("hed/superseded-before-fork", None, "epoch_superseded", acts=list(forked.acts), next="yes")
    row("hed/superseded-before-stale-view", None, "epoch_superseded", acts=acts, next="yes", synced_at=stale)

    # the view (S3): one second over, more than the skew ahead, and the exact boundary as the control
    row("hed/stale-view", None, "stale_view", acts=acts, synced_at=stale)
    row("hed/view-in-future", None, "view_in_future", acts=acts, synced_at=future)
    row("hed/age-exactly-max-ok", tip, acts=acts, synced_at=base.shift(NOW, -86400))

    # the witness (S4): the statement of a relay organization names its own tip
    relay, relay_tip = _three(ctx, wit=True)
    row("hed/relay-witness-missing", None, "witness_missing", wit=True, acts=list(relay.acts))
    statement = fx.tip_statement(tip=relay_tip)
    ctx.positive_statement(statement)
    row("hed/relay-ok", relay_tip, wit=True, acts=list(relay.acts), tip_statement=statement)
    row("hed/mode-none-statement-supplied", None, "witness_unexpected", acts=acts,
        tip_statement=fx.tip_statement(tip=tip))

    # the pin (S5): each before any fold or view code, so the bag is the good one
    org = fx.org_id
    row("hed/pin-missing", None, "pin_missing", acts=acts,
        pin=inputs.probe(org, b"", owner_ok=False, reason="pin_missing"))
    row("hed/pin-org-mismatch", None, "pin_org_mismatch", acts=acts, pin=dict(fx.pin_ok(), org=fx.wit_org_id))
    row("hed/lineage-broken", None, "lineage_broken", acts=acts, lineage=[])

    # a key missing is an error line, as for check-act (S5)
    missing("hed/next-input-missing", "next", acts)
    missing("hed/org-input-missing", "org", acts)
