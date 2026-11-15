"""Vectors rly/*: the relay a verdict names (VR-08, GP-02, ACT-09 field types).

The relay is read from the policy of the pinned state, never given: the act names `r.example`, which the policy of
ORG lists in `relays`. A row that needs another list is ORG with that list (its own org id, lineage and pin), and
a verdict made for that organization. `rly/relay-input-refused` shows an input that still carries `relay`
refused as `malformed_input`, so a stale consumer fails loudly.

`rly/relay-dropped-at-tip-mismatch` is the pair of `rck/relay-from-head-epoch`: the same lineage (a second document
drops `r.example`), but `check-act` judges the act at the tip, so the host its head's epoch lists is no longer
listed and the answer is `relay_mismatch` (VR-08). A checker that read the epoch of the head would answer `ok`.
"""
from lib import base, checkrows, epochs, forge, inputs
from lib.changes import E0, record_sigs


def _under(ctx, name, relays, host, reason):
    """The row `name`: an approve naming `host`, checked under ORG whose policy lists `relays`."""
    fx = ctx.fixtures
    doc = inputs.derive(fx.org, lambda d: d["policy"].__setitem__("relays", relays))
    lineage = inputs.original_lineage(fx, doc)
    record_sigs(ctx, lineage[0]["sigs"])
    org = inputs.doc_id(doc)
    jws = fx.approve(org=org, tip=org, relay=host)
    checkrows.row(ctx, name, jws, reason, signers=["alice"], lineage=lineage, org=org,
                  pin=inputs.probe_for(lineage))


def generate(ctx):
    fx = ctx.fixtures
    jws = fx.approve()
    checkrows.row(ctx, "rly/relay-input-refused", jws, None, error="malformed_input", relay=base.RELAY_HOST)
    other = forge.resign(fx, jws, forge.act_edit(lambda a: a.__setitem__("relay", "other.example")))
    checkrows.row(ctx, "rly/other-relay", other, "relay_mismatch", signers=["alice"])
    both = ["r.example", "s.example"]
    _under(ctx, "rly/two-names-old-ok", both, "r.example", "ok")
    _under(ctx, "rly/two-names-new-ok", both, "s.example", "ok")
    _under(ctx, "rly/empty-relays-mismatch", [], "r.example", "relay_mismatch")
    upper = forge.resign(fx, jws, forge.act_edit(lambda a: a.__setitem__("relay", "R.example")))
    checkrows.row(ctx, "rly/uppercase-relay-schema", upper, "schema")  # an act-object key: ACT-10

    # VR-08: `check-act` reads the policy of the tip's epoch; `recheck-act` that of the head (rck/relay-from-head-epoch)
    first = E0(ctx)
    renamed = first.change(0, carry=("alice", "bob", "carol"), new=(),
                           edit=lambda d: d["policy"].__setitem__("relays", ["s.example"]))
    sigs = epochs.sign_change(fx, renamed)
    record_sigs(ctx, sigs)
    lineage = epochs.lineage_with(first.lineage, renamed, sigs)
    checkrows.row(ctx, "rly/relay-dropped-at-tip-mismatch", jws, "relay_mismatch", signers=["alice"],
                  lineage=lineage, pin=inputs.probe_for(lineage))
