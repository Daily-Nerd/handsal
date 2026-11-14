"""Vectors rck/*: `recheck-act`, the time-free half of `check-act` for an act a consumer stored (VR-17).

The input is the `check-act` input without `now`, `synced_at`, `seen` and `tip_statement`; the answer is
`{class, not_proven, reason, receipt_id, rechecked}`. The state judged is the state at the act's own head, so
a key removed after that head still re-checks (section 14, L1) and a key added after it does not.

`rck/key-added-after-head-check-act-ok` is the one `check-act` row: the same act and bag as
`rck/key-not-active-at-head`, valid at the tip, which shows that the head and not the bag decides the recheck.
The four `*-input-malformed` rows put back one key that names a moment: the command refuses it.
"""
from lib import base, chain, checkrows, epochs, forge, inputs
from lib.changes import E0, add, record_sigs
from lib.forks import AB, child

ALL = ("alice", "bob", "carol")
BC = ("bob", "carol")
DEVICES = ("alice2", "bob2", "alice3", "bob3")


def _set_act(key, value):
    return lambda p: p["ext"]["dev.handsal/act"].__setitem__(key, value)


def generate(ctx):
    fx = ctx.fixtures
    row = checkrows.recheck_row

    ok = fx.approve()
    row(ctx, "rck/ok", ok, "ok", signers=["alice"])

    # ten days old: `check-act` at the fixture time says `expired`, the recheck reads no clock
    old = fx.approve(ts=base.shift(base.NOW, -864000))
    row(ctx, "rck/ok-expired-act", old, "ok", signers=["alice"])

    promote = fx.record_promote()
    row(ctx, "rck/ok-record-promote", promote, "ok", signers=["alice"], method=inputs.RECORD_PROMOTE)

    # two valid children of the root: `check-act` says `fork`; the state at the head, the root, is unchanged
    forked = chain.Chain(fx, ctx=ctx)
    child(forked, "alice2", AB, None)
    child(forked, "alice3", ("alice", "carol"), None)
    row(ctx, "rck/ok-fork-after-head", ok, "ok", acts=forked.acts)

    # L1 and VR-12: alice's key is removed after the third add; an act naming that add as its head still
    # re-checks, whenever it was signed
    removal = chain.Chain(fx, ctx=ctx)
    built = [removal.device_add(name, AB) for name in DEVICES]
    removal.device_remove("alice", BC)
    named = fx.approve(tip=built[2].id)
    row(ctx, "rck/removed-key-names-old-head-accepted", named, "ok", signers=["alice"], acts=removal.acts)

    # a head is a position in its own epoch, and the lineage proves which: the answer survives a change
    first = E0(ctx)
    doc = first.change(0, carry=("alice", "bob"), new=("grace",))
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    lineage = epochs.lineage_with(first.lineage, doc, sigs)
    row(ctx, "rck/ok-act-of-earlier-epoch", ok, "ok", signers=["alice"], lineage=lineage,
        pin=inputs.probe_for(lineage))
    beside = E0(ctx, [add("alice2")])
    doc = beside.change(0, carry=("alice", "bob"), new=("grace",))
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    lineage = epochs.lineage_with(beside.lineage, doc, sigs)
    row(ctx, "rck/head-past-change-stale-view", fx.approve(signer="alice2", tip=beside.ids[1]), "stale_view",
        cls=None, lineage=lineage, pin=inputs.probe_for(lineage), acts=beside.c.acts)

    tampered = forge.tamper(ok, _set_act("request_id", "req-00000002"))
    row(ctx, "rck/bad-signature", tampered, "bad_signature", bad=(["alice"], "bad_signature"))

    # alice2 exists at the tip and not at the root, the head the act names
    added = chain.Chain(fx, ctx=ctx)
    added.device_add("alice2", AB)
    late = fx.approve(signer="alice2")
    row(ctx, "rck/key-not-active-at-head", late, "unknown_key", cls=None, bad=(list(ALL), "unknown_key"),
        acts=added.acts)
    checkrows.row(ctx, "rck/key-added-after-head-check-act-ok", late, "ok", signers=["alice2"],
                  cls="apple-se-bio", acts=added.acts)

    row(ctx, "rck/inputs-mismatch", ok, "inputs_mismatch", request_b64=fx.request_b64(b"another request"))

    primary = fx.device_add("alice3", AB).acts[0]
    row(ctx, "rck/chain-method-refused", primary, "chain_method", cls=None)

    row(ctx, "rck/head-unknown", fx.approve(tip=base.hashstr(b"junk head")), "stale_view", cls=None)

    for name, key, value in (("rck/now-input-malformed", "now", base.NOW),
                             ("rck/synced-at-input-malformed", "synced_at", base.NOW),
                             ("rck/seen-input-malformed", "seen", []),
                             ("rck/tip-statement-input-malformed", "tip_statement", None)):
        row(ctx, name, ok, None, error="malformed_input", **{key: value})
