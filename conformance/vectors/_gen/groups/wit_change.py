"""Vectors wit/change-*: changing the witness is a genesis change (WT-08, GP-19, GP-12).

A change that sets, drops or rotates the relay witness needs the same quorum of clean keys at
H as any other change; alice's removed key never counts. Epoch 0 is ORG (mode `none`) or
WIT_ORG (mode `relay`). The rotated relay key is derived like the fixture keys from the label
`relay-fixture-rotated`; it is no device key.

wit/change-before-repin-old-mode: until the re-pin the old mode applies, so the input is the
`ok/approve` input (the change is not part of any pinned lineage yet).
wit/superseded-by-bag-successor is retired: a change is a lineage document, never a member
of the act bag, so a change in the bag cannot be built; `wit/next-no-latest-epoch-ok` is the case.
"""
from lib import epochs, inputs, keys, p256
from lib.changes import BC, E0, add, change_row, remove

OTHER = "relay-fixture-rotated"


def _relay_witness(fx, label=None):
    if label is None:
        return fx.wit_org["policy"]["witness"]
    x, y = p256.mul(keys.derive_scalar(label))
    xs, ys = keys.b64u(x.to_bytes(32, "big")), keys.b64u(y.to_bytes(32, "big"))
    return {"max_tip_age_s": "3600", "mode": "relay", "relay_kid": keys.thumbprint(xs, ys),
            "relay_pub_jwk": {"crv": "P-256", "kty": "EC", "x": xs, "y": ys}}


def _witness(witness):
    return lambda d: d["policy"].__setitem__("witness", witness)


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    relay, none = _relay_witness(fx), {"mode": "none"}

    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob", "carol"), new=(), edit=_witness(relay))
    sigs = epochs.sign_change(fx, doc)
    lineage = change_row(ctx, "wit/change-none-to-relay-quorum", e0, doc, sigs)

    # until the pin moves the old mode applies; once it is at the change a statement is needed
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    w.add("wit/change-before-repin-old-mode", "check-act", inputs.check_anchor(approve, "ok"),
          input=inputs.check_input(fx, approve))
    moved = fx.approve(tip=inputs.doc_id(doc))
    ctx.positive(moved, inputs.APPROVE, ["alice"])
    w.add("wit/change-after-repin-needs-statement", "check-act",
          inputs.check_anchor(moved, "witness_missing"),
          input=inputs.check_input(fx, moved, lineage=lineage, pin=inputs.probe_for(lineage)))

    doc = e0.change(0, carry=("alice",), edit=_witness(relay))
    change_row(ctx, "wit/change-none-to-relay-one-signer", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    e0 = E0(ctx, [add("bob2"), remove("alice"), add("bob3", BC), add("carol2", BC)])
    doc = e0.change(4, carry=("bob",), edit=_witness(relay))
    change_row(ctx, "wit/change-none-to-relay-revoked-signer", e0, doc,
               epochs.sign_change(fx, doc, also=["alice"]), error="genesis_change_unauthorized")

    # the witness is relay in epoch 0: a downgrade or a rotation is a change like any other
    e0 = E0(ctx, doc=fx.wit_org)
    doc = e0.change(0, carry=("alice",), edit=_witness(none))
    change_row(ctx, "wit/change-relay-to-none-one-signer", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")
    doc = e0.change(0, carry=("alice", "bob", "carol"), new=(),
                    edit=_witness(_relay_witness(fx, OTHER)))
    change_row(ctx, "wit/change-relay-key-rotation-ok", e0, doc, epochs.sign_change(fx, doc))
