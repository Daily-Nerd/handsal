"""Vectors chg/*, part 2: carried devices, deferred genesis-change rows, `genesis-check` (GP-20, GP-07, CF-03).

A carried device is byte-identical to its entry in S_H and active there, and never one removed
before H (GP-20, step 9 of GP-15 after authority, step 8). The change documents of this
module are CHG-NEW or CHG-VALID built by `lib/epochs.py`.

Not written: `chg/carry-class-change-refused` (registry v1 has one active biometric-only class,
so no second class reaches step 9 for a role holder) and `chg/unaccepted-signer-not-counted`
(a catalog follow-up: an unaccepted device has no authority, so the row has no only-defect form).

The rows of other groups that need a change are written here: gen/order-revoked-before-changed,
gen/order-unauthorized-before-carry, fld/epochs-in-one-bag, add/kid-removed-in-earlier-epoch,
mem/id-reused-across-epochs, quo/two-lost-persons-unreachable (the change half), and
cli/genesis-check-* (`genesis-check` returns the first failing link, `pin` null).
"""
from lib import chain, epochs, inputs, result
from lib.changes import AB, BC, AC, E0, add, change_row, fold_row, record_sigs, remove


def _entry_of(fx, name):
    return fx.device_entry(name)


def _with_bob2_revoked(fx, doc):
    """Add member bob with the removed bob2 device (a carried entry that is revoked)."""
    doc["members"] = sorted(doc["members"] + [{"id": "bob", "role": "maintainer"}],
                            key=lambda m: m["id"])
    doc["devices"] = sorted(doc["devices"] + [_entry_of(fx, "bob2")], key=lambda d: d["kid"])


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    e0 = E0(ctx, [add("bob2")])

    def relabel(d):
        for entry in d["devices"]:
            if entry["kid"] == fx.key("bob2").kid:
                entry["label"] = "renamed device"
    doc = e0.change(1, carry=("alice", "bob"), new=("grace",), edit=relabel)
    change_row(ctx, "chg/carry-entry-changed", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_device_changed")

    e0 = E0(ctx, [add("bob2"), remove("bob2", AC)])
    revoked = lambda d: _with_bob2_revoked(fx, d)
    doc = e0.change(2, carry=("alice", "carol"), new=("grace",), edit=revoked)
    change_row(ctx, "chg/carry-removed-kid-returns", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_device_revoked")

    def revoked_and_relabelled(d):
        _with_bob2_revoked(fx, d)
        for entry in d["devices"]:
            if entry["kid"] == fx.key("alice").kid:
                entry["label"] = "renamed device"
    doc = e0.change(2, carry=("alice", "carol"), new=("grace",), edit=revoked_and_relabelled)
    change_row(ctx, "gen/order-revoked-before-changed", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_device_revoked")
    doc = e0.change(2, carry=("alice",), new=("frank", "grace"), edit=revoked)
    change_row(ctx, "gen/order-unauthorized-before-carry", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    # alice's kid listed under bob: the entry differs from S_H, though the kid's own signature
    # (possession, performer bob) passes; bob and carol give the authority. Grace is a third
    # maintainer: with bob and carol alone the document is policy_unreachable (GP-02, step 3).
    e0 = E0(ctx)

    def under_bob(d):
        d["devices"] = sorted(d["devices"] + [dict(_entry_of(fx, "alice"), person="bob")],
                              key=lambda x: x["kid"])
    doc = e0.change(0, carry=("bob", "carol"), new=("grace",), edit=under_bob)
    # vitni refuses alice's kid under performer bob (a performer is the key's own person), so that
    # signature is not a positive act of the cross-check
    change_row(ctx, "chg/carried-kid-other-person-device-changed", e0, doc,
               epochs.sign_change(fx, doc, skip=["alice"],
                                  also=[("alice", {"performer": "bob"})]),
               error="genesis_device_changed",
               skip={fx.genesis_sign("alice", doc, performer="bob")})

    # bob2 is removed in epoch 0 before the first change; the epoch-2 document lists it again
    e0 = E0(ctx, [add("bob2"), remove("bob2", AC)])
    first = e0.change(2, carry=("alice", "carol"), new=("grace",))
    first_sigs = epochs.sign_change(fx, first)
    second = epochs.make_change(fx, first, inputs.doc_id(first), carry=("alice", "carol"),
                                new=("grace",), edit=revoked)
    lineage = epochs.lineage_with(epochs.lineage_with(e0.lineage, first, first_sigs), second,
                                  epochs.sign_change(fx, second))
    fold_row(ctx, "chg/carry-kid-removed-two-epochs-ago", lineage, e0.c.acts,
             error="genesis_device_revoked")

    # a class the epoch-0 policy does not list is a device that is not accepted; the change
    # lists it, so the carried device is accepted in the new epoch (dave holds no role)
    e0 = E0(ctx, [lambda c: c.member_add("dave", AB, role="member"),
                  lambda c: c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")])

    def list_pin(d):
        d["policy"]["classes"] = sorted(
            d["policy"]["classes"] + [{"class": "fixture-pin", "user_verification": "biometric_or_pin"}],
            key=lambda x: x["class"])
        for member in d["members"]:
            if member["id"] == "dave":
                member["role"] = "member"
    doc = e0.change(2, carry=("alice", "bob", "carol", "dave"), new=(), edit=list_pin)
    change_row(ctx, "chg/carry-newly-accepted-class-ok", e0, doc, epochs.sign_change(fx, doc))

    # bob2 is removed after H, so the change still carries it, active
    e1 = E0(ctx, [add("bob2"), remove("bob2", AC)])
    doc = e1.change(1, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/carry-revoked-after-head", e1, doc, epochs.sign_change(fx, doc))

    # epoch 1 on top of epoch 0: acts of both epochs share one bag
    e0 = E0(ctx, [add("alice2")])
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    lineage = epochs.lineage_with(e0.lineage, doc, epochs.sign_change(fx, doc))
    record_sigs(ctx, lineage[1]["sigs"])
    c1 = chain.Chain(fx, doc=doc, lineage=lineage, ctx=ctx)
    c1.device_add("alice3", AB)
    w.add("fld/epochs-in-one-bag", "fold", c1.expect(),
          input=inputs.fold_input(lineage, acts=e0.c.acts + c1.acts))

    # a kid removed in epoch 0 on the path to H cannot be added again in epoch 1 (FO-07)
    e0 = E0(ctx, [add("bob2"), remove("bob2", AC)])
    doc = e0.change(2, carry=("alice", "bob"), new=("grace",))
    lineage = epochs.lineage_with(e0.lineage, doc, epochs.sign_change(fx, doc))
    c1 = chain.Chain(fx, doc=doc, lineage=lineage, ctx=ctx)
    c1.device_add("bob2", AB, ok=False)
    w.add("add/kid-removed-in-earlier-epoch", "fold", c1.expect(),
          input=inputs.fold_input(lineage, acts=e0.c.acts + c1.acts))

    # a member id of epoch 0 that the change dropped cannot be added again in epoch 1
    e0 = E0(ctx, [lambda c: c.member_add("dave", AB, role="member")])
    doc = e0.change(1, carry=("alice", "bob", "carol"), new=())
    lineage = epochs.lineage_with(e0.lineage, doc, epochs.sign_change(fx, doc))
    c1 = chain.Chain(fx, doc=doc, lineage=lineage, ctx=ctx)
    c1.member_add("dave2", AB, role="member", member="dave", ok=False)
    w.add("mem/id-reused-across-epochs", "fold", c1.expect(),
          input=inputs.fold_input(lineage, acts=e0.c.acts + c1.acts))

    # bob's and carol's only devices are removed: alice alone cannot authorize a change
    e0 = E0(ctx, [remove("carol", AB), remove("bob", AB)])
    e0.c.device_add("alice2", ("alice",), short=True, ok=False)
    doc = e0.change(2, carry=("alice",))
    change_row(ctx, "quo/two-lost-persons-unreachable", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    # genesis-check: the first failing link, or the pin line
    lineage = inputs.original_lineage(fx, fx.org)
    org = inputs.doc_id(fx.org)
    pin = inputs.pin_line(org, org, fx.profile).decode("ascii")
    record_sigs(ctx, lineage[0]["sigs"])
    w.add("cli/genesis-check-original-ok", "genesis-check",
          result.line({"pin": pin, "reason": "ok", "valid": True}),
          input={"acts": [], "lineage": lineage})

    e0 = E0(ctx)
    forged = e0.change(0, carry=("alice",))
    forged_sigs = epochs.sign_change(fx, forged)
    later = epochs.make_change(fx, forged, inputs.doc_id(forged), carry=("frank", "grace"),
                               new=("heidi",))
    later_sigs = epochs.sign_change(fx, later)
    three = epochs.lineage_with(epochs.lineage_with(e0.lineage, forged, forged_sigs), later,
                                later_sigs)
    for entry in three[1:]:
        record_sigs(ctx, entry["sigs"])
    w.add("cli/genesis-check-forged-middle-link", "genesis-check",
          result.line({"pin": None, "reason": "genesis_change_unauthorized", "valid": False}),
          input={"acts": [], "lineage": three})

    e0 = E0(ctx, [add("bob2"), remove("alice"), add("bob3", BC), add("carol2", BC)])
    doc = e0.change(4, carry=("bob",))
    sigs = epochs.sign_change(fx, doc, also=["alice"])
    record_sigs(ctx, sigs)
    w.add("cli/genesis-check-change-revoked-signer", "genesis-check",
          result.line({"pin": None, "reason": "genesis_change_unauthorized", "valid": False}),
          input={"acts": list(e0.c.acts), "lineage": epochs.lineage_with(e0.lineage, doc, sigs)})

    # CF-03: `genesis-check` reads the acts on the path to H and nothing after it
    e0 = E0(ctx, [add("alice2"), add("bob2"), add("alice3", AB)])
    doc = e0.change(3, carry=("alice", "bob", "carol"), new=())
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    lineage = epochs.lineage_with(e0.lineage, doc, sigs)
    gap = [jws for built in (e0.built[1], e0.built[3]) for jws in built.acts]
    w.add("cli/genesis-check-missing-head-acts-invalid", "genesis-check",
          result.line({"pin": None, "reason": "genesis_head_unknown", "valid": False}),
          input={"acts": gap, "lineage": lineage})

    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob", "carol"), new=())
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    lineage = epochs.lineage_with(e0.lineage, doc, sigs)
    pin = inputs.pin_line(org, inputs.doc_id(doc), fx.profile).decode("ascii")
    same = result.line({"pin": pin, "reason": "ok", "valid": True})
    # an epoch-0 removal of a change signer after H changes nothing: the same result and pin
    e0.c.device_remove("alice", BC)
    w.add("cli/genesis-check-extra-acts-same-result", "genesis-check", same,
          input={"acts": list(e0.c.acts), "lineage": lineage})

    # an approve whose head is epoch 0's root, checked by a verifier on epoch 1 (GP-09, VR-12)
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    lineage = epochs.lineage_with(e0.lineage, doc, epochs.sign_change(fx, doc))
    record_sigs(ctx, lineage[1]["sigs"])
    stale = fx.approve()  # head: the epoch-0 root, which is no position of epoch 1
    ctx.positive(stale, inputs.APPROVE, ["alice"])
    pin = inputs.probe_for(lineage)
    w.add("chg/old-epoch-head-stale", "check-act", inputs.check_anchor(stale, "stale_view"),
          input=inputs.check_input(fx, stale, lineage=lineage, pin=pin))
