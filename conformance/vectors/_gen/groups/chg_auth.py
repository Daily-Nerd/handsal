"""Vectors chg/*, part 1: who may change the genesis, and what a lineage must be (GP-07, GP-15, GP-19).

Epoch 0 is ORG built to the positions the row names; a change names its H, carries persons'
devices byte-identical from S_H (GP-20) and every listed device signs with the document's
head (possession, GP-15 step 6). An authority signer that is not listed signs with the head
too. CHG-NEW (carrying fewer than Q clean persons, plus new maintainers frank and grace) and
CHG-VALID follow catalog-part3 section 0. The expected output is the state of the last
document (a valid change) or the first failing code of GP-15.

Not written: the rows that need a class outside the registry's accepted ones or a state the
helpers do not build (`chg/carry-class-change-refused`, `chg/carry-kid-removed-two-epochs-ago`,
`chg/carry-newly-accepted-class-ok`, `chg/carried-kid-other-person-device-changed`,
`chg/device-unaccepted-class`, `chg/unaccepted-signer-not-counted`), the two that need the
render (`chg/large-snapshot-small-diff-ok`, `chg/render-too-large-diff`) and `chg/r11-branch-change-valid`.
"""
from groups.frk_stage import minted_person_bag
from lib import base, epochs, forge, inputs, state
from lib.changes import AB, BC, E0, add, change_row, fold_row, record_sigs, remove
from lib.forks import child

OTHER_HEAD = base.hashstr(b"another position")


def _five(ctx):
    return E0(ctx, [add("bob2"), add("alice2"), add("bob3"), add("alice3"), add("alice4")])


def _grow(fx, previous, names):
    """A change of `previous` at its own root that adds a device of alice for each of `names`."""
    for name in names:
        try:
            fx.key(name)
        except KeyError:
            fx.register_device(name, "chg-grow/%s/sign" % name, "chg-grow/%s/agree" % name)

    def edit(doc):
        doc["devices"] = sorted(doc["devices"] + [fx.device_entry(n) for n in names],
                                key=lambda d: d["kid"])
    return epochs.make_change(fx, previous, inputs.doc_id(previous),
                              carry=tuple(m["id"] for m in previous["members"]), new=(),
                              edit=edit)


def _snapshot_rows(ctx):
    """RN-10: a change shows a difference, so a 40-device document is still changeable."""
    fx = ctx.fixtures
    lineage, doc = fx.lineage(), fx.org
    counter = 10
    for added in (12, 12, 12, 1, 1):
        names = ["alice%d" % n for n in range(counter, counter + added)]
        counter += added
        doc = _grow(fx, doc, names)
        lineage = epochs.lineage_with(lineage, doc, epochs.sign_change(fx, doc))
    fold_row(ctx, "chg/large-snapshot-small-diff-ok", lineage, [])


def generate(ctx):
    fx = ctx.fixtures
    _snapshot_rows(ctx)

    # ---- valid changes -------------------------------------------------------------
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    sigs = epochs.sign_change(fx, doc)
    change_row(ctx, "chg/ok-2-of-3", e0, doc, sigs)
    junk = forge.tamper(sigs[0], lambda p: p.__setitem__("status", "FAILED"))
    change_row(ctx, "chg/junk-sig-ignored", e0, doc, sigs + [junk], skip={junk})

    # alice removed after H: her key counts at H (GP-19)
    e0 = E0(ctx, [add("bob2"), add("bob3"), remove("alice")])
    doc = e0.change(2, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/signer-revoked-after-head", e0, doc, epochs.sign_change(fx, doc))

    e0 = E0(ctx, [add("bob2"), add("alice2"), add("bob3")])
    e0.c.device_add("alice4", AB, ok=False, valid=True, parent=e0.built[3])
    e0.c.device_add("alice3", AB)
    e0.c.device_remove("alice", BC)
    doc = e0.change(3, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/backdate-through-fork-residual", e0, doc, epochs.sign_change(fx, doc))

    e0 = _five(ctx)
    doc = e0.change(2, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/head-older-clean-ok", e0, doc, epochs.sign_change(fx, doc))

    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice",))
    change_row(ctx, "chg/unlisted-clean-signer-counts", e0, doc,
               epochs.sign_change(fx, doc, also=["carol"]))
    change_row(ctx, "chg/unlisted-signer-wrong-performer-ignored", e0, doc,
               epochs.sign_change(fx, doc, also=[("carol", {"performer": "alice"})]),
               error="genesis_change_unauthorized",
               skip={fx.genesis_sign("carol", doc, performer="alice")})

    def rotate(d):
        d["members"] = [{"id": p, "role": "maintainer"} for p in ("alice", "bob", "carol")]
        d["devices"] = sorted((fx.device_entry(n) for n in ("alice3", "bob3", "carol2")),
                              key=lambda x: x["kid"])
    doc = e0.change(0, carry=(), new=(), edit=rotate)
    change_row(ctx, "chg/full-key-rotation-ok", e0, doc,
               epochs.sign_change(fx, doc, also=["alice", "bob"]))

    # ---- who counts ------------------------------------------------------------------
    doc = e0.change(0, carry=("alice",))
    change_row(ctx, "chg/quorum-unmet-1-of-3", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    e0 = E0(ctx, [add("alice2")])
    doc = e0.change(1, carry=("alice",))
    change_row(ctx, "chg/two-devices-one-person", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    # alice removed at 2 by bob and carol, H = 4: her removed key signs and does not count
    e0 = E0(ctx, [add("bob2"), remove("alice"), add("bob3", BC), add("carol2", BC)])
    doc = e0.change(4, carry=("bob",))
    change_row(ctx, "chg/signer-revoked-before-head", e0, doc,
               epochs.sign_change(fx, doc, also=["alice"]), error="genesis_change_unauthorized")
    e0 = E0(ctx, [remove("alice")])
    doc = e0.change(1, carry=("bob",))
    change_row(ctx, "chg/signer-listed-in-prev-doc-revoked-in-chain", e0, doc,
               epochs.sign_change(fx, doc, also=["alice"]), error="genesis_change_unauthorized")

    e0 = E0(ctx)
    doc = e0.change(0, carry=(), new=("frank", "grace", "heidi"))
    change_row(ctx, "chg/signer-not-in-prev", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    # carol also signs once under head 2: that signature is ignored, her possession one counts
    e0 = E0(ctx, [add("bob2"), add("alice2"), add("bob3"), add("alice3")])
    doc = e0.change(4, carry=("alice", "bob", "carol"), new=())
    change_row(ctx, "chg/two-heads-one-authorized", e0, doc,
               epochs.sign_change(fx, doc, also=[("carol", {"head": e0.ids[2]})]))

    e0 = _five(ctx)
    doc = e0.change(4, carry=("alice",))
    change_row(ctx, "chg/heads-differ", e0, doc,
               epochs.sign_change(fx, doc, also=[("bob", {"head": e0.ids[5]})]),
               error="genesis_change_unauthorized")

    org4 = epochs.org4(fx)
    e0 = E0(ctx, doc=org4)

    def lower(d):
        for rule in d["policy"]["rules"].values():
            rule["persons"] = "2"
    doc = e0.change(0, carry=("alice", "bob"), new=("frank",), edit=lower)
    change_row(ctx, "chg/policy-change-needs-old-quorum", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_change_unauthorized")

    # a change at H = the fork parent recovers a frozen bag (FO-27); the old epoch's acts and
    # resolves are never read again
    e0 = E0(ctx)
    child(e0.c, "alice2", AB, None, applied=True)
    child(e0.c, "bob2", BC, None)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "frk/genesis-change-recovers", e0, doc, epochs.sign_change(fx, doc))

    e0 = E0(ctx)
    c1 = child(e0.c, "alice2", AB, None, applied=True)
    c2 = child(e0.c, "bob2", BC, None)
    ids = sorted([c1.id, c2.id])
    e0.c.resolve(AB, candidates=ids, choose=c1.id, heads=[c2.id], parent=None)
    e0.c.resolve(BC, candidates=ids, choose=c2.id, heads=[c1.id], parent=None)
    doc = e0.change(0, carry=("alice", "carol"), new=("grace",))
    change_row(ctx, "frk/conflicting-resolves-genesis-exit", e0, doc, epochs.sign_change(fx, doc))

    # old pin: the lineage and the pin end at the previous document, so epoch 0 stands
    e0 = E0(ctx, [add("bob2")])
    ctx.writer.add("chg/old-pin-still-valid", "fold", e0.c.expect(),
                   input=inputs.fold_input(e0.lineage, acts=e0.c.acts))

    # RN-10: a change that adds 12 members with a device each renders over 72 lines
    members, devices = inputs.synthetic_members(12)
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob", "carol"), new=(), edit=lambda d: d.update(
        members=sorted(d["members"] + members, key=lambda m: m["id"]),
        devices=sorted(d["devices"] + devices, key=lambda x: x["kid"])))
    sigs = [fx.genesis_sign(n, doc) for n in ("alice", "bob", "carol")]
    change_row(ctx, "chg/render-too-large-diff", e0, doc, sigs, error="genesis_render_too_large")

    # GP-15 step 3: a listed device of a class the policy does not accept
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",), edit=lambda d: [
        e.update({"class": "fixture-pin"}) for e in d["devices"]
        if e["kid"] == fx.key("grace").kid])
    change_row(ctx, "chg/device-unaccepted-class", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_schema")

    # R11: a change at H = x2 on the minted branch, signed by K, frank and the new maintainer
    c, _p, _h4, _h6, _m, _x1, x2 = minted_person_bag(ctx)
    keep = {fx.key(n).kid for n in ("alice", "frank", "grace")}
    doc = epochs.make_change(fx, fx.org, x2.id, carry=("alice", "frank"), new=("grace",),
                             st=c.state_at(x2),
                             edit=lambda d: d.update(devices=[e for e in d["devices"]
                                                              if e["kid"] in keep]))
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    fold_row(ctx, "chg/r11-branch-change-valid", epochs.lineage_with(c.lineage, doc, sigs), c.acts)

    # ---- the head -------------------------------------------------------------------
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",), head=OTHER_HEAD)
    change_row(ctx, "chg/head-unknown", e0, doc, epochs.sign_change(fx, doc),
               error="genesis_head_unknown")

    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/carried-device-no-pop", e0, doc,
               epochs.sign_change(fx, doc, skip=["bob"]), error="genesis_unsigned")
    change_row(ctx, "chg/new-key-no-pop", e0, doc, epochs.sign_change(fx, doc, skip=["grace"]),
               error="genesis_unsigned")
    change_row(ctx, "chg/possession-sig-other-head-ignored", e0, doc,
               epochs.sign_change(fx, doc, skip=["grace"],
                                  also=[("grace", {"head": OTHER_HEAD})]),
               error="genesis_unsigned")

    # ---- branches (GP-19: H may lie on any branch; only the path to H is read) --------
    e0 = E0(ctx, [add("bob2"), add("alice2")])
    c1 = e0.c.device_add("alice3", AB)
    e0.c.device_add("bob3", AB, ok=False, valid=True, parent=e0.built[2])
    doc = epochs.make_change(fx, fx.org, c1.id, carry=("alice", "bob"), new=("grace",),
                             st=e0.c.history[3])
    change_row(ctx, "chg/old-epoch-fork-before-head-path-selects", e0, doc,
               epochs.sign_change(fx, doc))

    e0 = E0(ctx, [add("bob2")])
    c2 = e0.c.device_remove("alice", BC, ok=False, valid=True, parent=None)
    e0.c.resolve(BC, candidates=[e0.built[1].id, c2.id], choose=e0.built[1].id,
                 heads=[c2.id], parent=None)
    doc = e0.change(1, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/removal-in-losing-branch-no-effect", e0, doc,
               epochs.sign_change(fx, doc))

    e0 = E0(ctx)
    e0.c.device_remove("alice", BC, ok=False, valid=True, parent=None)
    e0.c.device_add("bob2", AB)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    change_row(ctx, "chg/signer-revoked-on-branch", e0, doc, epochs.sign_change(fx, doc))

    # H on a dropped branch; alice is removed on the branch that stayed
    e0 = E0(ctx)
    main = e0.c.device_add("bob2", AB)
    e0.c.device_remove("alice", BC)
    side = e0.c.device_add("alice2", AB, ok=False, valid=True, parent=None)
    e0.c.resolve(BC, candidates=[main.id, side.id], choose=main.id, heads=[side.id], parent=None)
    st_side = state.State(fx.org)
    st_side.add_device("alice", fx.device_entry("alice2"))
    doc = epochs.make_change(fx, fx.org, side.id, carry=("alice", "bob"), new=("grace",),
                             st=st_side)
    change_row(ctx, "chg/head-on-side-branch-clean-rule", e0, doc, epochs.sign_change(fx, doc))

    # carol removed at a node that is not on the path to H
    e0 = E0(ctx)
    e0.c.device_remove("carol", AB)
    y = e0.c.device_add("bob2", AB, ok=False, valid=True, parent=None)
    st_y = state.State(fx.org)
    st_y.add_device("bob", fx.device_entry("bob2"))
    doc = epochs.make_change(fx, fx.org, y.id, carry=("bob", "carol"), new=("grace",), st=st_y)
    change_row(ctx, "chg/sibling-branch-removal-no-effect", e0, doc, epochs.sign_change(fx, doc))

    # ---- later acts of the old epoch are never read ------------------------------------
    for name, extra in (
            ("chg/old-epoch-act-after-head-ignored", lambda c: c.device_add("bob2", AB)),
            ("chg/old-epoch-fork-after-head-ignored", lambda c: (
                c.device_add("alice2", AB, ok=False, valid=True, parent=None),
                c.device_add("bob2", AB, ok=False, valid=True, parent=None))),
            ("chg/old-epoch-retroactive-act-no-effect", lambda c: c.device_add(
                "X1", ("alice", "alice2"), short=True, ok=False, parent=None))):
        e0 = E0(ctx)
        doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
        extra(e0.c)
        change_row(ctx, name, e0, doc, epochs.sign_change(fx, doc))

    # ---- lineage shape (GP-07, GP-15 step 4) ---------------------------------------------
    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",), edit=lambda d: d.update(
        org=fx.wit_org_id))
    change_row(ctx, "chg/org-mismatch", e0, doc, epochs.sign_change(fx, doc),
               error="lineage_broken")
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",), edit=lambda d: d.update(
        prev=base.hashstr(b"not the previous document")))
    change_row(ctx, "chg/prev-hash-mismatch", e0, doc, epochs.sign_change(fx, doc),
               error="lineage_broken")
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    sigs = epochs.sign_change(fx, doc)
    headless = {k: v for k, v in doc.items() if k != "head"}
    change_row(ctx, "chg/document-head-missing-schema", e0, headless, sigs,
               error="genesis_schema")
    with_head = inputs.derive(fx.org, lambda d: d.__setitem__("head", fx.org_id))
    fold_row(ctx, "chg/original-with-head-schema", inputs.original_lineage(fx, with_head), [],
             error="genesis_schema")

    lineage = epochs.lineage_with(e0.lineage, doc, sigs)
    fold_row(ctx, "chg/lineage-last-not-pinned", lineage, [], error="genesis_pin_mismatch",
             pin=inputs.probe_for(lineage[:1]))

    first = e0.change(0, carry=("alice", "bob"), new=("grace",))
    first_sigs = epochs.sign_change(fx, first)
    second = epochs.make_change(fx, first, inputs.doc_id(first), carry=("alice", "bob"),
                                new=("grace",))
    second_sigs = epochs.sign_change(fx, second)
    base_lineage = e0.lineage
    fold_row(ctx, "chg/lineage-missing-doc", epochs.lineage_with(base_lineage, second, second_sigs),
             [], error="lineage_broken")
    odd = e0.change(0, carry=("alice", "bob"), new=("grace",),
                    edit=lambda d: d.update(profile=base.hashstr(b"unimplemented profile")))
    odd_sigs = epochs.sign_change(fx, odd)
    after = epochs.make_change(fx, odd, inputs.doc_id(odd), carry=("alice", "bob"), new=("grace",))
    fold_row(ctx, "chg/profile-unimplemented-in-middle",
             epochs.lineage_with(epochs.lineage_with(base_lineage, odd, odd_sigs), after,
                                 epochs.sign_change(fx, after)), [], error="profile_mismatch")
    fold_row(ctx, "chg/three-epochs",
             epochs.lineage_with(epochs.lineage_with(base_lineage, first, first_sigs), second,
                                 second_sigs), [])
