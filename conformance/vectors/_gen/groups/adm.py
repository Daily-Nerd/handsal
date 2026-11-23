"""Vectors adm/*: `admit`, may one item enter the chain store of an organization (CF-11, RS5 to RS9).

The input is `{acts, docs, item, org}`: the store (the base fixture's original document with its receipts, and
the acts the row names) and one item, `{act, sigs}` or `{doc, sigs}`. The anchor is `{reason, store}`: `store` is
the item with only the signatures to keep when the answer is `ok`: one per kid, `sigs` sorted. An item whose
`sigs` name one kid twice is `kid_repeated` (CF-11): choosing between a kid's texts means verifying them all, so the
repeat is refused before any verification and the cost of an item is bounded by the keys of the state. Both are stated here from the spec (CF-06); no checker is asked.

A second signature of one payload by one key (another R, S low, the same receipt id) is made by `forge.twin`.

The rows of the resolve world (CF-11 S16 to S27) share one world: a fork at the root with two children, a resolve R1
(bob signs, carol endorses) that chooses the first, and a resolve S (alice signs, bob endorses) that chooses the
second and names R1 in an `overrides` entry together with `e_alice`, the endorsement that gives R1 its second person
for that entry. The two rows about a store the last two releases wrote (`adm/legacy-*`) are built under the profile
of the previous edition, the one such a store names, so the strings are ones those releases could have admitted.
"""
from types import SimpleNamespace

from lib import base, chain, dropscenes, epochs, forge, inputs, result
from lib.changes import E0, record_sigs
from lib.forks import AB, AC, BC

ENDORSE = chain.ENDORSE
DEVICE_ADD = "local:handsal.device.add"


def _group(built):
    """The item of the act group of `built`: its primary and every other act it holds."""
    return {"act": built.acts[0], "sigs": list(built.acts[1:])}


def _kept(item, sigs=None):
    """The `store` of an `ok` row: the item's act or document with `sigs` (default: all of them), sorted."""
    key = "doc" if "doc" in item else "act"
    return {key: item[key], "sigs": sorted(item["sigs"] if sigs is None else sigs)}


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    lineage = fx.lineage()

    def row(name, item, reason, *, acts=(), docs=lineage, store=None, org=None):
        anchor = result.line({"reason": reason, "store": store})
        w.add(name, "admit", anchor, input={"acts": list(acts), "docs": docs, "item": item, "org": org or fx.org_id})

    def fresh(**kw):
        return chain.Chain(fx, ctx=ctx, **kw)

    # ---- the documents
    fresh()   # the receipts of ORG go to the vitni cross-check
    original = {"doc": fx.org, "sigs": lineage[0]["sigs"]}
    row("adm/ok-original", original, "ok", docs=[], store=_kept(original))
    row("adm/already-stored-doc", original, "already_stored")

    e0 = E0(ctx)
    doc = e0.change(0, carry=("alice", "bob"), new=("grace",))
    sigs = epochs.sign_change(fx, doc)
    record_sigs(ctx, sigs)
    change = {"doc": doc, "sigs": sigs}
    row("adm/ok-change-doc", change, "ok", store=_kept(change))

    bob_receipt_twin = forge.twin(fx, fx.genesis_sign("bob", doc), "bob")   # a second receipt of bob: another R, S low
    record_sigs(ctx, [bob_receipt_twin])
    row("adm/kid-repeated-receipt", {"doc": doc, "sigs": sigs + [bob_receipt_twin]}, "kid_repeated")

    weak = e0.change(0, carry=("alice",), new=("frank", "grace"))   # one previous role holder signs
    weak_sigs = epochs.sign_change(fx, weak)
    record_sigs(ctx, weak_sigs)
    row("adm/change-unauthorized", {"doc": weak, "sigs": weak_sigs}, "genesis_change_unauthorized")

    later = epochs.make_change(fx, doc, inputs.doc_id(doc), carry=("alice", "bob"), new=("frank",))
    row("adm/parent-unknown-doc", {"doc": later, "sigs": epochs.sign_change(fx, later)}, "parent_unknown")

    wit = fresh(wit=True)   # another organization: its original, and a primary of its own
    foreign = wit.device_add("alice2", AB)
    row("adm/original-wrong-org", {"doc": fx.wit_org, "sigs": fx.lineage(wit=True)[0]["sigs"]},
        "lineage_broken", docs=[])
    row("adm/other-org-act", _group(foreign), "org_mismatch")
    held = fresh()   # the same act of another organization, hanging at a node of ORG's store (FO-06, GP-04)
    step = held.device_add("alice2", AB)
    anchored = fx.device_add("bob2", AB, parent=step, org=fx.wit_org_id)
    row("adm/other-org-act-at-our-node", _group(anchored), "org_mismatch", acts=step.acts)

    # ---- the act groups
    c = fresh()
    built = c.device_add("alice2", AB)   # alice signs, bob endorses, alice2 proves possession
    group = _group(built)
    _bob, _pop = built.acts[1], built.acts[2]
    row("adm/ok-device-add-group", group, "ok", store=_kept(group))

    stranger = fx.device_add("alice2", ("alice", "dave")).acts[1]   # an endorsement by a kid no state holds
    ctx.positive(stranger, ENDORSE, ["dave"])
    junk = dict(group, sigs=group["sigs"] + ["not a jws", stranger])
    row("adm/drops-junk-sig", junk, "ok", store=_kept(group))

    bob_twin = forge.twin(fx, _bob, "bob")
    ctx.positive(bob_twin, ENDORSE, ["bob"])
    two_bobs = dict(group, sigs=[_bob, bob_twin, _pop])
    row("adm/kid-repeated-endorsement", two_bobs, "kid_repeated")

    pop_twin = forge.twin(fx, _pop, "alice2")
    ctx.positive(pop_twin, ENDORSE, ["alice2"])
    two_pops = dict(group, sigs=[_bob, _pop, pop_twin])
    row("adm/kid-repeated-pop", two_pops, "kid_repeated")

    # a fork at the root, and a resolve that chooses the applied branch
    f = fresh()
    keep = f.device_add("alice2", AB)
    lose = f.device_add("alice3", AC, parent=None, ok=False, valid=True)
    resolve = f.resolve(AB, candidates=[keep.id, lose.id], choose=keep.id, heads=[lose.id], parent=None)
    row("adm/ok-resolve", _group(resolve), "ok", acts=keep.acts + lose.acts, store=_kept(_group(resolve)))

    # a valid act whose parent is the old root while the store already has children below it: it makes a fork
    o = fresh()
    first = o.device_add("alice2", AB)
    second = o.device_add("bob2", AB)
    side = o.device_remove("carol", AB, parent=None, ok=False, valid=True)
    row("adm/ok-valid-child-at-old-parent", _group(side), "ok", acts=first.acts + second.acts,
        store=_kept(_group(side)))

    row("adm/already-stored-act", {"act": built.acts[0], "sigs": []}, "already_stored", acts=built.acts)
    primary_twin = forge.twin(fx, built.acts[0], "alice")
    ctx.positive(primary_twin, DEVICE_ADD, ["alice"])
    row("adm/already-stored-low-s-twin", {"act": primary_twin, "sigs": group["sigs"]}, "already_stored",
        acts=built.acts)

    high = forge.resign(fx, built.acts[0], high_s=True)   # vitni accepts S above n/2; the profile does not (VR-04)
    ctx.negative(high, DEVICE_ADD, ["alice"], "ok")
    row("adm/high-s", {"act": high, "sigs": group["sigs"]}, "high_s")

    p = fresh()
    p1 = p.device_add("alice2", AB)
    p2 = p.device_add("bob2", AB)   # its parent is p1, which the store does not hold
    row("adm/parent-unknown-act", _group(p2), "parent_unknown")

    # relay design 5.1: one touch, no quorum; the new key's possession proof is all the group holds
    one = fresh().device_add("alice2", ("alice",), ok=False, short=True)
    row("adm/pending-device-add-not-valid", {"act": one.acts[0], "sigs": one.acts[1:]}, "act_not_valid")

    row("adm/lone-endorsement-not-chain", {"act": _bob, "sigs": []}, "not_chain_act")
    approve = fx.approve()
    ctx.positive(approve, inputs.APPROVE, ["alice"])
    row("adm/verdict-not-chain", {"act": approve, "sigs": []}, "not_chain_act")
    statement = fx.tip_statement()
    ctx.positive_statement(statement)
    row("adm/statement-method-unknown", {"act": statement, "sigs": []}, "method_unknown")

    # a store whose second document lists its members out of order
    bad = epochs.make_change(fx, fx.org, fx.org_id, carry=AB, new=("grace",),
                             edit=lambda d: d["members"].reverse())
    docs = lineage + [{"doc": bad, "sigs": epochs.sign_change(fx, bad)}]
    row("adm/store-doc-invalid", group, "doc_not_sorted", docs=docs)

    # ---- Phase 14: a closed epoch and a compacted store (CF-11, CF-14, SD6)
    closed = dropscenes.closed_epoch(ctx)   # CHG-VALID at H = 2, epoch 0 holding positions 3 and 4 above it
    e0, whole, compacted = closed.e0, closed.input(), closed.compacted()
    late = e0.c.device_add("carol2", BC, parent=e0.built[4], ok=False, valid=True)   # valid, below position 4
    row("adm/epoch-closed-act", _group(late), "epoch_closed", acts=whole["acts"], docs=whole["docs"])

    def second_change(position, name):
        doc = e0.change(position, carry=("alice", "bob"), new=(name,))
        sigs = epochs.sign_change(fx, doc)
        record_sigs(ctx, sigs)
        return {"doc": doc, "sigs": sigs}
    retained = second_change(1, "frank")   # H on the path of the stored change, so its act is still in the store
    row("adm/ok-change-at-retained-head", retained, "ok", acts=compacted["acts"], docs=compacted["docs"],
        store=_kept(retained))
    dropped = second_change(3, "frank")   # H a node of epoch 0 that the compaction dropped
    row("adm/change-head-dropped", dropped, "genesis_head_unknown", acts=compacted["acts"], docs=compacted["docs"])

    # a store with only a copy of the act that has a bad signature does not hold the act (FO-21)
    g = fresh()
    valid = g.device_add("alice2", AB)
    row("adm/garbage-twin-not-stored", _group(valid), "ok", acts=[forge.garbage_twin(valid.acts[0])],
        store=_kept(_group(valid)))

    # ---- the resolve world (CF-11 S16 to S27)
    def world(fx_):
        """The children, R1 with the texts the rows need, and a way to build a resolve at the root that names R1."""
        c = chain.Chain(fx_, ctx=ctx)
        c1 = c.device_add("alice2", AB)
        c2 = c.device_add("alice3", AC, parent=None, ok=False, valid=True)
        fork = {"candidates": [c1.id, c2.id], "heads": [c1.id], "parent": None}
        r1 = c.resolve(("bob", "carol", "alice"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
        r1_bob = c.resolve(("bob", "carol", "bob"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id],
                           parent=None)   # the same primary: bob endorses what bob signed

        def second(named, signers=AB, **hooks):
            """A resolve at the root that chooses the second child and names R1 with the endorsements `named`."""
            entry = {"endorsements": sorted(inputs.receipt_id(t) for t in named), "resolve": r1.id}
            return c.resolve(signers, candidates=fork["candidates"], choose=c2.id, heads=fork["heads"],
                             parent=None, overrides=[entry], **hooks)

        def later(text, seconds):
            """Another valid text of one endorsement: the payload moved by `seconds`, so another receipt id."""
            twin = forge.resign(fx_, text, lambda p: p.__setitem__("ts", base.shift(p["ts"], seconds)))
            ctx.positive(twin, ENDORSE, ["alice"])
            return twin
        return SimpleNamespace(
            c=c, c1=c1, c2=c2, r1=r1, second=second, later=later, e_alice=r1.acts[2], e_bob=r1_bob.acts[2],
            children=c1.acts + c2.acts, stored_r1=c1.acts + c2.acts + r1.acts[:2], r1_texts=r1.acts[:2])

    def offer(step, *extra):
        """The item of the act group of `step`: its primary and its own endorsements, then `extra` texts."""
        return {"act": step.acts[0], "sigs": list(step.acts[1:]) + list(extra)}

    def kept(step, *extra):
        return {"act": step.acts[0], "sigs": sorted(list(step.acts[1:]) + list(extra))}

    now = world(fx)
    s = now.second([now.e_alice])
    row("adm/evidence-resolve-absent-parent-unknown", offer(s, now.e_alice), "parent_unknown", acts=now.children)
    names_c1 = now.c.resolve(AB, candidates=[now.c1.id, now.c2.id], choose=now.c2.id, heads=[now.c1.id], parent=None,
                             overrides=[{"endorsements": [inputs.receipt_id(now.e_alice)], "resolve": now.c1.id}])
    row("adm/evidence-names-a-primary-act-not-valid", offer(names_c1, now.e_alice), "act_not_valid",
        acts=now.stored_r1)
    row("adm/evidence-missing", offer(s), "evidence_missing", acts=now.stored_r1)
    row("adm/evidence-missing-though-stored", offer(s), "evidence_missing", acts=now.stored_r1 + [now.e_alice])
    twin = forge.twin(fx, now.e_alice, "alice")
    ctx.positive(twin, ENDORSE, ["alice"])
    row("adm/evidence-twin-kid-repeated", offer(s, now.e_alice, twin), "kid_repeated", acts=now.stored_r1)
    weak = now.second([now.e_bob])   # bob signed R1, so bob's own endorsement never gives it a second person
    row("adm/evidence-s8-shape-act-not-valid", offer(weak, now.e_bob), "act_not_valid", acts=now.stored_r1)

    row("adm/evidence-ok-named-text-kept", offer(s, now.e_alice), "ok", acts=now.stored_r1,
        store=kept(s, now.e_alice))
    second_text = now.later(now.e_alice, 1)
    both = now.second([now.e_alice, second_text])
    row("adm/evidence-distinct-ids-one-kid-ok", offer(both, now.e_alice, second_text), "ok", acts=now.stored_r1,
        store=kept(both, now.e_alice, second_text))
    unnamed = [now.later(now.e_alice, n) for n in (2, 3, 4)]
    row("adm/evidence-unnamed-text-not-stored", offer(s, now.e_alice, *unnamed), "ok", acts=now.stored_r1,
        store=kept(s, now.e_alice))

    # a store the last two releases wrote: S admitted bare, its evidence in no store (CF-11, stores before the closure)
    fx1 = base.Fixtures(base.previous_profile("fixture"))
    old = world(fx1)
    s_old = old.second([old.e_alice])
    legacy = old.stored_r1 + s_old.acts
    row("adm/legacy-resolve-reoffered-already-stored", offer(s_old), "already_stored", acts=legacy,
        docs=fx1.lineage(), org=fx1.org_id)
    s_new = old.second([old.e_alice], ts=base.shift(base.NOW, -3601))   # a new resolve: another payload, the same entry
    row("adm/legacy-new-resolve-carries-evidence-ok", offer(s_new, old.e_alice), "ok", acts=legacy,
        docs=fx1.lineage(), org=fx1.org_id, store=kept(s_new, old.e_alice))

    # CF-11 S27: the store holds the valid copy of a pending act, the item a bad copy and the completing texts
    pending = fresh().device_add("alice2", AB)
    row("adm/ok-stored-twin-is-the-kept-copy",
        {"act": forge.garbage_twin(pending.acts[0]), "sigs": list(pending.acts[1:])}, "ok", acts=[pending.acts[0]],
        store={"act": pending.acts[0], "sigs": sorted(pending.acts[1:])})
