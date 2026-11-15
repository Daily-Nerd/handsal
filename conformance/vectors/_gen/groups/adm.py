"""Vectors adm/*: `admit`, may one item enter the chain store of an organization (CF-11, RS5 to RS9).

The input is `{acts, docs, item, org}`: the store (the base fixture's original document with its receipts, and
the acts the row names) and one item, `{act, sigs}` or `{doc, sigs}`. The anchor is `{reason, store}`: `store` is
the item with only the signatures to keep when the answer is `ok`: one per kid, `sigs` sorted. An item whose
`sigs` name one kid twice is `kid_repeated` (CF-11): choosing between a kid's texts means verifying them all, so the
repeat is refused before any verification and the cost of an item is bounded by the keys of the state. Both are stated here from the spec (CF-06); no checker is asked.

A second signature of one payload by one key (another R, S low, the same receipt id) is made by `_twin`: the
fixture signer is deterministic (RFC 6979), so a second R needs a nonce of its own.
"""
import hashlib

from lib import base, chain, epochs, es256, forge, inputs, p256, result
from lib.changes import E0, record_sigs
from lib.forks import AB, AC

ENDORSE = chain.ENDORSE
DEVICE_ADD = "local:handsal.device.add"


def _twin(fx, jws, name):
    """`jws` signed again by device `name` with another nonce: the same payload and receipt id, another R."""
    header, payload, _ = forge.parts(jws)
    signing = ("%s.%s" % (forge._b64u(header), forge._b64u(payload))).encode("ascii")
    digest = hashlib.sha256(signing).digest()
    key = fx.key(name)
    k = es256.rfc6979_k(key.d, hashlib.sha256(digest + b"/another-nonce").digest())
    r = p256.mul(k)[0] % es256.N
    s = pow(k, -1, es256.N) * (int.from_bytes(digest, "big") % es256.N + r * key.d) % es256.N
    if s > es256.HALF_N:
        s = es256.N - s
    return forge.join(header, payload, r.to_bytes(32, "big") + s.to_bytes(32, "big"))


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

    def row(name, item, reason, *, acts=(), docs=lineage, store=None):
        anchor = result.line({"reason": reason, "store": store})
        w.add(name, "admit", anchor, input={"acts": list(acts), "docs": docs, "item": item, "org": fx.org_id})

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

    bob_receipt_twin = _twin(fx, fx.genesis_sign("bob", doc), "bob")   # a second receipt of bob: another R, S low
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

    bob_twin = _twin(fx, _bob, "bob")
    ctx.positive(bob_twin, ENDORSE, ["bob"])
    two_bobs = dict(group, sigs=[_bob, bob_twin, _pop])
    row("adm/kid-repeated-endorsement", two_bobs, "kid_repeated")

    pop_twin = _twin(fx, _pop, "alice2")
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
    primary_twin = _twin(fx, built.acts[0], "alice")
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
