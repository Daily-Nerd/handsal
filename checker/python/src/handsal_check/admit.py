"""`admit` (CF-11): may one item enter the chain store of an organization.

The rule is "valid now", never "could matter later" (RS5): an act is admitted only together with the signatures
that make it valid against the state at its parent in the store, a document only as a valid lineage link with
its receipts. Nothing here is a rule of its own. The store is folded by the fold (`epoch.Lineage`, one
`extend` per document on its parent's fold), the act is judged by the fold's own `quorum.check_primary` and
`resolve.Resolves` over the store's tree, with the item and the texts that bear on it, and a signature is kept when `endorse` and `genesis_sigs` count it. What this module adds is the
order of the answers, the signatures to keep (one per kid, RS6) and the capacity (RS9).

One signature per kid is the invariant that bounds the cost: a signature counts only by a key of the state at
the parent (or the new key), each kid once, so the verifier is asked at most once per such key, whatever `sigs`
holds. An item whose `sigs` read as two signatures of one kid is `kid_repeated`, before any verification; a
signature by a kid that is no such key is dropped without being verified.

Input `{acts, docs, item, org}`: the snapshot of CF-13 (`snapshot.parse`) and `item`, exactly `{act, sigs}` or
exactly `{doc, sigs}`. Output `{reason, store}`: when `reason` is `ok`, `store` is the item as the retained set keeps
it, else null. For an act, `act` is the copy the retained set keeps (CF-14 item 5): the item's text, or a stored twin
of the same receipt id, which a create-only write leaves as it is; `sigs`, sorted, are the item's texts that it
keeps. For a document, `sigs` are the item's receipts that count.

Store checks, first failure wins (`opening.open_store`): no document whose hash is `org` with a null `prev` is
`lineage_broken` unless the item is that original (registration); a document that no `prev` chain links to the
original is `lineage_broken`; then every document in lineage order (depth, then hash) is folded with its own path,
its GP-15 code on failure; a fixture profile is `fixture_profile` unless the build allows it.

Act group, in order: `jws_shape`, `payload_not_canonical_subset`, `payload_too_large`, `schema`,
`method_unknown`, `not_chain_act` (any method but the three primaries and `chain.resolve`), `schema`,
`body_schema`, `org_mismatch`, `already_stored` (a valid copy is stored: a node, or an applicable resolve),
`parent_unknown`, `epoch_closed` (the parent lies in an epoch the store holds a successor of: the retained set
would drop the act at once, I8), `high_s`, `kid_repeated`, `act_not_valid`, `store_full`, `ok`.

Document group, in order: `already_stored`, `lineage_broken` (an original that is not `org`, a change of another
org), `parent_unknown` (`prev` not stored), `kid_repeated`, the GP-15 code of the path ending at the document,
`store_full`, `ok`.

The kept texts are exactly the ones the fold counts, and `retain` owns them (SD13): `retain.kept_act` (the copy of an
act and its endorsements), `retain.kept_endorsements` and `retain.kept_receipts` keep what `quorum.introduced` and
`epoch.authority_person`, the fold's own public functions, say counts, for this module, for `compact` and for
`sync`. What stays here is what only admission has: the order of the answers, `kid_repeated` (one text per kid,
before any verification) and the capacity.
"""
from collections import namedtuple

from . import acts as acts_module
from . import (chain, envelope, epoch, errors, foldcmd, genesis, ijson, jws, opening, quorum, render_genesis, resolve, retain,
               snapshot)
from . import verifier

Input = namedtuple("Input", "snapshot item")
ActItem = namedtuple("ActItem", "act sigs")
DocItem = namedtuple("DocItem", "doc sigs")

ADMITTED = chain.PRIMARIES | {chain.RESOLVE}


def _item(value):
    """The `ActItem` or `DocItem` of the member `item`, or raise Malformed: exactly `{act, sigs}` or `{doc, sigs}`."""
    if type(value) is not dict or set(value) not in ({"act", "sigs"}, {"doc", "sigs"}):
        raise errors.Malformed()
    if "doc" in value:
        found = snapshot.entry(value)
        return DocItem(found["doc"], found["sigs"])
    if type(value["act"]) is not str or type(value["sigs"]) is not list:
        raise errors.Malformed()
    foldcmd.check_texts(value["sigs"])
    return ActItem(value["act"], value["sigs"])


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-11), or raise Malformed."""
    snap, rest = snapshot.parse(value, extra=("item",))
    return Input(snap, _item(rest["item"]))


def _registering(snap, item):
    """True iff `item` is the original document of `snap.org`: the one item a store with no original takes."""
    return (type(item) is DocItem and item.doc.get("prev") is None and genesis.doc_hash(item.doc) == snap.org)


# ---- the act group ----

def _parse_act(text, wire):
    """VR-02 steps 1 to 5 for a group's act: the `ParsedAct`, or Refused. After `method_unknown`, a method that
    is not a chain primary or `chain.resolve` is `not_chain_act`, then the closed schemas."""
    parsed = jws.parse(text)
    payload = envelope.parse_payload(parsed.payload)
    envelope.check_envelope(payload)
    method = wire.method(payload["method"])
    if method is None:
        raise errors.Refused("method_unknown")
    if method.method not in ADMITTED:
        raise errors.Refused("not_chain_act")
    return acts_module.parse(text, wire, ADMITTED)


def _parent(epochs, parsed):
    """`(epoch, node)` the act hangs at: the node of any admitted epoch whose id is the act's parent, or None."""
    for found in epochs.values():
        found.build()
        node = found.nodes.get(parsed.parent)
        if node is not None:
            return found, node
    return None


def _stored(base, parent, parsed):
    """True iff a valid copy of the act is stored (CF-11): its receipt id is that of a node of `base`, or of a
    resolve that is applicable at `parent`. A string of the store with that receipt id that is no valid act of the
    store, a garbage twin, does not count (FO-21), so it never hides the valid act."""
    group = base.bag.groups.get(parsed.id)
    if group is None:
        return False
    if parsed.method in chain.PRIMARIES:
        return parsed.id in base.nodes
    return resolve.Resolves(base).applicable(group, parent) is not None


def _endorsements(base, parsed, sigs):
    """`[Endorsement]` for each distinct text of `sigs` that reads as an endorsement of the act `parsed` (by the
    rules that need no key: FO-08), read by `retain`. Refused `kid_repeated` when two texts name one kid: choosing
    among a kid's texts means verifying them all, so the repeat is refused before any verification. Nothing is
    verified here."""
    readings = [act for act in (chain.read(text, base.bag.wire, base.bag.org) for text in set(sigs))
                if act is not None]
    found, seen = retain.read_endorsements(parsed, readings), set()
    for item in found:
        if item.kid in seen:
            raise errors.Refused("kid_repeated")
        seen.add(item.kid)
    return found


def _judged(base, parent, parsed, kept):
    """`(act, sigs)` that the retained set keeps for the act, or None when it is not valid at `parent` over the
    store plus itself and `kept`: judged in the view of the store's tree whose bag is the act's stored copies, the
    act, `kept` and the act's stored endorsements, every text that can change its verdict (FO-26, FO-25). The texts
    are `retain.kept_act`'s over that view, the choice `retain.retained` makes for the grown store."""
    stored = [base.bag.groups.get(parsed.id)] + base.bag.endorsements_of(parsed)
    texts = [copy.jws for group in stored if group is not None for copy in group.copies]
    view = base.sharing_tree(texts + [parsed.jws] + kept)
    group = view.bag.groups[parsed.id]
    if parsed.method in chain.PRIMARIES:
        valid = quorum.check_primary(view, group, parent) is not None
    else:
        valid = resolve.Resolves(view).applicable(group, parent) is not None
    return retain.kept_act(view, group, parent) if valid else None


def _act_group(inp, epochs, wire):
    snap, item = inp.snapshot, inp.item
    parsed = _parse_act(item.act, wire)
    if parsed.act["org"] != snap.org:
        raise errors.Refused("org_mismatch")
    located = _parent(epochs, parsed)
    if located is not None and _stored(*located, parsed):
        raise errors.Refused("already_stored")
    if located is None:
        raise errors.Refused("parent_unknown")
    base, parent = located
    if base.root.id in retain.closing_heads(snap.docs):
        raise errors.Refused("epoch_closed")
    if not verifier.is_low_s(parsed.signature):
        raise errors.Refused("high_s")
    kept = retain.kept_endorsements(base, parent, parsed, _endorsements(base, parsed, item.sigs))
    found = _judged(base, parent, parsed, kept)
    if found is None:
        raise errors.Refused("act_not_valid")
    act, sigs = found[0], sorted(set(found[1]) & set(kept))   # the item's own texts that the retained set keeps
    limit = ijson.MAX_INPUT - 2 * wire.number("ADMIT_RESERVE")
    if snapshot.canonical_size(snap, extra_acts=[act] + sigs) > limit:
        raise errors.Refused("store_full")
    return {"act": act, "sigs": sigs}


# ---- the document group ----

def _receipts(doc, sigs, org, wire):
    """`[(act, text)]` for each distinct text of `sigs` that reads as a `genesis.sign` over `doc` (`retain`).
    Refused `kid_repeated` when two texts name one kid. Nothing is verified."""
    found, seen = retain.read_receipts(doc, sigs, org, wire), set()
    for act, _ in found:
        if act.kid in seen:
            raise errors.Refused("kid_repeated")
        seen.add(act.kid)
    return found


def _doc_group(inp, profiles, allow_fixture, vitni, render_size):
    snap, item = inp.snapshot, inp.item
    index = snapshot.by_hash(snap)
    digest, prev = genesis.doc_hash(item.doc), item.doc.get("prev")
    if digest in index:
        raise errors.Refused("already_stored")
    if prev is None and digest != snap.org:
        raise errors.Refused("lineage_broken")
    if prev is not None:
        if item.doc.get("org") != snap.org:
            raise errors.Refused("lineage_broken")
        if type(prev) is not str or prev not in index:
            raise errors.Refused("parent_unknown")
    receipts = _receipts(item.doc, item.sigs, snap.org, profiles.wire)
    given = {"doc": item.doc, "sigs": item.sigs}
    path = (snapshot.path_to(index, prev) if prev is not None else []) + [given]
    epochs = epoch.fold_lineage(path, snap.acts, profiles, allow_fixture, vitni, render_size)
    kept = retain.kept_receipts(epochs, item.doc, receipts, profiles.wire, vitni)
    kept_entry = {"doc": item.doc, "sigs": kept}
    if snapshot.canonical_size(snap, extra_docs=[kept_entry]) > ijson.MAX_INPUT - profiles.wire.number("ADMIT_RESERVE"):
        raise errors.Refused("store_full")
    return kept_entry


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{reason, store}` of `admit` for `inp` over `vitni`, the memo of the call."""
    try:
        epochs = opening.open_store(inp.snapshot, profiles, allow_fixture, vitni, render_size,
                            registering=_registering(inp.snapshot, inp.item))
        if type(inp.item) is ActItem:
            stored = _act_group(inp, epochs, profiles.wire)
        else:
            stored = _doc_group(inp, profiles, allow_fixture, vitni, render_size)
    except errors.Refused as err:
        return {"reason": err.code, "store": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "store": None}
    return {"reason": "ok", "store": stored}
