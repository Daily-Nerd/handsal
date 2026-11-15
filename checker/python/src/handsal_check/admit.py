"""`admit` (CF-11): may one item enter the chain store of an organization.

The rule is "valid now", never "could matter later" (RS5): an act is admitted only together with the signatures
that make it valid against the state at its parent in the store, a document only as a valid lineage link with
its receipts. Nothing here is a rule of its own. The store is folded by the fold (`epoch.fold_lineage`, one
`Epoch` per document), the act is judged by the fold's own `Epoch.build` and `resolve.Resolves` over the store
plus the item, and a signature is kept when `endorse` and `genesis_sigs` count it. What this module adds is the
order of the answers, the signatures to keep (one per kid, RS6) and the capacity (RS9).

One signature per kid is the invariant that bounds the cost: a signature counts only by a key of the state at
the parent (or the new key), each kid once, so the verifier is asked at most once per such key, whatever `sigs`
holds. An item whose `sigs` read as two signatures of one kid is `kid_repeated`, before any verification; a
signature by a kid that is no such key is dropped without being verified.

Input `{acts, docs, item, org}`: the snapshot of CF-13 (`snapshot.parse`) and `item`, exactly `{act, sigs}` or
exactly `{doc, sigs}`. Output `{reason, store}`: `store` is the item with only the signatures to keep, `sigs`
sorted, when `reason` is `ok`, else null.

Store checks, first failure wins (`open_store`): no document whose hash is `org` with a null `prev` is
`lineage_broken` unless the item is that original (registration); a document that no `prev` chain links to the
original is `lineage_broken`; then every document in lineage order (depth, then hash) is folded with its own path,
its GP-15 code on failure; a fixture profile is `fixture_profile` unless the build allows it.

Act group, in order: `jws_shape`, `payload_not_canonical_subset`, `payload_too_large`, `schema`,
`method_unknown`, `not_chain_act` (any method but the three primaries and `chain.resolve`), `schema`,
`body_schema`, `org_mismatch`, `already_stored`, `parent_unknown`, `high_s`, `kid_repeated`, `act_not_valid`,
`store_full`, `ok`.

Document group, in order: `already_stored`, `lineage_broken` (an original that is not `org`, a change of another
org), `parent_unknown` (`prev` not stored), `kid_repeated`, the GP-15 code of the path ending at the document,
`store_full`, `ok`.

The kept signatures are exactly the ones the fold counts: `quorum.introduced` (the key an introducing act brings)
and `epoch.authority_person` (a receipt by a clean role holder of the epoch before) are the fold's own public
functions, called here and by the fold, never copied.
"""
from collections import namedtuple

from . import acts as acts_module
from . import chain, endorse, envelope, epoch, errors, fold, foldcmd, genesis, genesis_sigs, ijson, jws, quorum
from . import render_genesis, resolve, snapshot, verifier

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


def _lineage_order(index, org):
    """The hashes of the documents linked to the original `org` by `prev`, parents first, siblings by hash;
    Refused `lineage_broken` when a document of the store is not linked to it."""
    children = {}
    for key, entry in index.items():
        prev = entry["doc"].get("prev")
        if type(prev) is str:
            children.setdefault(prev, []).append(key)
    order, level = [], [org] if org in index else []   # no original: no document is linked to it
    while level:
        order.extend(level)
        level = [child for parent in level for child in sorted(children.get(parent, ()))]
    if len(order) != len(index):
        raise errors.Refused("lineage_broken")
    return order


def open_store(snap, reg, profiles, allow_fixture, vitni, render_size, registering=False):
    """`{document hash: Epoch}` of the store `snap`, every document folded under its own path in lineage order, or
    raise Refused with the first failing code (the module note). A verifier that cannot answer raises
    VerifierUnavailable."""
    index = snapshot.by_hash(snap)
    if snap.org not in index and not registering:
        raise errors.Refused("lineage_broken")
    epochs = {}
    for key in _lineage_order(index, snap.org):
        path = snapshot.path_to(snap, key)
        epochs[key] = epoch.fold_lineage(path, snap.acts, reg, profiles, allow_fixture, vitni, render_size)[-1]
    return epochs


def _over(base, texts):
    """The epoch of `base`'s document, its policy and its earlier keys, over the bag of `texts`."""
    return fold.Epoch(base.doc, chain.Bag(texts, base.reg), base.reg, base.profiles, base.vitni, base.fixture,
                      base.earlier)


# ---- the act group ----

def _parse_act(text, reg):
    """VR-02 steps 1 to 5 for a group's act: the `ParsedAct`, or Refused. After `method_unknown`, a method that
    is not a chain primary or `chain.resolve` is `not_chain_act`, then the closed schemas."""
    parsed = jws.parse(text)
    payload = envelope.parse_payload(parsed.payload)
    envelope.check_envelope(payload)
    method = reg.method(payload["method"])
    if method is None:
        raise errors.Refused("method_unknown")
    if method.method not in ADMITTED:
        raise errors.Refused("not_chain_act")
    return acts_module.parse(text, reg, ADMITTED)


def _parent(epochs, parsed):
    """`(epoch, node)` the act hangs at: the node of any admitted epoch whose id is the act's parent."""
    for found in epochs.values():
        found.build()
        node = found.nodes.get(parsed.parent)
        if node is not None:
            return found, node
    raise errors.Refused("parent_unknown")


def _endorsements(base, parsed, sigs):
    """`[(kid, text, bag)]` for each distinct text of `sigs` that reads as an endorsement of the act `parsed` (by
    the rules that need no key: FO-08), `bag` holding the act and that text only. Refused `kid_repeated` when two
    texts name one kid. Nothing is verified here."""
    found, seen = [], set()
    for text in sorted(set(sigs)):
        alone = _over(base, [parsed.jws, text])
        groups = alone.bag.endorsements_of(parsed)
        if not groups:
            continue
        kid = groups[0].copies[0].kid
        if kid in seen:
            raise errors.Refused("kid_repeated")
        seen.add(kid)
        found.append((kid, text, alone))
    return found


def _kept(base, parent, parsed, sigs):
    """The signatures to store for the act `parsed` at the node `parent` of `base`: those that count (FO-21,
    FO-08: an endorsement that verifies against the keys of the state at the parent) and the possession
    endorsement of the new key. Each text is judged alone, over the act and itself only, so one signature never
    vouches for another. One kid names at most one text (`_endorsements`), and only a kid of the state or the new
    key is verified, so the verifier is called at most once per such key."""
    keys, new_key = parent.state.keys_map(), quorum.introduced(parsed)
    usable = {kid for entries in keys.values() for kid in entries}
    if new_key is not None:
        usable.add(new_key[1])
    kept = []
    for kid, text, alone in _endorsements(base, parsed, sigs):
        if kid not in usable:
            continue
        found = alone.bag.endorsements_of(parsed)[0]
        group = alone.bag.groups[parsed.id]
        if (endorse.verified(alone, found, keys)
                or (new_key is not None and endorse.possession(alone, group, parent.state, *new_key))):
            kept.append(text)
    return sorted(kept)


def _valid(base, parent, parsed, texts):
    """True iff the act is valid at `parent` over the store `texts` plus itself: it is a node of the rebuilt tree
    (a primary), or an applicable resolve (FO-25)."""
    full = _over(base, texts)
    full.build()
    if parsed.method in chain.PRIMARIES:
        return parsed.id in full.nodes
    return resolve.Resolves(full).applicable(full.bag.groups[parsed.id], full.nodes[parent.id]) is not None


def _act_group(inp, epochs, reg):
    snap, item = inp.snapshot, inp.item
    parsed = _parse_act(item.act, reg)
    if parsed.act["org"] != snap.org:
        raise errors.Refused("org_mismatch")
    if parsed.id in chain.Bag(snap.acts, reg).groups:
        raise errors.Refused("already_stored")
    base, parent = _parent(epochs, parsed)
    if not verifier.is_low_s(parsed.signature):
        raise errors.Refused("high_s")
    kept = _kept(base, parent, parsed, item.sigs)
    if not _valid(base, parent, parsed, list(snap.acts) + [parsed.jws] + kept):
        raise errors.Refused("act_not_valid")
    limit = ijson.MAX_INPUT - 2 * reg.number("ADMIT_RESERVE")
    if snapshot.canonical_size(snap, extra_acts=[parsed.jws] + kept) > limit:
        raise errors.Refused("store_full")
    return {"act": parsed.jws, "sigs": kept}


# ---- the document group ----

def _receipts(doc, sigs, org, reg):
    """`[(act, text)]` for each distinct text of `sigs` that reads as a `genesis.sign` over `doc` by the rules that
    need no key (`genesis_sigs.read`). Refused `kid_repeated` when two texts name one kid. Nothing is verified."""
    digest, found, seen = genesis.doc_hash(doc), [], set()
    for text in sorted(set(sigs)):
        act = genesis_sigs.read(text, doc, digest, org, reg)
        if act is None:
            continue
        if act.kid in seen:
            raise errors.Refused("kid_repeated")
        seen.add(act.kid)
        found.append((act, text))
    return found


def _kept_receipts(epochs, doc, receipts, reg, vitni):
    """The receipts (`_receipts`) that count for the valid change or original `doc` (the last of `epochs`): for
    possession, or for authority."""
    org = epochs[0].root.id
    previous = epochs[-2] if len(epochs) > 1 else None
    node = previous.nodes[doc["head"]] if previous is not None else None
    roles = previous.rule("genesis.change")[1] if previous is not None else ()
    kept = []
    for act, text in receipts:
        possession = bool(genesis_sigs.counting(doc, [text], org, reg, vitni))
        if possession or (previous is not None and epoch.authority_person(act, text, node, roles, vitni)):
            kept.append(text)
    return sorted(kept)


def _doc_group(inp, reg, profiles, allow_fixture, vitni, render_size):
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
    receipts = _receipts(item.doc, item.sigs, snap.org, reg)
    given = {"doc": item.doc, "sigs": item.sigs}
    path = (snapshot.path_to(snap, prev) if prev is not None else []) + [given]
    epochs = epoch.fold_lineage(path, snap.acts, reg, profiles, allow_fixture, vitni, render_size)
    kept = _kept_receipts(epochs, item.doc, receipts, reg, vitni)
    kept_entry = {"doc": item.doc, "sigs": kept}
    if snapshot.canonical_size(snap, extra_docs=[kept_entry]) > ijson.MAX_INPUT - reg.number("ADMIT_RESERVE"):
        raise errors.Refused("store_full")
    return kept_entry


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{reason, store}` of `admit` for `inp` over the verifier `vitni`."""
    vitni = verifier.Memoized(vitni)
    try:
        epochs = open_store(inp.snapshot, reg, profiles, allow_fixture, vitni, render_size,
                            registering=_registering(inp.snapshot, inp.item))
        if type(inp.item) is ActItem:
            stored = _act_group(inp, epochs, reg)
        else:
            stored = _doc_group(inp, reg, profiles, allow_fixture, vitni, render_size)
    except errors.Refused as err:
        return {"reason": err.code, "store": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "store": None}
    return {"reason": "ok", "store": stored}
