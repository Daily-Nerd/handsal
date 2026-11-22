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
EVIDENCE_MISSING = "evidence_missing"   # an `overrides` entry names a text the item does not carry


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


def _entries(parsed):
    """The `overrides` entries of a resolve `parsed`, `[]` for a primary."""
    return parsed.body["overrides"] if parsed.method == chain.RESOLVE else []


def _named(epochs, parsed):
    """Refused `parent_unknown` when an `overrides` entry of `parsed` names a receipt id that is no node and no
    applicable resolve of any admitted epoch: publish what the act names first, nothing is held pending. Every entry
    is read before any other code of the act group is chosen, so the code never depends on how the ids sort. The
    fold says what an applicable resolve is (`resolve.Resolves`); a resolve the store holds only as a string, with
    too few signatures, is not one."""
    judges = {key: resolve.Resolves(found) for key, found in epochs.items()}
    for entry in _entries(parsed):
        named = entry["resolve"]
        for key, found in epochs.items():
            found.build()
            if named in found.nodes or judges[key]._by_id(named) is not None:
                break
        else:
            raise errors.Refused("parent_unknown")


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


def _evidence(base, parsed, sigs):
    """`[ParsedAct]`, the texts of `sigs` whose receipt id an `overrides` entry of the resolve `parsed` names, one
    per id, in byte order of text (an empty list for a primary). The fold reads evidence by receipt id and a verdict
    counts persons, so a second text of one id is `kid_repeated` before any is verified, a low-S twin included. Refused
    `evidence_missing` when a named id has no text in `sigs`, whether or not the store holds one: evidence comes from
    the item only, so that every store that holds the act holds the texts its meaning needs. A text that endorses
    nothing of the act and whose id no entry names is not here: it is neither verified nor stored."""
    named = {ident for entry in _entries(parsed) for ident in entry["endorsements"]}
    if not named:
        return []
    found, seen = {}, set()
    for act in (chain.read(text, base.bag.wire, base.bag.org) for text in sorted(set(sigs))):
        if act is not None and act.id in named:
            if act.id in seen:
                raise errors.Refused("kid_repeated")
            seen.add(act.id)
            found[act.jws] = act
    if named - seen:
        raise errors.Refused(EVIDENCE_MISSING)
    return [found[text] for text in sorted(found)]


def _counted(base, parsed, readings):
    """`(named, texts)` for the resolve `parsed`: `named`, the groups of the applicable resolves of `base` that its
    entries name, and `texts`, the item's evidence that counts for them (`retain.kept_endorsements`: it verifies a
    named id only by a key of the state at the named resolve's parent). Refused `act_not_valid` when an entry's named
    text is not among them: a garbage text, a text by a key that is not a key there, or a text that endorses nothing
    of the resolve is no evidence. An entry that names no applicable resolve of `base` (a node, or a resolve of another
    parent) has nothing to verify here; the verdict of the view says it is not effective."""
    judge, named, texts = resolve.Resolves(base), [], []
    for entry in _entries(parsed):
        other = judge._by_id(entry["resolve"])
        if other is None:
            continue
        wanted = set(entry["endorsements"])
        found = [item for item in retain.read_endorsements(other.group.act, readings) if item.group.act.id in wanted]
        kept = retain.kept_endorsements(base, other.parent, other.group.act, found)
        if wanted - {item.group.act.id for item in found if item.text in kept}:
            raise errors.Refused("act_not_valid")
        named.append(other.group)
        texts.extend(kept)
    return named, sorted(set(texts))


def _judged(base, parent, parsed, kept, named=(), evidence=()):
    """`(act, sigs)` that the retained set keeps for the act, or None when it is not valid at `parent` over the
    store plus itself and `kept`: judged in the view of the store's tree whose bag is the act's stored copies, the
    act, `kept` and the act's stored endorsements, every text that can change its verdict (FO-26, FO-25). The texts
    are `retain.kept_act`'s over that view, the choice `retain.retained` makes for the grown store. A resolve is also
    judged with the groups it names (`named`), their stored endorsements and the item's `evidence`, and is valid only
    if every one of its entries is effective in that view; the endorsements the retained set keeps for the named
    resolves are added to the answer."""
    stored = [base.bag.groups.get(parsed.id)] + base.bag.endorsements_of(parsed)
    for other in named:
        stored += [other] + base.bag.endorsements_of(other.act)
    texts = [copy.jws for group in stored if group is not None for copy in group.copies]
    view = base.sharing_tree(texts + [parsed.jws] + kept + list(evidence))
    group = view.bag.groups[parsed.id]
    if parsed.method in chain.PRIMARIES:
        valid = quorum.check_primary(view, group, parent) is not None
    else:
        judge = resolve.Resolves(view)
        found = judge.applicable(group, parent)
        # every entry effective, as the fold says it (FO-25): the one rule of "effective" is the fold's
        valid = found is not None and judge._effective(found) == {entry["resolve"] for entry in _entries(parsed)}
    if not valid:
        return None
    act, sigs = retain.kept_act(view, group, parent)
    for other in named:
        sigs += retain.kept_act(view, view.bag.groups[other.act.id], view.nodes[other.act.parent])[1]
    return act, sigs


def _act_group(inp, epochs, wire):
    """Every step of the act group before the item's own texts are verified (the store's trees are built, the
    questions about what the store holds are asked); returns the rest, a function of nothing that gives the act
    and the texts the retained set keeps, or raises Refused. The rest builds no tree: it reads the built ones."""
    snap, item = inp.snapshot, inp.item
    parsed = _parse_act(item.act, wire)
    if parsed.act["org"] != snap.org:
        raise errors.Refused("org_mismatch")
    located = _parent(epochs, parsed)
    if located is not None and _stored(*located, parsed):
        raise errors.Refused("already_stored")
    if located is None:
        raise errors.Refused("parent_unknown")
    _named(epochs, parsed)
    base, parent = located
    if base.root.id in retain.closing_heads(snap.docs):
        raise errors.Refused("epoch_closed")
    if not verifier.is_low_s(parsed.signature):
        raise errors.Refused("high_s")
    readings = _endorsements(base, parsed, item.sigs)
    carried = _evidence(base, parsed, item.sigs)

    def rest():
        kept = retain.kept_endorsements(base, parent, parsed, readings)
        named, evidence = _counted(base, parsed, carried)
        found = _judged(base, parent, parsed, kept, named, evidence)
        if found is None:
            raise errors.Refused("act_not_valid")
        held = {copy.jws for each in base.bag.groups.values() for copy in each.copies}
        # the item's own texts that the retained set keeps, and its evidence that the store lacks
        act, sigs = found[0], sorted((set(found[1]) & set(kept)) | ((set(found[1]) & set(evidence)) - held))
        limit = ijson.MAX_INPUT - 2 * wire.number("ADMIT_RESERVE")
        if snapshot.canonical_size(snap, extra_acts=[act] + sigs) > limit:
            raise errors.Refused("store_full")
        return {"act": act, "sigs": sigs}

    return rest


# ---- the document group ----

class _Asked(Exception):
    """The first question the fold put to the verifier: every step before it needed none."""


class _FirstQuestion(verifier.Memoized):
    """Not a memo of the call but a stop in the shape of one: it holds no verifier and no answer, makes no memo of the
    call, and ends the fold at its first question. It must stay a `Memoized`, because `verifier.call_memo` checks
    `isinstance` and the fold refuses anything else; and it relies on the fold putting its questions through `verify`
    alone, so a fold that read the memo's answers any other way would not stop here."""

    def __init__(self):
        pass

    def verify(self, jws, keys, method):
        raise _Asked()


def _receipts(doc, sigs, org, wire):
    """`[(act, text)]` for each distinct text of `sigs` that reads as a `genesis.sign` over `doc` (`retain`).
    Refused `kid_repeated` when two texts name one kid. Nothing is verified."""
    found, seen = retain.read_receipts(doc, sigs, org, wire), set()
    for act, _ in found:
        if act.kid in seen:
            raise errors.Refused("kid_repeated")
        seen.add(act.kid)
    return found


def _doc_group(inp, epochs, profiles, allow_fixture, vitni, render_size):
    """Every step of the document group before its receipts are verified (the checks that need only the store, the
    store's own trees built, the receipts read); returns the rest, which extends the stored path by the document, the
    one fold of that path, and gives the entry. The rest builds no tree of the store."""
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
    stored = [epochs[genesis.doc_hash(entry["doc"])] for entry in snapshot.path_to(index, prev)] if prev is not None else []
    try:   # the refusals that need no question come first, as in the fold, and before the parent's tree is built
        epoch.Lineage(snap.acts, profiles, allow_fixture, _FirstQuestion(), render_size,
                      last=stored[-1] if stored else None).extend(given)
    except _Asked:
        pass
    if stored:
        stored[-1].build()   # a change reads its parent's tree: built here, over the answers `opened` reads

    def rest():
        found = epoch.Lineage(snap.acts, profiles, allow_fixture, vitni, render_size,
                              last=stored[-1] if stored else None).extend(given).last
        kept = retain.kept_receipts(stored + [found], item.doc, receipts, profiles.wire, vitni)
        kept_entry = {"doc": item.doc, "sigs": kept}
        if snapshot.canonical_size(snap, extra_docs=[kept_entry]) > ijson.MAX_INPUT - profiles.wire.number("ADMIT_RESERVE"):
            raise errors.Refused("store_full")
        return kept_entry

    return rest


def _answer(step):
    """`{reason, store}` of `step()`, a stage of the call."""
    try:
        return {"reason": "ok", "store": step()}
    except errors.Refused as err:
        return {"reason": err.code, "store": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "store": None}


def opened(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The first stage of `admit`: the store opened and every step before the item's own texts are verified (the
    store checks and the act group up to its endorsements, or the document group up to its receipts). Returns `finish`, a
    function of nothing that gives `{reason, store}` and asks the verifier about the item's texts alone. What `finish`
    reads is a function of the input and of the answers read here, so it can run again over other answers."""

    def located():
        epochs = opening.open_store(inp.snapshot, profiles, allow_fixture, vitni, render_size,
                                    registering=_registering(inp.snapshot, inp.item))
        if type(inp.item) is ActItem:
            return _act_group(inp, epochs, profiles.wire)
        return _doc_group(inp, epochs, profiles, allow_fixture, vitni, render_size)

    got = _answer(located)
    if got["reason"] != "ok":
        return lambda: got
    rest = got["store"]
    return lambda: _answer(rest)


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{reason, store}` of `admit` for `inp` over `vitni`, the memo of the call."""
    return opened(inp, profiles, allow_fixture, vitni, render_size)()
