"""What a store keeps (CF-14, SD13): the one owner of the retained set, and of the signatures that count.

A store keeps what a reader can read and nothing else. The rule is one function of the fold's own read set, applied
by each store's single writer: `compact` for the relay's store (`compact.py`), `sync` for a machine's (`sync.py`),
and `admit` keeps by it too (it never admits what the retained set of the resulting store would drop, I8). It is
built on the fold's own functions (`fold.Epoch`, `resolve.Resolves`, `endorse`, `quorum`, `genesis_sigs`,
`epoch.authority_person`); no rule of the fold is copied here.

`retained(epochs, closing, snap)` takes `epochs`, `{document hash: Epoch}` of the documents of the store, each folded
under its own path (`admit.open_store`), `closing`, `{document hash: heads}` (`closing_heads`: the epochs that have
a successor, and the head H of each successor), and `snap`, the documents with their receipts. It returns the
retained set (CF-14), epoch by epoch:

  open epoch    every node of the act tree, losing and forked branches included, and every applicable resolve
  closed epoch  the nodes on the path from the root to the head of each successor, and nothing else (no resolve)
  every kept act  every endorsement that counts against the state at its parent, and the possession endorsement of
                a new key, one text per receipt id: the smaller one in byte order that is valid
  every document  the receipts that count for possession or authority, one text per receipt id, the smaller one

An epoch is closed by the entries of `closing` and by nothing else, so the relay (every document it holds) and a
machine (the path up to its pin) differ in data and not in rule: a machine's pinned epoch is never in its own
`closing`.

The signatures that count are decided here and only here: `read_endorsements` and `read_receipts` read the texts a
caller offers by the rules that need no key, `kept_endorsements` and `kept_receipts` keep the ones that count.
`admit` offers the signatures of an item and adds its own rule on top (one text per kid, `kid_repeated`, before any
verification); the retained set offers every text of the store and applies no kid rule, because an `overrides`
entry names endorsements by receipt id and a choice among a kid's endorsements could change an answer.
"""
from collections import namedtuple

from . import chain, endorse, epoch, fold, genesis, genesis_sigs, quorum, resolve, snapshot, tree

Retained = namedtuple("Retained", "acts receipts")   # texts of acts; {document hash: texts of its receipts}
Endorsement = namedtuple("Endorsement", "kid text alone")


def over(base, texts):
    """The epoch of `base`'s document, its policy and its earlier keys, over the bag of `texts` (read on the wire of
    `base`'s own bag: one wire for the whole lineage)."""
    return fold.Epoch(base.doc, chain.Bag(texts, base.bag.wire, base.bag.org), base.profile, base.vitni, base.earlier)


# ---- the signatures that count: acts

def read_endorsements(base, parsed, texts):
    """`[Endorsement(kid, text, alone)]` for each distinct text of `texts` that reads as an endorsement of the act
    `parsed` by the rules that need no key (FO-08), in byte order; `alone` is `base` over the act and that text
    only, so one signature never vouches for another. Nothing is verified here and no kid rule is applied."""
    found = []
    for text in sorted(set(texts)):
        alone = over(base, [parsed.jws, text])
        groups = alone.bag.endorsements_of(parsed)
        if groups:
            found.append(Endorsement(groups[0].copies[0].kid, text, alone))
    return found


def kept_endorsements(base, parent, parsed, readings):
    """The texts of `readings` (`read_endorsements`) to store for the act `parsed` at the node `parent` of `base`,
    sorted: those that count (FO-21, FO-08: an endorsement that verifies against the keys of the state at the
    parent) and the possession endorsement of the new key (FO-07), the smaller text of one receipt id. Only a kid
    of the state or the new key is verified, so the verifier is asked at most once per such key for each receipt id,
    whatever the readings hold."""
    state, new_key = parent.state, quorum.introduced(parsed)
    new_kid = None if new_key is None else new_key[1]
    kept, seen = [], set()
    for kid, text, alone in readings:
        if kid != new_kid and not state.has_entry(kid):
            continue
        found = alone.bag.endorsements_of(parsed)[0]
        if found.act.id in seen:
            continue
        group = alone.bag.groups[parsed.id]
        if (endorse.verified(alone, found, state.keys_for)
                or (new_key is not None and endorse.possession(alone, group, state, *new_key))):
            seen.add(found.act.id)
            kept.append(text)
    return sorted(kept)


def _smallest_valid(base, group, state):
    """The smaller text of the act group `group` that verifies against its signer's entry in `state` with a low S
    (FO-21, ACT-12)."""
    for copy in sorted(group.copies, key=lambda item: item.jws):
        if endorse.verified(base, group._replace(copies=[copy]), state.keys_for):
            return copy.jws
    raise RuntimeError("a node whose every text is invalid")   # a node exists only for a valid text (FO-21)


def _kept_act(base, group, parent):
    """The texts of the act group `group` at the node `parent` that stay: its smaller valid text and every
    endorsement that counts (item 4 of CF-14)."""
    parsed = group.act
    found = base.bag.endorsements_of(parsed)
    readings = read_endorsements(base, parsed, [copy.jws for item in found for copy in item.copies])
    return {_smallest_valid(base, group, parent.state)} | set(
        kept_endorsements(base, parent, parsed, readings))


# ---- the signatures that count: documents

def read_receipts(doc, sigs, org, wire):
    """`[(act, text)]` for each distinct text of `sigs` that reads as a `genesis.sign` over `doc` by the rules that
    need no key (`genesis_sigs.read`), in byte order. Nothing is verified here and no kid rule is applied."""
    digest, found = genesis.doc_hash(doc), []
    for text in sorted(set(sigs)):
        act = genesis_sigs.read(text, doc, digest, org, wire)
        if act is not None:
            found.append((act, text))
    return found


def kept_receipts(epochs, doc, receipts, wire, vitni):
    """The receipts (`read_receipts`) that count for the valid change or original `doc` (the last of `epochs`): for
    possession, or for authority; sorted, the smaller text of one receipt id."""
    org = epochs[0].root.id
    previous = epochs[-2] if len(epochs) > 1 else None
    node = previous.nodes[doc["head"]] if previous is not None else None
    roles = previous.rule("genesis.change")[1] if previous is not None else ()
    kept, seen = [], set()
    for act, text in receipts:
        if act.id in seen:
            continue
        possession = bool(genesis_sigs.counting(doc, [text], org, wire, vitni))
        if possession or (previous is not None and epoch.authority_person(act, text, node, roles, vitni)):
            seen.add(act.id)
            kept.append(text)
    return sorted(kept)


# ---- the retained set

def closing_heads(docs):
    """`{document hash: frozenset of heads}` for the entries `docs` (`{doc, sigs}`): each document that has a
    successor among them, and the head H of every successor. The keys are the closed epochs of a store whose
    documents are `docs`. The documents are valid links, so every change has its `head`."""
    found = {}
    for item in docs:
        prev = item["doc"].get("prev")
        if type(prev) is str:
            found.setdefault(prev, set()).add(item["doc"]["head"])
    return {key: frozenset(heads) for key, heads in found.items()}


def _closed(found, heads):
    """`[(group, parent)]` of the closed epoch `found`: the primaries on the paths to the heads `heads`."""
    nodes = {item.id: item for head in heads for item in tree.path_from_root(found.nodes[head])}
    return [(found.bag.groups[item.id], item.parent) for item in nodes.values() if item.act is not None]


def _open(found):
    """`[(group, parent)]` of the open epoch `found`: every node and every applicable resolve."""
    resolves = resolve.Resolves(found)
    entries = [(found.bag.groups[item.id], item.parent) for item in found.nodes.values() if item.act is not None]
    for item in found.nodes.values():
        entries.extend((applicable.group, applicable.parent) for applicable in resolves.at(item))
    return entries


def retained(epochs, closing, snap):
    """The `Retained` of the store whose documents are `snap.docs`: `acts`, the texts of acts it keeps, and
    `receipts`, `{document hash: the receipt texts it keeps for that document}`."""
    acts = set()
    for key, found in epochs.items():
        found.build()
        heads = closing.get(key)
        for group, parent in (_open(found) if heads is None else _closed(found, heads)):
            acts |= _kept_act(found, group, parent)
    receipts, index = {}, snapshot.by_hash(snap)
    for key, item in index.items():
        path = [epochs[genesis.doc_hash(entry["doc"])] for entry in snapshot.path_to(index, key)]
        last = path[-1]
        reads = read_receipts(item["doc"], item["sigs"], path[0].root.id, last.bag.wire)
        receipts[key] = frozenset(kept_receipts(path, item["doc"], reads, last.bag.wire, last.vitni))
    return Retained(frozenset(acts), receipts)


def dropped(snap, kept):
    """`(acts, sigs)`, both sorted lists: the strings of `snap.acts` that the retained set `kept` does not hold, and
    the receipt texts in the `sigs` of its documents that no document keeps. A text that one document keeps is
    never listed, even where it sits in the `sigs` of another document that does not read it: the two lists
    cannot name a counting receipt."""
    held = set().union(*kept.receipts.values())
    sigs = {text for item in snap.docs for text in item["sigs"]} - held
    return sorted(set(snap.acts) - kept.acts), sorted(sigs)
