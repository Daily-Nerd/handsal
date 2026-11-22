"""`sync` (CF-09): the one writer of the per-machine store, production build only.

`handsal-check sync < {acts, docs, org}`: the snapshot of CF-13, read by `snapshot.parse` like `admit` and `pool`
read it (`acts` may be empty, `docs` is a set of `{doc, sigs}`), and no other key (`pin`, `now`, `synced_at`,
`tip_statement`, `witness`, `lineage` are `malformed_input`). The transport never reads the pin: `sync` takes the
path from the original to the pinned document out of `docs` itself. Steps, first failure wins, and nothing is
written on a failure:

  1  framing and shape                              `unparseable_input`, `malformed_input` (the table)
  2  the pin and the lineage                        VR-02 step 6 (a) to (h) over the path `docs` gives for the
                                                    pin's `genesis`: the document absent is `genesis_pin_mismatch`,
                                                    a missing link `lineage_broken`; documents off the path are
                                                    ignored and not stored; fixture profile refused; before the
                                                    lock and before any directory exists
  3  the lock, then the old store, inside it        absent is the empty set; `store_owner`, `store_malformed`,
                                                    `store_unavailable` refuse and an old store is never overwritten
  4  the union of the stored and the input acts,    sorted, deduplicated; held in memory only, the bound is on
     and of the receipts of each path document      what is written (step 8)
  5  the fold of the union under the pinned path    a state or `fork` continues; any other code and
     and the valid descendants of the pin           `verifier_unavailable` refuse; a descendant (a document in
                                                    `docs` below the pin, each by the fold of its path) that does
                                                    not fold is ignored, a valid one is an open epoch and is not stored
  6  the retained set (`retain`, CF-14)             the stored lineage closes the epochs before the pin, the
                                                    descendants are anchored as open epochs; what no reader reads
                                                    is dropped, an epoch off the pinned lineage included (GP-21)
  7  `next`                                          "yes" when a valid or a foreign successor was found at step 5
                                                    (a direct successor under an unlisted profile hash whose
                                                    structure, link, head and authority pass: `Lineage.moved_by`),
                                                    or the old store said "yes" for this same pinned document
  8  the retained store over MAX_INPUT              `store_full`
  9  the clock, read once, then the write           an I/O failure is `store_unavailable`: before the rename the
                                                    old store stays; at the directory `fsync` after it the new
                                                    store may be visible (a superset of what a reader needs, a
                                                    later `sync` converges)

Output `{reason, synced_at}`: `synced_at` is not null exactly when the store was written and made durable, and
`reason` is then `epoch_superseded` when `next` is "yes", else `ok` or `fork`; a refusal is its code and null. The
store never loses an item that a command on the machine reads, now or after a re-pin the pin can make: it is the
retained set of the union, so a store with fewer acts than before can be written only when the rest is something no
fold reads. The order is the point: the fold, then the retained set, then the size, then the write, so a
union that the retained set shrinks under MAX_INPUT is written. The pin probe, the store port and the clock are
arguments, as for the production table; no input reaches them.
"""
from collections import namedtuple

from . import epoch, errors, fold_out, genesis, ijson, pinfile, retain, snapshot, store, verifier

Input = snapshot.Snapshot


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-09, CF-13), or raise Malformed."""
    return snapshot.parse(value)[0]


def _pinned_path(index, org, answer):
    """`(path, ends)`: the entries from the original to the pin's `genesis` out of `index` (`snapshot.by_hash` of
    `docs`), and the ends `pinfile.check` compares with the pin. `answer` is the probe's. A pin that does not parse
    is refused by that check before any comparison with the ends, so they are None then, which is the empty
    lineage."""
    try:
        genesis = pinfile.parse(answer.raw).genesis
    except errors.Refused:
        return [], None
    path = snapshot.path_to(index, genesis)
    if path:
        return path, pinfile.ends(path)
    if path is None:   # the pinned document is absent: a lineage whose last document is none
        return [], pinfile.Ends(org if org in index else None, None, None)
    return [], None   # a missing link


def _united(lineage, old):
    """The entries of `lineage` with `sigs` united with those the stored lineage `old` holds for the same document:
    a source that carries fewer receipts never takes one away."""
    return [{"doc": entry["doc"],
             "sigs": store.canonical(entry["sigs"] + [text for held in old if held["doc"] == entry["doc"]
                                                      for text in held["sigs"]])}
            for entry in lineage]


def _descendants(index, pinned, tip):
    """`({document hash: (entry, Epoch)}, foreign)`: the valid descendants of the pinned document among `index`, and
    whether one of its direct successors is foreign (`Lineage.moved_by`). Each valid descendant is one
    more link read against the fold of its parent, `tip` for the pin (`epoch.Lineage`), so no document costs more
    than itself and a document that no one signed costs a parse. A document that is no valid successor is
    ignored with everything below it (nothing is refused for it): what `extend` refuses is a document code
    (GP-15) and nothing else, so an ignored document is exactly an invalid one. A verifier that cannot answer
    raises VerifierUnavailable, which is not a verdict on a document and is not caught."""
    children = {}
    for key, item in index.items():
        if type(item["doc"].get("prev")) is str:
            children.setdefault(item["doc"]["prev"], []).append(key)
    found, foreign, pending = {}, False, [(pinned, tip)]
    while pending:
        parent, above = pending.pop()
        for key in children.get(parent, ()):
            try:
                below = above.extend(index[key])
            except errors.Refused as err:
                # a hash no edition lists is not a verdict on the document: a direct successor the pinned quorum
                # signed has closed the epoch (CF-09 step 5). Nothing below it is read, and it is not stored. One
                # answer is all `next` needs, so once it is yes the other direct successors are not asked.
                if err.code == "profile_mismatch" and parent == pinned and not foreign and above.moved_by(index[key]):
                    foreign = True
                continue
            found[key] = (index[key], below.last)
            pending.append((key, below))
    return found, foreign


Decision = namedtuple("Decision", "reason acts lineage next")   # what a call makes of the old store and the input


def decide(old, inp, index, lineage, profiles, vitni, render_size):
    """Steps 4 to 8, pure: the `Decision` of the store to write over the old store `old` (`store.parse`, or
    `store.NOTHING`) for the input `inp`, whose documents are `index` and whose pinned path is `lineage`; or raise
    Refused. It reaches no port and reads no clock: the lock, the one read of the old store and the write belong to
    `_write`."""
    acts = store.canonical(old.acts + inp.acts)
    path = _united(lineage, old.lineage)
    tip = epoch.Lineage.empty(acts, profiles, False, vitni, render_size).extend_all(path)
    epochs = tip.epochs()
    reason = fold_out.view(epochs, None).error or "ok"   # at the tip the only error is `fork`: a verdict
    below, foreign = _descendants(index, genesis.doc_hash(path[-1]["doc"]), tip)
    anchors = {genesis.doc_hash(entry["doc"]): found for entry, found in zip(path, epochs)}
    entries = {genesis.doc_hash(entry["doc"]): entry for entry in path}
    for key, (entry, found) in below.items():
        anchors[key], entries[key] = found, entry
    everything = snapshot.Snapshot(acts, [entries[key] for key in sorted(entries)], inp.org)
    kept = retain.retained(anchors, retain.closing_heads(path), everything)
    written = [{"doc": entry["doc"], "sigs": sorted(kept.receipts[genesis.doc_hash(entry["doc"])])}
               for entry in path]
    carried = bool(old.lineage) and old.lineage[-1]["doc"] == path[-1]["doc"] and old.next == "yes"
    next_ = "yes" if below or foreign or carried else "no"
    retained = store.canonical(kept.acts)
    if len(store.encode(retained, written, next_, store.SIZING_TIME)) > ijson.MAX_INPUT:
        raise errors.Refused("store_full")
    return Decision(reason, retained, written, next_)


def _write(inp, index, lineage, profiles, vitni, render_size, port, clock):
    """Steps 3 to 9: `(reason, synced_at)` of the store written. The lock is taken once, the old store is read once
    inside it, `decide` is called, and the clock is read before the write. `lineage` is the pinned path."""
    with port.lock(inp.org) as held:
        raw = held.read()
        old = store.NOTHING if raw is None else store.parse(raw)
        made = decide(old, inp, index, lineage, profiles, vitni, render_size)
        synced_at = clock()
        held.write(store.encode(made.acts, made.lineage, made.next, synced_at))
    return ("epoch_superseded" if made.next == "yes" else made.reason), synced_at


def run(inp, profiles, vitni, render_size, probe, port, clock):
    """The `{reason, synced_at}` of `sync` for `inp` over the pin `probe`, the store `port`, `vitni`
    (the memo of the call) and the `clock`."""
    try:
        answer = probe.read(inp.org)
        index = snapshot.by_hash(inp)
        lineage, ends = _pinned_path(index, inp.org, answer)
        pinfile.check(answer, inp.org, profiles, ends, False)
        reason, synced_at = _write(inp, index, lineage, profiles, vitni, render_size, port, clock)
    except errors.Refused as err:
        return {"reason": err.code, "synced_at": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "synced_at": None}
    return {"reason": reason, "synced_at": synced_at}
