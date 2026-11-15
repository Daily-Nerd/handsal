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
  4  the union of the stored and the input acts     sorted, deduplicated; over MAX_INPUT is `store_full`
  5  the fold of the union under the pinned path     a state or `fork` continues; any other code and
                                                    `verifier_unavailable` refuse
  6  the clock, read once, then the write           an I/O failure is `store_unavailable`: before the rename the
                                                    old store stays; at the directory `fsync` after it the new
                                                    store may be visible (a superset, a later `sync` converges)

Output `{reason, synced_at}`: `synced_at` is not null exactly when the store was written and made durable, and `reason` is then `ok`
or `fork`; a refusal is its code and null. The set of acts only grows, because the writer holds the union: a store
with fewer acts than before cannot be written (CF-09). The pin probe, the store port and the clock are arguments,
as for the production table; no input reaches them.
"""
from . import epoch, errors, fold_out, ijson, pinfile, snapshot, store, verifier

Input = snapshot.Snapshot


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-09, CF-13), or raise Malformed."""
    return snapshot.parse(value)[0]


def _pinned_path(inp, answer):
    """`(path, ends)`: the entries from the original to the pin's `genesis` out of `inp.docs`, and the ends
    `pinfile.check` compares with the pin. `answer` is the probe's. A pin that does not parse is refused by that
    check before any comparison with the ends, so they are None then, which is the empty lineage."""
    try:
        genesis = pinfile.parse(answer.raw).genesis
    except errors.Refused:
        return [], None
    path = snapshot.path_to(inp, genesis)
    if path:
        return path, pinfile.ends(path)
    if path is None:   # the pinned document is absent: a lineage whose last document is none
        return [], pinfile.Ends(inp.org if inp.org in snapshot.by_hash(inp) else None, None, None)
    return [], None   # a missing link


def _write(inp, lineage, reg, profiles, vitni, render_size, port, clock):
    """Steps 3 to 6 under the lock: `(reason, synced_at)` of the store written. `lineage` is the pinned path."""
    with port.lock(inp.org) as held:
        raw = held.read()
        old = store.NOTHING if raw is None else store.parse(raw)
        acts = store.canonical(old.acts + inp.acts)
        if len(store.encode(acts, lineage, store.SIZING_TIME)) > ijson.MAX_INPUT:
            raise errors.Refused("store_full")
        epochs = epoch.fold_lineage(lineage, acts, reg, profiles, False, vitni, render_size)
        reason = fold_out.view(epochs, None).error or "ok"   # at the tip the only error is `fork`: a verdict
        synced_at = clock()
        held.write(store.encode(acts, lineage, synced_at))
    return reason, synced_at


def run(inp, reg, profiles, vitni, render_size, probe, port, clock):
    """The `{reason, synced_at}` of `sync` for `inp` over the pin `probe`, the store `port`, the verifier
    `vitni` and the `clock`."""
    vitni = verifier.Memoized(vitni)
    try:
        answer = probe.read(inp.org)
        lineage, ends = _pinned_path(inp, answer)
        pinfile.check(answer, inp.org, profiles, ends, False)
        reason, synced_at = _write(inp, lineage, reg, profiles, vitni, render_size, port, clock)
    except errors.Refused as err:
        return {"reason": err.code, "synced_at": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "synced_at": None}
    return {"reason": reason, "synced_at": synced_at}
