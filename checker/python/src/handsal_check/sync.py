"""`sync` (CF-09): the one writer of the per-machine store, production build only.

`handsal-check sync < {acts, lineage, org}`: `acts` and `lineage` as GP-07 (`acts` may be empty), `org` a hashstr,
and no other key (`pin`, `now`, `synced_at`, `tip_statement`, `witness` are `malformed_input`). Steps, first
failure wins, and nothing is written on a failure:

  1  framing and shape                              `unparseable_input`, `malformed_input` (the table)
  2  the pin and the lineage                        VR-02 step 6 (a) to (h), fixture profile refused; before the
                                                    lock and before any directory exists
  3  the lock, then the old store, inside it        absent is the empty set; `store_owner`, `store_malformed`,
                                                    `store_unavailable` refuse and an old store is never overwritten
  4  the union of the stored and the input acts     sorted, deduplicated; over MAX_INPUT is `store_full`
  5  the fold of the union under the input lineage  a state or `fork` continues; any other code and
                                                    `verifier_unavailable` refuse
  6  the clock, read once, then the write           an I/O failure is `store_unavailable`, the old store stays

Output `{reason, synced_at}`: `synced_at` is not null exactly when a store was written, and `reason` is then `ok`
or `fork`; a refusal is its code and null. The set of acts only grows, because the writer holds the union: a store
with fewer acts than before cannot be written (CF-09). The pin probe, the store port and the clock are arguments,
as for the production table; no input reaches them.
"""
from collections import namedtuple

from . import epoch, errors, fold_out, foldcmd, ijson, pinfile, schema, store, verifier

Input = namedtuple("Input", "acts lineage org")


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-09), or raise Malformed."""
    if type(value) is not dict or set(value) != set(Input._fields):
        raise errors.Malformed()
    acts, lineage, org = value["acts"], value["lineage"], value["org"]
    if type(acts) is not list or type(lineage) is not list or not schema.is_hashstr(org):
        raise errors.Malformed()
    foldcmd.check_texts(acts)
    foldcmd.check_lineage(lineage)
    return Input(acts, lineage, org)


def _write(inp, reg, profiles, vitni, render_size, port, clock):
    """Steps 3 to 6 under the lock: `(reason, synced_at)` of the store written."""
    with port.lock(inp.org) as held:
        raw = held.read()
        old = store.NOTHING if raw is None else store.parse(raw)
        acts = store.canonical(old.acts + inp.acts)
        if len(store.encode(acts, inp.lineage, store.SIZING_TIME)) > ijson.MAX_INPUT:
            raise errors.Refused("store_full")
        epochs = epoch.fold_lineage(inp.lineage, acts, reg, profiles, False, vitni, render_size)
        reason = fold_out.view(epochs, None).error or "ok"   # at the tip the only error is `fork`: a verdict
        synced_at = clock()
        held.write(store.encode(acts, inp.lineage, synced_at))
    return reason, synced_at


def run(inp, reg, profiles, vitni, render_size, probe, port, clock):
    """The `{reason, synced_at}` of `sync` for `inp` over the pin `probe`, the store `port`, the verifier
    `vitni` and the `clock`."""
    vitni = verifier.Memoized(vitni)
    try:
        pinfile.check(probe.read(inp.org), inp.org, profiles, pinfile.ends(inp.lineage), False)
        reason, synced_at = _write(inp, reg, profiles, vitni, render_size, port, clock)
    except errors.Refused as err:
        return {"reason": err.code, "synced_at": None}
    except verifier.VerifierUnavailable:
        return {"reason": "verifier_unavailable", "synced_at": None}
    return {"reason": reason, "synced_at": synced_at}
