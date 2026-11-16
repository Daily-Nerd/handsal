"""`compact` (CF-14): what a store may drop, as lists, for the store's operator to delete.

Input: exactly the snapshot of CF-13 (`snapshot.parse`), `{acts, docs, org}`, and nothing else. The store checks are
those of `admit` without the registration case (`admit.open_store`): no original is `lineage_broken`, every
document a valid link or its GP-15 code, a fixture profile `fixture_profile` unless the build allows it, and a
verifier that cannot answer is `verifier_unavailable`. Nothing here is a rule of its own: the retained set is
`retain.retained` over every document of the store (each epoch with a stored successor is closed), and the lists
are `retain.dropped`.

Output `{"drop":{"acts":A,"sigs":G},"reason":"ok"}`, A every string of `acts` the retained set does not hold and G
every receipt text of a document's `sigs` that no document keeps, both sorted and unique and possibly empty; a
refusal is `{"drop":null,"reason":R}`. It writes nothing: the caller deletes what `drop` lists, any prefix of it
is safe, and a second call over the result drops nothing. It reads no pin, no clock and no store (server and
conformance builds, `commands.admission`).
"""
from . import admit, errors, render_genesis, retain, snapshot, verifier

Input = snapshot.Snapshot


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-14, CF-13), or raise Malformed."""
    return snapshot.parse(value)[0]


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{drop, reason}` of `compact` for `inp` over the verifier `vitni`."""
    vitni = verifier.Memoized(vitni)
    try:
        epochs = admit.open_store(inp, profiles, allow_fixture, vitni, render_size)
        kept = retain.retained(epochs, retain.closing_heads(inp.docs), inp)
    except errors.Refused as err:
        return {"drop": None, "reason": err.code}
    except verifier.VerifierUnavailable:
        return {"drop": None, "reason": "verifier_unavailable"}
    acts, sigs = retain.dropped(inp, kept)
    return {"drop": {"acts": acts, "sigs": sigs}, "reason": "ok"}
