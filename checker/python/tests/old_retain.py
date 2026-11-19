"""The way `retain` once judged one endorsement text alone, kept here as a reference for the tests that compare it
with the way it is judged now: the epoch of the base document over the act and that one text, read again from
strings. The tests own this copy; the source no longer has it."""
from collections import namedtuple

from handsal_check import chain, endorse, fold, quorum

Endorsement = namedtuple("Endorsement", "kid text alone")


def over(base, texts):
    """The epoch of `base`'s document, its policy and its earlier keys, over the bag of `texts` (read on the wire of
    `base`'s own bag: one wire for the whole lineage)."""
    return fold.Epoch(base.doc, chain.Bag(texts, base.bag.wire, base.bag.org), base.profile, base.vitni, base.earlier)


def read_endorsements(base, parsed, texts):
    """`[Endorsement(kid, text, alone)]` for each distinct text of `texts` that reads as an endorsement of the act
    `parsed` (FO-08), in byte order; `alone` is `base` over the act and that text only."""
    found = []
    for text in sorted(set(texts)):
        alone = over(base, [parsed.jws, text])
        groups = alone.bag.endorsements_of(parsed)
        if groups:
            found.append(Endorsement(groups[0].copies[0].kid, text, alone))
    return found


def kept_endorsements(base, parent, parsed, readings):
    """The texts of `readings` (`read_endorsements`) that count for the act `parsed` at the node `parent`, sorted: a
    kid of the state or the new key, each judged in its own epoch `alone`, asked with its own signer's entry."""
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
