"""The store of `admit`, `pool`, `compact` and `agree-points`, opened: every document folded under its own path.

`open_store` is the first stage of every command that reads a store. First failure wins: no document whose hash is
`org` with a null `prev` is `lineage_broken` unless the build registers it; a document that no `prev` chain links to
the original is `lineage_broken`; then every document in lineage order (depth, then hash) is folded with its own path,
its GP-15 code on failure; a fixture profile is `fixture_profile` unless the build allows it; a verifier that cannot
answer is `VerifierUnavailable`. It belongs to no one command, so it lives here and not in any of them.
"""
from . import epoch, errors, snapshot


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


def open_store(snap, profiles, allow_fixture, vitni, render_size, registering=False):
    """`{document hash: Epoch}` of the store `snap`, every document folded under its own path in lineage order, or
    raise Refused with the first failing code (the module note). A verifier that cannot answer raises
    VerifierUnavailable."""
    index = snapshot.by_hash(snap)
    if snap.org not in index and not registering:
        raise errors.Refused("lineage_broken")
    tips, start = {}, epoch.Lineage.empty(snap.acts, profiles, allow_fixture, vitni, render_size)
    for key in _lineage_order(index, snap.org):   # parents first: a document is one more link on its parent's fold
        prev = index[key]["doc"].get("prev")
        tips[key] = (start if prev is None else tips[prev]).extend(index[key])
    return {key: tip.last for key, tip in tips.items()}
