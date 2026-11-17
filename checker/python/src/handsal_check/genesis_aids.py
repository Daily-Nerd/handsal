"""`genesis-aids` (CF-03, SG-12 steps 6 and 7): what the ceremony shows about the previous epoch of a change.

Input `{acts, lineage}`, the `genesis-check` input and nothing else: the answer is a function of it, so the command
reads no pin, no clock and no store and is wired like `genesis-check` (no `fill`). It folds the lineage as
`genesis-check` does (`genesis_check.fold`, the same epochs), so a lineage that `genesis-check` refuses is refused
here with the same code, and then reads the last link: the candidate document against the epoch before it.

Output `{aids, reason}`. `aids` is null for a lineage of one document, which has no previous epoch, and for a refused
lineage (`reason` is the first failing code, or `verifier_unavailable`). For a change it is `{head, removed}`:

  head     H, the `head` of the candidate, against the accepted chain of the previous epoch (`fork.walk`):
             `{at:"tip", place:"tip"|"not_tip", tip:T}`   the chain ends at T, and H is T or is not
             `{at:"fork", parent:P, candidates:[c, ...], place:"parent"|"below"|"not_below", candidate:c|null}`
                  the chain ends at the fork at P; H is P, lies at or below candidate c (a candidate counts as
                  below itself: H equal to c is the top of its branch), or lies elsewhere in the epoch
  removed  the sorted kids that the candidate carries, or whose key signed one of its `genesis.sign` receipts, and
           that a valid `device.remove` removes at some node of the previous epoch's act tree

The act tree holds every valid primary of the epoch, the branches a `chain.resolve` discarded and the branches
beyond a fork included (`fold.Epoch.build`), so a removal anywhere in it counts, and a fork inside a branch is no
reason to stop: these are aids, never a boundary (L4, L5), and the facts are the checker's, not the ceremony's.
"""
from . import fork, genesis, genesis_check, genesis_sigs, render_genesis, tree

parse_input = genesis_check.parse_input


def _head(previous, head):
    """The `head` object for the node `head` (an id of the previous epoch's tree) against its accepted chain."""
    walked = fork.walk(previous)
    if walked.fork is None:
        tip = walked.chain[-1].id
        return {"at": "tip", "place": "tip" if head == tip else "not_tip", "tip": tip}
    parent, candidates = walked.fork.parent.id, walked.fork.candidates
    above = {node.id for node in tree.path_from_root(previous.nodes[head])}
    found = next((c for c in candidates if c in above), None)
    place = "parent" if head == parent else "below" if found is not None else "not_below"
    return {"at": "fork", "candidate": found, "candidates": candidates, "parent": parent, "place": place}


def _removed(previous, doc, sigs, org, wire):
    """The kids of `doc`, or that signed one of its receipts, that some node of `previous` removes."""
    doc_hash = genesis.doc_hash(doc)
    named = {entry["kid"] for entry in doc["devices"]}
    for text in sigs:
        act = genesis_sigs.read(text, doc, doc_hash, org, wire)
        if act is not None:
            named.add(act.kid)
    return sorted(named & tree.removed_kids(previous.nodes.values()))


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The aids of the last link of the lineage, or the code `genesis-check` gives."""
    epochs, code = genesis_check.fold(inp, profiles, allow_fixture, vitni, render_size)
    if epochs is None:
        return {"aids": None, "reason": code}
    if len(epochs) == 1:
        return {"aids": None, "reason": "ok"}
    previous, last = epochs[-2], epochs[-1]
    previous.build()
    sigs = inp.lineage[-1]["sigs"]
    removed = _removed(previous, last.doc, sigs, epochs[0].root.id, profiles.wire)
    return {"aids": {"head": _head(previous, last.doc["head"]), "removed": removed}, "reason": "ok"}
