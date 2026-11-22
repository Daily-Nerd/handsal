"""`agree-points`: the `agree` points of the devices an organization has (`active`) and has ever introduced (`pool`).

Input: exactly the snapshot of CF-13 (`snapshot.parse`), `{acts, docs, org}`, and nothing else. The store checks are
those of `compact` (`opening.open_store`, no registration case): no original is `lineage_broken`, a document that is no
valid link its GP-15 code, a fixture profile `fixture_profile` unless the build allows it, and a verifier that cannot
answer is `verifier_unavailable`. It reads no pin, no clock and no store.

Output `{"active":A,"pool":P,"reason":"ok"}`, A and P lists of points `{x, y}` (ACT-11), unique and sorted by `x` then
`y`, possibly empty; a refusal is `{"active":null,"pool":null,"reason":R}`, so a null never stands for an empty set and
a code never comes with a list. An input that is no snapshot is `malformed_input`, written by `core.run` like every
command's.

Nothing here is a rule of its own. `pool` is the membership of CF-12 (`pool.agree_points`) taken as a set. `active`
reads the walk of each open epoch (an epoch with no stored successor, sibling successors included): where `fork.walk`
ends at a tip, the devices of its state; where it ends at a fork, the devices of the state of every leaf below the
candidates the walk names (every child: a fork is where no current resolve chose). A device
counts only where `tree.clean` says it is active and accepted, the test `enrolled` applies to a tip. A point counts if
any holder in any branch or epoch does, so an `active` point is always a `pool` point. The answer is a function of the
canonical snapshot and is not monotone under admission (a removal takes a point out of `active`).
"""
from . import errors, fork, opening, pool, render_genesis, retain, snapshot, state, tree, verifier

Input = snapshot.Snapshot


def parse_input(value):
    """The `Input` of the command JSON `value`, or raise Malformed."""
    return snapshot.parse(value)[0]


def _leaves(found, walked):
    """The nodes whose states count for the epoch `found`: the tip of the walk, or the leaves below the candidates
    of the fork it ends at."""
    if walked.fork is None:
        return [walked.chain[-1]]
    below = []
    for top in (found.nodes[child] for child in walked.fork.candidates):
        below.extend(node for node in [top] + tree.subtree(top) if not node.children)
    return below


def _active(found):
    """The agree points of the devices that count in the open epoch `found`."""
    found.build()
    return {device.agree for leaf in _leaves(found, fork.walk(found))
            for kid, device in leaf.state.devices.items() if tree.clean(leaf, kid)}


def _listed(points):
    return [state.point_obj(item) for item in sorted(points)]


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{active, pool, reason}` of `agree-points` for `inp` over `vitni`, the memo of the call."""
    try:
        epochs = opening.open_store(inp, profiles, allow_fixture, vitni, render_size)
        closed = retain.closing_heads(inp.docs)
        members = set(pool.agree_points(epochs))
        active = set()
        for key, found in epochs.items():
            if key not in closed:
                active |= _active(found)
    except errors.Refused as err:
        return {"active": None, "pool": None, "reason": err.code}
    except verifier.VerifierUnavailable:
        return {"active": None, "pool": None, "reason": "verifier_unavailable"}
    return {"active": _listed(active), "pool": _listed(members), "reason": "ok"}
