"""`pool` (CF-12): is a point an `agree` key the organization introduced, at any time, on any branch.

Input `{acts, agree, docs, org}`: `agree` is `{x, y}` in the ACT-11 form (a point not on the curve is
`malformed_input`) and the rest is the snapshot of CF-13. The store checks are those of `admit` (`opening.open_store`).
Output `{in_pool, reason}`: `in_pool` is true only with `ok`, else false with `not_in_pool`, a store code or
`verifier_unavailable`, whether the verifier fails at a document or while the act tree is built.

Membership reads the fold's own states: the `agree` point of any device of the state of any node of the act
tree of any admitted epoch, the root included (it holds the devices the document lists). Every branch counts,
the losing and forked ones too, and a removed device stays in its state. It reads the devices the root lists and
the one each node's act introduces, which together are the devices of every state: a state is its parent's plus
the device its act introduces, and a removal or a resolve keeps the agree points as they were. A `sign` point is not in the pool, and a
pending act is no node. Documents and nodes are permanent and FO-07 never re-admits a removed kid, so a `true`
for a store is `true` for every larger store (I4): a caller may cache `true` and must not cache `false`.
"""
from collections import namedtuple

from . import devicekey, errors, opening, quorum, render_genesis, snapshot, verifier

Input = namedtuple("Input", "snapshot agree")


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-12), or raise Malformed; `agree` is the point `(x, y)`."""
    snap, rest = snapshot.parse(value, extra=("agree",))
    if not devicekey.point_ok(rest["agree"]):
        raise errors.Malformed()
    return Input(snap, (rest["agree"]["x"], rest["agree"]["y"]))


def agree_points(epochs):
    """The `agree` point of every device any epoch of `epochs` introduced: the devices its document lists, then the
    one each node's act introduces. Each epoch is built when the walk reaches it, so a caller that stops early
    leaves the later epochs unbuilt, and one that takes every point asks every question the walk needs. A point
    may come more than once (a device that stays in a later document)."""
    for found in epochs.values():
        found.build()
        for device in found.root.state.devices.values():
            yield device.agree
        for node in found.nodes.values():
            new = None if node.act is None else quorum.introduced(node.act)
            if new is not None:
                yield node.state.devices[new[1]].agree


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{in_pool, reason}` of `pool` for `inp` over `vitni`, the memo of the call."""
    try:
        epochs = opening.open_store(inp.snapshot, profiles, allow_fixture, vitni, render_size)
        # an epoch is built as the walk reaches it, so the questions of the last ones are asked here, and only if needed
        found = any(point == inp.agree for point in agree_points(epochs))
    except errors.Refused as err:
        return {"in_pool": False, "reason": err.code}
    except verifier.VerifierUnavailable:
        return {"in_pool": False, "reason": "verifier_unavailable"}
    return {"in_pool": True, "reason": "ok"} if found else {"in_pool": False, "reason": "not_in_pool"}
