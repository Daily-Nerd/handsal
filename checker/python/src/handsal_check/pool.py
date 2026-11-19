"""`pool` (CF-12): is a point an `agree` key the organization introduced, at any time, on any branch.

Input `{acts, agree, docs, org}`: `agree` is `{x, y}` in the ACT-11 form (a point not on the curve is
`malformed_input`) and the rest is the snapshot of CF-13. The store checks are those of `admit` (`open_store`).
Output `{in_pool, reason}`: `in_pool` is true only with `ok`, else false with `not_in_pool` or a store code.

Membership reads the fold's own states: the `agree` point of any device of the state of any node of the act
tree of any admitted epoch, the root included (it holds the devices the document lists). Every branch counts,
the losing and forked ones too, and a removed device stays in its state. A `sign` point is not in the pool, and a
pending act is no node. Documents and nodes are permanent and FO-07 never re-admits a removed kid, so a `true`
for a store is `true` for every larger store (I4): a caller may cache `true` and must not cache `false`.
"""
from collections import namedtuple

from . import admit, devicekey, errors, render_genesis, snapshot, verifier

Input = namedtuple("Input", "snapshot agree")


def parse_input(value):
    """The `Input` of the command JSON `value` (CF-12), or raise Malformed; `agree` is the point `(x, y)`."""
    snap, rest = snapshot.parse(value, extra=("agree",))
    if not devicekey.point_ok(rest["agree"]):
        raise errors.Malformed()
    return Input(snap, (rest["agree"]["x"], rest["agree"]["y"]))


def _introduced(epochs, agree):
    for found in epochs.values():
        found.build()
        if any(device.agree == agree for node in found.nodes.values() for device in node.state.devices.values()):
            return True
    return False


def run(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{in_pool, reason}` of `pool` for `inp` over `vitni`, the memo of the call."""
    try:
        epochs = admit.open_store(inp.snapshot, profiles, allow_fixture, vitni, render_size)
    except errors.Refused as err:
        return {"in_pool": False, "reason": err.code}
    except verifier.VerifierUnavailable:
        return {"in_pool": False, "reason": "verifier_unavailable"}
    if _introduced(epochs, inp.agree):
        return {"in_pool": True, "reason": "ok"}
    return {"in_pool": False, "reason": "not_in_pool"}
