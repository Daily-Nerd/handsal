"""The fold result (FO-01, FO-02, FO-03, FO-16): `view` picks the node, `result` writes the object.

`view` walks the last epoch (`fork.walk`) and applies `at`: an `n` at or before the last accepted node
is that prefix state, also when the chain ends at a fork parent; an `n` beyond the tip is
`at_beyond_tip`, an `n` beyond a fork parent or no `n` at a fork is `fork`.

`result` is `{devices, keys, org, org_name, policy, spec, tip}`. `devices` lists every device of the
state with its `accepted` flag. `keys` is the projection of the same state to the vitni keys map,
computed by `State.keys_map` and nowhere else: the accepted devices only, so a consumer that hands it
to vitni can never get `ok` for an unproven key. A person with no accepted device has no entry. An
error carries no `keys`. `tip.n` is derived, never signed; its JSON type is `_tip_n` (FO-01: a decimal string).
"""
from collections import namedtuple

from . import fork
from .state import point_obj

def _tip_n(n):
    """The JSON form of `tip.n`: the ONE place that decides its type, a decimal string (FO-01)."""
    return str(n)


View = namedtuple("View", "node error fork")   # node: the Node of the result; error: a code or None


def view(epochs, at):
    """The node the fold reports for `at` (None: the tip), or the error `fork` / `at_beyond_tip`."""
    last = epochs[-1]
    last.build()
    walked = fork.walk(last)
    chain = walked.chain
    if at is not None and int(at) < len(chain):
        return View(chain[int(at)], None, None)
    if walked.fork is not None:
        return View(None, "fork", walked.fork)
    if at is not None:
        return View(None, "at_beyond_tip", None)
    return View(chain[-1], None, None)


def class_of(state, kid):
    """The class of the device `kid` in `state`, or None when the state has no such device."""
    device = state.devices.get(kid)
    return device.cls if device is not None else None


def _devices(state):
    out = {}
    for kid, device in state.devices.items():
        out.setdefault(device.person, {})[kid] = {
            "accepted": device.accepted, "agree": point_obj(device.agree), "class": device.cls,
            "label": device.label, "sign": point_obj(device.sign), "status": device.status}
    return out


def result(epochs, at):
    """The FO-01 result object for `epochs` and the optional `at` (a decimal string)."""
    found = view(epochs, at)
    if found.error == "fork":
        return {"error": "fork", "fork": {"candidates": found.fork.candidates, "parent": found.fork.parent.id}}
    if found.error is not None:
        return {"error": found.error}
    last, node = epochs[-1], found.node
    return {"devices": _devices(node.state), "keys": node.state.keys_map(),
            "org": epochs[0].root.id, "org_name": last.doc["name"], "policy": last.doc["policy"],
            "spec": last.doc["profile"], "tip": {"genesis": last.root.id, "id": node.id, "n": _tip_n(node.n)}}
