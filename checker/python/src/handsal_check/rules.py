"""`check-act` from step 7 on (VR-02): the context, the ordered steps, and the steps that read the fold.

`context` is built once from the fold: the last epoch (its policy), the tip node (the state `check-act`
judges the key in), the signer's device in that state, and the positions of the accepted chain. `STEPS`
is the single ordered list of steps 7 to 16; each takes the context and raises Refused or returns:

  7  org              the act's `org` is the pin's (GP-04)                          `org_mismatch`
  8  relay            `rules_replay`
  9  verify           vitni, with the fold `keys` or the one-entry map (VR-03)
  10 low_s            S above n/2 (VR-04)
  11 identity, 12 request, inputs, outputs      `rules_hash`
  13 time, 14 view, witness                     `rules_time`
  15 duplicate                                  `rules_ingest`
  16 proven           the key is accepted (KC-04)                                   `unproven_class`

`class` of a result, from step 7 on, is `device_class`: the class of the device in the pinned state whose
kid is the header kid, else None (VR-01). Whether it is accepted is not part of it.
"""
from collections import namedtuple

from . import errors, rules_hash, rules_ingest, rules_replay, rules_time, tree, verifier
from .state import point_obj

Ctx = namedtuple("Ctx", "inp kid signature payload act receipt epoch node pin vitni device positions")


def context(inp, parsed, payload, receipt, epochs, node, pin, vitni):
    """The `Ctx` of an act that passed steps 1 to 6; `parsed` is its `jws.Jws`."""
    return Ctx(inp, parsed.kid, parsed.signature, payload, payload["ext"]["dev.handsal/act"], receipt,
               epochs[-1], node, pin, vitni, node.state.devices.get(parsed.kid),
               tree.positions(node))


def device_class(ctx):
    """The `class` field of a result from step 7 on."""
    return ctx.device.cls if ctx.device is not None else None


def org(ctx):
    """Step 7."""
    if ctx.act["org"] != ctx.pin.org:
        raise errors.Refused("org_mismatch")


def _keys(ctx):
    """The vitni keys map (VR-03): the fold `keys`, except for a signer that is a device with
    `accepted:false`, whose key is still verified from a one-entry map keyed by its person, so a bad
    signature is `bad_signature` before step 16 can say `unproven_class`."""
    device = ctx.device
    if device is None or device.accepted:
        return ctx.node.state.keys_map()
    status = "active" if device.status == "active" else "revoked"
    return {device.person: {ctx.kid: verifier.key_entry(point_obj(device.sign), status)}}


def verify(ctx):
    """Step 9: vitni's reason, the four pass-through ones unchanged, any other `verifier_unexpected`."""
    reason = verifier.classify(ctx.vitni.verify(ctx.inp.jws, _keys(ctx), ctx.inp.expect_method))
    if reason != "ok":
        raise errors.Refused(reason)


def low_s(ctx):
    """Step 10."""
    if not verifier.is_low_s(ctx.signature):
        raise errors.Refused("high_s")


def proven(ctx):
    """Step 16: `ok` only for an accepted key."""
    if not ctx.device.accepted:
        raise errors.Refused("unproven_class")


relay = rules_replay.relay
identity, request, inputs, outputs = rules_hash.identity, rules_hash.request, rules_hash.inputs, rules_hash.outputs
time, view, witness = rules_time.time, rules_time.view, rules_time.witness
duplicate = rules_ingest.duplicate

STEPS = (org, relay, verify, low_s, identity, request, inputs, outputs, time, view, witness, duplicate, proven)
