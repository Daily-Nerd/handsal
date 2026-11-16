"""The ordered pipeline of one non-chain act (VR-02), shared by `check-act` and `recheck-act`.

`judge` runs steps 1 to 6 (the act by itself, the pin and the fold), picks the node whose state is judged
(`locate`: the tip for `check-act`, the act's own head for `recheck-act`) and runs `steps` over it. It returns
a `Verdict`: `reason` is `ok` or the first failure, `receipt` and `cls` are filled as soon as they are known
(VR-01). A verifier that cannot answer is the reason `verifier_unavailable`, at the fold or at step 9: never a
skip. Each command only chooses `locate` and `steps` and writes the verdict in its own output shape, so the
steps both run exist once.
"""
from collections import namedtuple

from . import envelope, errors, jws, pinned, render_genesis, rules, verifier
from .human import HUMAN_METHODS

Verdict = namedtuple("Verdict", "reason receipt cls")


def parse_act(inp, wire):
    """Steps 1 to 5: `(jws, payload, receipt id)` of a well-formed human act, or the failing `Verdict`."""
    try:
        parsed = jws.parse(inp.jws)
        payload = envelope.parse_payload(parsed.payload)
    except errors.Refused as err:
        return Verdict(err.code, None, None)
    receipt = envelope.receipt_id(parsed.payload)
    try:
        envelope.check_envelope(payload)
        if wire.method(payload["method"]) is None:
            raise errors.Refused("method_unknown")
        if payload["method"] not in HUMAN_METHODS:
            raise errors.Refused("chain_method")
        envelope.check_act_object(payload, parsed.kid, wire)
    except errors.Refused as err:
        return Verdict(err.code, receipt, None)
    return parsed, payload, receipt


def tip(epochs, payload, inp):
    """`check-act` examines the key in the state at the tip (VR-12); `inp.next` says whether the pin is superseded."""
    return pinned.tip(epochs, inp.next)


def head(epochs, payload, inp):
    """`recheck-act` examines the key in the state at the act's own head, in the epoch the lineage proves it
    belongs to (VR-17)."""
    return pinned.head(epochs, payload["ext"]["dev.handsal/act"]["head"]["id"])


def judge(inp, profiles, allow_fixture, vitni, render_size=render_genesis.render_size, *, locate, steps):
    """The `Verdict` for `inp` over the `(epoch, node)` that `locate(epochs, payload, inp)` picks and the ordered
    `steps`."""
    early = parse_act(inp, profiles.wire)
    if type(early) is Verdict:
        return early
    parsed, payload, receipt = early
    vitni = verifier.Memoized(vitni)
    try:
        pin, epochs = pinned.folded(inp.pin, inp.org, inp.lineage, inp.acts, profiles, allow_fixture,
                                    vitni, render_size, inp.store_reason)
        epoch, node = locate(epochs, payload, inp)
    except errors.Refused as err:
        return Verdict(err.code, receipt, None)
    except verifier.VerifierUnavailable:
        return Verdict("verifier_unavailable", receipt, None)
    ctx = rules.context(inp, parsed, payload, receipt, epoch, node, pin, vitni)
    cls = rules.device_class(ctx)
    try:
        for step in steps:
            step(ctx)
    except errors.Refused as err:
        return Verdict(err.code, receipt, cls)
    except verifier.VerifierUnavailable:
        return Verdict("verifier_unavailable", receipt, cls)
    return Verdict("ok", receipt, cls)
