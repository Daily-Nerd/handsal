"""Identity, the consumer, `inputs_hash` and `outputs_hash` (VR-05, VR-06, VR-07, VR-18): VR-02 steps 11 and 12.

`identity`: a verdict's `performer_id` is its `recipient`. `request`: a verdict's `request_id` and `recipient`
are the ones the consumer expects (`request_mismatch`), and a decision's `consumer` is the consumer the
verifier is (`consumer_mismatch`). `inputs`: the raw bytes (never re-canonicalized) hash to `inputs_hash`.
`outputs`: a verdict's `outputs_hash` is the hash of the canonical object `{"request_id": R, "verdict": V}`,
a decision's the hash of `{"action": A, "subject": S}` of the words the CALLER expects, and its body says
the same words (VR-18): no consumer compares them again.

VR-07 is the single owner of `outputs_hash`. A mismatch is `outputs_mismatch` for both.
"""
from . import emit, encoding, errors, human


def identity(ctx):
    """Step 11: for a verdict, `performer_id` equals `recipient` (`identity_mismatch`)."""
    if ctx.payload["method"] in human.VERDICTS and ctx.payload["performer_id"] != ctx.act["recipient"]:
        raise errors.Refused("identity_mismatch")


def request(ctx):
    """Step 12 (a): what the act names equals what the consumer expects. A verdict: its `request_id` and
    `recipient` (`request_mismatch`). A decision: its `consumer` (`consumer_mismatch`, VR-18)."""
    method = ctx.payload["method"]
    if method in human.VERDICTS and (
            ctx.act["request_id"] != ctx.inp.request_id or ctx.act["recipient"] != ctx.inp.recipient):
        raise errors.Refused("request_mismatch")
    if method == human.DECISION and ctx.act["body"]["consumer"] != ctx.inp.consumer:
        raise errors.Refused("consumer_mismatch")


def _held_bytes(ctx):
    """The bytes the consumer holds for the act's method (VR-01): the request or the decided content."""
    method = ctx.payload["method"]
    if method in human.VERDICTS:
        return ctx.inp.request_bytes
    return ctx.inp.decision_bytes


def inputs(ctx):
    """Step 12 (b): the bytes the consumer holds hash to `inputs_hash` (`inputs_mismatch`)."""
    if encoding.hashstr(_held_bytes(ctx)) != ctx.payload["inputs_hash"]:
        raise errors.Refused("inputs_mismatch")


def _expected_outputs(ctx):
    method = ctx.payload["method"]
    if method == human.DECISION:
        return encoding.hashstr(emit.emit_subset({"action": ctx.inp.action, "subject": ctx.inp.subject}))
    return encoding.hashstr(emit.emit_subset(
        {"request_id": ctx.act["request_id"], "verdict": human.verdict_name(method)}))


def outputs(ctx):
    """Step 12 (c): `outputs_hash` is what ACT-09 derives: for a verdict from the verdict and the request
    id, for a decision from the caller's expected `action` and `subject`, which
    the act's body must also say."""
    if _expected_outputs(ctx) != ctx.payload["outputs_hash"]:
        raise errors.Refused("outputs_mismatch")
    if ctx.payload["method"] == human.DECISION and (
            ctx.act["body"]["action"], ctx.act["body"]["subject"]) != (ctx.inp.action, ctx.inp.subject):
        raise errors.Refused("outputs_mismatch")   # the hash is the caller's words, the body must say them too
