"""Identity, `inputs_hash` and `outputs_hash` (VR-05, VR-06, VR-07): VR-02 steps 11 and 12.

`identity`: a verdict's `performer_id` is its `recipient`. `request`: the act's `request_id` and
`recipient` are the ones the consumer expects. `inputs`: the raw bytes (never re-canonicalized) hash to
`inputs_hash`. `outputs`: a verdict's `outputs_hash` is the hash of the canonical object
`{"request_id": R, "verdict": V}` (ACT-09).

VR-07 is the single owner of `outputs_hash`: for `record.promote` the value is EMPTY_HASH (ACT-09). A
mismatch is `outputs_mismatch` for both.
"""
from . import emit, encoding, errors, human


def identity(ctx):
    """Step 11: for a verdict, `performer_id` equals `recipient` (`identity_mismatch`)."""
    if ctx.payload["method"] in human.VERDICTS and ctx.payload["performer_id"] != ctx.act["recipient"]:
        raise errors.Refused("identity_mismatch")


def request(ctx):
    """Step 12 (a): the act's `request_id` and `recipient` equal the inputs (`request_mismatch`)."""
    if ctx.payload["method"] in human.VERDICTS and (
            ctx.act["request_id"] != ctx.inp.request_id or ctx.act["recipient"] != ctx.inp.recipient):
        raise errors.Refused("request_mismatch")


def inputs(ctx):
    """Step 12 (b): the bytes the consumer holds hash to `inputs_hash` (`inputs_mismatch`)."""
    raw = ctx.inp.request_bytes if ctx.payload["method"] in human.VERDICTS else ctx.inp.record_bytes
    if encoding.hashstr(raw) != ctx.payload["inputs_hash"]:
        raise errors.Refused("inputs_mismatch")


def outputs(ctx):
    """Step 12 (c): `outputs_hash` is what ACT-09 derives: for a verdict from the verdict and the request
    id, for `record.promote` EMPTY_HASH."""
    method = ctx.payload["method"]
    if method == human.PROMOTE:
        expected = encoding.EMPTY_HASH
    else:
        expected = encoding.hashstr(emit.emit_subset(
            {"request_id": ctx.act["request_id"], "verdict": human.verdict_name(method)}))
    if expected != ctx.payload["outputs_hash"]:
        raise errors.Refused("outputs_mismatch")
