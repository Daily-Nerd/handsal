"""Duplicate receipt, the ingestion contract and verifier-side limits (VR-14, VR-15, VR-16): step 15.

`seen` holds only the receipt ids of acts the consumer previously found valid, so a presented act whose
receipt id is in it is `duplicate_receipt`. An invalid twin was never found valid, so it is never in
`seen` and cannot make the consumer refuse the valid act later (VR-14). The recording itself is the
consumer's duty: `check-act` is pure and a result carries `receipt_id` and `class` for the record. The
payload limit (VR-16) is enforced where the payload is read, before any other work (`jws`, `subset`).
"""
from . import errors


def duplicate(ctx):
    """Step 15."""
    if ctx.receipt in ctx.inp.seen:
        raise errors.Refused("duplicate_receipt")
