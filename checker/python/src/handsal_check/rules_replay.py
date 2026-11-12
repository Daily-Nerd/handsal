"""Relay and replay across contexts (VR-08, VR-09, VR-10): VR-02 step 8.

A verdict names the relay it was made for; the verifier supplies its own (VR-01). One verdict per
request and recipient is the consumer's to keep (VR-09); the checker's only duty there is
`duplicate_receipt` (`rules_ingest`). A swapped org, relay, `request_id` or `inputs_hash` fails with its
own reason: `org_mismatch` (`rules.org`), `relay_mismatch` here, `bad_signature` from vitni for an
edited payload, `inputs_mismatch` (`rules_hash`).
"""
from . import errors, human


def relay(ctx):
    """Step 8: a verdict made for another relay than the verifier's is `relay_mismatch`."""
    if ctx.payload["method"] in human.VERDICTS and ctx.act["relay"] != ctx.inp.relay:
        raise errors.Refused("relay_mismatch")
