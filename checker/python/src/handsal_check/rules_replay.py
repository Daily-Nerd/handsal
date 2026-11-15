"""Relay and replay across contexts (VR-08, VR-09, VR-10): VR-02 step 8.

A verdict names the relay it was made for, and the policy of the state the step reads lists the relays an
organization accepts (GP-02): the host is an org-wide fact with one owner, so it is no input (VR-08). One
verdict per request and recipient is the consumer's to keep (VR-09); the checker's only duty there is
`duplicate_receipt` (`rules_ingest`). A swapped org, relay, `request_id` or `inputs_hash` fails with its
own reason: `org_mismatch` (`rules.org`), `relay_mismatch` here, `bad_signature` from vitni for an
edited payload, `inputs_mismatch` (`rules_hash`).
"""
from . import errors, human


def relay(ctx):
    """Step 8: a verdict whose relay the policy of the epoch judged does not list is `relay_mismatch`. That epoch
    is the tip's for `check-act` and the head's own for `recheck-act` (VR-17), so a rename never breaks history."""
    if ctx.payload["method"] in human.VERDICTS and ctx.act["relay"] not in ctx.epoch.policy["relays"]:
        raise errors.Refused("relay_mismatch")
