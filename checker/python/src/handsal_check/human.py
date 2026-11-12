"""The methods `check-act` decides: verdicts and `record.promote` (VR-02 step 4). Every other registry
method is a chain method, decided by the fold, never by `check-act`."""
PREFIX = "local:handsal.request."
VERDICTS = frozenset((PREFIX + "approve", PREFIX + "reject", PREFIX + "needs-info"))
PROMOTE = "local:handsal.record.promote"
HUMAN_METHODS = VERDICTS | {PROMOTE}


def verdict_name(method):
    """`approve`, `reject` or `needs-info` for a verdict method (ACT-09: the verdict in `outputs_hash`)."""
    return method[len(PREFIX):]
