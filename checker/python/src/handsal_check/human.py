"""The methods `check-act` decides: verdicts and `decision` (VR-02 step 4). Every other
registry method is a chain method, decided by the fold, never by `check-act`."""
PREFIX = "local:handsal.request."
VERDICTS = frozenset((PREFIX + "approve", PREFIX + "reject", PREFIX + "needs-info"))
DECISION = "local:handsal.decision"
HUMAN_METHODS = VERDICTS | {DECISION}


def verdict_name(method):
    """`approve`, `reject` or `needs-info` for a verdict method (ACT-09: the verdict in `outputs_hash`)."""
    return method[len(PREFIX):]
