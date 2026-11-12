"""A relay tip statement for tests (WT-02): a JWS over the act envelope signed, in stand-in form, by the
fixture relay key. Built from the spec text, never through a checker validator."""
import copy

from handsal_check import encoding

from .act_builder import GOOD, build
from .genesis_fixtures import KEYS

RELAY_KID = KEYS["relay-fixture"]["kid"]
METHOD = "relay.tip"
NEXT_NO = "no"


def _prune(payload):
    del payload["ext"]["dev.handsal/act"]["kid"]   # a statement has no act-object kid (ACT-14 does not apply)


def statement(*, epoch, tip, org, next=NEXT_NO, ts="2026-11-08T11:59:00Z", sig=GOOD, kid=RELAY_KID, body=None,
              performer="relay", edit=None, head=None, salt="", **over):
    """The statement of `epoch` (a document hash), `tip` (a position id of that epoch) and `org`."""
    stmt_body = body if body is not None else {"epoch": epoch, "next": next, "tip": tip}

    def shape(payload):
        _prune(payload)
        if edit:
            edit(payload)
    fields = dict(org=org, body=stmt_body, performer=performer, ts=ts, sig=sig, kid=kid, head=head, salt=salt,
                  edit=shape)
    fields.update(over)
    return build("relay", METHOD, **fields)
