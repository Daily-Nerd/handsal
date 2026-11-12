"""The relay tip statement (WT-02): its exact shape, read once.

A statement is a JWS over the act envelope, so the same recognizers read it: `jws.parse` (ACT-02,
ACT-03), `envelope.parse_payload` (ACT-04, size) and `envelope.check_envelope` (ACT-01, ACT-07).
On top of those it is closed in the ways WT-02 lists: method `local:handsal.relay.tip`, performer
`relay`, both parent fields null, both hashes the empty hash, and `ext` exactly
`{"dev.handsal/act": {"body": {"epoch", "next", "tip"}, "org"}}` with no `head` and no act-object
`kid`. `next` is the string `yes` or `no`, nothing else (WT-10). Any violation is `witness_malformed`
(WT-05 step 2). The signature is not judged here: apart from the header kid, no field of an
unauthenticated statement decides anything (WT-05, step 4 comes first).
"""
from collections import namedtuple

from . import encoding, envelope, errors, jws, schema

METHOD = "local:handsal.relay.tip"
PERFORMER = "relay"
NEXT = ("yes", "no")

Statement = namedtuple("Statement", "jws kid signature org epoch next tip ts")


def _malformed():
    return errors.Refused("witness_malformed")


def _shape(text):
    if type(text) is not str:
        raise _malformed()
    parsed = jws.parse(text)
    payload = envelope.parse_payload(parsed.payload)
    envelope.check_envelope(payload)
    if (payload["method"] != METHOD or payload["performer_id"] != PERFORMER
            or payload["parent_receipt_hash"] is not None or payload["parent_performer_id"] is not None
            or payload["inputs_hash"] != encoding.EMPTY_HASH or payload["outputs_hash"] != encoding.EMPTY_HASH):
        raise _malformed()
    act = payload["ext"][envelope.EXT_KEY]
    if set(act) != {"body", "org"} or not schema.is_hashstr(act["org"]):
        raise _malformed()
    body = act["body"]
    if type(body) is not dict or set(body) != {"epoch", "next", "tip"}:
        raise _malformed()
    if (not schema.is_hashstr(body["epoch"]) or not schema.is_hashstr(body["tip"])
            or type(body["next"]) is not str or body["next"] not in NEXT):
        raise _malformed()
    return Statement(text, parsed.kid, parsed.signature, act["org"], body["epoch"], body["next"], body["tip"],
                     payload["ts"])


def parse(text):
    """The `Statement` in the JWS `text`, or Refused `witness_malformed`."""
    try:
        return _shape(text)
    except errors.Refused:   # every recognizer failure below this boundary is one code here (WT-05 step 2)
        raise _malformed() from None
