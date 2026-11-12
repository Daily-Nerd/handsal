"""One act, read once: the parts of ACT-01 to ACT-14 that need no state.

`parse` is `check-act` steps 1 to 5 for a text the caller wants as a chain act, an endorsement or a
`genesis.sign`: the JWS shape, the canonical payload, the envelope, the method (one the caller
reads), the act object with its closed body, and the hashes a method fixes to the empty hash. It
returns a `ParsedAct` or raises `Refused`; the fold ignores a refused text (FO-06), and nothing here
reads a key, a state or a clock. The receipt id is the identity (ACT-12): two texts of one payload
differ only by their signature.
"""
from collections import namedtuple

from . import encoding, envelope, errors, jws

ParsedAct = namedtuple("ParsedAct", "jws kid signature payload method id performer parent "
                                    "parent_performer act body head")


def _refuse(code):
    return errors.Refused(code)


def parse(text, reg, wanted, head_present=None):
    """The `ParsedAct` of the text `text`, whose method must be in `wanted`, else Refused.

    `head_present` says whether the act must carry a `head` when the method's head is conditional
    (`genesis.sign`: true iff the document it signs has a non-null `prev`).
    """
    if type(text) is not str:
        raise _refuse("jws_shape")
    parsed = jws.parse(text)
    payload = envelope.parse_payload(parsed.payload)
    envelope.check_envelope(payload)
    method = reg.method(payload["method"])
    if method is None or method.method not in wanted:
        raise _refuse("method_unknown")
    envelope.check_act_object(payload, parsed.kid, reg, head_present)
    if method.inputs_hash == "empty" and payload["inputs_hash"] != encoding.EMPTY_HASH:
        raise _refuse("schema")
    if method.outputs_hash == "empty" and payload["outputs_hash"] != encoding.EMPTY_HASH:
        raise _refuse("schema")
    act = payload["ext"][envelope.EXT_KEY]
    return ParsedAct(text, parsed.kid, parsed.signature, payload, method.method,
                     envelope.receipt_id(parsed.payload), payload["performer_id"],
                     payload["parent_receipt_hash"], payload["parent_performer_id"], act,
                     act["body"], act.get("head"))
