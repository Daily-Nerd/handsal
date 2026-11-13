"""RN-09: attachments are bound to the payload, then the whole render, and the `render` command (CF-03).

Every renderer verifies every attachment against the signed payload before it shows a word, so the
words a person sees are a function of signed bytes only. An attachment is bound by hash or by id:

  verdicts          `request_b64`      hashstr(bytes) = `inputs_hash`
  record.promote    `record_body_b64`  hashstr(bytes) = `inputs_hash`
  genesis.sign      `document`         hashstr(JCS(document)) = `inputs_hash`
                    `previous`         (a change) hashstr(JCS(previous)) = `document.prev`
                    `head.id` of the payload = `document.head` (a change)
                    both are valid alone (GP-15 steps 1 and 3), else `attachment_mismatch`
  act.endorse       `act`              receipt id = `body.act` = `parent_receipt_hash`; `performer_id` =
                                       `parent_performer_id`; its `parent_receipt_hash` = `head.id`;
                                       a chain primary or a resolve
  chain.resolve     `candidates`       one JWS per id of `body.candidates`, each with the resolve's parent
                    `heads`            one JWS per id of `body.heads`, each a chain primary
  act.endorse of a resolve: `candidates` and `heads` bound against the attached resolve, the same way

A list holds exactly one JWS per id and nothing else, in any order. Every attached act passes ACT-01
to ACT-14 (`acts.parse`), whatever its defect: that is `attachment_mismatch`. An absent attachment or
list is `attachment_missing`. Attachments the method does not bind (a `sender`, say) are never read.
Whether a head lies in a losing subtree is the fold's to decide (FO-25), not the render's.

Order (RN-09, "Order of checks"): envelope and method (`schema`, `method_unknown`), for `genesis.sign` its
document (which fixes whether a head is due), the act object and body (`schema`, `body_schema`), then the
other attachments in the order above, each read and bound completely before the next; the first defect wins.
"""
import base64
import binascii

from . import acts, chain, emit, encoding, errors, genesis, render, render_genesis, render_methods
from .render import (ENDORSE, GENESIS_SIGN, PROMOTE, RESOLVE, VERDICTS, Facts, act_object, first_line, refuse)


def _missing():
    return refuse("attachment_missing")


def _mismatch():
    return refuse("attachment_mismatch")


def _bytes(attachments, name, expected_hash):
    """The raw bytes of the base64 attachment `name`, bound to `expected_hash` (verdicts, record.promote)."""
    if name not in attachments:
        raise _missing()
    text = attachments[name]
    if type(text) is not str:
        raise errors.Malformed()
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise errors.Malformed() from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise errors.Malformed()
    if encoding.hashstr(raw) != expected_hash:
        raise _mismatch()
    return raw


def _bound_to(value, expected_hash):
    """`value` (a JSON value) hashes, as canonical subset bytes, to `expected_hash`."""
    try:
        return genesis.doc_hash(value) == expected_hash
    except emit.EmitError:
        return False


def _document(attachments, name, expected_hash, ctx):
    """The genesis document attachment `name`, bound to `expected_hash` and valid alone (RN-09): GP-15
    steps 1 and 3 by `genesis.check_alone`. One that binds but is no valid document is
    `attachment_mismatch`, like an act that fails ACT-01 to ACT-14."""
    if name not in attachments:
        raise _missing()
    doc = attachments[name]
    if not _bound_to(doc, expected_hash):
        raise _mismatch()
    try:
        genesis.check_alone(doc, ctx)
    except errors.Refused:
        raise _mismatch() from None
    return doc


def _act(text, reg, wanted):
    """The `ParsedAct` of an attached act of one of the `wanted` methods, else `attachment_mismatch`."""
    try:
        return acts.parse(text, reg, wanted)
    except errors.Refused:
        raise _mismatch() from None


def _act_list(attachments, name, ids, reg, accept):
    """`{receipt id: line 1}` of the JWS list `name`, exactly one per id in `ids`, each passing `accept`."""
    if name not in attachments:
        raise _missing()
    items = attachments[name]
    if type(items) is not list:
        raise _mismatch()
    parsed = [_act(text, reg, chain.PRIMARIES) for text in items]
    if sorted(item.id for item in parsed) != sorted(ids):
        raise _mismatch()
    if not all(accept(item) for item in parsed):
        raise _mismatch()
    return {item.id: first_line(item.method, item.payload, Facts()) for item in parsed}


def _resolve_facts(payload, attachments, reg):
    """The `Facts` of a resolve `payload` (the resolve itself or one an endorsement carries)."""
    body = act_object(payload)["body"]
    parent = payload["parent_receipt_hash"]
    return Facts(candidates=_act_list(attachments, "candidates", body["candidates"], reg,
                                      lambda item: item.parent == parent),
                 heads=_act_list(attachments, "heads", body["heads"], reg, lambda item: True))


def _endorse_facts(payload, attachments, reg):
    act = act_object(payload)
    if "act" not in attachments:
        raise _missing()
    endorsed = _act(attachments["act"], reg, chain.PRIMARIES | {RESOLVE})
    if (endorsed.id != act["body"]["act"] or payload["parent_receipt_hash"] != endorsed.id
            or payload["parent_performer_id"] != endorsed.performer or endorsed.parent != act["head"]["id"]):
        raise _mismatch()
    if endorsed.method == RESOLVE:
        inner = _resolve_facts(endorsed.payload, attachments, reg)
    else:
        if "candidates" in attachments or "heads" in attachments:
            raise _mismatch()
        inner = Facts()
    return Facts(endorsed_line1=first_line(endorsed.method, endorsed.payload, inner),
                 endorsed_lines=render_methods.method_lines(endorsed.method, endorsed.payload, inner))


def _frame(payload, first, body):
    act = act_object(payload)
    head = act.get("head")
    return render.frame(first=first, method=payload["method"], org=act["org"], performer=payload["performer_id"],
                        kid=act["kid"], body=body, ts=payload["ts"], expires=act.get("expires"),
                        parent=payload["parent_receipt_hash"], head=head["id"] if head else None,
                        sender=payload["method"] in VERDICTS)


def _genesis(inp, ctx):
    payload = inp.payload
    doc = _document(inp.attachments, "document", payload["inputs_hash"], ctx)
    render.check_act(payload, inp.kid, ctx.reg, doc["prev"] is not None)   # the document fixes whether a head is due
    previous = None
    if doc["prev"] is not None:
        previous = _document(inp.attachments, "previous", doc["prev"], ctx)
    head = act_object(payload).get("head")
    if head is not None and head["id"] != doc.get("head"):   # a change: the signed head is the document's
        raise _mismatch()
    return _frame(payload, render_genesis.summary(doc, previous), render_genesis.lines(doc, previous))


def render_payload(inp, reg, profiles):
    """The `Rendered` of an `Input` (`render.parse_input`), or Refused with the code of section 11."""
    payload, method = inp.payload, inp.method
    render.check_envelope(payload, method, reg)
    if method == GENESIS_SIGN:
        return _genesis(inp, genesis.Context(reg, profiles, True))
    render.check_act(payload, inp.kid, reg)
    if method in VERDICTS:
        facts = Facts(raw=_bytes(inp.attachments, "request_b64", payload["inputs_hash"]))
    elif method == PROMOTE:
        facts = Facts(raw=_bytes(inp.attachments, "record_body_b64", payload["inputs_hash"]))
    elif method == RESOLVE:
        facts = _resolve_facts(payload, inp.attachments, reg)
    elif method == ENDORSE:
        facts = _endorse_facts(payload, inp.attachments, reg)
    else:
        facts = Facts()
    return _frame(payload, first_line(method, payload, facts), render_methods.method_lines(method, payload, facts))


def command(value, reg, profiles):
    """The `render` command (CF-03) over the registry `reg` and the `profiles`: `{first_line, text}` or `{"error": code}`.
    A mistyped input is Malformed, for the command line to answer."""
    try:
        rendered = render_payload(render.parse_input(value), reg, profiles)
    except errors.Refused as err:
        return {"error": err.code}
    return {"first_line": rendered.first_line, "text": rendered.text}
