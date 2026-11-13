"""Helpers for the signer `emit` vector rows (CF-04, SG-04).

An `emit` input is `{attachments, draft, fixed}`. The draft is written here from the fixture
constants, `fixed` is read off an act the base builders signed, and the expected bytes are that
act's payload, so the signer model (`lib/signer_emit.py`) and the base builders are two
derivations of one payload. A row states its outcome and the model must agree before it is
written; a refusal row whose input has a second defect is found here.
"""
import base64
import json

from . import base, forge, signer_emit

AB, BC = ("alice", "bob"), ("bob", "carol")
GENESIS_SIGN = "local:handsal.genesis.sign"


def fixed_of(jws):
    """`fixed = {kid, nonce, performer, ts}` of a signed act (SG-04)."""
    payload = json.loads(forge.parts(jws)[1])
    return {"kid": json.loads(forge.parts(jws)[0])["kid"], "nonce": payload["nonce"],
            "performer": payload["performer_id"], "ts": payload["ts"]}


def verdict_input(fx, kind="approve", signer="alice", request_id=base.REQUEST_ID):
    """(input, jws): an `emit` input for a verdict, and the act whose payload it must give."""
    jws = fx.verdict(kind, signer, request_id=request_id)
    draft = {"body": {}, "expires_in_s": "3600", "head": {"id": fx.org_id, "kind": "chain"},
             "method": "local:handsal.request.%s" % kind, "org": fx.org_id,
             "recipient": base.person_of_name(signer), "relay": base.RELAY_HOST,
             "request_id": request_id}
    return {"attachments": {"request_b64": fx.request_b64()}, "draft": draft,
            "fixed": fixed_of(jws)}, jws


def _parent(act):
    return {"id": act.id, "performer": act.performer}


def device_add_input(fx, label=None):
    """(input, jws): a `device.add` draft of bob2 under a non-root parent (a root parent has no
    performer, which SG-04 does not say how to write)."""
    first = fx.device_add("alice2", AB)
    built = fx.device_add("bob2", BC, parent=first, label=label)
    entry = fx.device_entry("bob2")
    body = {"agree": entry["agree"], "class": entry["class"], "kid": entry["kid"],
            "label": label or entry["label"], "link_code_hash": base.hashstr(b"link-code/bob2"),
            "person": entry["person"], "sign": entry["sign"]}
    draft = {"body": body, "method": "local:handsal.device.add", "org": fx.org_id,
             "parent": _parent(first)}
    return {"attachments": {}, "draft": draft, "fixed": fixed_of(built.acts[0])}, built.acts[0]


def device_remove_input(fx):
    """(input, jws): a `device.remove` draft of alice2 under a non-root parent."""
    first = fx.device_add("alice2", AB)
    built = fx.device_remove("alice2", BC, parent=first)
    entry = fx.device_entry("alice2")
    draft = {"body": {"kid": entry["kid"], "person": entry["person"]},
             "method": "local:handsal.device.remove", "org": fx.org_id, "parent": _parent(first)}
    return {"attachments": {}, "draft": draft, "fixed": fixed_of(built.acts[0])}, built.acts[0]


def genesis_input(fx, org):
    """An original `genesis.sign` draft over ORG whose draft `org` is `org`."""
    jws = fx.genesis_sign("alice", fx.org)
    return {"attachments": {"document": fx.org},
            "draft": {"body": {}, "method": GENESIS_SIGN, "org": org},
            "fixed": fixed_of(jws)}


def member_add_input(fx):
    """(input, jws): a `member.add` of dave (role member) under a non-root parent."""
    first = fx.device_add("alice2", AB)
    built = fx.member_add("dave", AB, role="member", parent=first)
    entry = fx.device_entry("dave")
    device = {key: entry[key] for key in ("agree", "class", "kid", "label", "sign")}
    body = {"device": device, "link_code_hash": base.hashstr(b"link-code/dave"),
            "member": entry["person"], "role": "member"}
    draft = {"body": body, "method": "local:handsal.member.add", "org": fx.org_id,
             "parent": _parent(first)}
    return {"attachments": {}, "draft": draft, "fixed": fixed_of(built.acts[0])}, built.acts[0]


def chain_resolve_input(fx):
    """(input, jws): a `chain.resolve` of two sibling device additions under a non-root parent,
    with the candidate and head acts attached (RN-09). The lists are in sorted order, as ACT-09
    asks, and the attachments follow the order of `body.candidates` and `body.heads`."""
    first = fx.device_add("alice2", AB)
    one = fx.device_add("bob2", BC, parent=first)
    two = fx.device_add("carol2", AB, parent=first)
    built = fx.chain_resolve(BC, candidates=[one.id, two.id], choose=one.id, heads=[two.id],
                             parent=first)
    by_id = {one.id: one.acts[0], two.id: two.acts[0]}
    candidates = sorted(by_id)
    body = {"candidates": candidates, "choose": one.id, "heads": [two.id], "overrides": []}
    draft = {"body": body, "method": "local:handsal.chain.resolve", "org": fx.org_id,
             "parent": _parent(first)}
    attachments = {"candidates": [by_id[i] for i in candidates], "heads": [two.acts[0]]}
    return {"attachments": attachments, "draft": draft,
            "fixed": fixed_of(built.acts[0])}, built.acts[0]


def endorse_input(fx):
    """(input, jws): the endorsement by bob of a `device.add` primary, which is attached."""
    built = fx.device_add("alice2", AB)
    draft = {"body": {"act": built.id}, "head": {"id": built.parent, "kind": "chain"},
             "method": "local:handsal.act.endorse", "org": fx.org_id, "parent": _parent(built)}
    return {"attachments": {"act": built.acts[0]}, "draft": draft,
            "fixed": fixed_of(built.acts[1])}, built.acts[1]


def record_promote_input(fx):
    """(input, jws): a `record.promote` with its record body attached."""
    jws = fx.record_promote()
    draft = {"body": {"anchors": ["anchor-1"], "record_id": base.RECORD_ID},
             "expires_in_s": "3600", "head": {"id": fx.org_id, "kind": "chain"},
             "method": "local:handsal.record.promote", "org": fx.org_id}
    attachments = {"record_body_b64": base64.b64encode(base.RECORD_BODY).decode("ascii")}
    return {"attachments": attachments, "draft": draft, "fixed": fixed_of(jws)}, jws


def genesis_original_input(fx):
    """(input, jws): an original `genesis.sign` over ORG, whose `org` is the document hash."""
    return genesis_input(fx, fx.org_id), fx.genesis_sign("alice", fx.org)


def change_document(fx):
    """A genesis change of ORG: names the original as `prev`, carries `head`."""
    doc = dict(fx.org)
    doc.update({"org": fx.org_id, "prev": fx.org_id, "head": fx.org_id})
    problems = base.check_genesis_shape(doc)
    if problems:
        raise AssertionError("change document is not schema-valid: %s" % problems)
    return doc


def genesis_change_input(fx):
    """(input, jws): a `genesis.sign` over a change, with `head`, its document and the previous
    document attached."""
    doc = change_document(fx)
    jws = fx.genesis_sign("alice", doc)
    draft = {"body": {}, "head": {"id": doc["head"], "kind": "chain"}, "method": GENESIS_SIGN,
             "org": doc["org"]}
    return {"attachments": {"document": doc, "previous": fx.org}, "draft": draft,
            "fixed": fixed_of(jws)}, jws


def ok(ctx, name, inp, jws):
    """Write the `emit` row `name`: the payload of `jws`, which the model must give for `inp`."""
    expected = {"payload_hex": forge.parts(jws)[1].hex()}
    got = signer_emit.run(signer_emit.stdin_for(inp))
    if got != (0, expected):
        raise AssertionError("%s: the model says %r" % (name, got))
    ctx.writer.add(name, "emit", signer_emit.line(expected), input=inp)


def refused(ctx, name, inp, code, pad=None):
    """Write the `emit` row `name`: exit 2 and `{"error": code}`, which the model must give."""
    got = signer_emit.run(signer_emit.stdin_for(inp, pad))
    if got != (2, {"error": code}):
        raise AssertionError("%s: the model says %r, the row says %r" % (name, got, code))
    ctx.writer.add(name, "emit", signer_emit.line({"error": code}), input=inp, exit=2, pad=pad)
