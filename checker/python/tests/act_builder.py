"""Builders for acts in tests, and a stand-in for vitni.

The checker never does ES256, so a test act carries a stand-in signature: `GOOD` (low S, the fake
accepts it), `BAD` (the fake answers `bad_signature`) and `HIGH` (a high S: the fake accepts it, as
vitni does, and the checker must refuse it, VR-04). Payloads and headers are exact canonical bytes.
Nothing here calls a checker validator: an act is valid because of how it is built.
"""
import json
from collections import namedtuple

from handsal_check import emit, encoding, verifier

from .genesis_fixtures import KEYS

EMPTY = encoding.EMPTY_HASH
GOOD = b"\x01" * 64
BAD = b"\x00" * 64
HIGH = b"\x01" * 32 + b"\xff" * 32
TS = "2026-01-01T00:00:00Z"
PREFIX = "local:handsal."

Act = namedtuple("Act", "jws id performer kid")


def kid_of(name):
    return KEYS[name + ".sign"]["kid"]


def person_of(name):
    return name.split("-")[0].rstrip("0123456789")


def _segment(raw):
    return encoding.b64u_encode(raw)


def build(signer, method, *, org, body, parent=None, parent_performer=None, performer=None,
          inputs_hash=EMPTY, outputs_hash=EMPTY, head=None, extra=None, ts=TS, sig=GOOD, salt="",
          act_kid=None, edit=None, kid=None):
    """An act of `method` signed (in stand-in form) by the fixture device `signer`, or by `kid`."""
    kid = kid or kid_of(signer)
    obj = {"body": body, "kid": act_kid or kid, "org": org}
    if head is not None:
        obj["head"] = head
    obj.update(extra or {})
    payload = {
        "action_ref": None, "binding": "local",
        "cost": {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
        "ext": {"dev.handsal/act": obj}, "inputs_hash": inputs_hash, "log_policy": "best_effort",
        "method": PREFIX + method, "outputs_hash": outputs_hash,
        "parent_performer_id": parent_performer, "parent_receipt_hash": parent,
        "performer_id": performer or person_of(signer), "reason": None, "requester_id": None,
        "status": "OK", "ts": ts, "v": "vitni/0.2",
    }
    payload["nonce"] = encoding.hashstr(emit.emit_subset(payload) + salt.encode())
    if edit:
        edit(payload)
    raw = emit.emit_subset(payload)
    header = ('{"alg":"ES256","kid":"%s"}' % kid).encode()
    text = ".".join((_segment(header), _segment(raw), _segment(sig)))
    return Act(text, encoding.hashstr(raw), payload["performer_id"], kid)


def with_signature(act, sig):
    """The same act with another signature: a twin of one receipt id."""
    head, payload, _ = act.jws.split(".")
    return Act(".".join((head, payload, _segment(sig))), act.id, act.performer, act.kid)


def head_of(parent_id):
    return {"id": parent_id, "kind": "chain"}


def genesis_sign(signer, doc, org_id, *, sig=GOOD, **over):
    """A `genesis.sign` over `doc` by device `signer` (GP-03, GP-15)."""
    from handsal_check import genesis
    change = doc["prev"] is not None
    fields = dict(org=org_id, body={}, inputs_hash=genesis.doc_hash(doc),
                  head=head_of(doc["head"]) if change else None, sig=sig)
    fields.update(over)
    return build(signer, "genesis.sign", **fields)


class FakeVitni(verifier.Verifier):
    """What vitni answers from the pieces the checker sends (CONTRACT section 7), no ES256."""

    def __init__(self):
        self.calls = []

    def verify(self, jws_text, keys, method):
        self.calls.append((jws_text, json.dumps(keys, sort_keys=True), method))
        parts = jws_text.split(".")
        header = json.loads(encoding.b64u_decode(parts[0]))
        payload = json.loads(encoding.b64u_decode(parts[1]))
        signature = encoding.b64u_decode(parts[2])
        entry = (keys.get(payload["performer_id"]) or {}).get(header["kid"])
        if entry is None:
            return "unknown_key"
        if entry["status"] == "revoked":
            return "revoked_key"
        if signature == BAD:
            return "bad_signature"
        if payload["method"] != method:
            return "context_mismatch"
        return "ok"


def memo(vitni=None):
    """The memo a test call is made with, as `commands.per_call` makes one per command call."""
    return verifier.Memoized(FakeVitni() if vitni is None else vitni)


class Unavailable(verifier.Verifier):
    def verify(self, *args):
        raise verifier.VerifierUnavailable("down")
