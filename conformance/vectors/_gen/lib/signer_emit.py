"""The generator's model of the signer `emit` command, written from the spec (CF-04, SG-01 to SG-04,
SG-08, SG-13, ACT-01, ACT-05, ACT-09, ACT-13).

`run(stdin)` answers `(exit code, result object)` for the bytes a harness sends to
`handsal-sign-conformance emit`. A row states its expected outcome on its own (a payload taken
from the base builders, or a refusal code) and the model must agree before the row is written,
as the render model does for `rnd/*`; a refusal row with a second defect is found here.

What the spec does not say is not decided here: a case no vector needs raises NotModeled.
The order of defects is SG-08 step 1 (framing, draft, method, method forms, `fixed` forms) then 3.
"""
import base64
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from . import base, forge, jcs, result

# the harness owns how a vector becomes stdin (CF-02, `pad`); import it, never copy it
_CONFORMANCE = str(Path(__file__).resolve().parents[3])
if _CONFORMANCE not in sys.path:
    sys.path.insert(0, _CONFORMANCE)
import run as harness  # noqa: E402

MAX_INPUT = 16777216
MAX_EXPIRES_IN_S = 2592000
SCHEMA, UNSUPPORTED_METHOD = "schema_refused", "unsupported_method"
IDENTITY, MISMATCH, MISSING = "identity_mismatch", "attachment_mismatch", "attachment_missing"

_KID = re.compile(r"^[A-Za-z0-9_-]{43}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MEMBER = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,35}$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DECIMAL = re.compile(r"^[1-9][0-9]{0,8}$")
_KINDS = ("approve", "reject", "needs-info")
_CONSUMER = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_SUBJECT = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_ACTION = re.compile(r"^[a-z]+(?: [a-z]+)*$")
MAX_ACTION = 24

# ACT-09: the closed body of each method; the SG-04 draft keys follow from where a method has them
_BODY = {
    "genesis.sign": (),
    "device.add": ("agree", "class", "kid", "label", "link_code_hash", "person", "sign"),
    "device.remove": ("kid", "person"),
    "member.add": ("device", "link_code_hash", "member", "role"),
    "chain.resolve": ("candidates", "choose", "heads", "overrides"),
    "act.endorse": ("act",),
    "request.approve": (), "request.reject": (), "request.needs-info": (),
    "decision": ("action", "consumer", "subject"),
}
_PARENT = {"device.add", "device.remove", "member.add", "chain.resolve", "act.endorse"}
_EXPIRES = {"request.approve", "request.reject", "request.needs-info", "decision"}
_HEAD_ALWAYS = _EXPIRES | {"act.endorse"}  # ACT-08
_VERDICT = {"request.%s" % k for k in _KINDS}
PREFIX = "local:handsal."


class NotModeled(Exception):
    """The spec or the vectors do not need this case, so the model does not decide it."""


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _refuse(code=SCHEMA):
    raise Refused(code)


def _hostname(text):
    return (isinstance(text, str) and 1 <= len(text) <= 253
            and all(_LABEL.match(label) for label in text.split(".")))


def _pair(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _head(value):
    return _pair(value, ("id", "kind")) and base.is_hashstr(value["id"]) and value["kind"] == "chain"


def _check_draft(draft):
    """SG-08 step 1: the draft as a closed object, then the method, then the forms the method gives.
    The `head` of a `genesis.sign` is checked for form only: whether one is due is known from the
    attached document, which is step 3."""
    if not isinstance(draft, dict) or not isinstance(draft.get("method"), str):
        _refuse()
    method = draft["method"]
    if not method.startswith(PREFIX) or method[len(PREFIX):] not in _BODY:
        _refuse(UNSUPPORTED_METHOD)
    name = method[len(PREFIX):]
    has_head = name in _HEAD_ALWAYS
    want = {"body", "method", "org"}
    want |= {"head"} if has_head else set()
    want |= {"parent"} if name in _PARENT else set()
    want |= {"expires_in_s"} if name in _EXPIRES else set()
    want |= {"recipient", "relay", "request_id"} if name in _VERDICT else set()
    optional = {"head"} if name == "genesis.sign" else set()
    if not want <= set(draft) <= want | optional:
        _refuse()
    if not base.is_hashstr(draft["org"]):
        _refuse()
    if not _pair(draft["body"], _BODY[name]):
        _refuse()
    if name == "decision":   # VR-18: the three forms of the body, a draft defect like any other
        body = draft["body"]
        if not (all(isinstance(v, str) for v in body.values())
                and _ACTION.match(body["action"]) and len(body["action"]) <= MAX_ACTION
                and _CONSUMER.match(body["consumer"]) and _SUBJECT.match(body["subject"])):
            _refuse()
    if "head" in draft and not _head(draft["head"]):
        _refuse()
    if name in _PARENT and not (_pair(draft["parent"], ("id", "performer"))
                                and base.is_hashstr(draft["parent"]["id"])
                                and isinstance(draft["parent"]["performer"], str)
                                and _MEMBER.match(draft["parent"]["performer"])):
        _refuse()
    if name in _EXPIRES:
        text = draft["expires_in_s"]
        if not (isinstance(text, str) and _DECIMAL.match(text) and 1 <= int(text) <= MAX_EXPIRES_IN_S):
            _refuse()
    if name in _VERDICT:
        if not (isinstance(draft["recipient"], str) and _MEMBER.match(draft["recipient"])
                and _hostname(draft["relay"])
                and isinstance(draft["request_id"], str) and _REQUEST_ID.match(draft["request_id"])):
            _refuse()
    return name


def _time(text):
    if not (isinstance(text, str) and _TIME.match(text)):
        return False
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _check_fixed_shape(fixed):
    """SG-08 step 1, framing: `fixed` holds exactly its four members, each a string."""
    if not (_pair(fixed, ("kid", "nonce", "performer", "ts"))
            and all(isinstance(value, str) for value in fixed.values())):
        _refuse()


def _check_fixed(fixed):
    """SG-04: `emit` checks the forms of the four `fixed` values as `sign` fills them (ACT-07),
    last in step 1 (SG-08)."""
    if not (_KID.match(fixed["kid"]) and base.is_hashstr(fixed["nonce"])
            and _MEMBER.match(fixed["performer"]) and _time(fixed["ts"])):
        _refuse()


def _need(attachments, name):
    if name not in attachments:
        _refuse(MISSING)
    return attachments[name]


def _act_parts(jws):
    """(payload object, receipt id) of an attached act, or a mismatch (RN-09)."""
    if not (isinstance(jws, str) and jws.count(".") == 2):
        _refuse(MISMATCH)
    try:
        raw = forge.parts(jws)[1]
        return json.loads(raw), base.hashstr(raw)
    except ValueError:
        _refuse(MISMATCH)


def _bound_list(attachments, name, ids, parent=None):
    """The JWS list `name` holds exactly one act per id of `ids`, in any order (RN-09)."""
    items = _need(attachments, name)
    if not isinstance(items, list):
        _refuse(MISMATCH)
    seen = []
    for jws in items:
        payload, rid = _act_parts(jws)
        if parent is not None and payload.get("parent_receipt_hash") != parent:
            _refuse(MISMATCH)
        seen.append(rid)
    if sorted(seen) != sorted(ids):
        _refuse(MISMATCH)


def _check_identity_and_attachments(name, draft, fixed, attachments):
    """SG-08 steps 2 and 3: the person first, then the attachments in the order the spec gives."""
    if name in _VERDICT and draft["recipient"] != fixed["performer"]:
        _refuse(IDENTITY)
    if name in _VERDICT:
        _need(attachments, "request_b64")
    elif name == "decision":
        _need(attachments, "decision_b64")
    elif name == "genesis.sign":
        _check_genesis(draft, attachments)
    elif name == "act.endorse":
        _check_endorse(draft, attachments)
    elif name == "chain.resolve":
        body, parent = draft["body"], draft["parent"]["id"]
        _bound_list(attachments, "candidates", body["candidates"], parent)
        _bound_list(attachments, "heads", body["heads"])


def _check_genesis(draft, attachments):
    """SG-08 step 3 for `genesis.sign`: the document, the head against its `prev` (a form defect),
    the draft's org against the document's, then `previous`, then `head.id`."""
    document = _need(attachments, "document")
    if not isinstance(document, dict) or "prev" not in document:
        _refuse(MISMATCH)
    original = document["prev"] is None
    if not original and not isinstance(document.get("org"), str):
        _refuse(MISMATCH)
    if ("head" in draft) == original:
        _refuse()
    # an original: org is the hash of the document (GP-03); a change: the document's own org
    if draft["org"] != (base.hashstr(jcs.emit(document)) if original else document["org"]):
        _refuse(MISMATCH)
    if original:
        return
    previous = _need(attachments, "previous")
    if base.hashstr(jcs.emit(previous)) != document["prev"]:
        _refuse(MISMATCH)
    if draft["head"]["id"] != document["head"]:
        _refuse(MISMATCH)


def _check_endorse(draft, attachments):
    payload, rid = _act_parts(_need(attachments, "act"))
    if payload.get("method") == PREFIX + "chain.resolve":
        raise NotModeled("the endorsement of a resolve carries nested attachments")
    if payload.get("method") not in {PREFIX + n for n in _PARENT - {"act.endorse"}}:
        _refuse(MISMATCH)
    if not (draft["body"]["act"] == draft["parent"]["id"] == rid
            and draft["parent"]["performer"] == payload["performer_id"]
            and draft["head"]["id"] == payload["parent_receipt_hash"]):
        _refuse(MISMATCH)


def _payload(name, draft, attachments, fixed):
    """The payload of an act of `name`, derived from the draft and `fixed` (ACT-01, ACT-09, ACT-13)."""
    act = {"body": draft["body"], "kid": fixed["kid"], "org": draft["org"]}
    inputs_hash = outputs_hash = base.EMPTY_HASH
    parent_hash = parent_performer = None
    if "head" in draft:
        act["head"] = draft["head"]
    if name in _EXPIRES:
        act["expires"] = base.shift(fixed["ts"], int(draft["expires_in_s"]))
    if name in _VERDICT:
        act.update(recipient=draft["recipient"], relay=draft["relay"],
                   request_id=draft["request_id"])
        inputs_hash = base.hashstr(base64.b64decode(attachments["request_b64"], validate=True))
        outputs_hash = base.hashstr(jcs.emit({"request_id": draft["request_id"],
                                              "verdict": name[len("request."):]}))
    elif name == "decision":
        inputs_hash = base.hashstr(base64.b64decode(attachments["decision_b64"], validate=True))
        outputs_hash = base.hashstr(jcs.emit({"action": draft["body"]["action"],
                                              "subject": draft["body"]["subject"]}))
    elif name == "genesis.sign":
        inputs_hash = base.hashstr(jcs.emit(attachments["document"]))
    if name in _PARENT:
        parent_hash, parent_performer = draft["parent"]["id"], draft["parent"]["performer"]
    return jcs.emit({
        "action_ref": None, "binding": "local",
        "cost": {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
        "ext": {"dev.handsal/act": act}, "inputs_hash": inputs_hash, "log_policy": "best_effort",
        "method": PREFIX + name, "nonce": fixed["nonce"], "outputs_hash": outputs_hash,
        "parent_performer_id": parent_performer, "parent_receipt_hash": parent_hash,
        "performer_id": fixed["performer"], "reason": None, "requester_id": None, "status": "OK",
        "ts": fixed["ts"], "v": "vitni/0.2"})


def run(stdin):
    """`(exit code, result object)` of `emit` for the stdin bytes `stdin` (SG-01, SG-08)."""
    try:
        if len(stdin) > MAX_INPUT:
            _refuse()
        raw = stdin[:-1] if stdin.endswith(b"\n") else stdin  # one trailing LF is framing
        good, reason = jcs.recognize(raw)
        if not good:
            if reason == jcs.TOO_LARGE:
                raise NotModeled("stdin between MAX_PAYLOAD and MAX_INPUT bytes")
            _refuse()
        top = json.loads(raw)
        if not _pair(top, ("attachments", "draft", "fixed")) or not isinstance(top["attachments"], dict):
            _refuse()
        attachments, draft, fixed = top["attachments"], top["draft"], top["fixed"]
        _check_fixed_shape(fixed)
        name = _check_draft(draft)
        _check_fixed(fixed)
        _check_identity_and_attachments(name, draft, fixed, attachments)
        return 0, {"payload_hex": _payload(name, draft, attachments, fixed).hex()}
    except Refused as err:
        return 2, {"error": err.code}


def stdin_for(inp, pad=None):
    """The stdin the harness builds for the vector input `inp`, padded at the path `pad` to
    MAX_INPUT + 1 bytes when given (CF-02)."""
    # the writer stores a vector with sorted keys and the harness sends the file's order
    vector = {"name": "emit", "input": json.loads(json.dumps(inp, sort_keys=True))}
    if pad:
        vector["pad"] = list(pad)
    return harness.build_stdin(vector)


def padded_stdin(inp, path):
    return stdin_for(inp, path)


def line(obj):
    """The anchor text of a result object."""
    return result.line(obj)
