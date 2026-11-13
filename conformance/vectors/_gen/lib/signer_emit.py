"""The generator's model of the signer `emit` command, written from the spec (CF-04, SG-01 to SG-04,
SG-08, SG-13, ACT-01, ACT-05, ACT-09, ACT-13).

`run(stdin)` answers `(exit code, result object)` for the bytes a harness sends to
`handsal-sign-conformance emit`. A row states its expected outcome on its own (a payload taken
from the base builders, or a refusal code) and the model must agree before the row is written,
as the render model does for `rnd/*`; a refusal row with a second defect is found here.

What the spec does not say is not decided here. `fixed` is taken as given (SG-04 calls caller
values there harmless and does not say that `emit` checks their forms), and only the methods the
vectors emit are derived: anything else raises NotModeled.
"""
import base64
import copy
import json
import re
import sys
from pathlib import Path

from . import base, jcs, result

# the harness owns how a vector becomes stdin (CF-02, `pad`); import it, never copy it
_CONFORMANCE = str(Path(__file__).resolve().parents[3])
if _CONFORMANCE not in sys.path:
    sys.path.insert(0, _CONFORMANCE)
import run as harness  # noqa: E402

MAX_INPUT = 16777216
MAX_EXPIRES_IN_S = 2592000
SCHEMA, UNSUPPORTED_METHOD = "schema_refused", "unsupported_method"
IDENTITY, MISMATCH = "identity_mismatch", "attachment_mismatch"

_MEMBER = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,35}$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DECIMAL = re.compile(r"^[1-9][0-9]{0,8}$")
_KINDS = ("approve", "reject", "needs-info")

# ACT-09: the closed body of each method; the SG-04 draft keys follow from where a method has them
_BODY = {
    "genesis.sign": (),
    "device.add": ("agree", "class", "kid", "label", "link_code_hash", "person", "sign"),
    "device.remove": ("kid", "person"),
    "member.add": ("device", "link_code_hash", "member", "role"),
    "chain.resolve": ("candidates", "choose", "heads", "overrides"),
    "act.endorse": ("act",),
    "request.approve": (), "request.reject": (), "request.needs-info": (),
    "record.promote": ("anchors", "record_id"),
}
_PARENT = {"device.add", "device.remove", "member.add", "chain.resolve", "act.endorse"}
_EXPIRES = {"request.approve", "request.reject", "request.needs-info", "record.promote"}
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


def _check_draft(draft, document):
    if not isinstance(draft, dict) or not isinstance(draft.get("method"), str):
        _refuse()
    method = draft["method"]
    if not method.startswith(PREFIX) or method[len(PREFIX):] not in _BODY:
        _refuse(UNSUPPORTED_METHOD)
    name = method[len(PREFIX):]
    has_head = name in _HEAD_ALWAYS
    if name == "genesis.sign":
        if not isinstance(document, dict):
            raise NotModeled("a genesis.sign draft needs its attached document")
        has_head = document.get("prev") is not None
    want = {"body", "method", "org"}
    want |= {"head"} if has_head else set()
    want |= {"parent"} if name in _PARENT else set()
    want |= {"expires_in_s"} if name in _EXPIRES else set()
    want |= {"recipient", "relay", "request_id"} if name in _VERDICT else set()
    if set(draft) != want:
        _refuse()
    if not base.is_hashstr(draft["org"]):
        _refuse()
    if not _pair(draft["body"], _BODY[name]):
        _refuse()
    if has_head and not _head(draft["head"]):
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


def _check_identity_and_attachments(name, draft, fixed, document):
    if name in _VERDICT and draft["recipient"] != fixed["performer"]:
        _refuse(IDENTITY)
    if name == "genesis.sign" and document["prev"] is None:
        if draft["org"] != base.hashstr(jcs.emit(document)):
            _refuse(MISMATCH)


def _payload(name, draft, attachments, fixed):
    """The payload of an act of `name`, derived from the draft and `fixed` (ACT-01, ACT-09, ACT-13)."""
    act = {"body": draft["body"], "kid": fixed["kid"], "org": draft["org"]}
    inputs_hash = outputs_hash = base.EMPTY_HASH
    parent_hash = parent_performer = None
    if name in _VERDICT:
        act.update(head=draft["head"], expires=base.shift(fixed["ts"], int(draft["expires_in_s"])),
                   recipient=draft["recipient"], relay=draft["relay"], request_id=draft["request_id"])
        inputs_hash = base.hashstr(_request_bytes(attachments))
        outputs_hash = base.hashstr(jcs.emit({"request_id": draft["request_id"],
                                              "verdict": name[len("request."):]}))
    elif name == "device.add":
        parent_hash, parent_performer = draft["parent"]["id"], draft["parent"]["performer"]
    else:
        raise NotModeled("no vector emits %s" % name)
    return jcs.emit({
        "action_ref": None, "binding": "local",
        "cost": {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"},
        "ext": {"dev.handsal/act": act}, "inputs_hash": inputs_hash, "log_policy": "best_effort",
        "method": PREFIX + name, "nonce": fixed["nonce"], "outputs_hash": outputs_hash,
        "parent_performer_id": parent_performer, "parent_receipt_hash": parent_hash,
        "performer_id": fixed["performer"], "reason": None, "requester_id": None, "status": "OK",
        "ts": fixed["ts"], "v": "vitni/0.2"})


def _request_bytes(attachments):
    text = attachments.get("request_b64")
    if not isinstance(text, str):
        raise NotModeled("a verdict draft without its request attachment")
    return base64.b64decode(text, validate=True)


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
        if not _pair(fixed, ("kid", "nonce", "performer", "ts")):
            _refuse()
        document = attachments.get("document")
        name = _check_draft(draft, document)
        _check_identity_and_attachments(name, draft, fixed, document)
        return 0, {"payload_hex": _payload(name, draft, attachments, fixed).hex()}
    except Refused as err:
        return 2, {"error": err.code}


def stdin_for(inp, pad=None):
    """The stdin the harness builds for the vector input `inp`, padded at the path `pad` to
    MAX_INPUT + 1 bytes when given (CF-02)."""
    vector = {"name": "emit", "input": copy.deepcopy(inp)}
    if pad:
        vector["pad"] = list(pad)
    return harness.build_stdin(vector)


def padded_stdin(inp, path):
    return stdin_for(inp, path)


def line(obj):
    """The anchor text of a result object."""
    return result.line(obj)
