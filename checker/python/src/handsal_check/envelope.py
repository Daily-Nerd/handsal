"""The act envelope (ACT-01, ACT-06, ACT-08, ACT-12, ACT-13, ACT-14): `check-act` steps 2, 3 and 5.

Step 2 turns payload bytes into an object (canonical subset, object root).
Step 3 checks the envelope alone: the 16 keys, the constants, the forms of the
envelope fields and the shape of `ext`. Step 5 checks the act object once the
method is known: its closed key set, `head`, the extra keys of the method, the
per-method parent fields (ACT-13), the signer kid (ACT-14), then the body.
Every defect is `schema` except a body structure defect, which is `body_schema`,
and `schema` is reported first (the engine in `schema` does the ordering).

Closed schemas are not written here. The method table is the registry's, and
`schema` interprets it; this module only adds what the registry cannot say:
the constants, the parent-field table and the `head` shape.
"""
from . import encoding, errors, schema, subset

ENVELOPE_KEYS = frozenset((
    "action_ref", "binding", "cost", "ext", "inputs_hash", "log_policy", "method", "nonce",
    "outputs_hash", "parent_performer_id", "parent_receipt_hash", "performer_id", "reason",
    "requester_id", "status", "ts", "v"))
CONSTANTS = {"v": "vitni/0.2", "binding": "local", "status": "OK", "log_policy": "best_effort"}
NULLS = ("reason", "action_ref", "requester_id")
COST = {"rail_ref": None, "tokens": "0", "usd_micros": "0", "wall_ms": "0"}
EXT_KEY = "dev.handsal/act"
HEAD_NODE = {"keys": {"id": {"type": "hashstr"}, "kind": {"const": "chain"}}}

# ACT-13: what a method's parent fields look like at the envelope.
#   null      both null (verdicts, decision, genesis.sign)
#   primary   parent_receipt_hash is a position id, never null; the performer may be null (root)
#   endorse   both set: the endorsed act and its performer
_PARENTS = {
    "local:handsal.request.approve": "null",
    "local:handsal.request.reject": "null",
    "local:handsal.request.needs-info": "null",
    "local:handsal.decision": "null",
    "local:handsal.genesis.sign": "null",
    "local:handsal.device.add": "primary",
    "local:handsal.device.remove": "primary",
    "local:handsal.member.add": "primary",
    "local:handsal.chain.resolve": "primary",
    "local:handsal.act.endorse": "endorse",
}


def parse_payload(raw):
    """The payload object of the bytes `raw` (step 2), or Refused with the subset's reason."""
    try:
        value = subset.parse(raw)
    except subset.SubsetError as err:
        raise errors.Refused(err.reason) from None
    if type(value) is not dict:
        raise errors.Refused(subset.NOT_CANONICAL)
    return value


def receipt_id(raw):
    """The identity of an act (ACT-12): the hashstr of its payload bytes, never of its signature."""
    return encoding.hashstr(raw)


def _refuse():
    return errors.Refused("schema")


def check_envelope(payload):
    """Step 3: ACT-01 constants and key set, ACT-07 forms of envelope fields, shape of `ext`."""
    if type(payload) is not dict or set(payload) != ENVELOPE_KEYS:
        raise _refuse()
    for key, value in CONSTANTS.items():
        if payload[key] != value or type(payload[key]) is not str:
            raise _refuse()
    if any(payload[key] is not None for key in NULLS):
        raise _refuse()
    if payload["cost"] != COST or type(payload["cost"]) is not dict:
        raise _refuse()
    if type(payload["method"]) is not str:
        raise _refuse()
    for key in ("inputs_hash", "outputs_hash", "nonce"):
        if not schema.is_hashstr(payload[key]):
            raise _refuse()
    parent = payload["parent_receipt_hash"]
    if parent is not None and not schema.is_hashstr(parent):
        raise _refuse()
    parent_performer = payload["parent_performer_id"]
    if parent_performer is not None and not schema.is_member_id(parent_performer):
        raise _refuse()
    if not schema.is_member_id(payload["performer_id"]) or not schema.is_time(payload["ts"]):
        raise _refuse()
    ext = payload["ext"]
    if type(ext) is not dict or set(ext) != {EXT_KEY} or type(ext[EXT_KEY]) is not dict:
        raise _refuse()


def _parents_ok(method, payload):
    parent, performer = payload["parent_receipt_hash"], payload["parent_performer_id"]
    rule = _PARENTS[method]
    if rule == "null":
        return parent is None and performer is None
    if rule == "primary":
        return parent is not None
    return parent is not None and performer is not None


def _act_node(method, wire, head_present):
    keys = {
        "body": {"code": "body_schema", **method.body},
        "kid": {"type": "kid"},
        "org": {"type": "hashstr"},
    }
    if method.head == "conditional":
        if type(head_present) is not bool:
            raise ValueError("a conditional head needs the caller to say if it is present")
        wanted = head_present
    else:
        wanted = method.head == "always"
    if wanted:
        keys["head"] = HEAD_NODE
    for name in method.act_extra_keys:
        keys[name] = {"type": wire.act_extra_key_types[name]}
    return {"keys": keys}


def check_act_object(payload, header_kid, wire, head_present=None):
    """Step 5 for a payload whose envelope passed step 3 and whose method is in the registry.

    `head_present` is required for a method whose `head` is `conditional` (genesis.sign: true
    iff the document it signs has a non-null `prev`) and ignored otherwise.
    """
    method = wire.methods[payload["method"]]
    act = payload["ext"][EXT_KEY]
    found = schema.defects(_act_node(method, wire, head_present), act, wire, "schema")
    if not _parents_ok(method.method, payload):
        found.append("schema")
    if act.get("kid") != header_kid:
        found.append("schema")
    schema.refuse(found)
