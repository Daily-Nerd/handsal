"""The generator's model of `render` (RN-01 to RN-12), used to author `rnd/*` anchors.

Written from the spec text, independent of every checker (CF-06). Input is the
checker `render` input `{attachments, kid, method, payload}`; the output is
`{first_line, text}` or `{"error": code}` (RN-06, RN-09).

Input shape (CF-03): `payload` is the signed payload as a JSON object, `kid` the JWS header
kid, `attachments` keyed by the RN-09 names `request_b64`, `record_body_b64`, `document`,
`previous`, `act`, `candidates`, `heads`. Texts follow RN-02 to RN-05, RN-08, RN-10 and RN-12
exactly; a method whose text the spec does not give raises `RenderGap` instead of a guess.
"""
import base64
import json

from . import base, forge, jcs

MAX_LINES = 72
MAX_REQUEST = 2048
MAX_REQUEST_LINES = 32
MAX_ESCAPED = 96
MAX_LINE = 100
MAX_WRAP = 98

ENVELOPE = frozenset(
    "action_ref binding cost ext inputs_hash log_policy method nonce outputs_hash "
    "parent_performer_id parent_receipt_hash performer_id reason requester_id status ts v".split())
PREFIX = "local:handsal."
VERDICTS = {PREFIX + "request.approve": "APPROVE request", PREFIX + "request.reject": "REJECT request",
            PREFIX + "request.needs-info": "NEEDS-INFO on request"}
DEVICE_ADD, DEVICE_REMOVE = PREFIX + "device.add", PREFIX + "device.remove"
MEMBER_ADD, RESOLVE = PREFIX + "member.add", PREFIX + "chain.resolve"
ENDORSE, RECORD, GENESIS = PREFIX + "act.endorse", PREFIX + "record.promote", PREFIX + "genesis.sign"
PRIMARIES = (DEVICE_ADD, DEVICE_REMOVE, MEMBER_ADD)
CHAIN = PRIMARIES + (RESOLVE,)
METHODS = frozenset(VERDICTS) | {DEVICE_ADD, DEVICE_REMOVE, MEMBER_ADD, RESOLVE, ENDORSE, RECORD,
                                 GENESIS}
_VERDICT_EXTRA = ("expires", "recipient", "relay", "request_id")
_TEXT = frozenset(range(0x20, 0x7F)) - {0x22, 0x5C}


class RenderGap(Exception):
    """The spec does not say what the text is."""


class _Refuse(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _raise(code):
    raise _Refuse(code)


# ---- short forms -----------------------------------------------------------

def _group(text):
    return "-".join(text[i:i + 4] for i in (0, 4, 8))


def hash12(hashstr):
    """Characters 3 to 14 of a hashstr (after the constant `uEi`), grouped by four."""
    return _group(hashstr[3:15])


def kid12(kid):
    """The first 12 characters of a kid, grouped by four."""
    return _group(kid[:12])


def free(text):
    """A free field longer than 12 characters: its first 11 plus `~` (RN-03)."""
    return text if len(text) <= 12 else text[:11] + "~"


def cut(line, limit):
    """`line` cut to `limit` bytes, plus `~` when cut."""
    return line if len(line) <= limit else line[:limit] + "~"


def _thumb(point):
    from . import keys
    return keys.thumbprint(point["x"], point["y"])


# ---- reading signed bytes ---------------------------------------------------

def _receipt_id(jws):
    return base.hashstr(forge.parts(jws)[1])


def _text_ok(value, maximum):
    return (isinstance(value, str) and 1 <= len(value) <= maximum
            and all(ord(c) in _TEXT for c in value))


def _body_schema(method, body):
    """Closed body shapes (ACT-09); anything else is `body_schema`."""
    point = lambda p: isinstance(p, dict) and set(p) == {"x", "y"}
    ok = isinstance(body, dict)
    if ok and method == DEVICE_ADD:
        ok = (set(body) == {"agree", "class", "kid", "label", "link_code_hash", "person", "sign"}
              and point(body["agree"]) and point(body["sign"]) and _text_ok(body["label"], 64))
    elif ok and method == DEVICE_REMOVE:
        ok = set(body) == {"kid", "person"}
    elif ok and method == MEMBER_ADD:
        ok = (set(body) == {"device", "link_code_hash", "member", "role"}
              and isinstance(body["device"], dict)
              and set(body["device"]) == {"agree", "class", "kid", "label", "sign"}
              and point(body["device"]["agree"]) and point(body["device"]["sign"])
              and _text_ok(body["device"]["label"], 64))
    elif ok and method == RESOLVE:
        ok = set(body) == {"candidates", "choose", "heads", "overrides"}
    elif ok and method == ENDORSE:
        ok = set(body) == {"act"}
    elif ok and method == RECORD:
        ok = (set(body) == {"anchors", "record_id"} and isinstance(body["anchors"], list)
              and all(_text_ok(a, 128) for a in body["anchors"]))
    elif ok:
        ok = body == {}
    if not ok:
        _raise("body_schema")


def _read_payload(inp):
    method, payload = inp.get("method"), inp.get("payload")
    if method not in METHODS or not (isinstance(payload, dict) and payload.get("method") == method):
        _raise("method_unknown")
    if set(payload) != ENVELOPE:
        _raise("schema")
    ext = payload["ext"]
    if not (isinstance(ext, dict) and set(ext) == {"dev.handsal/act"}):
        _raise("schema")
    act = ext["dev.handsal/act"]
    want = {"body", "kid", "org"}
    if method in VERDICTS:
        want |= set(_VERDICT_EXTRA) | {"head"}
    elif method == RECORD:
        want |= {"expires", "head"}
    elif method == ENDORSE:
        want |= {"head"}
    elif method == GENESIS and "head" in act:
        want |= {"head"}
    if not isinstance(act, dict) or set(act) != want:
        _raise("schema")
    _body_schema(method, act["body"])
    return payload, act


def _read_attached(jws):
    """(payload, act) of an attached act JWS; ACT-14: its act kid is its header kid."""
    try:
        header, raw, _sig = forge.parts(jws)
        payload = json.loads(raw)
        act = payload["ext"]["dev.handsal/act"]
        if json.loads(header)["kid"] != act["kid"]:
            _raise("attachment_mismatch")
    except (ValueError, KeyError, TypeError, AttributeError):
        _raise("attachment_mismatch")
    return payload, act


# ---- attachments (RN-09) ----------------------------------------------------

def _need(attachments, key):
    if key not in attachments:
        _raise("attachment_missing")
    return attachments[key]


def _bytes_attachment(attachments, key, inputs_hash):
    value = _need(attachments, key)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        _raise("attachment_mismatch")
    if base.hashstr(raw) != inputs_hash:
        _raise("attachment_mismatch")
    return raw


def _jws_list(attachments, key, ids):
    """One JWS per id of `ids` and nothing else, in any order (RN-09)."""
    jws_list = _need(attachments, key)
    if not isinstance(jws_list, list):
        _raise("attachment_mismatch")
    got = {}
    for jws in jws_list:
        rid = _receipt_id(jws)
        if rid in got or rid not in ids:
            _raise("attachment_mismatch")
        got[rid] = jws
    if set(got) != set(ids):
        _raise("attachment_mismatch")
    return got


def _bind_resolve(attachments, payload, act):
    """The candidate and head acts of a resolve, bound as RN-09 says: ({id: jws}, {id: jws})."""
    body = act["body"]
    cands = _jws_list(attachments, "candidates", body["candidates"])
    heads = _jws_list(attachments, "heads", body["heads"])
    for jws in cands.values():
        cp, _ = _read_attached(jws)
        if cp["parent_receipt_hash"] != payload["parent_receipt_hash"]:
            _raise("attachment_mismatch")
    for jws in heads.values():
        hp, _ = _read_attached(jws)
        if hp["method"] not in CHAIN:
            _raise("attachment_mismatch")
    return cands, heads


# ---- line 1 and method lines (RN-03, RN-04) ----------------------------------

def _line1_of(payload, act, attachments):
    """Line 1 of the act `payload` (any method but a verdict or genesis, needing no request)."""
    method, body = payload["method"], act["body"]
    if method == DEVICE_ADD:
        return "Add device %s (%s) to %s" % (kid12(body["kid"]), free(body["class"]),
                                               free(body["person"]))
    if method == DEVICE_REMOVE:
        return "Remove device %s of %s" % (kid12(body["kid"]), free(body["person"]))
    if method == MEMBER_ADD:
        return "Add device %s as member %s (%s)" % (kid12(body["device"]["kid"]),
                                                    free(body["member"]), free(body["role"]))
    if method == RESOLVE:
        chosen = _bind_resolve(attachments, payload, act)[0][body["choose"]]
        cp, ca = _read_attached(chosen)
        return "Resolve fork, keep: " + cut(_line1_of(cp, ca, {}), 59)
    raise RenderGap("line 1 of %s" % method)


def _escaped(line):
    """The tokens of one source line: a printable byte as is, any other as `\\xHH` (RN-05)."""
    return [chr(b) if 0x20 <= b <= 0x7E else "\\x%02x" % b for b in line]


def _segments(tokens):
    """Escaped content of one source line in segments of at most 96 bytes, never splitting a token."""
    out, current = [], ""
    for token in tokens:
        if len(current) + len(token) > MAX_ESCAPED:
            out.append(current)
            current = ""
        current += token
    return out + [current]


def _block(title, raw, hash_text):
    """The request or record block (RN-05, RN-12) as rendered lines."""
    if len(raw) > MAX_REQUEST:
        _raise("render_refused")
    source = raw.split(b"\n")
    if source[-1] == b"":  # a final LF ends the last line and starts no other
        source.pop()
    content = []
    for line in source:
        for index, segment in enumerate(_segments(_escaped(line))):
            content.append(("| " if index == 0 else "|+") + segment)
    if len(content) > MAX_REQUEST_LINES:
        _raise("render_refused")
    return (["----- %s (%d bytes, sha256 %s) -----" % (title, len(raw), hash_text)] + content
            + ["----- end -----"])


def _method_lines(payload, act, attachments):
    method, body = payload["method"], act["body"]
    if method == DEVICE_ADD:
        return ["Person: " + body["person"], "New device: " + body["kid"],
                "Agree key: " + _thumb(body["agree"]), "Class: " + body["class"],
                "Label: " + body["label"], "Link code: " + hash12(body["link_code_hash"])]
    if method == DEVICE_REMOVE:
        return ["Person: " + body["person"], "Remove device: " + body["kid"]]
    if method == MEMBER_ADD:
        dev = body["device"]
        return ["Member: " + body["member"], "Role: " + body["role"], "New device: " + dev["kid"],
                "Agree key: " + _thumb(dev["agree"]), "Class: " + dev["class"],
                "Label: " + dev["label"]]
    if method == RESOLVE:
        cands, heads = _bind_resolve(attachments, payload, act)
        out = ["Fork parent: " + payload["parent_receipt_hash"], "Choose: " + body["choose"],
               "Candidates:"]
        for cid in body["candidates"]:
            cp, ca = _read_attached(cands[cid])
            out.append("%s%s %s" % ("  > " if cid == body["choose"] else "    ", hash12(cid),
                                    _line1_of(cp, ca, {})))
        out.append("Heads:")
        for hid in body["heads"]:
            hp, ha = _read_attached(heads[hid])
            out.append("  - %s %s" % (hash12(hid), _line1_of(hp, ha, {})))
        if body["overrides"]:
            out.append("Overrides:")
            out.extend("  - %s (endorsements: %d)" % (hash12(e["resolve"]), len(e["endorsements"]))
                       for e in body["overrides"])
        else:
            out.append("Overrides: none")
        return out
    raise RenderGap("method lines of %s" % method)


def _endorse(attachments, payload, act):
    """(line 1 tail, lines) of an endorsement after binding its `act` (RN-09)."""
    jws = _need(attachments, "act")
    ap, aa = _read_attached(jws)
    if (_receipt_id(jws) != act["body"]["act"]
            or payload["parent_receipt_hash"] != act["body"]["act"]
            or ap["performer_id"] != payload["parent_performer_id"]
            or ap["parent_receipt_hash"] != act["head"]["id"] or ap["method"] not in CHAIN):
        _raise("attachment_mismatch")
    if ap["method"] != RESOLVE and ("candidates" in attachments or "heads" in attachments):
        _raise("attachment_mismatch")
    return ap, aa


def _wrap(line):
    """RN-02: a line over 100 bytes is its first 98 bytes, then `+ ` and at most 98 bytes each."""
    if len(line) <= MAX_LINE:
        return [line]
    return [line[:MAX_WRAP]] + ["+ " + line[i:i + MAX_WRAP] for i in range(MAX_WRAP, len(line), MAX_WRAP)]


def _finish(first, payload, act, middle, *, sender):
    lines = [first, "Method: " + payload["method"], "Org: " + hash12(act["org"]),
             "Signer: %s key %s" % (payload["performer_id"], kid12(act["_kid"]))]
    lines += middle
    lines.append("Signed at: " + payload["ts"])
    if "expires" in act:
        lines.append("Expires: " + act["expires"])
    if payload["parent_receipt_hash"] is not None:
        lines.append("Parent: " + hash12(payload["parent_receipt_hash"]))
    if "head" in act:
        lines.append("Head: " + hash12(act["head"]["id"]))
    if sender:
        lines.append("Sender: not proven")
    lines = [first] + [part for line in lines[1:] for part in _wrap(line)]
    if len(lines) > MAX_LINES:
        _raise("render_refused")
    return {"first_line": first, "text": "\n".join(lines) + "\n"}


def _document(attachments, name, bound_to):
    """The attached genesis document `name`, bound to the hashstr `bound_to` and valid alone (RN-09).

    Valid by itself is GP-15 steps 1 and 3, which `base.check_genesis_shape` states for the
    generator (structure, then policy and devices). A bound document that is not valid is
    `attachment_mismatch`, like an act attachment that fails ACT-01 to ACT-14.
    """
    document = _need(attachments, name)
    if not isinstance(document, dict) or base.hashstr(jcs.emit(document)) != bound_to:
        _raise("attachment_mismatch")
    if base.check_genesis_shape(document):
        _raise("attachment_mismatch")
    return document


def _policy_lines(policy):
    """The policy lines of RN-04, the same in an original and in a change."""
    out = ["Policy:", "  Roles: " + ",".join(policy["roles"])]
    for name in sorted(policy["rules"]):
        rule = policy["rules"][name]
        out.append("  Rule %s: %s of %s" % (name, rule["persons"], ",".join(rule["roles"])))
    out += ["  Class %s: %s" % (c["class"], c["user_verification"]) for c in policy["classes"]]
    fresh = policy["freshness"]
    out += ["  Clock skew: %s s" % fresh["clock_skew_s"],
            "  Max validity: %s s" % fresh["max_validity_s"],
            "  Max view age: %s s" % fresh["max_view_age_s"]]
    witness = policy["witness"]
    if witness["mode"] == "none":
        out.append("  Witness: none")
    else:
        out += ["  Witness: relay", "  Relay key: " + witness["relay_kid"],
                "  Max tip age: %s s" % witness["max_tip_age_s"]]
    return out


def _device_lines(entry):
    return ["  - %s of %s" % (entry["kid"], entry["person"]), "    Class: " + entry["class"],
            "    Label: " + entry["label"], "    Agree: " + _thumb(entry["agree"])]


def _genesis(attachments, payload, act):
    """(line 1, method lines) of a `genesis.sign` over an original or a change (RN-04, RN-10)."""
    doc = _document(attachments, "document", payload["inputs_hash"])
    hash_text = hash12(payload["inputs_hash"])
    opening = ["Org name: " + doc["name"], "Profile: " + doc["profile"]]
    if doc["prev"] is None:
        first = "Sign genesis of %s (%s): %d members, %d devices" % (
            free(doc["name"]), hash_text, len(doc["members"]), len(doc["devices"]))
        lines = opening + ["Members:"] + ["  - %s %s" % (m["id"], m["role"]) for m in doc["members"]]
        lines.append("Devices:")
        for entry in doc["devices"]:
            lines += _device_lines(entry)
        return first, lines + _policy_lines(doc["policy"]) + ["Document hash: " + hash_text]
    previous = _document(attachments, "previous", doc["prev"])
    if act.get("head", {}).get("id") != doc["head"]:
        _raise("attachment_mismatch")
    old_kids = {d["kid"]: d for d in previous["devices"]}
    new_kids = {d["kid"]: d for d in doc["devices"]}
    old_roles = {m["id"]: m["role"] for m in previous["members"]}
    new_roles = {m["id"]: m["role"] for m in doc["members"]}
    devices_added = [d for d in doc["devices"] if d["kid"] not in old_kids]
    devices_removed = [d for d in previous["devices"] if d["kid"] not in new_kids]
    members_added = [m for m in doc["members"] if m["id"] not in old_roles]
    members_removed = [m for m in previous["members"] if m["id"] not in new_roles]
    changed = [m for m in doc["members"] if m["id"] in old_roles and old_roles[m["id"]] != m["role"]]
    same_policy = jcs.emit(previous["policy"]) == jcs.emit(doc["policy"])
    first = "Change %s (%s): +%d/-%d dev, %d mem, policy %s" % (
        free(doc["name"]), hash_text, len(devices_added), len(devices_removed),
        len(members_added) + len(members_removed) + len(changed), "same" if same_policy else "NEW")
    lines = opening + ["Previous: " + hash12(doc["prev"]), "Head: " + doc["head"]]
    if members_added:
        lines += ["Members added:"] + ["  - %s %s" % (m["id"], m["role"]) for m in members_added]
    if members_removed:
        lines += ["Members removed:"] + ["  - %s %s" % (m["id"], m["role"]) for m in members_removed]
    if changed:
        lines += ["Role changed:"] + ["  - %s %s -> %s" % (m["id"], old_roles[m["id"]], m["role"])
                                       for m in changed]
    if devices_added:
        lines.append("Devices added:")
        for entry in devices_added:
            lines += _device_lines(entry)
    if devices_removed:
        lines += ["Devices removed:"] + ["  - %s of %s" % (d["kid"], d["person"])
                                          for d in devices_removed]
    lines += _policy_lines(doc["policy"])
    unchanged_devices = sum(1 for kid in new_kids if kid in old_kids)
    unchanged_members = sum(1 for i, role in new_roles.items() if old_roles.get(i) == role)
    lines.append("Unchanged: %d devices, %d members" % (unchanged_devices, unchanged_members))
    return first, lines


def render(inp):
    """The `render` result for the checker input `inp`."""
    try:
        payload, act = _read_payload(inp)
        method, attachments = payload["method"], inp.get("attachments", {})
        view = dict(act, _kid=inp["kid"])
        if method in VERDICTS:
            raw = _bytes_attachment(attachments, "request_b64", payload["inputs_hash"])
            req_hash = hash12(payload["inputs_hash"])
            body = act
            first = "%s %s (%s, %d bytes)" % (VERDICTS[method], free(body["request_id"]), req_hash,
                                              len(raw))
            middle = ["Request: " + body["request_id"], "Recipient: " + body["recipient"],
                      "Relay: " + body["relay"], "Request hash: " + req_hash]
            middle += _block("request", raw, req_hash)
            return _finish(first, payload, view, middle, sender=True)
        if method == RECORD:
            raw = _bytes_attachment(attachments, "record_body_b64", payload["inputs_hash"])
            body_hash = hash12(payload["inputs_hash"])
            body = act["body"]
            first = "Promote record %s (%s, %d bytes)" % (free(body["record_id"]), body_hash,
                                                          len(raw))
            middle = ["Record: " + body["record_id"], "Anchors:"]
            middle += ["  - " + a for a in body["anchors"]]
            middle += ["Body hash: " + body_hash]
            middle += _block("record body", raw, body_hash)
            return _finish(first, payload, view, middle, sender=False)
        if method == GENESIS:
            first, middle = _genesis(attachments, payload, act)
            return _finish(first, payload, view, middle, sender=False)
        if method == ENDORSE:
            ap, aa = _endorse(attachments, payload, act)
            first = "Endorse: " + cut(_line1_of(ap, aa, attachments), 70)
            middle = ["Endorsed act: " + act["body"]["act"]] + _method_lines(ap, aa, attachments)
            return _finish(first, payload, view, middle, sender=False)
        first = _line1_of(payload, act, attachments)
        return _finish(first, payload, view, _method_lines(payload, act, attachments), sender=False)
    except _Refuse as refusal:
        return {"error": refusal.code}
