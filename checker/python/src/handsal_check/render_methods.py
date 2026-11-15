"""Method lines (RN-04) and the request and decision blocks (RN-05, RN-12).

`method_lines` returns the lines between `Signer` and `Signed at` for every method but `genesis.sign`
(that is `render_genesis`). Every value is shown verbatim, one line per field. Lists that name acts
(a resolve's candidates and heads) take the line 1 of each attached act from `Facts`, which
`render_attach` filled after binding the attachments.

`block` renders untrusted bytes. They are never decoded as UTF-8: each source line is `| ` plus its
escaped bytes, 0x20 to 0x7E as is and every other byte as `\\xHH`, so no Unicode table is needed, a
line `----- end -----` in the request cannot end the block, and control and bidirectional bytes are
visible. A block over 2048 source bytes or 32 lines is `render_refused`: nothing is truncated.
"""
from . import encoding, render
from .render import PREFIX, hash12

MAX_BLOCK_BYTES = 2048
MAX_BLOCK_LINES = 32
CONTENT = 96


def escape(raw):
    """The tokens of `raw`: a printable ASCII character is itself, any other byte is `\\xHH`."""
    return [chr(b) if 0x20 <= b <= 0x7E else "\\x%02x" % b for b in raw]


def _source_lines(raw):
    pieces = raw.split(b"\n")
    if pieces[-1] == b"":   # a final LF ends the last line, it does not start another
        pieces.pop()
    return pieces


def _segments(tokens):
    """The content of one source line in segments of at most 96 characters, never splitting an escape."""
    out, current, size = [], [], 0
    for token in tokens:
        if size + len(token) > CONTENT:
            out.append("".join(current))
            current, size = [], 0
        current.append(token)
        size += len(token)
    out.append("".join(current))
    return out


def block(title, raw, inputs_hash):
    """The lines of the block of `raw` under `title` (`request` or `decision`), or `render_refused`."""
    if len(raw) > MAX_BLOCK_BYTES:
        raise render.refuse("render_refused")
    content = []
    for source in _source_lines(raw):
        first, *rest = _segments(escape(source))
        content.append("| " + first)
        content.extend("|+" + segment for segment in rest)
    if len(content) > MAX_BLOCK_LINES:
        raise render.refuse("render_refused")
    header = "----- %s (%d bytes, sha256 %s) -----" % (title, len(raw), hash12(inputs_hash))
    return [header] + content + ["----- end -----"]


def _agree(device):
    return "Agree key: " + encoding.thumbprint(device["agree"]["x"], device["agree"]["y"])


def _device_add(payload, act, facts):
    body = act["body"]
    return ["Person: " + body["person"], "New device: " + body["kid"], _agree(body), "Class: " + body["class"],
            "Label: " + body["label"], "Link code: " + hash12(body["link_code_hash"])]


def _device_remove(payload, act, facts):
    body = act["body"]
    return ["Person: " + body["person"], "Remove device: " + body["kid"]]


def _member_add(payload, act, facts):
    body = act["body"]
    device = body["device"]
    return ["Member: " + body["member"], "Role: " + body["role"], "New device: " + device["kid"], _agree(device),
            "Class: " + device["class"], "Label: " + device["label"]]


def _verdict(payload, act, facts):
    out = ["Request: " + act["request_id"], "Recipient: " + act["recipient"], "Relay: " + act["relay"],
           "Request hash: " + hash12(payload["inputs_hash"])]
    return out + block("request", facts.raw, payload["inputs_hash"])


def _decision(payload, act, facts):
    body = act["body"]
    out = ["Consumer: " + body["consumer"], "Action: " + body["action"], "Subject: " + body["subject"],
           "Decision hash: " + hash12(payload["inputs_hash"])]
    return out + block("decision", facts.raw, payload["inputs_hash"])


def _listed(title, ids, line_of, marker=None):
    out = [title]
    for act_id in ids:
        lead = "  - " if marker is None else ("  > " if act_id == marker else "    ")
        out.append("%s%s %s" % (lead, hash12(act_id), line_of[act_id]))
    return out


def _resolve(payload, act, facts):
    body = act["body"]
    out = ["Fork parent: " + payload["parent_receipt_hash"], "Choose: " + body["choose"]]
    out += _listed("Candidates:", body["candidates"], facts.candidates, body["choose"])
    out += _listed("Heads:", body["heads"], facts.heads)
    if not body["overrides"]:
        return out + ["Overrides: none"]
    out.append("Overrides:")
    out.extend("  - %s (endorsements: %d)" % (hash12(entry["resolve"]), len(entry["endorsements"]))
               for entry in body["overrides"])
    return out


def _endorse(payload, act, facts):
    return ["Endorsed act: " + act["body"]["act"]] + list(facts.endorsed_lines)


_LINES = {PREFIX + "device.add": _device_add, PREFIX + "device.remove": _device_remove,
          PREFIX + "member.add": _member_add,
          PREFIX + "decision": _decision,
          PREFIX + "chain.resolve": _resolve, PREFIX + "act.endorse": _endorse}
_LINES.update({method: _verdict for method in render.VERDICTS})


def method_lines(method, payload, facts):
    """The RN-04 lines of `payload`, a method other than `genesis.sign`."""
    return _LINES[method](payload, render.act_object(payload), facts)
