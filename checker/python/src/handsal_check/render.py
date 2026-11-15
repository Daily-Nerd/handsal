"""The render, core (RN-01, RN-02, RN-03, RN-06): short forms, the layout frame, line 1 and the refusals.

The render is a pure function of signed bytes plus the attachments bound to them: ASCII, no locale,
no clock, no I/O. It is also the ONE owner of "what fits" (RN-10): `frame` is the only place that
lays lines out, wraps them and counts them against 72, and the fold's genesis size check calls it
too (`render_genesis.render_size`), so the two can never disagree.

Layers, none importing the one above it:
  render          this module: short forms, `frame`, line 1, input and payload checks
  render_methods  the method lines of RN-04 and the request block (RN-05, RN-12)
  render_genesis  genesis documents, the difference of a change and the size bound (RN-08, RN-10)
  render_attach   RN-09 bindings and the `render` command

`Facts` carries what a bound attachment tells line 1 and the method lines: the raw bytes of a
request or a decision, the line 1 of each attached candidate and head act, the endorsed act, the
genesis summary. Nothing here reads an attachment; `render_attach` binds them first.

Failures are `errors.Refused` with the codes of section 11: `schema`, `method_unknown`,
`body_schema`, `attachment_missing`, `attachment_mismatch`, `render_refused`. A mistyped command
input is `errors.Malformed`.
"""
from collections import namedtuple

from . import envelope, errors

MAX_LINES = 72
MAX_LINE = 100
SEGMENT = 98
CONT = "+ "
EXT = envelope.EXT_KEY
PREFIX = "local:handsal."
DEVICE_ADD, DEVICE_REMOVE, MEMBER_ADD = (PREFIX + name for name in ("device.add", "device.remove", "member.add"))
RESOLVE, ENDORSE, GENESIS_SIGN, DECISION = (PREFIX + name for name in (
    "chain.resolve", "act.endorse", "genesis.sign", "decision"))
VERDICTS = {PREFIX + "request.approve": "APPROVE request", PREFIX + "request.reject": "REJECT request",
            PREFIX + "request.needs-info": "NEEDS-INFO on request"}

Input = namedtuple("Input", "attachments kid method payload")
Rendered = namedtuple("Rendered", "first_line text")
Facts = namedtuple("Facts", "raw summary candidates heads endorsed_line1 endorsed_lines genesis",
                   defaults=(None,) * 7)


def refuse(code):
    return errors.Refused(code)


# The group separator is never a character of what it groups: kids and hashstrs are base64url, which
# holds `-`, so a `-` separator made `pbubEyWn-20K` read `pbub-EyWn--20K` (section 2.1).
GROUP_SEPARATOR = " "


def _group(text):
    return GROUP_SEPARATOR.join(text[i:i + 4] for i in range(0, len(text), 4))


def hash12(value):
    """The 12 characters after the constant `uEi` of a hashstr, grouped `xxxx xxxx xxxx` (section 2.1)."""
    return _group(value[3:15])


def kid12(value):
    """The first 12 characters of a kid, grouped like `hash12`."""
    return _group(value[:12])


def cut12(value):
    """A free field in line 1: as is up to 12 characters, else its first 11 and `~` (RN-03)."""
    return value if len(value) <= 12 else value[:11] + "~"


def cut_to(text, size):
    """`text` as is up to `size` bytes, else its first `size` bytes and `~` (RN-03)."""
    return text if len(text) <= size else text[:size] + "~"


def wrap(line):
    """A line of at most 100 bytes as is; a longer one in segments of at most 98 bytes, each
    continuation prefixed `+ `, so no signed byte is hidden (RN-02)."""
    if len(line) <= MAX_LINE:
        return [line]
    out = [line[:SEGMENT]]
    out.extend(CONT + line[i:i + SEGMENT] for i in range(SEGMENT, len(line), SEGMENT))
    return out


def frame(*, first, method, org, performer, kid, body, ts, expires, parent, head, sender):
    """The `Rendered` of RN-02: line 1, `Method`, `Org`, `Signer`, the method lines `body`, `Signed at`,
    `Expires`, `Parent`, `Head`, and `Sender: not proven` for verdicts. A render over 72 lines is
    `render_refused`. `org`, `parent` and `head` are hashstrs shown as `hash12`; `expires`, `parent` and
    `head` are None where the act has none."""
    lines = [first, "Method: " + method, "Org: " + hash12(org), "Signer: %s key %s" % (performer, kid12(kid))]
    lines.extend(body)
    lines.append("Signed at: " + ts)
    if expires is not None:
        lines.append("Expires: " + expires)
    if parent is not None:
        lines.append("Parent: " + hash12(parent))
    if head is not None:
        lines.append("Head: " + hash12(head))
    if sender:
        lines.append("Sender: not proven")
    out = lines[:1]
    for line in lines[1:]:
        out.extend(wrap(line))
    if len(out) > MAX_LINES:
        raise refuse("render_refused")
    return Rendered(first, "\n".join(out) + "\n")


def parse_input(value):
    """The `Input` of the command JSON: exactly `attachments`, `kid`, `method`, `payload`, else Malformed."""
    if type(value) is not dict or set(value) != {"attachments", "kid", "method", "payload"}:
        raise errors.Malformed()
    if (type(value["attachments"]) is not dict or type(value["kid"]) is not str
            or type(value["method"]) is not str or type(value["payload"]) is not dict):
        raise errors.Malformed()
    return Input(value["attachments"], value["kid"], value["method"], value["payload"])


def act_object(payload):
    return payload["ext"][EXT]


def check_envelope(payload, method, reg):
    """The payload's envelope (`schema`), that it is the method asked for (`schema`), and that the
    registry knows it (`method_unknown`): the order of `check-act` steps 3 and 4 (VR-02)."""
    envelope.check_envelope(payload)
    if payload["method"] != method:
        raise refuse("schema")
    if reg.method(method) is None:
        raise refuse("method_unknown")


def check_act(payload, kid, reg, head_present=None):
    """The act object and the body of a payload whose envelope passed (`schema`, `body_schema`), and
    that a resolve chooses one of its own candidates (`body_schema`, ACT-09)."""
    envelope.check_act_object(payload, kid, reg, head_present)
    if payload["method"] == RESOLVE:
        body = act_object(payload)["body"]
        if body["choose"] not in body["candidates"]:
            raise refuse("body_schema")


def _device_add(payload, act, facts):
    body = act["body"]
    return "Add device %s (%s) to %s" % (kid12(body["kid"]), cut12(body["class"]), cut12(body["person"]))


def _device_remove(payload, act, facts):
    body = act["body"]
    return "Remove device %s of %s" % (kid12(body["kid"]), cut12(body["person"]))


def _member_add(payload, act, facts):
    body = act["body"]
    return "Add device %s as member %s (%s)" % (kid12(body["device"]["kid"]), cut12(body["member"]), cut12(body["role"]))


def _verdict(payload, act, facts):
    return "%s %s (%s, %d bytes)" % (VERDICTS[payload["method"]], cut12(act["request_id"]),
                                     hash12(payload["inputs_hash"]), len(facts.raw))


def _decision(payload, act, facts):
    """`<consumer>: <action> <subject> (<hash12>, <N> bytes)`: the consumer and the subject are free fields (cut to
    12), the action is whole. Its grammar bounds it at 24, which is what keeps the line at 80 bytes (RN-03)."""
    body = act["body"]
    return "%s: %s %s (%s, %d bytes)" % (cut12(body["consumer"]), body["action"], cut12(body["subject"]),
                                         hash12(payload["inputs_hash"]), len(facts.raw))


def _resolve(payload, act, facts):
    return "Resolve fork, keep: " + cut_to(facts.candidates[act["body"]["choose"]], 59)


def _endorse(payload, act, facts):
    return "Endorse: " + cut_to(facts.endorsed_line1, 70)


def _genesis(payload, act, facts):
    return facts.summary


_FIRST = {DEVICE_ADD: _device_add, DEVICE_REMOVE: _device_remove, MEMBER_ADD: _member_add,
          DECISION: _decision, RESOLVE: _resolve, ENDORSE: _endorse, GENESIS_SIGN: _genesis}
_FIRST.update({method: _verdict for method in VERDICTS})


def first_line(method, payload, facts):
    """Line 1 of a payload of `method` (RN-03): the decision summary, at most 80 bytes. It is also the
    OS prompt text (RN-11)."""
    return _FIRST[method](payload, act_object(payload), facts)
