"""`check-act` (VR-01, VR-02): the input and the ordered pipeline.

`parse_input` turns the JSON of a command into an `Input` or raises `Malformed`: every required input of
VR-01 is checked before anything else, `acts` and every `sigs` hold strings only (GP-07), and the two
`_b64` inputs are canonical base64 (section 2.2). `run` evaluates the steps in order and returns the
four-key result of the first failure:

  1 to 5   the act by itself: JWS shape, payload, envelope, method, act object and body (`envelope`)
  6        the pin (a) to (h), then the real fold (`pinned.fold`):
           a fold error code, or `fork`, is the reason. `class` is null up to here.
  7 to 16  `rules.STEPS`, over the state at the tip. From step 7 on `class` is the class of the pinned
           state's device whose kid is the header kid, else null (VR-01).

A verifier that cannot answer is the reason `verifier_unavailable`, at the fold or at step 9: never a skip.
`receipt_id` is null until the payload parses (step 2).

`pin` and `now` are inputs of the conformance build only (CF-08): with `conformance_build=False` an input
that carries either is `malformed_input`, and the result's `pin` and `now` are None, to be filled
in-process by the production build.
"""
from collections import namedtuple

import base64
import binascii

from . import envelope, errors, foldcmd, jws, pinned, render_genesis, rules, schema, verifier
from .human import HUMAN_METHODS, PROMOTE, VERDICTS
from .pinfile import Probe

Input = namedtuple("Input", "acts expect_method jws lineage now org pin recipient record_body_b64 "
                            "relay request_b64 request_id seen synced_at tip_statement request_bytes record_bytes")


def _malformed():
    return errors.Malformed()


def _get(value, key, kind):
    """`value[key]`, which must be present and of exactly the type `kind`."""
    if key not in value or type(value[key]) is not kind:
        raise _malformed()
    return value[key]


def _raw(text):
    """The bytes of a canonical standard base64 input, else Malformed."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise _malformed() from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise _malformed()
    return raw


def parse_input(value, conformance_build=True):
    """The `Input` of the command JSON `value` (VR-01), or raise Malformed."""
    if type(value) is not dict:
        raise _malformed()
    for key in ("pin", "now"):
        if (key in value) != conformance_build:   # required here, refused in production
            raise _malformed()
    acts, lineage, seen = (_get(value, key, list) for key in ("acts", "lineage", "seen"))
    foldcmd.check_texts(acts)
    foldcmd.check_lineage(lineage)
    expect_method, jws_text = _get(value, "expect_method", str), _get(value, "jws", str)
    org = _get(value, "org", str)
    synced_at = _get(value, "synced_at", str)
    if not schema.is_hashstr(org) or not schema.is_time(synced_at):
        raise _malformed()
    if not all(schema.is_hashstr(item) for item in seen):
        raise _malformed()
    if "tip_statement" not in value or not (value["tip_statement"] is None
                                            or type(value["tip_statement"]) is str):
        raise _malformed()
    now = pin = None
    if conformance_build:
        now = _get(value, "now", str)
        if not schema.is_time(now):
            raise _malformed()
        pin = Probe.from_json(value["pin"])
    recipient = record_body_b64 = relay = request_b64 = request_id = request_bytes = record_bytes = None
    if expect_method in VERDICTS:
        request_b64, request_id = _get(value, "request_b64", str), _get(value, "request_id", str)
        recipient, relay = _get(value, "recipient", str), _get(value, "relay", str)
        request_bytes = _raw(request_b64)
    elif expect_method == PROMOTE:
        record_body_b64 = _get(value, "record_body_b64", str)
        record_bytes = _raw(record_body_b64)
    return Input(acts, expect_method, jws_text, lineage, now, org, pin, recipient, record_body_b64,
                 relay, request_b64, request_id, seen, synced_at, value["tip_statement"], request_bytes,
                 record_bytes)


def _result(reason, receipt, cls=None):
    return {"class": cls, "reason": reason, "receipt_id": receipt, "valid": False}


def _parse_act(inp, reg):
    """Steps 1 to 5: `(jws, payload, receipt id)` of a well-formed human act, or the Refused result."""
    try:
        parsed = jws.parse(inp.jws)
        payload = envelope.parse_payload(parsed.payload)
    except errors.Refused as err:
        return _result(err.code, None)
    receipt = envelope.receipt_id(parsed.payload)
    try:
        envelope.check_envelope(payload)
        if reg.method(payload["method"]) is None:
            raise errors.Refused("method_unknown")
        if payload["method"] not in HUMAN_METHODS:
            raise errors.Refused("chain_method")
        envelope.check_act_object(payload, parsed.kid, reg)
    except errors.Refused as err:
        return _result(err.code, receipt)
    return parsed, payload, receipt


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The result of `check-act` for `inp`: the first failing step, or `valid:true` with `ok`. `vitni` is
    the verifier (CF-05)."""
    early = _parse_act(inp, reg)
    if type(early) is dict:
        return early
    parsed, payload, receipt = early
    vitni = verifier.Memoized(vitni)
    try:
        pin, epochs, node = pinned.fold(inp.pin, inp.org, inp.lineage, inp.acts, reg, profiles, allow_fixture,
                                         vitni, render_size)
    except errors.Refused as err:
        return _result(err.code, receipt)
    except verifier.VerifierUnavailable:
        return _result("verifier_unavailable", receipt)
    ctx = rules.context(inp, parsed, payload, receipt, epochs, node, pin, vitni)
    cls = rules.device_class(ctx)
    try:
        for step in rules.STEPS:
            step(ctx)
    except errors.Refused as err:
        return _result(err.code, receipt, cls)
    except verifier.VerifierUnavailable:
        return _result("verifier_unavailable", receipt, cls)
    return {"class": cls, "reason": "ok", "receipt_id": receipt, "valid": True}
