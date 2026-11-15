"""`check-act` (VR-01, VR-02): the input and the ordered pipeline.

`parse_input` turns the JSON of a command into an `Input` or raises `Malformed`: every required input of
VR-01 is checked before anything else, `acts` and every `sigs` hold strings only (GP-07), and the two
`_b64` inputs are canonical base64 (section 2.2). `run` evaluates the steps in order and returns the
four-key result of the first failure. The steps run in `pipeline.judge`, which `recheck-act` shares:

  1 to 5   the act by itself: JWS shape, payload, envelope, method, act object and body (`envelope`)
  6        the pin (a) to (h), then the real fold (`pinned.folded`, `pinned.tip`):
           a fold error code, or `fork`, is the reason. `class` is null up to here.
  7 to 16  `rules.STEPS`, over the state at the tip. From step 7 on `class` is the class of the pinned
           state's device whose kid is the header kid, else null (VR-01).

`receipt_id` is null until the payload parses (step 2).

`pin`, `now` and the store's content (`acts`, `lineage`, `synced_at`, `tip_statement`) are inputs of the
conformance build only (CF-08, CF-09): with `conformance_build=False` an input that carries any is
`malformed_input`, and the result holds placeholders for them (None, or empty lists), to be filled in-process
by the production build, with the store's failure as `store_reason` (VR-02 step 6 (f)).
"""
from collections import namedtuple

import base64
import binascii

from . import errors, foldcmd, pipeline, render_genesis, rules, schema
from .human import DECISION, VERDICTS
from .pinfile import Probe

# the inputs of the act and its evidence, read the same way by `check-act` and `recheck-act`
ACT_FIELDS = ("acts action consumer decision_b64 decision_bytes expect_method jws lineage org pin recipient "
              "relay request_b64 request_id subject request_bytes store_reason")
Input = namedtuple("Input", "acts action consumer decision_b64 decision_bytes expect_method jws lineage now org pin "
                            "recipient relay request_b64 request_id seen subject synced_at tip_statement "
                            "request_bytes store_reason")


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


def parse_act_fields(value, conformance_build):
    """The inputs of the act and of its evidence, as a dict keyed by `ACT_FIELDS`: what `check-act` and
    `recheck-act` read the same way (VR-01, VR-17). `value` is a dict; `pin` is the probe in the conformance
    build and None in production. Raises Malformed."""
    acts, lineage = foldcmd.read_chain(value, conformance_build)
    expect_method, jws_text = _get(value, "expect_method", str), _get(value, "jws", str)
    org = _get(value, "org", str)
    if not schema.is_hashstr(org):
        raise _malformed()
    pin = Probe.from_json(value["pin"]) if conformance_build else None
    fields = dict(acts=acts, action=None, subject=None, consumer=None, decision_b64=None, decision_bytes=None, expect_method=expect_method,
                  jws=jws_text, lineage=lineage, org=org, pin=pin, recipient=None,
                  relay=None, request_b64=None, request_id=None, request_bytes=None, store_reason=None)
    if expect_method in VERDICTS:
        fields.update(request_b64=_get(value, "request_b64", str), request_id=_get(value, "request_id", str),
                      recipient=_get(value, "recipient", str), relay=_get(value, "relay", str))
        fields["request_bytes"] = _raw(fields["request_b64"])
    elif expect_method == DECISION:
        fields["consumer"] = _get(value, "consumer", str)
        if not schema.is_consumer_id(fields["consumer"]):   # a name no act can carry is told at once (VR-18)
            raise _malformed()
        fields["action"], fields["subject"] = _get(value, "action", str), _get(value, "subject", str)
        if not (schema.is_action(fields["action"]) and schema.is_subject_id(fields["subject"])):
            raise _malformed()   # the words the caller expects have the forms of the body (VR-18)
        fields["decision_b64"] = _get(value, "decision_b64", str)
        fields["decision_bytes"] = _raw(fields["decision_b64"])
    return fields


def parse_input(value, conformance_build=True):
    """The `Input` of the command JSON `value` (VR-01), or raise Malformed."""
    if type(value) is not dict:
        raise _malformed()
    for key in ("pin", "now"):
        if (key in value) != conformance_build:   # required here, refused in production
            raise _malformed()
    seen = _get(value, "seen", list)
    if not all(schema.is_hashstr(item) for item in seen):
        raise _malformed()
    synced_at, tip_statement = foldcmd.read_view(value, conformance_build)
    fields = parse_act_fields(value, conformance_build)
    now = None
    if conformance_build:
        now = _get(value, "now", str)
        if not schema.is_time(now):
            raise _malformed()
    return Input(now=now, seen=seen, synced_at=synced_at, tip_statement=tip_statement, **fields)


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The result of `check-act` for `inp`: the first failing step, or `valid:true` with `ok`. `vitni` is
    the verifier (CF-05)."""
    got = pipeline.judge(inp, reg, profiles, allow_fixture, vitni, render_size,
                         locate=pipeline.tip, steps=rules.STEPS)
    return {"class": got.cls, "reason": got.reason, "receipt_id": got.receipt, "valid": got.reason == "ok"}
