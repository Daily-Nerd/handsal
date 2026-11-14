"""Command inputs and anchors for check-act, fold and enrolled (VR-01, GP-13, GP-14, CF-03).

Inputs are assembled from the base fixtures. Anchors are authored from the
expected behaviour with the serializer of lib/result.py; no checker code is
involved (CF-06).

check-act output is `{class, reason, receipt_id, valid}` (VR-01). The rule:

- `receipt_id` is null for steps 1 and 2 and hashstr(payload bytes) from step 3 on;
- `class` is null for steps 1 to 6, and from step 7 on it is the class of the
  device of the pinned state whose kid is the header kid, or null when the state
  has no such device.

`check_anchor` is the one place that applies it. The caller passes the class the
state gives the header kid (`signer_class`), because only the caller knows whether
the kid is in the state (vtn/unknown-key: not; vtn/unaccepted-map-keyed-by-person:
yes, with another performer).
"""
import base64
import copy

from . import base, forge, jcs, keys, p256, result

APPROVE = "local:handsal.request.approve"
REJECT = "local:handsal.request.reject"
NEEDS_INFO = "local:handsal.request.needs-info"
RECORD_PROMOTE = "local:handsal.record.promote"
DECISION = "local:handsal.decision"
_VERDICT_METHODS = (APPROVE, REJECT, NEEDS_INFO)

DROP = object()  # as an override value: remove the key from the input

# check-act reasons by the step they arise at (VR-02, section 11)
_NO_PAYLOAD = frozenset(("jws_shape", "payload_not_canonical_subset", "payload_too_large"))
FOLD_ERRORS = frozenset((
    "genesis_schema", "doc_not_sorted", "genesis_key_invalid", "duplicate_key", "profile_mismatch",
    "fixture_profile", "policy_invalid", "policy_out_of_bounds", "policy_unreachable",
    "class_unknown", "class_pending", "class_test_only", "class_policy_mismatch",
    "role_key_class", "fixture_key", "lineage_broken", "genesis_render_too_large",
    "genesis_unsigned", "genesis_head_unknown", "genesis_change_unauthorized",
    "genesis_device_revoked", "genesis_device_changed", "genesis_pin_mismatch", "fork",
    "at_beyond_tip", "verifier_unavailable"))
# steps 3 to 6: the payload parsed, the pinned state is not yet usable
_BEFORE_STATE = (FOLD_ERRORS - {"verifier_unavailable"}) | frozenset((
    "schema", "method_unknown", "chain_method", "body_schema", "pin_org_mismatch", "pin_missing",
    "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected", "pin_malformed",
    "pin_spec_mismatch"))
# step 7 on: the state exists, so the header kid has a class or none
_FROM_STATE = frozenset((
    "ok", "org_mismatch", "relay_mismatch", "consumer_mismatch", "unknown_key", "revoked_key", "bad_signature",
    "context_mismatch", "verifier_unexpected", "high_s", "identity_mismatch", "request_mismatch",
    "inputs_mismatch", "outputs_mismatch", "ts_in_future", "bad_expiry", "validity_too_long",
    "expired", "view_in_future", "stale_view", "witness_unexpected", "witness_missing",
    "witness_malformed", "witness_key_mismatch", "witness_bad_signature", "witness_org_mismatch",
    "witness_epoch_mismatch", "witness_superseded", "witness_in_future", "stale_witness",
    "behind_witness", "duplicate_receipt", "unproven_class"))

UNSET = object()  # signer_class not given: alice's class from step 7, null before it


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def doc_id(doc):
    """The id of a genesis document: hashstr(JCS(doc)) (GP-04)."""
    return base.hashstr(jcs.emit(doc))


def derive(doc, edit):
    """A deep copy of `doc` after `edit(copy)`."""
    out = copy.deepcopy(doc)
    edit(out)
    return out


# ---- the pin probe (GP-05, GP-14) -------------------------------------------

def pin_line(org, genesis, spec):
    """The pin file bytes: one JCS line plus LF (GP-05)."""
    return jcs.emit({"genesis": genesis, "org": org, "spec": spec, "v": "handsal-pin/1"}) + b"\n"


def filename_of(org):
    """`<hex64>.pin` for an org id (GP-05)."""
    return _unb64u(org[1:])[2:].hex() + ".pin"


def probe(org, line, *, filename=None, owner_ok=True, reason="ok", probe_org=None):
    """The probe object `{bytes_b64, filename, org, owner_ok, reason}` (GP-14)."""
    return {"bytes_b64": _b64(line), "filename": filename or filename_of(org),
            "org": probe_org or org, "owner_ok": owner_ok, "reason": reason}


def probe_for(lineage):
    """A passing probe for the original and last documents of `lineage`."""
    org, last = doc_id(lineage[0]["doc"]), lineage[-1]["doc"]
    return probe(org, pin_line(org, doc_id(last), last["profile"]))


# ---- genesis lineages -------------------------------------------------------

def original_lineage(fx, doc, signers=None):
    """`[{doc, sigs}]` with one genesis.sign of `doc` per signer.

    Signers default to every listed device that is a fixture device.
    """
    if signers is None:
        signers = []
        for entry in doc["devices"]:
            try:
                signers.append(fx.name_of_kid(entry["kid"]))
            except KeyError:
                pass
    return [{"doc": doc, "sigs": [fx.genesis_sign(n, doc) for n in signers]}]


def change_doc(fx, previous=None, edit=None):
    """A change of `previous` (default ORG) made at position 0, before `edit`."""
    previous = previous or fx.org
    org = previous["org"] or doc_id(previous)

    def apply(doc):
        doc.update({"org": org, "prev": doc_id(previous), "head": org})
        if edit:
            edit(doc)
    return derive(previous, apply)


def synthetic_members(count, role="maintainer"):
    """`count` members `m01`.. with a device each, from derived keys that are no fixture device.

    Returns (members, devices), both sorted as a genesis document requires.
    """
    members, devices = [], []
    for index in range(1, count + 1):
        person = "m%02d" % index
        pair = {}
        for use in ("sign", "agree"):
            x, y = p256.mul(keys.derive_scalar("synthetic/%s.%s" % (person, use)))
            pair[use] = {"x": keys.b64u(x.to_bytes(32, "big")), "y": keys.b64u(y.to_bytes(32, "big"))}
        members.append({"id": person, "role": role})
        devices.append({"agree": pair["agree"], "class": base.CLASS,
                        "kid": keys.thumbprint(pair["sign"]["x"], pair["sign"]["y"]),
                        "label": "%s se-bio" % person, "person": person, "sign": pair["sign"]})
    return members, sorted(devices, key=lambda d: d["kid"])


# ---- command inputs ---------------------------------------------------------

def _apply(data, override):
    for key, value in override.items():
        if value is DROP:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def check_input(fx, jws, *, method=APPROVE, wit=False, **override):
    """The conformance `check-act` input for `jws` (VR-01).

    Verdicts carry the request, its id, the recipient and the relay; a
    `record.promote` carries the record body. Overrides replace a key, or
    remove it with DROP.
    """
    data = {"acts": [], "expect_method": method, "jws": jws, "lineage": fx.lineage(wit),
            "now": base.NOW, "org": fx.wit_org_id if wit else fx.org_id, "pin": fx.pin_ok(wit),
            "seen": [], "synced_at": base.NOW, "tip_statement": None}
    if method in _VERDICT_METHODS:
        data.update(request_b64=fx.request_b64(), request_id=base.REQUEST_ID,
                    recipient="alice", relay=base.RELAY_HOST)
    elif method == RECORD_PROMOTE:
        data["record_body_b64"] = _b64(base.RECORD_BODY)
    elif method == DECISION:
        data.update(action=base.DECISION_ACTION, consumer=base.DECISION_CONSUMER,
                    decision_b64=_b64(base.DECISION_BODY), subject=base.DECISION_SUBJECT)
    else:
        raise ValueError("no input form for %s" % method)
    return _apply(data, override)


TIMED_KEYS = ("now", "seen", "synced_at", "tip_statement")


def recheck_input(fx, jws, *, method=APPROVE, wit=False, **override):
    """The conformance `recheck-act` input for `jws` (VR-17): the `check-act` input without the four keys
    that name a moment. An override may put one back, to show that it is refused."""
    data = {k: v for k, v in check_input(fx, jws, method=method, wit=wit).items() if k not in TIMED_KEYS}
    return _apply(data, override)


def fold_input(lineage, *, acts=(), org=None, pin=None):
    """The conformance `fold` input (FO-01); org and pin come from the lineage."""
    return {"acts": list(acts), "lineage": lineage,
            "org": org or doc_id(lineage[0]["doc"]), "pin": pin or probe_for(lineage)}


def enrolled_input(fx, *, device="alice", wit=False, **override):
    """The conformance `enrolled` input (GP-13)."""
    data = {"acts": [], "device_kid": fx.key(device).kid, "lineage": fx.lineage(wit),
            "now": base.NOW, "org": fx.wit_org_id if wit else fx.org_id, "pin": fx.pin_ok(wit),
            "synced_at": base.NOW, "tip_statement": None}
    return _apply(data, override)


# ---- anchors ---------------------------------------------------------------

def receipt_id(jws):
    """hashstr of the payload bytes of `jws` (a canonical payload is its own JCS form)."""
    return base.hashstr(forge.parts(jws)[1])


def _class_and_receipt(jws, reason, signer_class, in_fold, before=()):
    """`(class, receipt_id)` of an answer for `reason` (the rule of the module note). `before` lists reasons
    that arise before step 7 in the command asked, beyond those every command shares."""
    if reason == "verifier_unavailable":
        if in_fold is None:
            raise ValueError("verifier_unavailable: state in_fold=True (step 6) or False (step 9)")
        before_state = in_fold
    else:
        before_state = reason in _NO_PAYLOAD or reason in _BEFORE_STATE or reason in before
        if not before_state and reason not in _FROM_STATE:
            raise ValueError("unclassified check-act reason: %r" % (reason,))
    rid = None if reason in _NO_PAYLOAD else receipt_id(jws)
    if before_state:
        if signer_class not in (UNSET, None):
            raise ValueError("%s is before step 7: class is null" % reason)
        return None, rid
    return (base.CLASS if signer_class is UNSET else signer_class), rid


def check_anchor(jws, reason, signer_class=UNSET, *, in_fold=None):
    """The `check-act` result line for `reason` (see the module note).

    `signer_class` is the class of the pinned-state device whose kid is the header
    kid, or None when there is none; it defaults to alice's class from step 7 on, and
    must not be given before it. `verifier_unavailable` is a fold error at step 6 (i)
    and a vitni failure at step 9, so `in_fold` must say which.
    """
    cls, rid = _class_and_receipt(jws, reason, signer_class, in_fold)
    return result.line({"class": cls, "reason": reason, "receipt_id": rid, "valid": reason == "ok"})


# What `recheck-act` never proves (VR-17): one sorted list, the same in every answer.
NOT_PROVEN = ["expiry", "freshness", "order_of_arrival", "replay", "revocation_after_head"]


def recheck_anchor(jws, reason, signer_class=UNSET, *, in_fold=None):
    """The `recheck-act` result line for `reason` (VR-17): the class and receipt rule of `check_anchor`, where
    `stale_view` is the act's head being no position of the chain, so it precedes the state (class null), and
    the answer is `rechecked`, never `valid`."""
    cls, rid = _class_and_receipt(jws, reason, signer_class, in_fold, before=("stale_view",))
    return result.line({"class": cls, "not_proven": NOT_PROVEN, "reason": reason, "receipt_id": rid,
                        "rechecked": reason == "ok"})


def error_anchor(code):
    return result.line({"error": code})


def enrolled_anchor(enrolled, reason):
    return result.line({"enrolled": enrolled, "reason": reason})
