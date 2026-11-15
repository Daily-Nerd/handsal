"""The generator's own `check-act`, steps 6 and 14: the oracle of the `hed` whole-set guard (CF-06, VR-19, SH6).

`head` names the position a producer puts in `head` (ACT-08), and VR-19 states its equality with `check-act`: the
answered head is exactly one that `check-act` of an otherwise perfect non-chain act naming it accepts at steps 6 and
14, and a refusal is the code `check-act` gives at one of those steps. Nothing in the generator may take that from
the checker, so the claim is proved here, by a second statement of the two steps written from the spec over the
generator's own fold (`lib/foldmodel.py`):

- step 6 (VR-02, GP-14, GP-07): the probe and pin checks (a) to (e), the lineage checks (g) and (h), then the fold
  (i), where a `fork` is `epoch_superseded` if `next` is `"yes"` (VR-12);
- step 14 (VR-12, WT-04, WT-05, WT-10): `epoch_superseded`, `view_in_future`, `stale_view` by age, the act's head
  not being a position of the accepted chain of the last epoch (`stale_view`), then the witness rules of the mode.

The conformance build only: step 6 (f) is a production step. The act is a decision, read for its head and nothing
else, so every other step is taken as passed ("otherwise perfect").

What it does not read, and so does not state: the schema of a document or of an act body, classes, and the ACT-01
to ACT-07 shape of a tip statement beyond the closed fields WT-02 names. A world whose answer rests on those is
outside its scope: the fold says so with `Unsupported`, and the statement checks are the ones WT-05 lists.
"""
import base64
import json
from datetime import datetime, timezone

from . import base, es256, forge, foldmodel, inputs, jcs

REQUIRED = ("acts", "lineage", "next", "now", "org", "pin", "synced_at", "tip_statement")
STEP_6 = ("pin_org_mismatch", "pin_malformed", "profile_mismatch", "lineage_broken", "genesis_pin_mismatch",
          "pin_spec_mismatch", "fork", "epoch_superseded")
STEP_14 = ("epoch_superseded", "view_in_future", "stale_view", "witness_unexpected", "witness_missing",
           "witness_malformed", "witness_key_mismatch", "witness_bad_signature", "witness_org_mismatch",
           "witness_epoch_mismatch", "witness_superseded", "witness_in_future", "stale_witness", "behind_witness")
# the codes this model states; the probe's own reasons (`pin_missing` and its siblings) are data (GP-14 (b))
CODES = frozenset(STEP_6 + STEP_14 + ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected"))
RELAY_PERFORMER = "relay"


class Disagreement(AssertionError):
    """`head` and the model of `check-act` give different answers for one input."""


def _seconds(text):
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def _pin_line(probe):
    """The pin object of a probe's bytes: one JCS line plus LF with the four keys of GP-05, else None."""
    try:
        raw = base64.b64decode(probe["bytes_b64"], validate=True)
        if not raw.endswith(b"\n"):
            return None
        pin = json.loads(raw[:-1])
        if jcs.emit(pin) != raw[:-1]:
            return None
    except (ValueError, KeyError, TypeError, jcs.JcsError):
        return None
    shape = isinstance(pin, dict) and set(pin) == {"genesis", "org", "spec", "v"} and pin["v"] == "handsal-pin/1"
    return pin if shape and all(base.is_hashstr(pin[k]) for k in ("genesis", "org", "spec")) else None


def _well_formed(inp):
    """VR-01, GP-14: every key is there and has its form, else the input is `malformed_input`."""
    if any(k not in inp for k in REQUIRED) or not isinstance(inp["org"], str) or not base.is_hashstr(inp["org"]):
        return False
    return (inp["next"] in ("yes", "no") and isinstance(inp["acts"], list) and isinstance(inp["lineage"], list)
            and isinstance(inp["pin"], dict) and isinstance(inp["now"], str) and isinstance(inp["synced_at"], str)
            and (inp["tip_statement"] is None or isinstance(inp["tip_statement"], str)))


def _step_6(fx, inp):
    """`(code, pin)`: the first failure of VR-02 step 6 (a) to (h) over the probe, the pin and the lineage."""
    probe, org, lineage = inp["pin"], inp["org"], inp["lineage"]
    if probe.get("org") != org or probe.get("filename") != inputs.filename_of(org):
        return "pin_org_mismatch", None
    if not probe.get("owner_ok"):
        return probe.get("reason"), None
    pin = _pin_line(probe)
    if pin is None:
        return "pin_malformed", None
    if pin["org"] != org:
        return "pin_org_mismatch", None
    if pin["spec"] != fx.profile:
        return "profile_mismatch", None
    if not lineage:
        return "lineage_broken", None
    if inputs.doc_id(lineage[0]["doc"]) != pin["org"]:
        return "lineage_broken", None
    if inputs.doc_id(lineage[-1]["doc"]) != pin["genesis"]:
        return "genesis_pin_mismatch", None
    if lineage[-1]["doc"]["profile"] != pin["spec"]:
        return "pin_spec_mismatch", None
    return None, pin


def _fold(fx, inp, pin):
    """`(code, positions)`: the fold error (a fork is `epoch_superseded` where `next` is `"yes"`, VR-12) or the
    positions of the accepted chain of the last epoch, root first."""
    model = foldmodel.Model(fx, inp["acts"], inp["lineage"])
    leaf = pin["genesis"]
    line = json.loads(model.answer(leaf))
    if "error" in line:
        return ("epoch_superseded" if line["error"] == "fork" and inp["next"] == "yes" else line["error"]), None
    return None, model.accepted(leaf)


def _statement(text):
    """The parts of a tip statement the WT-05 steps read, or None where WT-05 step 2 refuses it."""
    try:
        header, raw, sig = forge.parts(text)
        head, payload = json.loads(header), json.loads(raw)
        act = payload["ext"]["dev.handsal/act"]
        body = act["body"]
        shaped = (payload["method"] == base.RELAY_TIP and payload["performer_id"] == RELAY_PERFORMER
                  and set(act) == {"body", "org"} and set(body) == {"epoch", "next", "tip"}
                  and body["next"] in ("yes", "no") and all(base.is_hashstr(body[k]) for k in ("epoch", "tip"))
                  and base.is_hashstr(act["org"]))
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    if not shaped:
        return None
    return {"kid": head.get("kid"), "message": text.rsplit(".", 1)[0].encode("ascii"), "sig": sig,
            "org": act["org"], "ts": payload["ts"], "epoch": body["epoch"], "next": body["next"], "tip": body["tip"]}


def _witness(inp, pin, doc, positions):
    """WT-04, WT-05 and WT-10: the code of the witness rules of the policy's mode, or None."""
    witness, fresh = doc["policy"]["witness"], doc["policy"]["freshness"]
    statement = inp["tip_statement"]
    if witness["mode"] == "none":
        return None if statement is None else "witness_unexpected"
    if statement is None:
        return "witness_missing"
    s = _statement(statement)
    if s is None:
        return "witness_malformed"
    if s["kid"] != witness["relay_kid"]:
        return "witness_key_mismatch"
    jwk = witness["relay_pub_jwk"]
    point = (foldmodel._unb64u(jwk["x"]), foldmodel._unb64u(jwk["y"]))
    if not (es256.verify(point, s["message"], s["sig"]) and es256.is_low_s(s["sig"])):
        return "witness_bad_signature"
    if s["org"] != pin["org"]:
        return "witness_org_mismatch"
    if s["epoch"] != pin["genesis"]:
        return "witness_epoch_mismatch"
    if s["next"] == "yes":
        return "witness_superseded"
    now = _seconds(inp["now"])
    if _seconds(s["ts"]) > now + int(fresh["clock_skew_s"]):
        return "witness_in_future"
    if now - _seconds(s["ts"]) > int(witness["max_tip_age_s"]):
        return "stale_witness"
    return None if s["tip"] in positions else "behind_witness"


def run(fx, inp, jws):
    """`ok`, `malformed_input` or the code `check-act` gives at step 6 or 14 for the decision `jws` over `inp`
    (a conformance `head` input; a `check-act` input also serves, its extra keys are not read)."""
    if not _well_formed(inp):
        return "malformed_input"
    code, pin = _step_6(fx, inp)
    if code is not None:
        return code
    code, positions = _fold(fx, inp, pin)
    if code is not None:
        return code
    doc = inp["lineage"][-1]["doc"]
    fresh = doc["policy"]["freshness"]
    now, view = _seconds(inp["now"]), _seconds(inp["synced_at"])
    if inp["next"] == "yes":
        return "epoch_superseded"
    if view > now + int(fresh["clock_skew_s"]):
        return "view_in_future"
    if now - view > int(fresh["max_view_age_s"]):
        return "stale_view"
    if foldmodel.parse(jws)[0].head not in positions:
        return "stale_view"
    return _witness(inp, pin, doc, positions) or "ok"


def tip(fx, inp):
    """The id of the tip the fold gives for `inp` (FO-01): the last position of the accepted chain, or None."""
    if not _well_formed(inp):
        return None
    code, pin = _step_6(fx, inp)
    if code is not None:
        return None
    code, positions = _fold(fx, inp, pin)
    return positions[-1] if code is None else None


def decision(fx, inp, head):
    """The otherwise perfect decision of the guard: alice's, for the organization of the input, naming `head`."""
    return fx.decision(org=inp.get("org") or fx.org_id, tip=head)


def root(fx, inp):
    """The root of the last epoch of `inp`: a position of every accepted chain, so a decision there passes the head
    rule of VR-12 and the code a refusal gets is the one of the step under test (the organization where no
    document is given)."""
    return inputs.doc_id(inp["lineage"][-1]["doc"]) if inp.get("lineage") else inp.get("org") or fx.org_id


def agree(fx, inp, anchor):
    """The guard for one `head` vector: raise `Disagreement` unless the model of `check-act` agrees with `anchor`.

    An answered head: a decision signed at it must pass steps 6 and 14, and it is the tip the fold gives (VR-19
    says which head). A refusal, and the input of a refusal that carries no head: a decision at the root of the
    last epoch of the input must be refused with that very code at one of the two steps. An error line is the
    refusal of an input with a key missing, which `check-act` shares."""
    out = json.loads(anchor)
    if "error" in out:
        want, head = out["error"], None
    elif out["head"] is None:
        want, head = out["reason"], None
    else:
        want, head = "ok", out["head"]["id"]
        if out["head"].get("kind") != "chain" or out["reason"] != "ok":
            raise Disagreement("an answered head is {id, kind: chain} with reason ok: %s" % anchor)
    got = run(fx, inp, decision(fx, inp, head or root(fx, inp)))
    if got != want:
        raise Disagreement("head says %s, the model of check-act says %s" % (want, got))
    if head is not None and tip(fx, inp) != head:
        raise Disagreement("the head %s is not the tip of the fold, %s" % (head, tip(fx, inp)))
