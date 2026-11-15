"""The shape of the retired `local:handsal.record.promote`, owned in one place (ACT-09, S9).

The method is not in the registry, so no builder of the generator makes it. Three regression
vectors prove that a verifier refuses it, each through its own path: `check-act` (`mth/`), every
`render` (`rnd/`) and the signer `emit` (`sgn/`). They read the act, its payload, its draft and its
attachment from here, so the old bytes exist once. The act is a decision's envelope, signed by
alice, with the body, the hashes and the method the retired method had.
"""
import base64
import json

from . import base, forge, inputs

METHOD = "local:handsal.record.promote"
BODY = b"record body v1"   # the 14 bytes the old method bound as `inputs_hash`
_ACT_BODY = {"anchors": ["anchor-1"], "record_id": "rec-0001"}


def _as_retired(payload):
    payload["method"] = METHOD
    payload["ext"]["dev.handsal/act"]["body"] = json.loads(json.dumps(_ACT_BODY))
    payload["inputs_hash"] = base.hashstr(BODY)
    payload["outputs_hash"] = base.EMPTY_HASH


def jws(fx):
    """The act of the retired method, signed by alice: `expires` and a `head`, EMPTY_HASH as outputs."""
    return forge.resign(fx, fx.decision(), _as_retired)


def payload(fx):
    """The payload of `jws(fx)` as a JSON object (the `render` input shape)."""
    return json.loads(forge.parts(jws(fx))[1])


def attachments():
    """The record body a caller of the retired method attached."""
    return {"record_body_b64": base64.b64encode(BODY).decode("ascii")}


def check_input(fx):
    """The `check-act` input of a caller of the retired method: it names the method as `expect_method` and sends
    the record body. Nothing else is required of it (VR-01: any other string requires nothing more)."""
    data = inputs.check_input(fx, jws(fx), method=inputs.DECISION)
    for key in ("action", "consumer", "decision_b64", "subject"):
        del data[key]
    data["expect_method"] = METHOD
    data.update(attachments())
    return data


def draft(fx):
    """The `emit` draft of the retired method, as its signer took it."""
    return {"body": json.loads(json.dumps(_ACT_BODY)), "expires_in_s": "3600",
            "head": {"id": fx.org_id, "kind": "chain"}, "method": METHOD, "org": fx.org_id}
