"""Policy field `witness` (WT-01): the shape and the bounds, checked in two passes.

GP-15 step 3 reports every `policy_invalid` before any `policy_out_of_bounds`, so
`policy` calls `shape` over the whole policy first and `bounds` afterwards.

    {"mode":"none"}
    {"max_tip_age_s":D,"mode":"relay","relay_kid":K,"relay_pub_jwk":{"crv":"P-256","kty":"EC","x":X,"y":Y}}

Shape: exactly those keys for the mode, `mode` byte-exact; D a decimal string; the
JWK exactly the thumbprint input with a canonical point on P-256; K its thumbprint;
the relay key disjoint from every device key of the document (kid, sign point,
agree point). Bounds: 60 <= D <= 86400.
"""
from . import devicekey, encoding, errors, schema

_JWK_KEYS = {"crv", "kty", "x", "y"}
_RELAY_KEYS = {"max_tip_age_s", "mode", "relay_kid", "relay_pub_jwk"}


def _invalid():
    return errors.Refused("policy_invalid")


def _point_of(entry):
    return (entry["x"], entry["y"])


def shape(witness, devices):
    """Raise Refused `policy_invalid` unless `witness` is a well-formed WT-01 value for a
    document whose (already validated) device entries are `devices`."""
    if type(witness) is not dict or type(witness.get("mode")) is not str:
        raise _invalid()
    mode = witness["mode"]
    if mode == "none":
        if set(witness) != {"mode"}:
            raise _invalid()
        return
    if mode != "relay" or set(witness) != _RELAY_KEYS:
        raise _invalid()
    if not schema.is_decimal(witness["max_tip_age_s"]):
        raise _invalid()
    jwk = witness["relay_pub_jwk"]
    if type(jwk) is not dict or set(jwk) != _JWK_KEYS or jwk["crv"] != "P-256" or jwk["kty"] != "EC":
        raise _invalid()
    if not devicekey.point_ok({"x": jwk["x"], "y": jwk["y"]}):
        raise _invalid()
    kid = witness["relay_kid"]
    if kid != encoding.thumbprint(jwk["x"], jwk["y"]):
        raise _invalid()
    relay_point = (jwk["x"], jwk["y"])
    for device in devices:
        if kid == device["kid"] or relay_point in (_point_of(device["sign"]), _point_of(device["agree"])):
            raise _invalid()


def bounds(witness, reg):
    """Raise Refused `policy_out_of_bounds` unless `max_tip_age_s` is within WT-01's bounds.
    The caller ran `shape` first, so `witness` is well-formed."""
    if witness["mode"] != "relay":
        return
    age = int(witness["max_tip_age_s"])
    if not reg.number("max_tip_age_s", "min") <= age <= reg.number("max_tip_age_s", "max"):
        raise errors.Refused("policy_out_of_bounds")
