"""Device key validity (ACT-11, KC-05).

One definition for a device's keys, read by genesis documents (a defect is
`genesis_key_invalid`) and by introducing acts (a defect keeps the act off the
chain). A device has a signing key and an agreement key, both P-256 points
written as `{x, y}`, 32 big-endian bytes each in canonical base64url, and a
`kid` that is the thumbprint of the signing key. The agreement key must differ
from the signing key. There is no algorithm member (KC-05): the point has
exactly the two members.
"""
from . import encoding, p256, schema


def coordinates(point):
    """`(x, y)` as 32-byte values of a well-formed point object. The caller checked `point_ok`."""
    return encoding.b64u_decode(point["x"]), encoding.b64u_decode(point["y"])


def point_ok(point):
    """True iff `point` is exactly `{x, y}`, canonical 32-byte coordinates, on P-256."""
    if type(point) is not dict or set(point) != {"x", "y"}:
        return False
    if not schema.is_b64u32(point["x"]) or not schema.is_b64u32(point["y"]):
        return False
    return p256.is_on_curve(*coordinates(point))


def defect(kid, sign, agree):
    """None for a valid device key set, else the first defect found, named for the caller:
    `sign_point`, `agree_point`, `kid_not_thumbprint`, `agree_equals_sign`."""
    if not point_ok(sign):
        return "sign_point"
    if not point_ok(agree):
        return "agree_point"
    if kid != encoding.thumbprint(sign["x"], sign["y"]):
        return "kid_not_thumbprint"
    if sign == agree:
        return "agree_equals_sign"
    return None
