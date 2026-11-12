"""Pure-Python P-256 public points for tests that need keys outside the fixture list.

A public point is computed from a scalar by double-and-add. Nothing here signs.
Production-profile documents in tests use these, because every fixture key is
refused under a production profile (GP-18).
"""
import hashlib

from handsal_check import encoding

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def public_point(scalar):
    """`{x, y}` in canonical base64url for the public key of `scalar`."""
    result, addend = None, (GX, GY)
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    x, y = result
    return {"x": encoding.b64u_encode(x.to_bytes(32, "big")), "y": encoding.b64u_encode(y.to_bytes(32, "big"))}


def production_device(label, person, cls="apple-se-bio"):
    """A device entry whose keys derive from `label` and are in no fixture list."""
    scalar = lambda suffix: int.from_bytes(hashlib.sha256(("test-prod/%s.%s" % (label, suffix)).encode()).digest(), "big") % (P - 1) + 1
    sign, agree = public_point(scalar("sign")), public_point(scalar("agree"))
    return {"agree": agree, "class": cls, "kid": encoding.thumbprint(sign["x"], sign["y"]),
            "label": "laptop", "person": person, "sign": sign}
