"""Point validation on P-256 (ACT-11).

Only the curve equation is needed: the checker never does ES256 (vitni owns
it, CF-05). The cofactor is 1, so a point on the curve is in the group.
"""

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def is_on_curve(x_bytes, y_bytes):
    """True iff the two 32-byte big-endian coordinates are a point of P-256."""
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        return False
    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")
    if x >= _P or y >= _P:
        return False
    return (y * y - (x * x * x - 3 * x + _B)) % _P == 0
