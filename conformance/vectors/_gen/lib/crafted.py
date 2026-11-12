"""Crafted public keys for rows the fixture devices cannot serve (ACT-11).

A key whose x coordinate starts with the byte 0x00, so its encoding keeps the
leading zero (32 bytes, not 31). Found by a fixed search over labels with the
same derivation as the fixture keys (lib/keys.py): the first counter whose
point qualifies. Published test material, like every fixture scalar.
"""
from . import keys, p256

LABEL = "crafted-leading-zero/%d"


def leading_zero_point():
    """(x bytes, y bytes, label) of the first qualifying derived key."""
    counter = 0
    while True:
        label = LABEL % counter
        x, y = p256.mul(keys.derive_scalar(label))
        if x >> 248 == 0:
            return x.to_bytes(32, "big"), y.to_bytes(32, "big"), label
        counter += 1
