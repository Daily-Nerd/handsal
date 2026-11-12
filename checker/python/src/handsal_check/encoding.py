"""Encodings shared by every command (ACT-03, ACT-07, ACT-10, ACT-11).

Standard library only. Nothing here reads input or decides a reason code: the
callers do. A function that refuses raises ValueError.
"""
import base64
import hashlib
import re

_B64U = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)
_MULTIHASH = b"\x12\x20"   # SHA-256, 32 bytes


def b64u_encode(raw):
    """base64url of `raw` without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def is_b64u_text(text):
    """True for a string made only of base64url alphabet characters."""
    return type(text) is str and _B64U.fullmatch(text) is not None


def b64u_decode(text):
    """The bytes of canonical base64url `text`.

    Canonical means decoding then encoding gives `text` back (ACT-03): no
    padding, no other alphabet, no spare bits set in the last character.
    """
    if not is_b64u_text(text) or len(text) % 4 == 1:
        raise ValueError("not canonical base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:
        raise ValueError("not canonical base64url")
    return raw


def hashstr(raw):
    """`u` + base64url(0x12 0x20 || SHA-256(raw)): the profile's hash string."""
    return "u" + b64u_encode(_MULTIHASH + hashlib.sha256(raw).digest())


EMPTY_HASH = hashstr(b"")


def is_hashstr(text):
    """True for a canonical hash string (ACT-07)."""
    if type(text) is not str or len(text) != 47 or not text.startswith("uEi"):
        return False
    try:
        raw = b64u_decode(text[1:])
    except ValueError:
        return False
    return raw[:2] == _MULTIHASH and len(raw) == 34


def thumbprint_input(x, y):
    """The RFC 7638 JSON of a P-256 key: members crv, kty, x, y in that order."""
    return ('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (x, y)).encode("ascii")


def thumbprint(x, y):
    """The kid of the key `{x, y}` (ACT-11): base64url of SHA-256 of its RFC 7638 JSON."""
    return b64u_encode(hashlib.sha256(thumbprint_input(x, y)).digest())


def is_plain_char(ch):
    """One character of a signed string: 0x20 to 0x7E except `"` and `\\` (ACT-04, ACT-10)."""
    return type(ch) is str and len(ch) == 1 and " " <= ch <= "~" and ch != '"' and ch != "\\"


def is_plain_text(text):
    return type(text) is str and all(is_plain_char(ch) for ch in text)
