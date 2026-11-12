"""JWS shape and header (ACT-02, ACT-03, KC-05), `check-act` step 1.

Three base64url segments without padding, each canonical; the header is the one
exact byte string `{"alg":"ES256","kid":"<kid>"}`; the signature is the 64 raw
bytes R||S. Anything else is `jws_shape`. The header is matched as bytes, not
parsed, so there is one accepted form and nothing for two parsers to disagree
about (vitni alone accepts `typ`, `crit`, `b64` and a `null` header). ES256 is
never computed here (vitni owns it, CF-05).
"""
import re
from collections import namedtuple

from . import encoding, errors, schema

Jws = namedtuple("Jws", "kid payload signature")

_HEADER = re.compile(rb'\{"alg":"ES256","kid":"([A-Za-z0-9_-]{43})"\}')
_SHAPE = "jws_shape"


def _segment(text):
    try:
        return encoding.b64u_decode(text)
    except ValueError:
        raise errors.Refused(_SHAPE) from None


def parse(text):
    """The kid, payload bytes and signature of the act `text` (a str), or Refused `jws_shape`."""
    parts = text.split(".")
    if len(parts) != 3:
        raise errors.Refused(_SHAPE)
    header, payload, signature = (_segment(part) for part in parts)
    match = _HEADER.fullmatch(header)
    if match is None:
        raise errors.Refused(_SHAPE)
    kid = match.group(1).decode("ascii")
    if not schema.is_kid(kid):
        raise errors.Refused(_SHAPE)
    if len(signature) != 64:
        raise errors.Refused(_SHAPE)
    return Jws(kid, payload, signature)
