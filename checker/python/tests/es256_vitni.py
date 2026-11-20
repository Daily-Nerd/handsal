"""A stand-in for vitni that checks the real ES256 signature, standard library only, for the tests that run the
signed conformance vectors without a vitni binary.

It answers like `act_builder.FakeVitni` (unknown key, revoked key, method, bad signature) but the signature check
is the mathematical ECDSA check over P-256 with SHA-256, so a vector signed by a fixture key is `ok` and a flipped
bit is `bad_signature`. Like vitni it accepts a high S: the profile's low-S rule is the checker's. Answers are kept
per question across instances, because one vector set asks the same question many times and the check is slow.
"""
import hashlib
import json

from handsal_check import encoding, jws, verifier

from . import p256_helper
from .act_builder import FakeVitni

_G = (p256_helper.GX, p256_helper.GY)
_CHECKED = {}


def _mul(scalar, point):
    result, addend = None, point
    while scalar:
        if scalar & 1:
            result = p256_helper._add(result, addend)
        addend = p256_helper._add(addend, addend)
        scalar >>= 1
    return result


def signature_is_valid(entry, signing_input, signature):
    """True iff `signature` (raw R||S) is a valid ES256 signature of `signing_input` (bytes) under `entry`."""
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    order = verifier._N
    if not (1 <= r < order and 1 <= s < order):
        return False
    public = (int.from_bytes(encoding.b64u_decode(entry["x"]), "big"), int.from_bytes(encoding.b64u_decode(entry["y"]), "big"))
    e = int.from_bytes(hashlib.sha256(signing_input).digest(), "big") % order
    w = pow(s, -1, order)
    point = p256_helper._add(_mul(e * w % order, _G), _mul(r * w % order, public))
    return point is not None and point[0] % order == r


class Es256Vitni(FakeVitni):
    def verify(self, jws_text, keys, method):
        self.calls.append((jws_text, json.dumps(keys, sort_keys=True), method))
        head, body, _ = jws_text.split(".")
        parsed = jws.parse(jws_text)
        payload = json.loads(parsed.payload)
        entry = (keys.get(payload["performer_id"]) or {}).get(parsed.kid)
        if entry is None:
            return "unknown_key"
        if entry["status"] == "revoked":
            return "revoked_key"
        key = (jws_text, entry["x"], entry["y"])
        if key not in _CHECKED:
            _CHECKED[key] = signature_is_valid(entry, (head + "." + body).encode("ascii"), parsed.signature)
        if not _CHECKED[key]:
            return "bad_signature"
        if payload["method"] != method:
            return "context_mismatch"
        return "ok"
