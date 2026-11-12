"""Forged acts for negative vectors (ACT-02, ACT-03, ACT-06, ACT-07, ACT-13).

A negative act is a real act with one edit, signed again, so that the edit is
the only defect: every earlier step of VR-02 passes and the step under test is
the first to fail. Edits are applied to the payload as data and re-emitted with
the generator's own emitter (lib/jcs.py); the signature is made by lib/es256.py.
Nothing here imports a checker.
"""
import base64
import json

from . import es256, jcs

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parts(jws):
    """(header bytes, payload bytes, signature bytes) of a well-formed compact JWS."""
    h, p, s = jws.split(".")
    return _unb64u(h), _unb64u(p), _unb64u(s)


def join(header, payload, signature):
    return ".".join(_b64u(x) for x in (header, payload, signature))


def resign(fx, jws, mutate=None, *, signer=None, header=None, high_s=False, raw_edit=None):
    """`jws` with `mutate(payload dict)` applied, signed again.

    `raw_edit(bytes)` then changes the emitted bytes (content the subset cannot
    express, such as a number), which are signed as they are.

    `signer` is a device name. Without it the device of the original header kid
    signs; with it the header names that device (a re-signed act is signed by
    the key its header names). `header` is the exact header bytes to sign and
    wins over both.
    """
    old_header, raw, _sig = parts(jws)
    payload = json.loads(raw)
    if mutate is not None:
        mutate(payload)
    if signer is None:
        signer = fx.name_of_kid(json.loads(old_header)["kid"])
    elif header is None:
        header = jcs.emit({"alg": "ES256", "kid": fx.key(signer).kid})
    if header is None:
        header = old_header
    raw = jcs.emit(payload)
    if raw_edit is not None:
        raw = raw_edit(raw)
    return es256.sign_jws(fx.key(signer).d, header, raw, high_s=high_s)


def tamper(jws, mutate):
    """`jws` with `mutate(payload dict)` applied and the OLD signature kept (it no longer verifies)."""
    header, raw, sig = parts(jws)
    payload = json.loads(raw)
    mutate(payload)
    return join(header, jcs.emit(payload), sig)


def act_edit(edit):
    """A `mutate` for `resign` that edits the act object `ext["dev.handsal/act"]`."""
    def mutate(payload):
        edit(payload["ext"]["dev.handsal/act"])
    return mutate


def flip_spare_bits(segment):
    """`segment` with its last character changed so the spare bits are nonzero.

    The decoded bytes stay the same; only the string stops being canonical
    (ACT-03). A segment whose length is a multiple of 4 has no spare bits.
    """
    if len(segment) % 4 == 0:
        raise ValueError("segment has no spare bits")
    value = _ALPHABET.index(segment[-1])
    return segment[:-1] + _ALPHABET[value | 1]


def verdict_with_spare_payload_bits(fx):
    """An approve whose payload length is not a multiple of 3 (so it has spare bits)."""
    for extra in range(3):
        jws = fx.approve(request_id="req-%08d" % 1 + "x" * extra)
        if len(parts(jws)[1]) % 3:
            return jws
    raise AssertionError("no request id length gives spare bits")
