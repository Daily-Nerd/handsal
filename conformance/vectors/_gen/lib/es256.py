"""Deterministic ES256 for the generator (CF-06, SG-06, VR-04).

Signing is ECDSA over P-256 with SHA-256, the nonce from RFC 6979 section
3.2, then the signature is written as raw 64-byte R||S and S is normalized to
the low half (S <= n/2). Every run is byte-identical. The high-S twin of a
signature (same R, S replaced by n - S) is the other valid encoding of the
same payload, used for the vectors that exercise `high_s`.

Standard library only. Not constant time and not for secrets: every scalar
this touches is published fixture material. Independent of the checker.
"""
import base64
import hashlib
import hmac

from . import p256

N = p256.N
HALF_N = N // 2


def _int2octets(x):
    return x.to_bytes(32, "big")


def _bits2int(b):
    # qlen == hlen == 256, so no truncation
    return int.from_bytes(b, "big")


def _bits2octets(b):
    z1 = _bits2int(b)
    return _int2octets(z1 - N if z1 >= N else z1)


def _k_candidates(d, h1):
    """RFC 6979 3.2 steps b to h, yielding successive candidates for k."""
    v = b"\x01" * 32
    k = b"\x00" * 32
    seed = _int2octets(d) + _bits2octets(h1)
    k = hmac.new(k, v + b"\x00" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = _bits2int(v)
        if 1 <= cand < N:
            yield cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def rfc6979_k(d, h1):
    """First nonce for private scalar d and message digest h1 (32 bytes)."""
    return next(_k_candidates(d, h1))


def _check_scalar(d):
    if not (isinstance(d, int) and 1 <= d <= N - 1):
        raise ValueError("private scalar out of range")


def sign_raw(d, message):
    """RFC 6979 signature (r, s) of SHA-256(message). S is NOT normalized."""
    _check_scalar(d)
    h1 = hashlib.sha256(message).digest()
    e = _bits2int(h1) % N
    for k in _k_candidates(d, h1):
        point = p256.mul(k)
        r = point[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (e + r * d) % N
        if s == 0:
            continue
        return r, s
    raise AssertionError("unreachable")


def sign(d, message):
    """Raw 64-byte R||S with S in the low half."""
    r, s = sign_raw(d, message)
    if s > HALF_N:
        s = N - s
    return _int2octets(r) + _int2octets(s)


def _split(sig):
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        raise ValueError("signature must be 64 bytes")
    return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")


def is_low_s(sig):
    return _split(sig)[1] <= HALF_N


def high_s_twin(sig):
    """Same R, S replaced by n - S. Defined from a low-S signature only."""
    r, s = _split(sig)
    if s > HALF_N:
        raise ValueError("input is already high-S")
    return _int2octets(r) + _int2octets(N - s)


def verify(public, message, sig):
    """Mathematical ECDSA check. Accepts high-S on purpose (see is_low_s)."""
    try:
        r, s = _split(sig)
    except ValueError:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = _bits2int(hashlib.sha256(message).digest()) % N
    w = pow(s, -1, N)
    point = p256._add(p256.mul(e * w % N), p256.mul(r * w % N, public))
    return point is not None and point[0] % N == r


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_jws(d, header, payload, high_s=False):
    """Compact JWS `b64url(header).b64url(payload).b64url(R||S)` (SG-06).

    `header` and `payload` are the exact bytes to sign. `high_s=True` returns
    the high-S twin of the same signing input.
    """
    signing_input = "%s.%s" % (_b64u(header), _b64u(payload))
    sig = sign(d, signing_input.encode("ascii"))
    if high_s:
        sig = high_s_twin(sig)
    return "%s.%s" % (signing_input, _b64u(sig))
