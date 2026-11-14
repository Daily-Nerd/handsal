"""Known answers of the signer command `agree` (SG-16, KC-09), from public fixture keys.

The derivation is the one the profile states, written here in pure Python (the P-256 arithmetic of
`lib/p256.py` and HMAC-SHA-256 of the standard library) so that it shares nothing with the Swift and
Rust signers that read the file. `tests/test_agree_kat.py` recomputes every answer a third way, with
the `cryptography` package.

    secret = x-coordinate of d * peer                       (32 bytes, never written to the file)
    info   = "handsal-agree/1" || 0x00 || lo || hi || context
    key    = HKDF-SHA-256(IKM = secret, salt = empty, info, L = 32)

`lo` and `hi` are the two uncompressed public points (65 bytes each, 0x04 || x || y) in ascending byte
order, so the two parties of one agreement build the same info whichever of them is asking.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path

from . import keys, p256

LABEL = b"handsal-agree/1"
KEY_LENGTH = 32
CONTEXT_MAX = 128

# (id, own, peer, context): the fixture keys named by label, so the file is reproducible.
CASES = (
    ("basic", "X1.agree", "X2.agree", "mail/v1"),
    ("other-context", "X1.agree", "X2.agree", "mail/v2"),
    ("other-side", "X2.agree", "X1.agree", "mail/v1"),
    ("other-pair", "alice.agree", "bob.agree", "a"),
    ("longest-context", "alice.agree", "carol.agree", ("~!0Zz" * 26)[:CONTEXT_MAX]),
)


def context_ok(context):
    """The `agree_context` form: 1 to 128 bytes of the signed alphabet (0x20 to 0x7E, not `"` or `\\`) without the space."""
    raw = context.encode("utf-8")
    return 1 <= len(raw) <= CONTEXT_MAX and all(0x21 <= b <= 0x7E and b not in (0x22, 0x5C) for b in raw)


def _unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _point(entry):
    return b"\x04" + _unb64u(entry["x"]) + _unb64u(entry["y"])


def _hkdf(secret, info, length):
    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def info_for(own, peer, context):
    low, high = sorted([_point(own), _point(peer)])
    return LABEL + b"\x00" + low + high + context.encode("ascii")


def derive(own, peer, context):
    """(key, info) for `own` (an entry of keys.json with its scalar) and the public entry `peer`."""
    shared = p256.mul(int(own["d"], 16), (int.from_bytes(_unb64u(peer["x"]), "big"), int.from_bytes(_unb64u(peer["y"]), "big")))
    info = info_for(own, peer, context)
    return _hkdf(shared[0].to_bytes(32, "big"), info, KEY_LENGTH), info


def build():
    entries = keys.build_keys_doc()["keys"]
    vectors = []
    for ident, own_label, peer_label, context in CASES:
        own, peer = entries[own_label], entries[peer_label]
        key, info = derive(own, peer, context)
        vectors.append({
            "context": context,
            "id": ident,
            "info_hex": info.hex(),
            "key": _b64u(key),
            "own": {"d": own["d"], "label": own_label, "x": own["x"], "y": own["y"]},
            "peer": {"label": peer_label, "x": peer["x"], "y": peer["y"]},
        })
    return {
        "comment": "Public test material. The keys are the published fixture keys; the answers protect nothing.",
        "derivation": ("key = HKDF-SHA-256(IKM = x of d * peer, salt = empty, L = 32, info = 'handsal-agree/1' || 0x00 || lo || hi || context); "
                       "lo and hi are the two 65-byte uncompressed public points in ascending byte order"),
        "label": LABEL.decode("ascii"),
        "vectors": vectors,
    }


def write(fixtures_dir):
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    (Path(fixtures_dir) / "agree-kat.json").write_text(text, encoding="utf-8")
