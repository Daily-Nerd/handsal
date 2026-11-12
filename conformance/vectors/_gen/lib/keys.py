"""Deterministic fixture keys (spec KC-07, GP-18, CF-06).

Every private scalar is published test material, never a secret. A scalar is
derived from a label so the files are reproducible and obviously test-only:

    d = (int.from_bytes(SHA-256(b"handsal-fixture-v1/" + label), "big") mod (n - 1)) + 1

which always lands in [1, n - 1]. A kid is the RFC 7638 thumbprint of the
public key (spec section 2, "thumbprint"; ACT-02 for the JWS header). No
production key material is produced or listed here (PRODK, CF-08).
"""
import base64
import hashlib
import json
from pathlib import Path

from . import p256

DOMAIN = b"handsal-fixture-v1/"
RELAY_LABEL = "relay-fixture"

# Devices of the catalog named keys (catalog-part2 section 20, PINORG in
# catalog-part3 section 21). Each has a signing key and an agreement key.
DEVICES = (
    "alice", "alice2", "alice3", "alice4",
    "bob", "bob2", "bob3",
    "carol", "carol2",
    "dave", "dave2",
    "frank", "grace",
    "X1", "X2",
    # fixture-pin class devices held by role holders (KC-08 refusal vectors)
    "alice-pin", "frank-pin",
)

DERIVATION = (
    "d = (int(SHA-256(b'handsal-fixture-v1/' + label), big-endian) mod (n - 1)) + 1; "
    "n is the P-256 group order; public point = d * G; "
    "kid = base64url(SHA-256(RFC 7638 JSON of crv, kty, x, y))"
)


def labels():
    out = []
    for dev in DEVICES:
        out.append(dev + ".sign")
        out.append(dev + ".agree")
    out.append(RELAY_LABEL)
    return out


def derive_scalar(label):
    digest = hashlib.sha256(DOMAIN + label.encode("ascii")).digest()
    return int.from_bytes(digest, "big") % (p256.N - 1) + 1


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def thumbprint(x, y):
    text = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (x, y)
    return b64u(hashlib.sha256(text.encode("ascii")).digest())


def _entry(label):
    d = derive_scalar(label)
    px, py = p256.mul(d)
    x = b64u(px.to_bytes(32, "big"))
    y = b64u(py.to_bytes(32, "big"))
    entry = {"d": "%064x" % d, "x": x, "y": y}
    if not label.endswith(".agree"):
        entry["kid"] = thumbprint(x, y)
    return entry


def build_keys_doc():
    return {
        "comment": "Public test material. These scalars are published and protect nothing.",
        "curve": "P-256",
        "derivation": DERIVATION,
        "keys": {label: _entry(label) for label in labels()},
    }


def build_kids_list():
    doc = build_keys_doc()
    return sorted(e["kid"] for e in doc["keys"].values() if "kid" in e)


def _dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def write(fixtures_dir):
    fixtures_dir = Path(fixtures_dir)
    (fixtures_dir / "keys.json").write_text(_dump(build_keys_doc()), encoding="utf-8")
    (fixtures_dir / "fixture-kids.json").write_text(_dump(build_kids_list()), encoding="utf-8")

