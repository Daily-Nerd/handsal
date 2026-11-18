"""Make a throwaway genesis org for tests: software keys, a draft, and the receipts that sign it.

Usage: genesis_throwaway.py mint DIR          (input JSON on stdin)

It needs cryptography>=43, declared in tools/throwaway/pyproject.toml. Run it with that project:

  uv run --project tools/throwaway python -I tools/genesis_throwaway.py mint DIR < tmp-acme.json

What this is, in plain words:

  This makes a throwaway org for tests. It generates software keys in memory, builds the draft with the same
  code as genesis_build.py, signs one receipt per software key, and writes the draft and the receipts to DIR.

  The key class is declared, not attested, so the keys do not prove a person or a device.

  The name prefix tmp- and the label phrase "throwaway software key" are a courtesy that readers can see.
  They are not a protection.

  Such an org must never be pinned on a real machine, because a pin is permanent.

The input is the input of genesis_build.py with two changes. The name must start with tmp-. A device without a
pubkey is a software device: its label must start with "throwaway software key" and a key is made for it.
"""
import sys
from pathlib import Path

# The directory of this file is not on sys.path under -I, and genesis_build pins the checker of this checkout
# before any checker module is imported: the order of these lines is the contract.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import genesis_build  # noqa: E402,F401

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,  # noqa: E402
                                                            encode_dss_signature)

from handsal_check import emit, encoding, envelope, genesis, genesis_sigs, verifier  # noqa: E402

# TODO(root-cause): class is declared, not attested (L7)
DECLARED_CLASS = "apple-se-bio"
# The order of the P-256 group. It only folds S to the low form; every signature is then checked with is_low_s
# and against the public key, so a wrong value here fails loudly and is never trusted.
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def emit_payload(sign_in, fixed):
    """The bytes the signer's `emit` writes for the `genesis.sign` original described by `sign_in`
    ({draft, attachments}) and `fixed` ({kid, nonce, performer, ts}). Every constant is the checker's."""
    doc = sign_in["attachments"]["document"]
    draft = sign_in["draft"]
    if doc["prev"] is not None:
        raise ValueError("originals only: a change document needs a head")
    payload = {
        **envelope.CONSTANTS,
        **dict.fromkeys(envelope.NULLS),
        "cost": dict(envelope.COST),
        "ext": {envelope.EXT_KEY: {"body": draft["body"], "kid": fixed["kid"], "org": draft["org"]}},
        "inputs_hash": genesis.doc_hash(doc),
        "method": draft["method"],
        "nonce": fixed["nonce"],
        "outputs_hash": encoding.EMPTY_HASH,
        "parent_performer_id": None,
        "parent_receipt_hash": None,
        "performer_id": fixed["performer"],
        "ts": fixed["ts"],
    }
    return emit.emit_subset(payload)


def _point(public_key):
    numbers = public_key.public_numbers()
    return {"x": encoding.b64u_encode(numbers.x.to_bytes(32, "big")),
            "y": encoding.b64u_encode(numbers.y.to_bytes(32, "big"))}


class SoftwareKey:
    """A device made of two random P-256 keys that live in this process only: the signing key and the agreement
    key. Nothing here prints, stores or reprs a private scalar."""

    def __init__(self, sign_key, agree_key):
        self._sign = sign_key
        self._agree = agree_key

    @classmethod
    def generate(cls):
        return cls(ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1()))

    def pubkey(self):
        """The public half as a document reads it: {agree, class, kid, sign}, the kid derived by the checker."""
        sign = _point(self._sign.public_key())
        return {"agree": _point(self._agree.public_key()), "class": DECLARED_CLASS,
                "kid": encoding.thumbprint(sign["x"], sign["y"]), "sign": sign}

    def sign(self, signing_input):
        """The 64 raw bytes R||S of ES256 over `signing_input`, with the low S the profile counts (VR-04)."""
        r, s = decode_dss_signature(self._sign.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        if s > _N // 2:
            s = _N - s
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if not verifier.is_low_s(raw):
            raise RuntimeError("the signature is not in the low form")
        try:
            self._sign.public_key().verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise RuntimeError("the signature does not verify with its own public key") from None
        return raw


def receipt(key, sign_in, person, ts, nonce, wire):
    """The receipt {jws, receipt_id} of `person` and `key` over `sign_in`. It is returned only if the checker's
    key-free reader accepts it as a genesis.sign of this document by this key."""
    kid = key.pubkey()["kid"]
    payload = emit_payload(sign_in, {"kid": kid, "nonce": nonce, "performer": person, "ts": ts})
    signing = (encoding.b64u_encode(emit.emit_subset({"alg": "ES256", "kid": kid})) + "."
               + encoding.b64u_encode(payload))
    jws = signing + "." + encoding.b64u_encode(key.sign(signing.encode("ascii")))
    doc = sign_in["attachments"]["document"]
    act = genesis_sigs.read(jws, doc, genesis.doc_hash(doc), sign_in["draft"]["org"], wire)
    if act is None or act.kid != kid:
        raise RuntimeError("the checker does not read this receipt as a genesis.sign of the document")
    return {"jws": jws, "receipt_id": envelope.receipt_id(payload)}
