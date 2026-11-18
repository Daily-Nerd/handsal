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
import argparse
import os
import secrets
import sys
from datetime import datetime, timezone
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

from handsal_check import emit, encoding, envelope, genesis, genesis_sigs, profiles, verifier  # noqa: E402

# TODO(root-cause): class is declared, not attested (L7)
DECLARED_CLASS = "apple-se-bio"
# The order of the P-256 group. It only folds S to the low form; every signature is then checked with is_low_s
# and against the public key, so a wrong value here fails loudly and is never trusted.
SOFTWARE_LABEL = "throwaway software key"
# Stands in for the public key of a software device while the builder reads the shape of the input: its types are
# right, its values are never used (a key made at run time replaces it before anything is built).
_SLOT = {"agree": {}, "class": DECLARED_CLASS, "kid": "", "sign": {}}
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


def read_input(value):
    """`(spec, slots)`: the builder's `read_input` of `value`, and the indexes of its software devices, the ones
    that have no pubkey. A software device is a `{person, label}` object; every other shape fault is the builder's."""
    devices = value.get("devices") if type(value) is dict else None
    slots = [i for i, d in enumerate(devices) if type(d) is dict and "pubkey" not in d] if type(devices) is list else []
    filled = {**value, "devices": [{**d, "pubkey": _SLOT} if i in slots else d for i, d in enumerate(devices)]} if slots else value
    return genesis_build.read_input(filled), slots


def mint(value, profile_set, new_key, now, nonce):
    """The draft and the receipts of a throwaway org: `{document, draft_bytes, receipts: {kid: bytes}, result}`.
    The marker is checked before any key exists. `new_key()` makes a SoftwareKey, `now()` a UTC time text and
    `nonce()` a hashstr, all injected."""
    spec, slots = read_input(value)
    if not spec["name"].startswith(genesis_build.THROWAWAY_PREFIX):
        raise genesis_build.Refusal("name_not_throwaway")
    for index in slots:
        if not spec["devices"][index]["label"].startswith(SOFTWARE_LABEL):
            raise genesis_build.Refusal("label_not_throwaway", device=index)
    keys = {index: new_key() for index in slots}
    for index, key in keys.items():
        spec["devices"][index] = {**spec["devices"][index], "pubkey": key.pubkey()}
    made = genesis_build.compose(spec, profile_set)
    sign_in = genesis_build.sign_input(made["document"])
    receipts = {}
    for index, key in keys.items():
        signed = receipt(key, sign_in, spec["devices"][index]["person"], now(), nonce(), profile_set.wire)
        receipts[key.pubkey()["kid"]] = emit.emit_result(signed) + b"\n"
    unsigned = sorted(d["kid"] for d in made["document"]["devices"] if d["kid"] not in receipts)
    result = {"document_hash": made["document_hash"], "draft_hash": made["draft_hash"], "hash12": made["hash12"],
              "signed": sorted(receipts), "unsigned": unsigned}
    return {"document": made["document"], "draft_bytes": made["draft_bytes"], "receipts": receipts, "result": result}


def _clock():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nonce():
    return encoding.hashstr(secrets.token_bytes(32))


def _mint(args, stdin, stdout):
    value = genesis_build.read_text(stdin.read())
    genesis_build.make_directory(args.dir)   # first: an existing DIR is refused before any key is made
    try:
        out = mint(value, profiles.load(), SoftwareKey.generate, _clock, _nonce)
    except BaseException:
        os.rmdir(args.dir)   # the empty directory this run just made: a refused draft leaves nothing behind
        raise
    genesis_build.write_once(Path(args.dir) / "draft.json", out["draft_bytes"])
    for kid, data in out["receipts"].items():
        genesis_build.write_once(Path(args.dir) / ("receipt-%s.json" % kid), data)
    stdout.write(emit.emit_result(out["result"]) + b"\n")


def _parser():
    parser = argparse.ArgumentParser(prog="genesis_throwaway.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    minted = commands.add_parser("mint", help="write a throwaway draft and its receipts to a new directory")
    minted.add_argument("dir", metavar="DIR")
    minted.set_defaults(run=_mint)
    return parser


def main(argv=None, stdin=None, stdout=None):
    """0 when the command did its job, 2 when it printed a refusal. A crash is never caught."""
    args = _parser().parse_args(argv)
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    try:
        args.run(args, stdin, stdout)
    except genesis_build.Refusal as refusal:
        stdout.write(emit.emit_result({"error": refusal.code, **refusal.extra}) + b"\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
