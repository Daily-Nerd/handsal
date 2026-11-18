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

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402,F401  (software keys, below)

from handsal_check import emit, encoding, envelope, genesis  # noqa: E402


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
