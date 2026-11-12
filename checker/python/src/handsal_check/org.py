"""The org id (GP-01, GP-04, GP-05): the hashstr of the original genesis document.

It is stored in every later document's `org` and in every act, and never in the
original's own bytes. The pin file name derives from the digest inside it, in
lowercase hex so that NTFS case folding cannot merge two names.
"""
from . import encoding, genesis


def org_id(original_doc):
    """The org id of the original genesis document `original_doc` (already validated)."""
    return genesis.doc_hash(original_doc)


def digest_hex(org):
    """The lowercase hex of the SHA-256 digest inside the org id `org`."""
    if not encoding.is_hashstr(org):
        raise ValueError("not an org id")
    return encoding.b64u_decode(org[1:])[2:].hex()


def pin_filename(org):
    """`<hex64>.pin` for the org id `org` (GP-05)."""
    return digest_hex(org) + ".pin"
