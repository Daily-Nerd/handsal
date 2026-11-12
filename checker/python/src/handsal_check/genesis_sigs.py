"""Possession: which `genesis.sign` receipts count for a lineage document (GP-03, GP-15, ACT-13).

A signature over document D counts iff all hold:
- it passes ACT-01 to ACT-14 for `genesis.sign` (`acts.parse`): the body is `{}`, the parent fields
  are null, a `head` is present iff D's `prev` is non-null;
- `inputs_hash` is hashstr(JCS(D)), `outputs_hash` the empty hash, `org` the original org id, and
  for a change `head.id` is D's `head`;
- its kid is listed in D;
- vitni says `ok` with the one-entry keys map of that device, keyed by its `person`, and S is low
  (VR-04): a `performer_id` that is not that person is `unknown_key` to vitni (VR-03, ACT-13), so the
  binding of signer to person has one owner.

Every other text is ignored, never an error (FO-06, FO-21): junk, unlisted keys, another document,
duplicates. Only a listed device left without a counting signature is `genesis_unsigned` (step 6).
A verifier that cannot answer raises `VerifierUnavailable`: it is not a missing signature.

`read` is the part of the test that authority (GP-19) shares: it needs no key.
"""
from . import acts, errors, genesis, verifier

GENESIS_SIGN = frozenset(("local:handsal.genesis.sign",))


def read(text, doc, doc_hash, original_org, reg):
    """The `ParsedAct` of `text` if it is a `genesis.sign` over `doc` by the rules that need no key,
    else None. `doc_hash` is hashstr(JCS(doc))."""
    change = doc["prev"] is not None
    try:
        act = acts.parse(text, reg, GENESIS_SIGN, head_present=change)
    except errors.Refused:
        return None
    if act.payload["inputs_hash"] != doc_hash or act.act["org"] != original_org:
        return None
    if change and act.head["id"] != doc["head"]:
        return None
    return act


def counting(doc, sigs, original_org, reg, vitni):
    """The kids of the devices of `doc` that have a counting signature in `sigs`."""
    doc_hash = genesis.doc_hash(doc)
    devices = {device["kid"]: device for device in doc["devices"]}
    counted = set()
    for text in sigs:
        act = read(text, doc, doc_hash, original_org, reg)
        if act is None or act.kid not in devices or act.kid in counted:
            continue
        device = devices[act.kid]
        keys = {device["person"]: {device["kid"]: verifier.key_entry(device["sign"], "active")}}
        if vitni.verify(text, keys, act.method) == "ok" and verifier.is_low_s(act.signature):
            counted.add(act.kid)
    return frozenset(counted)


def check_possession(doc, sigs, original_org, reg, vitni):
    """GP-15 step 6: raise Refused `genesis_unsigned` unless every listed device counts."""
    counted = counting(doc, sigs, original_org, reg, vitni)
    if any(device["kid"] not in counted for device in doc["devices"]):
        raise errors.Refused("genesis_unsigned")
