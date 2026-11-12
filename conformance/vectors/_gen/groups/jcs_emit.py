"""Vectors jcs/emit-roundtrip-*, seen through `subset` (ACT-05).

The input is the exact payload a base fixture signs, which the generator
emitted with its own emitter (lib/jcs.py). `subset` must accept it: emit then
recognize is the identity. The signer `emit` form of these rows (bytes equal to
an anchor) is run against the signers by their own groups. Every method of
ACT-09 has a row.
"""
import base64

from lib import base, subset_rows
from lib.subset_rows import OK


def _payload(jws):
    seg = jws.split(".")[1]
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _change_doc(fx):
    """A genesis change of ORG: names the original as `prev`, carries `head`."""
    doc = dict(fx.org)
    doc.update({"org": fx.org_id, "prev": fx.org_id, "head": fx.org_id})
    problems = base.check_genesis_shape(doc)
    if problems:
        raise AssertionError("change document is not schema-valid: %s" % problems)
    return doc


def generate(ctx):
    fx = ctx.fixtures
    add = fx.device_add("alice2", ["alice", "bob"])
    sibling = fx.device_add("bob2", ["alice", "bob"])
    remove = fx.device_remove("alice2", ["bob", "carol"])
    member = fx.member_add("dave", ["alice", "bob"], role="member")
    resolve = fx.chain_resolve(["bob", "carol"], candidates=[add.id, sibling.id], choose=add.id,
                               heads=[sibling.id])
    rows = (
        ("jcs/emit-roundtrip-device-add", add.acts[0]),
        ("jcs/emit-roundtrip-endorse", add.acts[1]),
        ("jcs/emit-roundtrip-approve", fx.approve()),
        ("jcs/emit-roundtrip-genesis-sign", fx.genesis_sign("alice", _change_doc(fx))),
        ("jcs/emit-roundtrip-device-remove", remove.acts[0]),
        ("jcs/emit-roundtrip-member-add", member.acts[0]),
        ("jcs/emit-roundtrip-reject", fx.verdict("reject")),
        ("jcs/emit-roundtrip-needs-info", fx.verdict("needs-info")),
        ("jcs/emit-roundtrip-record-promote", fx.record_promote()),
        ("jcs/emit-roundtrip-chain-resolve", resolve.acts[0]),
    )
    for name, jws in rows:
        subset_rows.add(ctx.writer, name, _payload(jws), OK)
