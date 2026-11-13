"""Vectors jcs/emit-*: the canonical emitter (ACT-05).

`jcs/emit-roundtrip-*` are seen through `subset`. The input is the exact payload a base fixture
signs, which the generator emitted with its own emitter (lib/jcs.py). `subset` must accept it:
emit then recognize is the identity. Every method of ACT-09 has a row.

`jcs/emit-sorted`, `jcs/emit-slash-raw` and `jcs/emit-value-with-number-refused` are signer
`emit` vectors (CF-04): the bytes the signer's emitter writes for a draft, or its refusal.
A signer reads its stdin through the canonical recognizer (SG-01), so a draft is never given with
unsorted keys: `jcs/emit-sorted` is a `device.add` draft whose payload nests objects (`body`,
`agree`, `sign`, `ext`) that the emitter must sort, and its bytes are those of the base builder.
The `emit` form of the other methods has no id (see the batch report).
"""
import base64

from lib import base, emitrows, subset_rows
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

    # the signer `emit` rows (CF-04)
    inp, jws = emitrows.device_add_input(fx)
    emitrows.ok(ctx, "jcs/emit-sorted", inp, jws)
    inp, jws = emitrows.device_add_input(fx, label="a/b")
    emitrows.ok(ctx, "jcs/emit-slash-raw", inp, jws)
    inp, _jws = emitrows.verdict_input(fx)
    inp["draft"]["expires_in_s"] = 3600  # a JSON number: no number is in the subset (ACT-04)
    emitrows.refused(ctx, "jcs/emit-value-with-number-refused", inp, "schema_refused")
