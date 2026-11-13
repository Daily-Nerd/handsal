"""Vectors jcs/emit-*: the canonical emitter (ACT-05).

`jcs/emit-roundtrip-*` are seen through `subset`. The input is the exact payload a base fixture
signs, which the generator emitted with its own emitter (lib/jcs.py). `subset` must accept it:
emit then recognize is the identity. Every method of ACT-09 has a row.

`jcs/emit-sorted`, `jcs/emit-slash-raw` and `jcs/emit-value-with-number-refused` are signer
`emit` vectors (CF-04): the bytes the signer's emitter writes for a draft, or its refusal.
A signer reads its stdin through the canonical recognizer (SG-01), so a draft is never given with
unsorted keys: `jcs/emit-sorted` is a `device.add` draft whose payload nests objects (`body`,
`agree`, `sign`, `ext`) that the emitter must sort, and its bytes are those of the base builder.
Every other method has its own `emit` row (`jcs/emit-device-remove` to
`jcs/emit-genesis-sign-change`): the draft of the base fixtures with its fixed values gives the
payload the base builders sign, so an emitter bug in array order or `head` presence shows
before a verifier rejects a real signature (ACT-05 S1).
"""
import base64

from lib import base, emitrows, subset_rows
from lib.subset_rows import OK


def _payload(jws):
    seg = jws.split(".")[1]
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


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
        ("jcs/emit-roundtrip-genesis-sign", fx.genesis_sign("alice", emitrows.change_document(fx))),
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

    # one row per remaining method (ACT-05 S1)
    for name, build in (
            ("jcs/emit-device-remove", lambda: emitrows.device_remove_input(fx)),
            ("jcs/emit-member-add", lambda: emitrows.member_add_input(fx)),
            ("jcs/emit-chain-resolve", lambda: emitrows.chain_resolve_input(fx)),
            ("jcs/emit-endorse", lambda: emitrows.endorse_input(fx)),
            ("jcs/emit-reject", lambda: emitrows.verdict_input(fx, "reject")),
            ("jcs/emit-needs-info", lambda: emitrows.verdict_input(fx, "needs-info")),
            ("jcs/emit-record-promote", lambda: emitrows.record_promote_input(fx)),
            ("jcs/emit-genesis-sign-original", lambda: emitrows.genesis_original_input(fx)),
            ("jcs/emit-genesis-sign-change", lambda: emitrows.genesis_change_input(fx))):
        inp, jws = build()
        emitrows.ok(ctx, name, inp, jws)
