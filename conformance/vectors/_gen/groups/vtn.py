"""Vectors vtn/*: the vitni verdict at step 9 of VR-02 (VR-03, VR-01).

Every `check-act` row is an act whose earlier steps pass, so the vitni reason is
the first failure. `class` follows VR-01: the class of the pinned-state device
whose kid is the header kid, null when the state has no such device. Each
negative is also put to both vitni binaries, which must give the same reason
(CF-06).

vtn/unexpected-vitni-reason and vtn/unknown-vitni-reason-string left the catalog (CF-07):
they need a verifier that answers a chosen reason, and a vector input has no such field.
`verifier_unexpected` is proven by an implementation test of the checker.

The two `unaccepted` rows use dave, a member with role `member`, who holds an
accepted device and a `fixture-pin` device added by `device.add`; a genesis
document cannot list a class the policy does not accept (GP-15 step 3), and a
role holder cannot hold `fixture-pin` (KC-08). The catalog names bob for the key
that is not accepted; dave is the person who can hold one.
"""
from lib import base, chain, forge, inputs

APPROVE, REJECT = inputs.APPROVE, inputs.REJECT
KEEP = "apple-se-bio"
PIN_CLASS = "fixture-pin"


def _flip_s(jws):
    head, payload, sig = forge.parts(jws)
    return forge.join(head, payload, sig[:32] + bytes([sig[32] ^ 1]) + sig[33:])


def _dave(ctx):
    """A chain where dave (role member) has an accepted and a fixture-pin device."""
    c = chain.Chain(ctx.fixtures, ctx=ctx)
    c.member_add("dave", ("alice", "bob"), role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=PIN_CLASS)
    return c


def _row(ctx, name, jws, reason, *, signers, cls=inputs.UNSET, acts=(), revoked=(),
         method=APPROVE, **override):
    fx = ctx.fixtures
    ctx.negative(jws, method, signers, reason, revoked=revoked)
    ctx.writer.add(name, "check-act", inputs.check_anchor(jws, reason, cls),
                   input=inputs.check_input(fx, jws, method=method, acts=list(acts), **override))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    org_keys = ["alice", "bob", "carol"]

    jws = _flip_s(fx.approve())
    _row(ctx, "vtn/bad-signature", jws, "bad_signature", signers=["alice"])

    jws = fx.verdict("reject")
    _row(ctx, "vtn/context-mismatch", jws, "context_mismatch", signers=["alice"])

    jws = fx.approve()
    w.add("vtn/missing-expect-method", "check-act", inputs.error_anchor("malformed_input"),
          input=inputs.check_input(fx, jws, expect_method=inputs.DROP))

    removal = chain.Chain(fx, ctx=ctx)
    removal.device_remove("alice", ("bob", "carol"))
    jws = fx.approve()
    _row(ctx, "vtn/revoked-key", jws, "revoked_key", signers=["alice"], revoked=["alice"],
         acts=removal.acts)

    jws = fx.verdict("approve", "dave", recipient="dave")
    _row(ctx, "vtn/unknown-key", jws, "unknown_key", signers=org_keys, cls=None,
         recipient="dave")

    dave = _dave(ctx)
    jws = _flip_s(fx.verdict("approve", "dave2", recipient="dave"))
    _row(ctx, "vtn/unaccepted-bad-sig", jws, "bad_signature", signers=["dave2"], cls=PIN_CLASS,
         acts=dave.acts, recipient="dave")

    jws = fx.verdict("approve", "dave2", recipient="alice")
    _row(ctx, "vtn/unaccepted-map-keyed-by-person", jws, "unknown_key", signers=["dave2"],
         cls=PIN_CLASS, acts=dave.acts)
