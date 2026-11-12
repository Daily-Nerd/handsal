"""Vectors sig/*: the signature form (VR-04).

All rows are an approve by alice, with the signature changed in one way.

- sig/low-s-ok and sig/high-s are the two forms of one payload: vitni says `ok`
  to both, and the profile accepts only the low form (`high_s`, step 10).
- r and s out of range (0 or n) fail the signature itself: `bad_signature`
  (step 9), which both vitni binaries must give too.

sig/s-equals-half left the catalog (CF-07): no valid ECDSA signature has a chosen S, so a
vector with S = (n - 1) / 2 and a verifying signature cannot be made. VR-04 at that
boundary is an implementation test of the checker.
"""
from lib import forge, inputs, p256

N = p256.N


def _with_rs(jws, r=None, s=None):
    head, payload, sig = forge.parts(jws)
    r_bytes = sig[:32] if r is None else r.to_bytes(32, "big")
    s_bytes = sig[32:] if s is None else s.to_bytes(32, "big")
    return forge.join(head, payload, r_bytes + s_bytes)


def _add(ctx, name, jws, reason, vitni_reason):
    fx = ctx.fixtures
    ctx.negative(jws, inputs.APPROVE, ["alice"], vitni_reason)
    ctx.writer.add(name, "check-act", inputs.check_anchor(jws, reason),
                   input=inputs.check_input(fx, jws))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    low = fx.approve()
    ctx.positive(low, inputs.APPROVE, ["alice"])
    w.add("sig/low-s-ok", "check-act", inputs.check_anchor(low, "ok"),
          input=inputs.check_input(fx, low))
    _add(ctx, "sig/high-s", forge.resign(fx, low, high_s=True), "high_s", "ok")
    for name, r, s in (("sig/r-zero", 0, None), ("sig/r-ge-n", N, None),
                       ("sig/s-zero", None, 0), ("sig/s-ge-n", None, N)):
        _add(ctx, name, _with_rs(low, r, s), "bad_signature", "bad_signature")
