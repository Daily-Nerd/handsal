"""Vectors key/*: key encoding in `device.add` (ACT-11), observed as fold state.

Each defective row is a two-person `device.add` of alice's second device whose
body carries one key defect. The kid names the strings as given (it is the
thumbprint of `sign` as written), so the encoding or the curve is the only
defect of the key. The act is not on the chain (FO-06): the state is the genesis
state. `key/x-leading-zero-ok` is the one valid row: a crafted key whose x starts
with the byte 0x00 and is written with all 32 bytes, so the device is added.

The proof of possession of a defective row is signed by alice2's real key: no
private key exists for an off-curve point, and the act is not on the chain
whether or not the proof would pass.
"""
import hashlib

from lib import chain, crafted, forge, keys

SIGNERS = ("alice", "bob")
AGREE_LABEL = "crafted-leading-zero-agree"


def _sign(x, y):
    """A body edit that puts `x` and `y` (strings as written) in `sign`, kid to match."""
    def edit(body):
        body["sign"] = {"x": x, "y": y}
        body["kid"] = keys.thumbprint(x, y)
    return edit


def _rows(fx):
    own = fx.key("alice2")
    x_zero, y_zero, _label = crafted.leading_zero_point()
    off = (own.y_int + 1).to_bytes(32, "big")
    return (
        ("key/infinity-or-zero", _sign("A" * 43, "A" * 43)),
        ("key/kid-not-thumbprint",
         lambda b: b.__setitem__("kid", keys.b64u(hashlib.sha256(b"wrong kid").digest()))),
        ("key/not-on-curve", _sign(own.x, keys.b64u(off))),
        ("key/x-31-bytes", _sign(keys.b64u(x_zero[1:]), keys.b64u(y_zero))),
        ("key/y-33-bytes", _sign(own.x, keys.b64u(b"\x00" + own.y_int.to_bytes(32, "big")))),
        ("key/y-not-canonical-b64", _sign(own.x, forge.flip_spare_bits(own.y))),
    )


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    for name, edit in _rows(fx):
        c = chain.Chain(fx, ctx=ctx)
        c.device_add("alice2", SIGNERS, ok=False, body_edit=edit)
        w.add(name, "fold", c.expect(), input=c.fold_input())

    _x, _y, label = crafted.leading_zero_point()
    fx.register_device("alice5", label, AGREE_LABEL)
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice5", SIGNERS)
    w.add("key/x-leading-zero-ok", "fold", c.expect(), input=c.fold_input())
