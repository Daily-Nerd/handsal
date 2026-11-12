"""Helpers shared by the groups that write `render` rows (rnd/*, wit/render-genesis-*).

A row is a `render` input `{attachments, kid, method, payload}` over a real act, and its
anchor is authored by `lib/render.py`, the generator's model of RN-01 to RN-12. A refusal
row states its code here and the model must agree before the row is written.
"""
import json

from . import forge, render, result

GENESIS_SIGN = "local:handsal.genesis.sign"


def header_kid(jws):
    return json.loads(forge.parts(jws)[0])["kid"]


def pos(ctx, jws):
    """Record `jws` for the vitni cross-check, signed by the device of its header kid."""
    payload = json.loads(forge.parts(jws)[1])
    ctx.positive(jws, payload["method"], [ctx.fixtures.name_of_kid(header_kid(jws))])


def render_input(jws, attachments):
    payload = json.loads(forge.parts(jws)[1])
    return {"attachments": attachments, "kid": header_kid(jws), "method": payload["method"],
            "payload": payload}


def add(ctx, name, inp, error=None):
    """Write the render row `name`; the model must give `error` (or any text when None)."""
    got = render.render(inp)
    if (error is None) != ("error" not in got) or (error is not None and got["error"] != error):
        raise AssertionError("%s: the model says %r, the row says %r" % (name, got, error))
    ctx.writer.add(name, "render", result.line(got), input=inp)
    return got


def genesis_row(ctx, name, doc, attachments, error=None, signer="alice", **kwargs):
    """A `genesis.sign` render row over `doc` with `attachments`."""
    jws = ctx.fixtures.genesis_sign(signer, doc, **kwargs)
    pos(ctx, jws)
    return add(ctx, name, render_input(jws, attachments), error)
