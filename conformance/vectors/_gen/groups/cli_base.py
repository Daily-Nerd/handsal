"""Vectors cli/* base rows (CF-03, ACT-11): framing, dispatch, `kid`, `subset`.

Framing (I-JSON, MAX_INPUT, duplicate names) runs before any command logic, so
the framing rows ride on `kid`, the smallest command that takes a JSON object.
The rows that need `fold`, `check-act`, `render`, `genesis-check` or the
production build belong to the groups that build those inputs. `cli/build-approve` is a signer
`emit` vector (CF-04). `cli/build-bad-nonce` is not written: SG-04 does not say that `emit`
checks the forms of `fixed`.
"""
import json

from lib import crafted, emitrows, keys, renderrows, result, subset_rows
from lib.subset_rows import BAD, OK

UNSUPPORTED = result.line({"error": "unsupported_command"})
UNPARSEABLE = result.line({"error": "unparseable_input"})
MALFORMED = result.line({"error": "malformed_input"})


def _b64u(raw):
    return keys.b64u(raw)


def generate(ctx):
    w = ctx.writer
    alice = ctx.fixtures.key("alice")
    point = {"x": alice.x, "y": alice.y}

    w.add("cli/unsupported-command", "x", UNSUPPORTED, input={})
    w.add("cli/unparseable-stdin", "kid", UNPARSEABLE, input_raw="not json")
    w.add("cli/malformed-input", "kid", MALFORMED, input={"x": alice.x})
    dup = '{"x":%s,"x":%s,"y":%s}' % tuple(json.dumps(s) for s in (alice.x, alice.x, alice.y))
    w.add("cli/stdin-duplicate-key-unparseable", "kid", UNPARSEABLE, input_raw=dup)
    w.add("cli/stdin-over-max-input-unparseable", "kid", UNPARSEABLE, input=dict(point),
          pad=["x"])

    w.add("cli/kid-ok", "kid", result.line({"kid": alice.kid}), input=dict(point))
    x, y, _label = crafted.leading_zero_point()
    cx, cy = _b64u(x), _b64u(y)
    w.add("cli/kid-leading-zero", "kid", result.line({"kid": keys.thumbprint(cx, cy)}),
          input={"x": cx, "y": cy})

    # CF-03: `render` answers `{first_line, text}`
    fx = ctx.fixtures
    jws = fx.approve()
    renderrows.pos(ctx, jws)
    renderrows.add(ctx, "cli/render-shape",
                   renderrows.render_input(jws, {"request_b64": fx.request_b64()}))

    subset_rows.add(w, "cli/jcs-profile-recognize", b'{"a":"b"}', OK)
    subset_rows.add(w, "cli/output-is-jcs", b'{"b":"x","a":"y"}', BAD)

    # CF-04 S3: an approve draft with fixed values, through the signer's `emit`
    inp, jws = emitrows.verdict_input(fx)
    emitrows.ok(ctx, "cli/build-approve", inp, jws)
