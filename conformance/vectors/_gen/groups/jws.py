"""Vectors jws/*: the compact serialization and the header (ACT-02, ACT-03, KC-05).

Every row is `jws_shape` at step 1 of VR-02, before the payload is read, so
`receipt_id` and `class` are null. The base act is ok/approve; each row damages
its shape in one way. A header row re-signs the unchanged payload under the
bad header, so the header is the only defect.
"""
from lib import forge, inputs


def _flip_payload(fx, base_jws):
    """`base_jws` with spare bits set in its payload segment.

    A payload whose length is a multiple of 3 has no spare bits, so an act with
    a request id of another length stands in for it.
    """
    if len(forge.parts(base_jws)[1]) % 3 == 0:
        base_jws = forge.verdict_with_spare_payload_bits(fx)
    segments = base_jws.split(".")
    segments[1] = forge.flip_spare_bits(segments[1])
    return ".".join(segments)


def _row(fx, base_jws):
    h, p, s = forge.parts(base_jws)
    kid = fx.key("alice").kid
    segments = base_jws.split(".")

    def header(raw):
        return forge.resign(fx, base_jws, header=raw)

    def with_segment(index, text):
        out = list(segments)
        out[index] = text
        return ".".join(out)

    jwk = '{"alg":"ES256","jwk":%s,"kid":"%s"}' % (
        '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (fx.key("alice").x, fx.key("alice").y),
        kid)
    return (
        ("jws/b64-padding", with_segment(1, segments[1] + "=")),
        ("jws/b64-trailing-bits-header", with_segment(0, forge.flip_spare_bits(segments[0]))),
        ("jws/b64-trailing-bits-payload", _flip_payload(fx, base_jws)),
        ("jws/b64-trailing-bits-sig", with_segment(2, forge.flip_spare_bits(segments[2]))),
        ("jws/empty", ""),
        ("jws/four-segments", base_jws + ".AAAA"),
        ("jws/header-alg-eddsa", header(('{"alg":"EdDSA","kid":"%s"}' % kid).encode())),
        ("jws/header-alg-none", header(('{"alg":"none","kid":"%s"}' % kid).encode())),
        ("jws/header-extra-member", header(('{"alg":"ES256","kid":"%s","typ":"JWT"}' % kid).encode())),
        ("jws/header-jwk-present", header(jwk.encode())),
        ("jws/header-key-order", header(('{"kid":"%s","alg":"ES256"}' % kid).encode())),
        ("jws/header-null", header(b"null")),
        ("jws/header-whitespace", header(('{"alg": "ES256","kid":"%s"}' % kid).encode())),
        ("jws/sig-63-bytes", forge.join(h, p, s[:63])),
        ("jws/sig-65-bytes", forge.join(h, p, s + b"\x00")),
        ("jws/two-segments", ".".join(segments[:2])),
    )


def generate(ctx):
    fx = ctx.fixtures
    for name, jws in _row(fx, fx.approve()):
        ctx.writer.add(name, "check-act", inputs.check_anchor(jws, "jws_shape"),
                       input=inputs.check_input(fx, jws))
