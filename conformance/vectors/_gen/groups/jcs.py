"""Vectors jcs/*: the canonical subset grammar (ACT-04), through `subset`.

Each row is one defect (or none) in a small valid-looking value. Reasons:
`ok` accepts; `payload_not_canonical_subset` and `payload_too_large` reject.
`jcs/payload-null` and `jcs/payload-array` are signed acts whose payload is a top-level `null`
or array, run through `check-act` (the grammar accepts any root, a signed payload must be an
object: ACT-04). The signer `emit` rows are written by a later group.
"""
from lib import es256, inputs, jcs, subset_rows
from lib.subset_rows import BAD, BIG, OK


def _nest(inner, wrap, times):
    text = inner
    for _ in range(times):
        text = wrap % text
    return text


ROWS = (
    ("jcs/number-anywhere", b'{"a":1}', BAD),
    ("jcs/true-literal", b'{"a":true}', BAD),
    ("jcs/dup-key-top", b'{"a":"x","a":"y"}', BAD),
    ("jcs/dup-key-ext", b'{"ext":{"a":"x","a":"y"}}', BAD),
    ("jcs/dup-key-body", b'{"ext":{"dev.handsal/act":{"body":{"a":"x","a":"y"}}}}', BAD),
    ("jcs/unsorted-keys", b'{"b":"x","a":"y"}', BAD),
    ("jcs/whitespace", b'{"a": "x"}', BAD),
    ("jcs/escape-slash", b'{"a":"\\/"}', BAD),
    ("jcs/escape-quote", b'{"a":"\\""}', BAD),
    ("jcs/escape-u0041", b'{"a":"\\u0041"}', BAD),
    ("jcs/escape-lone-surrogate", b'{"a":"\\ud800"}', BAD),
    ("jcs/escape-upper-hex", b'{"a":"\\u00E9"}', BAD),
    ("jcs/raw-non-ascii-e9", '{"a":"é"}'.encode("utf-8"), BAD),
    ("jcs/raw-del", b'{"a":"\x7f"}', BAD),
    ("jcs/raw-u2028", '{"a":" "}'.encode("utf-8"), BAD),
    ("jcs/raw-newline-in-string", b'{"a":"x\ny"}', BAD),
    ("jcs/bom", b"\xef\xbb\xbf{}", BAD),
    ("jcs/invalid-utf8", b"\xc3\x28", BAD),
    ("jcs/key-non-ascii", '{"é":"x"}'.encode("utf-8"), BAD),
    ("jcs/depth-9", _nest("[]", "[%s]", jcs.MAX_DEPTH).encode("ascii"), BAD),
    ("jcs/trailing-bytes", b"{}x", BAD),
    ("jcs/empty-input", b"", BAD),
    ("jcs/oversize", b'"' + b"a" * (jcs.MAX_PAYLOAD - 1) + b'"', BIG),
    ("jcs/depth-8-ok", _nest("{}", '{"a":%s}', jcs.MAX_DEPTH - 1).encode("ascii"), OK),
    ("jcs/null-where-allowed", b'{"a":null}', OK),
    ("jcs/raw-slash-ok", b'"a/b"', OK),
    ("jcs/empty-containers-ok", b'{"a":[],"b":{}}', OK),
)


def generate(ctx):
    for name, raw, reason in ROWS:
        subset_rows.add(ctx.writer, name, raw, reason)

    fx = ctx.fixtures
    alice = fx.key("alice")
    header = jcs.emit({"alg": "ES256", "kid": alice.kid})
    for name, root in (("jcs/payload-null", b"null"), ("jcs/payload-array", b"[]")):
        jws = es256.sign_jws(alice.d, header, root)
        ctx.writer.add(name, "check-act", inputs.check_anchor(jws, "payload_not_canonical_subset"),
                       input=inputs.check_input(fx, jws))
