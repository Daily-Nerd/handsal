# Fixture keys

`keys.json` holds P-256 private scalars for every principal the conformance
vectors need. They are **public test material**. Anyone can read them, so they
protect nothing and must never be trusted outside a vector.

`fixture-kids.json` lists the kid of every key in `keys.json` that can appear
as a kid: each `*.sign` key and `relay-fixture`. A production profile never
accepts a kid on this list (spec GP-18, KC-07). The `*.agree` keys have no kid.

## Derivation

Each scalar comes from its label, so the files are reproducible and clearly
not secret:

    d = (int(SHA-256("handsal-fixture-v1/" + label), big-endian) mod (n - 1)) + 1

`n` is the P-256 group order, so `d` is always in `[1, n - 1]`. The public
point is `d * G`. A kid is the RFC 7638 thumbprint of the public key:
`base64url(SHA-256({"crv":"P-256","kty":"EC","x":...,"y":...}))`.

## Labels

- `<device>.sign` and `<device>.agree` for the devices `alice`, `alice2`,
  `alice3`, `alice4`, `bob`, `bob2`, `bob3`, `carol`, `carol2`, `dave`,
  `dave2`, `frank`, `grace`, `X1`, `X2`.
- `alice-pin` and `frank-pin`: devices of the fixture-only PIN class held by
  role holders, used by the role-holder class refusal vectors.
- `relay-fixture`: the single relay signing key.

There is no production key material here. Production vectors use separate keys
whose scalars are destroyed after signing.

## Regenerate

    uv run python -I conformance/vectors/_gen/make_keys.py

A rerun must leave `git diff --exit-code conformance/fixtures` clean. The test
`conformance/vectors/_gen/tests/test_keys.py` checks that the committed files
equal a fresh derivation.
