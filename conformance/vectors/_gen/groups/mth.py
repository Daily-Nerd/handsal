"""Vectors mth/*: the method registry at `check-act` (ACT-09, VR-02 step 4).

An unknown method string is `method_unknown`; a known chain method is
`chain_method`, so no human act is ever treated as permanent. Each act passes
steps 1 to 3 (signed, canonical, envelope valid). The consumer expects an
approve in every row; the expectation is checked at step 9 only.
"""
from lib import forge, inputs, retired


def _method(fx, text):
    return forge.resign(fx, fx.approve(), lambda p: p.__setitem__("method", text))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    add = fx.device_add("alice2", ["alice", "bob"])
    sibling = fx.device_add("bob2", ["alice", "bob"])
    resolve = fx.chain_resolve(["bob", "carol"], candidates=[add.id, sibling.id],
                               choose=add.id, heads=[sibling.id])
    unknown = (
        ("mth/case-variant", "Local:Handsal.request.approve"),
        ("mth/mcp-prefix", "mcp:handsal.request.approve"),
        ("mth/request-send", "local:handsal.request.send"),
        ("mth/unknown-verb", "local:handsal.request.cancel"),
    )
    for name, method in unknown:
        jws = _method(fx, method)
        w.add(name, "check-act", inputs.check_anchor(jws, "method_unknown"),
              input=inputs.check_input(fx, jws))
    # ACT-09 S9: the retired record method is one more string outside the registry. A caller of it still
    # sends its record body and names it as `expect_method`: nothing more is required, and nothing is read
    retired_act = retired.jws(fx)
    w.add("mth/record-promote-retired", "check-act", inputs.check_anchor(retired_act, "method_unknown"),
          input=retired.check_input(fx))
    chain = (
        ("mth/chain-method-to-check-act", add.acts[0]),
        ("mth/endorse-to-check-act", add.acts[1]),
        ("mth/genesis-sign-to-check-act", fx.genesis_sign("alice", fx.org)),
        ("mth/resolve-to-check-act", resolve.acts[0]),
    )
    for name, jws in chain:
        w.add(name, "check-act", inputs.check_anchor(jws, "chain_method"),
              input=inputs.check_input(fx, jws))
