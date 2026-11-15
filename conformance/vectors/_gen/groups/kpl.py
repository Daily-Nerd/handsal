"""Vectors kpl/*: `pool`, is a point an `agree` key the organization introduced (CF-12, RS10).

The input is `{acts, agree, docs, org}`; the anchor is `{in_pool, reason}`. A point is in the pool when a
document lists it as an `agree` key or a valid `device.add` or `member.add` introduced it, on any branch,
removed or not. A `sign` point never is, and a pending `device.add` (no quorum) introduces nothing. Stated from
the spec (CF-06).
"""
from lib import chain, result
from lib.forks import AB, AC, BC


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    lineage = fx.lineage()

    def row(name, point, in_pool, reason, *, acts=(), docs=lineage):
        w.add(name, "pool", result.line({"in_pool": in_pool, "reason": reason}),
              input={"acts": list(acts), "agree": point, "docs": docs, "org": fx.org_id})

    def fresh(**kw):
        return chain.Chain(fx, ctx=ctx, **kw)

    def agree(name):
        return fx.key(name, "agree").point()

    fresh()
    row("kpl/genesis-device", agree("alice"), True, "ok")
    row("kpl/sign-point-not-in-pool", fx.key("alice", "sign").point(), False, "not_in_pool")
    row("kpl/unknown", agree("dave"), False, "not_in_pool")

    f = fresh()
    keep = f.device_add("alice2", AB)
    lose = f.device_add("alice3", AC, parent=None, ok=False, valid=True)
    resolve = f.resolve(AB, candidates=[keep.id, lose.id], choose=keep.id, heads=[lose.id], parent=None)
    row("kpl/added-on-losing-branch", agree("alice3"), True, "ok", acts=keep.acts + lose.acts + resolve.acts)

    r = fresh()
    r.device_add("alice2", AB)
    r.device_remove("alice2", BC)
    row("kpl/removed-device", agree("alice2"), True, "ok", acts=r.acts)

    one = fresh().device_add("alice2", ("alice",), ok=False, short=True)
    row("kpl/pending-add-not-in-pool", agree("alice2"), False, "not_in_pool", acts=one.acts)

    fresh(wit=True)
    row("kpl/store-original-wrong-org", agree("alice"), False, "lineage_broken", docs=fx.lineage(wit=True))
