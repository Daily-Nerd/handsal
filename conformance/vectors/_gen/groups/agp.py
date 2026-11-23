"""Vectors agp/*: `agree-points`, which `agree` points an organization introduced and which of them count now (CF-16).

The input is the snapshot of CF-13, `{acts, docs, org}`, and nothing else. The anchor is `{active, pool, reason}`:
`pool` lists the `agree` point of every device any document lists or any valid act introduced, on any branch, removed
or not; `active` lists those of a device that counts now (active and accepted), where an open epoch ends at a tip or
at an unresolved fork (every leaf below its candidates counts), and a branch a current resolve discarded counts for
`pool` only. A `sign` point is in neither list. A refusal is `{"active":null,"pool":null,"reason":R}`.

The devices of each row are the author's statement from the spec (CF-06), written by name next to the scene that
shows them; the points are read from the fixture keys, unique and sorted by `x` then `y`. No checker is asked.
"""
from lib import base, chain, inputs, result
from lib.changes import E0, record_sigs
from lib.epochs import lineage_with, sign_change
from lib.forks import AB, AC, BC, child, removal

GEN = ("alice", "bob", "carol")   # the devices ORG lists
CLASS_NOT_LISTED = "test-sw-p256"   # a class the policy of ORG does not list (KC-03)


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    lineage = fx.lineage()

    def points(names):
        found = {}
        for name in names:
            point = fx.key(name, "agree").point()
            found[(point["x"], point["y"])] = point
        return [found[key] for key in sorted(found)]

    def row(name, active, pool, *, acts=(), docs=lineage):
        anchor = result.line({"active": points(active), "pool": points(pool), "reason": "ok"})
        w.add(name, "agree-points", anchor, input={"acts": list(acts), "docs": docs, "org": fx.org_id})

    def refused(name, reason, docs):
        w.add(name, "agree-points", result.line({"active": None, "pool": None, "reason": reason}),
              input={"acts": [], "docs": docs, "org": fx.org_id})

    def fresh(**kw):
        return chain.Chain(fx, ctx=ctx, **kw)

    # ---- S1, S5: genesis devices, an added device, a removed one
    row("agp/empty-acts-genesis-devices", GEN, GEN)
    fresh()   # the receipts of ORG go to the vitni cross-check
    c = fresh()
    c.device_add("alice2", AB)
    row("agp/active-genesis-device", GEN + ("alice2",), GEN + ("alice2",), acts=c.acts)
    c = fresh()
    c.device_add("alice2", AB)
    c.device_remove("alice2", BC)
    row("agp/removed-device", GEN, GEN + ("alice2",), acts=c.acts)

    # ---- S2, S3: the two store refusals the snapshot can show
    fresh(wit=True)
    refused("agp/lineage-broken-refused", "lineage_broken", fx.lineage(wit=True))
    mixed = inputs.change_doc(fx, edit=lambda d: d.update(profile=base.production_profile()))
    mixed_sigs = [fx.genesis_sign(n, mixed) for n in GEN]
    record_sigs(ctx, mixed_sigs)
    refused("agp/fixture-profile-refused", "fixture_profile",
            [inputs.original_lineage(fx, fx.org)[0], {"doc": mixed, "sigs": mixed_sigs}])

    # ---- S6: an unresolved fork at the node that added alice2
    c = fresh()
    added = c.device_add("alice2", AB)
    removal(c, "alice2", BC, added)   # one branch removes it, the other adds bob2: it is in `active` through the other
    child(c, "bob2", AB, added)
    row("agp/removed-on-one-fork-branch", GEN + ("alice2", "bob2"), GEN + ("alice2", "bob2"), acts=c.acts)
    c = fresh()
    added = c.device_add("alice2", AB)
    removal(c, "alice2", BC, added)   # both branches remove it: in `pool`, in `active` on no leaf
    removal(c, "alice2", ("carol", "bob"), added)
    row("agp/removed-on-all-branches", GEN, GEN + ("alice2",), acts=c.acts)

    # ---- S7: a branch a current resolve discarded
    c = fresh()
    keep = c.device_add("alice2", AB)
    lose = c.device_add("alice3", AC, parent=None, ok=False, valid=True)
    resolve = c.resolve(AB, candidates=[keep.id, lose.id], choose=keep.id, heads=[lose.id], parent=None)
    row("agp/added-on-losing-branch-only", GEN + ("alice2",), GEN + ("alice2", "alice3"),
        acts=keep.acts + lose.acts + resolve.acts)

    # ---- S8: a device add without quorum, sign points, a class the policy does not accept
    one = fresh().device_add("alice2", ("alice",), ok=False, short=True)
    row("agp/pending-add-in-neither", GEN, GEN, acts=one.acts)
    c = fresh()
    c.device_add("alice2", AB)
    c.device_add("bob2", AB)
    row("agp/sign-point-in-neither", GEN + ("alice2", "bob2"), GEN + ("alice2", "bob2"), acts=c.acts)
    c = fresh()
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=CLASS_NOT_LISTED)
    row("agp/unaccepted-device-pool-only", GEN + ("dave",), GEN + ("dave", "dave2"), acts=c.acts)

    # ---- S9: successor epochs
    def successors(name, active, pool, carry, news):
        e0 = E0(ctx)
        docs = list(e0.lineage)
        for new in news:
            doc = e0.change(0, carry=carry, new=(new,))
            sigs = sign_change(fx, doc)
            record_sigs(ctx, sigs)
            docs = lineage_with(docs, doc, sigs)
        row(name, active, pool, docs=docs)

    # two siblings at one head: the epoch they succeed counts for nothing, so carol (carried by neither) is `pool` only
    successors("agp/sibling-epochs-both-active", ("alice", "bob", "grace", "frank"), GEN + ("grace", "frank"),
               ("alice", "bob"), ("grace", "frank"))
    successors("agp/change-drops-device", ("alice", "bob", "grace"), GEN + ("grace",), ("alice", "bob"), ("grace",))
    # the same three persons carried into both epochs: each point is listed once
    successors("agp/same-point-two-epochs-once", GEN + ("grace", "frank"), GEN + ("grace", "frank"), GEN,
               ("grace", "frank"))
