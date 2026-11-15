"""Stores and their drop lists, for the vectors that read what a store may drop (CF-14, design 21.2).

A `Scene` is a CF-13 snapshot of ORG `{acts, docs, org}` and the drop list the author states for it: the strings
of `acts` and the receipts of `docs` that no fold reads. The statement is the author's, made from the retained set of
CF-14 (an open epoch whole, a closed epoch only along the path to the head of each successor, one valid copy per
receipt id, and so on); no checker is asked (CF-06). `check` is the whole-set guard of lib/foldmodel.py: the
generator's second statement of the fold must give every leaf document the same answer over the snapshot and over the
snapshot without the drop, so a drop that contradicts the fold is refused before a vector is written.

One builder per store. A row of another group that needs "that store after compaction" (`adm`, `kpl`) asks the scene
for `compacted()`, so it cannot drift from the `cmp` row it comes from.
"""
from . import chain, epochs, foldmodel, forge, inputs, result
from .changes import E0, add, record_sigs
from .forks import AB, BC, child, evidence

GENESIS_SIGN = chain.GENESIS_SIGN
ENDORSE = chain.ENDORSE
DEVICE_ADD = "local:handsal.device.add"


class Scene:
    """A snapshot of ORG and its drop list."""

    def __init__(self, fx, acts, docs, drop_acts=(), drop_sigs=()):
        self.fx = fx
        self.acts, self.docs = list(acts), list(docs)
        self.drop = {"acts": sorted(set(drop_acts)), "sigs": sorted(set(drop_sigs))}

    def input(self):
        """The `compact` input: exactly the snapshot (CF-13)."""
        return {"acts": list(self.acts), "docs": [dict(e, sigs=list(e["sigs"])) for e in self.docs],
                "org": self.fx.org_id}

    def anchor(self):
        return result.line({"drop": self.drop, "reason": "ok"})

    def compacted(self):
        """The snapshot a deletion job leaves after applying the whole drop."""
        return foldmodel.without(self.input(), self.drop)

    def check(self):
        """The whole-set guard; the fold lines of every leaf document when the drop is safe."""
        return foldmodel.guard(self.fx, self.input(), self.drop)


class ClosedEpoch(Scene):
    """The scene of `closed_epoch`, with the epoch it was built on: a row of `adm` builds its item on `e0`."""

    def __init__(self, fx, acts, docs, drop_acts, e0):
        super().__init__(fx, acts, docs, drop_acts)
        self.e0 = e0


def _signed_change(ctx, e0, position, *, carry=("alice", "bob"), new=("grace",)):
    """A change of ORG at `position` of epoch 0 with every listed device's `genesis.sign`: (document, receipts)."""
    doc = e0.change(position, carry=carry, new=new)
    sigs = epochs.sign_change(ctx.fixtures, doc)
    record_sigs(ctx, sigs)
    return doc, sigs


def open_epoch(ctx):
    """Epoch 0 with no successor: a fork at the root and a branch below the losing child. All of it stays."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    lose = c.device_add("bob2", BC, parent=None, ok=False, valid=True)
    c.device_add("alice3", AB, parent=lose, ok=False, valid=True)
    return Scene(fx, c.acts, fx.lineage())


def closed_epoch(ctx, *, fork=False):
    """Epoch 0 of four positions closed by a change at position 2 (CHG-VALID, H = 2).

    Positions 3 and 4 lie above H and go. With `fork`, position 1 also has a second child, `X1` (a device that exists
    only on that branch), and a resolve at position 1 lifts the fork: the resolve is dropped as well (GP-19 Path, a
    resolve is never read on the path) and so is the side branch.
    """
    fx = ctx.fixtures
    e0 = E0(ctx, [add("alice2"), add("bob2"), add("alice3"), add("bob3")])
    dropped = e0.built[3].acts + e0.built[4].acts
    if fork:
        top, keep = e0.built[1], e0.built[2]
        side = e0.c.device_add("X1", AB, parent=top, ok=False, valid=True)
        resolve = e0.c.resolve(AB, candidates=[keep.id, side.id], choose=keep.id, heads=[side.id], parent=top)
        dropped += side.acts + resolve.acts
    doc, sigs = _signed_change(ctx, e0, 2)
    return ClosedEpoch(fx, e0.c.acts, epochs.lineage_with(e0.lineage, doc, sigs), dropped, e0)


def sibling_successors(ctx):
    """Two changes of ORG whose heads lie on two branches of epoch 0: the paths to both stay, the rest goes."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    a2 = c.device_add("bob2", AB)
    a3 = c.device_add("alice3", AB)                                          # above the head of the first change
    b1 = c.device_add("bob3", BC, parent=None, ok=False, valid=True)         # the second branch, beside the first
    b2 = c.device_add("alice4", AB, parent=b1, ok=False, valid=True)         # above the head of the second change
    docs = list(c.lineage)
    for head, new in ((a2, "grace"), (b1, "frank")):
        doc = epochs.make_change(fx, fx.org, head.id, carry=("alice", "bob"), new=(new,), st=c.state_at(head))
        sigs = epochs.sign_change(fx, doc)
        record_sigs(ctx, sigs)
        docs.append({"doc": doc, "sigs": sigs})
    return Scene(fx, c.acts, docs, a3.acts + b2.acts)


def change_at_root(ctx):
    """A change whose head is the root of epoch 0: its path is empty, so the three acts of the epoch all go."""
    fx = ctx.fixtures
    e0 = E0(ctx, [add("alice2"), add("bob2"), add("alice3")])
    doc, sigs = _signed_change(ctx, e0, 0)
    return Scene(fx, e0.c.acts, epochs.lineage_with(e0.lineage, doc, sigs), e0.c.acts)


def junk_and_non_chain(ctx):
    """A kept group, and three strings that are no chain item: no JWS, a verdict, a `genesis.sign` in `acts` (FO-15)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    verdict = fx.approve()
    ctx.positive(verdict, inputs.APPROVE, ["alice"])
    junk = ["this is not a jws", verdict, fx.lineage()[0]["sigs"][0]]
    return Scene(fx, c.acts + junk, fx.lineage(), junk)


def other_org_act(ctx):
    """A kept group and a valid primary of another organization (FO-06)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    foreign = chain.Chain(fx, wit=True, ctx=ctx).device_add("alice2", AB).acts[0]
    return Scene(fx, c.acts + [foreign], fx.lineage(), [foreign])


def other_org_anchored_act(ctx):
    """A kept group, and a primary of another organization with its endorsement and proof of possession, every
    signature valid, whose parent is the root of ORG (FO-06, GP-04: it is no node, so nothing of it is retained)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    foreign = chain.Chain(fx, ctx=ctx, org_id=fx.wit_org_id).device_add("bob2", AB, ok=False).acts
    return Scene(fx, c.acts + foreign, fx.lineage(), foreign)


def invalid_twin(ctx):
    """A stored primary and a copy of it with a bad signature, listed first (FO-21)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    twin = forge.garbage_twin(c.device_add("alice2", AB).acts[0])
    return Scene(fx, [twin] + c.acts, fx.lineage(), [twin])


def second_valid_copy(ctx):
    """A stored primary and a low-S copy of it, both valid, one receipt id: the larger text in byte order goes (FO-21)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    primary = c.device_add("alice2", AB).acts[0]
    twin = forge.twin(fx, primary, "alice")
    ctx.positive(twin, DEVICE_ADD, ["alice"])
    return Scene(fx, c.acts + [twin], fx.lineage(), [max(primary, twin)])


def stranger_endorsement(ctx):
    """A stored `device.add` with an endorsement by a kid that no state holds (FO-08)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    stranger = fx.device_add("alice2", ("alice", "dave")).acts[1]   # the same primary, endorsed by dave
    ctx.positive(stranger, ENDORSE, ["dave"])
    return Scene(fx, c.acts + [stranger], fx.lineage(), [stranger])


def pending_primary(ctx):
    """A kept group and a one-touch `device.add` (no quorum) at a node: pending, so no child (FO-24)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    kept = c.device_add("alice2", AB)
    pending = c.device_add("alice3", ("alice",), ok=False, short=True).acts[0]
    return Scene(fx, kept.acts + [pending], fx.lineage(), [pending])


def unanchored_act(ctx):
    """A kept group and a valid act whose parent is no node of the store (FO-06)."""
    fx = ctx.fixtures
    kept = chain.Chain(fx, ctx=ctx).device_add("alice3", AB)
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)                         # the parent, which the store does not hold
    orphan = c.device_add("bob2", AB).acts[0]
    return Scene(fx, kept.acts + [orphan], fx.lineage(), [orphan])


def override_evidence(ctx):
    """A fork lifted by a resolve whose `overrides` entry names two endorsements of the resolve it overrides (FO-25).

    R1 (bob, endorsed by carol and alice) chooses c1; S (alice and bob) chooses c2 and names R1 with both
    endorsements as evidence, so S is current and the fold takes c2. Nothing is dropped: every valid endorsement of an
    applicable resolve is kept, because an entry names them by receipt id.
    """
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c2 = child(c, "bob2", BC, None, applied=True)
    c1 = child(c, "alice2", AB, None)
    r1 = c.resolve(("bob", "carol", "alice"), candidates=[c1.id, c2.id], choose=c1.id, heads=[c2.id], parent=None)
    named = sorted([evidence(r1, 1), evidence(r1, 2)])
    c.resolve(AB, candidates=[c1.id, c2.id], choose=c2.id, heads=[c1.id], parent=None,
              overrides=[{"endorsements": named, "resolve": r1.id}])
    return Scene(fx, c.acts, fx.lineage())


def non_counting_receipt(ctx):
    """The original document with a `genesis.sign` by a key that is listed nowhere and holds no authority (GP-15)."""
    fx = ctx.fixtures
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    stranger = fx.genesis_sign("dave", fx.org)
    ctx.positive(stranger, GENESIS_SIGN, ["dave"])
    original = {"doc": fx.org, "sigs": fx.lineage()[0]["sigs"] + [stranger]}
    return Scene(fx, c.acts, [original], drop_sigs=[stranger])


def store_doc_invalid(ctx):
    """The store of a refusal: a second document that lists its members out of order. There is no drop to state."""
    fx = ctx.fixtures
    bad = epochs.make_change(fx, fx.org, fx.org_id, carry=AB, new=("grace",),
                             edit=lambda d: d["members"].reverse())
    docs = fx.lineage() + [{"doc": bad, "sigs": epochs.sign_change(fx, bad)}]
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", AB)
    return Scene(fx, c.acts, docs)


# the rows of group `cmp`, in the order of the catalog table: name, builder
CMP = (
    ("cmp/open-epoch-kept-whole", open_epoch),
    ("cmp/closed-off-path-dropped", closed_epoch),
    ("cmp/closed-resolve-dropped", lambda ctx: closed_epoch(ctx, fork=True)),
    ("cmp/sibling-successor-paths-kept", sibling_successors),
    ("cmp/change-at-root-keeps-nothing-of-epoch", change_at_root),
    ("cmp/junk-and-non-chain-dropped", junk_and_non_chain),
    ("cmp/other-org-act-dropped", other_org_act),
    ("cmp/other-org-anchored-act-dropped", other_org_anchored_act),
    ("cmp/invalid-twin-dropped", invalid_twin),
    ("cmp/second-valid-copy-dropped", second_valid_copy),
    ("cmp/stranger-endorsement-dropped", stranger_endorsement),
    ("cmp/pending-primary-dropped", pending_primary),
    ("cmp/unanchored-act-dropped", unanchored_act),
    ("cmp/override-evidence-kept", override_evidence),
    ("cmp/non-counting-receipt-dropped", non_counting_receipt),
)
