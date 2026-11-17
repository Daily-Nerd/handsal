"""Scenario helpers for genesis-change rows: epoch 0 on a `Chain`, a change at one of its
positions, and the `fold` row for the lineage that results (GP-07, GP-15, GP-19).

Epoch 0 is built first, step by step; `at(n)` gives the id and the state of position n (the
H a change names and the S_H it reads). The expected output is the author's statement: the
state of the last lineage document for a valid change, or the code of the first failing step.
"""
import json

from . import chain, epochs, forge, inputs, state

AB, BC, AC = ("alice", "bob"), ("bob", "carol"), ("alice", "carol")


class E0:
    """Epoch 0 of `doc` (default ORG): `steps` are callables `(chain) -> built` applied in order."""

    def __init__(self, ctx, steps=(), doc=None, fx=None):
        """`fx` builds the epoch when it is not the context's own fixtures (a cross-edition row builds epoch 0 under
        the previous edition's profile)."""
        self.ctx, self.fx = ctx, fx or ctx.fixtures
        self.doc = doc or self.fx.org
        self.c = (chain.Chain(self.fx, ctx=ctx) if doc is None
                  else epochs.original_chain(self.fx, doc, ctx=ctx))
        self.ids, self.built = [self.c.root], [None]
        for step in steps:
            built = step(self.c)
            self.ids.append(built.id)
            self.built.append(built)

    @property
    def lineage(self):
        return self.c.lineage

    def at(self, n):
        """(id, state) of position n of the accepted chain: the H of a change and its S_H."""
        return self.ids[n], self.c.history[n]

    def change(self, n, *, carry, new=("frank", "grace"), head=None, st=None, **kwargs):
        """A change at position n carrying `carry` persons' devices (see epochs.make_change)."""
        h, st_h = self.at(n)
        return epochs.make_change(self.fx, self.doc, head or h, carry=carry, new=new,
                                  st=st or st_h, **kwargs)


def add(name, signers=AB, **kw):
    return lambda c: c.device_add(name, signers, **kw)


def remove(name, signers=BC, **kw):
    return lambda c: c.device_remove(name, signers, **kw)


def record_sigs(ctx, sigs, skip=()):
    """Every genesis.sign that verifies goes to the vitni cross-check (skip the junk ones)."""
    for jws in sigs:
        if jws in skip:
            continue
        kid = json.loads(forge.parts(jws)[0])["kid"]
        ctx.positive(jws, chain.GENESIS_SIGN, [ctx.fixtures.name_of_kid(kid)])


def fold_row(ctx, name, lineage, acts, *, error=None, expect=None, pin=None, skip=()):
    """Write the `fold` row: `error` is the expected code, else the state of `expect` (a document)."""
    for entry in lineage[1:]:
        record_sigs(ctx, entry["sigs"], skip)
    anchor = (inputs.error_anchor(error) if error is not None
              else state.anchor(state.State(expect if expect is not None else lineage[-1]["doc"])))
    ctx.writer.add(name, "fold", anchor, input=inputs.fold_input(lineage, acts=list(acts), pin=pin))


def change_row(ctx, name, e0, doc, sigs, *, error=None, acts=None, skip=(), pin=None):
    """`fold_row` for the lineage E0 followed by the change `doc` with `sigs`."""
    lineage = epochs.lineage_with(e0.lineage, doc, sigs)
    fold_row(ctx, name, lineage, e0.c.acts if acts is None else acts, error=error, skip=skip,
             pin=pin)
    return lineage
