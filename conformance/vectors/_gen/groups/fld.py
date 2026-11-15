"""Vectors fld/*: the fold over a bag of acts (FO-01 to FO-06, FO-16, FO-21, ACT-14).

Each row is a bag and the state the spec gives it, authored with lib/state.py.
Valid acts are applied with `chain.Chain`; an act that must not be on the chain is
built with `ok=False`, so it sits in the bag and the state does not move (FO-06).

Not written: fld/epochs-in-one-bag (needs a change document, see groups/chg_*.py).
fld/cycle and fld/verifier-unavailable left the catalog (CF-07): no vector input sets them up.
Each `at` of FO-16 S1 is its own id over one chain of four: fld/at-0-state, fld/at-1-state,
fld/at-prefix-states (2), fld/at-3-state and fld/at-4-state.
"""
import hashlib

from lib import base, chain, forge, inputs, state

PAIR = ("alice", "bob")


def _ghost(act_id, performer="alice"):
    """A parent that is not in the bag, with the given id and performer."""
    return base.DeviceAdd([], act_id, None, performer, "ghost")


def _bad_signature(jws):
    head, payload, _sig = forge.parts(jws)
    return forge.join(head, payload, b"\x01" * 64)


def _add(w, name, c, **kw):
    w.add(name, "fold", kw.pop("anchor", None) or c.expect(), input=c.fold_input(**kw))


def _dave(ctx):
    c = chain.Chain(ctx.fixtures, ctx=ctx)
    c.member_add("dave", PAIR, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")
    return c


def _four(ctx):
    c = chain.Chain(ctx.fixtures, ctx=ctx)
    c.device_add("alice2", ("alice", "bob"))
    c.device_add("bob2", ("bob", "carol"))
    return c


def _fork_at_two(ctx):
    """Two valid children (carol2, alice3) of node 2 of a chain of two."""
    c = _four(ctx)
    c1 = c.device_add("carol2", ("carol", "alice"), ok=False, valid=True)
    c2 = c.device_add("alice3", ("alice", "bob"), ok=False, valid=True)
    return c, state.fork_anchor(c.tip.id, [c1.id, c2.id])


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer

    def new():
        return chain.Chain(fx, ctx=ctx)

    c = new()
    c.device_add("alice2", PAIR, ok=False, body_edit=lambda b: b.__setitem__("agree", dict(b["sign"])))
    _add(w, "fld/agree-equals-sign", c)

    c = new()
    _add(w, "fld/agree-not-in-keys", c)
    _add(w, "fld/empty-bag-tip-0", c)

    c = new()
    c.device_add("alice2", PAIR, ok=False, parent=_ghost(base.hashstr(b"no such act")))
    _add(w, "fld/dangling-parent", c)

    c = new()
    c.device_add("alice2", PAIR)
    _add(w, "fld/duplicate-act-twice", c, extra_acts=list(c.acts))

    c = new()
    built = c.device_add("alice2", PAIR, ok=False)
    c.edit_act(built, 0, _bad_signature(built.acts[0]))
    _add(w, "fld/forged-sig-ignored", c)

    c = new()
    built = c.device_add("alice2", PAIR)
    c.acts.insert(0, _bad_signature(built.acts[0]))
    _add(w, "fld/garbage-twin-does-not-shadow", c)

    c = new()
    built = c.device_add("alice2", PAIR, ok=False)
    c.edit_act(built, 0, _bad_signature(built.acts[0]))
    _add(w, "fld/garbage-twin-only", c)

    # FO-15: a verdict and a decision are never on the chain
    c = new()
    c.device_add("alice2", PAIR)
    verdict, decision = fx.approve(), fx.decision()
    ctx.positive(verdict, inputs.APPROVE, ["alice"])
    ctx.positive(decision, inputs.DECISION, ["alice"])
    _add(w, "fld/non-chain-acts-ignored", c, extra_acts=[verdict, decision])

    # FO-15, VR-18: a decision is never on the chain either
    c = new()
    c.device_add("alice2", PAIR)
    decision = fx.decision()
    ctx.positive(decision, inputs.DECISION, ["alice"])
    _add(w, "fld/decision-ignored", c, extra_acts=[decision])

    c = new()
    c.device_add("alice2", PAIR)
    junk = [hashlib.sha256(b"junk-%d" % i).hexdigest() for i in range(100)]
    _add(w, "fld/junk-appended", c, extra_acts=junk)

    c = new()
    first = c.device_add("alice2", PAIR)
    wrong = _ghost(base.hashstr(first.acts[0].encode("ascii")))  # hashed the JWS, not the payload
    c.device_add("bob2", ("bob", "carol"), ok=False, parent=wrong)
    _add(w, "fld/link-mismatch", c)

    one = fx.device_add("alice2", PAIR, org=fx.org_id)
    two = fx.device_add("bob2", ("bob", "carol"), parent=one, org=fx.org_id)
    c = new()
    c.acts.extend(two.acts)
    _add(w, "fld/orphan-ignored", c)

    for name, performer in (("fld/parent-performer-mismatch", "bob"),
                            ("fld/parent-performer-null-non-root", None)):
        c = new()
        first = c.device_add("alice2", PAIR)
        c.device_add("bob2", ("bob", "carol"), ok=False, parent=first._replace(performer=performer))
        _add(w, name, c)

    c = new()
    c.device_add("alice2", PAIR, ok=False,
                 primary_edit=lambda p: p.__setitem__("parent_receipt_hash", None))
    _add(w, "fld/primary-parent-null", c)

    c = new()
    c.device_add("alice2", PAIR, ok=False,
                 primary_edit=lambda p: p.__setitem__("parent_performer_id", "alice"))
    _add(w, "fld/root-child-parent-performer-set", c)

    c = new()
    c.device_remove("carol", PAIR)
    _add(w, "fld/removed-stays-revoked", c)

    c = new()
    built = c.device_add("bob2", ("bob", "carol"), ok=False)
    c.edit_act(built, 1, forge.resign(fx, built.acts[1], signer="alice"))
    _add(w, "fld/same-payload-other-key-not-counted", c)

    c = _four(ctx)
    c.acts.reverse()  # the bag is unordered (FO-01): this order does not follow the chain
    _add(w, "fld/shuffle-same-output", c)

    c = _dave(ctx)
    _add(w, "fld/unaccepted-not-in-keys", c)

    c = new()
    c.device_add("alice2", PAIR)
    _add(w, "fld/at-beyond-tip", c, anchor=inputs.error_anchor("at_beyond_tip"), at=9)

    c = new()
    for name, signers in (("alice2", PAIR), ("bob2", ("bob", "carol")),
                          ("carol2", ("carol", "alice")), ("alice3", PAIR)):
        c.device_add(name, signers)
    for at, name in ((0, "fld/at-0-state"), (1, "fld/at-1-state"), (2, "fld/at-prefix-states"),
                     (3, "fld/at-3-state"), (4, "fld/at-4-state")):
        _add(w, name, c, anchor=c.expect(at=at), at=at)

    c, fork = _fork_at_two(ctx)
    _add(w, "fld/at-fork-parent-state", c, anchor=c.expect(at=2), at=2)
    _add(w, "fld/at-beyond-fork-parent", c, anchor=fork, at=3)

    c = new()
    c1 = c.device_add("alice2", PAIR, ok=False, valid=True, parent=None)
    c2 = c.device_add("carol2", ("carol", "bob"), ok=False, valid=True, parent=None)
    _add(w, "fld/fork-error-no-keys", c, anchor=state.fork_anchor(fx.org_id, [c1.id, c2.id]))
