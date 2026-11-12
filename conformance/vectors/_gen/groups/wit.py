"""Vectors wit/*: the witness policy, the tip statement and the relay check (WT-01 to WT-10).

Fixtures: WIT_ORG (ORG with a relay witness, max tip age 3600 s), the WIT bag of four
chain positions T1 to T4 on it (alice2 added, bob2 added, carol removed, alice3 added,
each by alice and bob), and TIP_OK, the statement by RELAY_FX for tip T4 at NOW minus
60 s with `next` `"no"` (lib/base.py `tip_statement`). A `check-act` row is an approve
by alice whose other steps pass, with the stated `tip_statement`, so the witness step is
the first failure. `class` follows VR-01: alice's class from step 7 on.

Positive statements go to the vitni cross-check under the one-entry relay key map
(WT-05 step 4); a statement the checker refuses for its signature records vitni's own
verdict.

Not written here: the change rows (groups/wit_change.py). `wit/pol-tip-age-bounds-ok` is the
`"60"` case and `wit/pol-tip-age-upper-bound-ok` the `"86400"` case; `wit/next-hashstr-malformed`
is the hashstr case of `next` and `wit/next-other-string-malformed` the string `"true"`.
The two genesis render rows are `render` rows over ORG and over the none-to-relay change.
"""
from lib import base, chain, epochs, forge, inputs, keys, renderrows, result, scenes, state

AB = ("alice", "bob")
APPROVE = inputs.APPROVE
NOW = base.NOW
PIN_CLASS = "fixture-pin"
OK, UNSET = "ok", inputs.UNSET


class Bag:
    """The WIT bag: T1 to T4 on WIT_ORG, and the ids of the positions."""

    def __init__(self, ctx, extra=0):
        self.chain = c = chain.Chain(ctx.fixtures, wit=True, ctx=ctx)
        built = [c.device_add("alice2", AB), c.device_add("bob2", AB),
                 c.device_remove("carol", AB), c.device_add("alice3", AB)]
        self.ids = [b.id for b in built]
        self.acts = list(c.acts)
        self.t = {n + 1: i for n, i in enumerate(self.ids)}
        self.extra = [c.device_add("bob3", AB) for _ in range(extra)]


def _check(ctx, name, jws, reason, *, stmt, acts=(), wit=True, cls=UNSET, **override):
    fx = ctx.fixtures
    ctx.writer.add(name, "check-act", inputs.check_anchor(jws, reason, cls),
                   input=inputs.check_input(fx, jws, wit=wit, acts=list(acts),
                                            tip_statement=stmt, **override))


def _approve(ctx, **kwargs):
    jws = ctx.fixtures.approve(wit=kwargs.pop("wit", True), **kwargs)
    ctx.positive(jws, APPROVE, ["alice"])
    return jws


def _statement_rows(ctx):
    fx = ctx.fixtures
    bag = Bag(ctx)
    jws = _approve(ctx)

    def stmt(name, reason, positive=True, **kwargs):
        kwargs.setdefault("tip", bag.t[4])
        statement = fx.tip_statement(**kwargs)
        if positive:
            ctx.positive_statement(statement)
        _check(ctx, name, jws, reason, stmt=statement, acts=bag.acts)
        return statement

    stmt("wit/valid-tip-ok", OK)
    stmt("wit/tip-older-than-consumer-tip-ok", OK, tip=bag.t[2])
    stmt("wit/tip-age-exactly-max-ok", OK, ts=base.shift(NOW, -3600))
    stmt("wit/stale-tip", "stale_witness", ts=base.shift(NOW, -3601))
    stmt("wit/future-within-skew-ok", OK, ts=base.shift(NOW, 300))
    stmt("wit/future-tip", "witness_in_future", ts=base.shift(NOW, 301))
    stmt("wit/wrong-org", "witness_org_mismatch", org=fx.org_id)
    other_epoch = inputs.doc_id(inputs.change_doc(fx, fx.wit_org))
    stmt("wit/wrong-epoch-newer", "witness_epoch_mismatch", epoch=other_epoch)
    stmt("wit/tip-junk", "behind_witness", tip=base.hashstr(b"tip junk"))
    stmt("wit/next-no-latest-epoch-ok", OK, tip=bag.t[3], next_="no")
    stmt("wit/superseded-epoch-refused", "witness_superseded", next_="yes")
    stmt("wit/order-superseded-before-stale", "witness_superseded", next_="yes",
         ts=base.shift(NOW, -3601))
    stmt("wit/ord-stale-before-behind", "stale_witness", tip=base.hashstr(b"unknown tip"),
         ts=base.shift(NOW, -3601))

    # the root is a position: no primaries in the bag, the statement names the root
    statement = fx.tip_statement(tip=fx.wit_org_id)
    ctx.positive_statement(statement)
    _check(ctx, "wit/tip-root-position-ok", jws, OK, stmt=statement)

    # a tip the consumer lacks: T5 exists, the consumer's bag ends at T4
    beyond = Bag(ctx, extra=1)
    statement = fx.tip_statement(tip=beyond.extra[0].id)
    ctx.positive_statement(statement)
    _check(ctx, "wit/behind-tip", jws, "behind_witness", stmt=statement, acts=beyond.acts)

    # a losing candidate of a current resolve is not a position of the accepted chain
    scene = scenes.losing_branch(fx, wit=True, ctx=ctx)
    statement = fx.tip_statement(tip=scene.lost.id)
    ctx.positive_statement(statement)
    _check(ctx, "wit/tip-other-branch", jws, "behind_witness", stmt=statement, acts=scene.bag)

    # signature rows: the checker's own answer is `witness_bad_signature`
    bob = fx.key("bob")
    bad = fx.tip_statement(key=bob, header_kid=fx.relay.kid)
    ctx.negative_statement(bad, "bad_signature")
    _check(ctx, "wit/wrong-key-signature", jws, "witness_bad_signature", stmt=bad, acts=bag.acts)
    high = fx.tip_statement(tip=bag.t[4], high_s=True)
    ctx.negative_statement(high, "ok")
    _check(ctx, "wit/statement-high-s", jws, "witness_bad_signature", stmt=high, acts=bag.acts)
    both = fx.tip_statement(key=bob, header_kid=fx.relay.kid, org=fx.org_id)
    ctx.negative_statement(both, "bad_signature")
    _check(ctx, "wit/ord-signature-before-content", jws, "witness_bad_signature", stmt=both,
           acts=bag.acts)

    # the header kid is read first (step 3): a wrong kid wins over a bad signature
    alice = fx.key("alice")
    _check(ctx, "wit/wrong-key-kid", jws, "witness_key_mismatch",
           stmt=fx.tip_statement(key=alice, tip=bag.t[4]), acts=bag.acts)
    _check(ctx, "wit/ord-key-before-signature", jws, "witness_key_mismatch",
           stmt=fx.tip_statement(key=bob, header_kid=alice.kid, tip=bag.t[4]), acts=bag.acts)

    # structure (WT-02): the first violation is `witness_malformed`
    def malformed(name, **kwargs):
        kwargs.setdefault("tip", bag.t[4])
        _check(ctx, name, jws, "witness_malformed", stmt=fx.tip_statement(**kwargs),
               acts=bag.acts)

    good = fx.tip_statement(tip=bag.t[4])
    _check(ctx, "wit/malformed-jws", jws, "witness_malformed",
           stmt=".".join(good.split(".")[:2]), acts=bag.acts)
    malformed("wit/malformed-head-present", act_edit=lambda a: a.__setitem__(
        "head", {"id": fx.wit_org_id, "kind": "chain"}))
    malformed("wit/malformed-body-extra-key", act_edit=lambda a: a["body"].__setitem__(
        "time", NOW))
    malformed("wit/malformed-method", method=APPROVE)
    malformed("wit/malformed-performer", performer="alice")
    malformed("wit/next-missing-malformed", act_edit=lambda a: a["body"].pop("next"))
    malformed("wit/next-boolean-not-canonical-malformed",
              raw_edit=lambda raw: raw.replace(b'"next":"no"', b'"next":false'))
    malformed("wit/next-other-string-malformed", next_="true")
    malformed("wit/next-hashstr-malformed", next_=base.hashstr(b"next is not a tip"))

    # mode none: any statement is refused unparsed; null is the ordinary path
    plain = _approve(ctx, wit=False)
    for name, supplied in (("wit/mode-none-statement-supplied", good),
                           ("wit/mode-none-garbage-statement", "x")):
        ctx.writer.add(name, "check-act", inputs.check_anchor(plain, "witness_unexpected"),
                       input=inputs.check_input(fx, plain, tip_statement=supplied))
    ctx.writer.add("wit/mode-none-null-ok", "check-act", inputs.check_anchor(plain, OK),
                   input=inputs.check_input(fx, plain))

    # mode relay without a statement, and the input contract (WT-03)
    _check(ctx, "wit/mode-relay-no-statement", jws, "witness_missing", stmt=None, acts=bag.acts)
    ctx.writer.add("wit/statement-key-absent", "check-act", inputs.error_anchor("malformed_input"),
                   input=inputs.check_input(fx, jws, wit=True, acts=bag.acts,
                                            tip_statement=inputs.DROP))
    ctx.writer.add("wit/statement-wrong-type", "check-act", inputs.error_anchor("malformed_input"),
                   input=inputs.check_input(fx, jws, wit=True, acts=bag.acts, tip_statement=[]))

    # a statement is not an act (WT-02), and VR-02 steps 1 to 13 run unchanged (WT-06)
    _check(ctx, "wit/statement-as-act", good, "method_unknown", stmt=good, acts=bag.acts)
    ctx.positive_statement(good)
    _never_validates(ctx, bag, good)

    # the earlier VR-02 steps win over the witness (WT-07, CF-07)
    ts = base.shift(NOW, -7200)
    expired = _approve(ctx, ts=ts, expires=base.shift(NOW, -60))
    _check(ctx, "wit/ord-time-before-witness", expired, "expired", stmt=None, acts=bag.acts)
    stale_view = base.shift(NOW, -86401)
    _check(ctx, "wit/ord-view-before-witness", jws, "stale_view", stmt=None, acts=bag.acts,
           synced_at=stale_view)
    _check(ctx, "wit/synced-at-still-checked", jws, "stale_view", stmt=good, acts=bag.acts,
           synced_at=stale_view)
    stale = fx.tip_statement(tip=bag.t[4], ts=base.shift(NOW, -3601))
    ctx.positive_statement(stale)
    _check(ctx, "wit/ord-witness-before-duplicate", jws, "stale_witness", stmt=stale,
           acts=bag.acts, seen=[inputs.receipt_id(jws)])

    # no relay head kind (WT-09)
    relay_head = forge.resign(fx, jws, forge.act_edit(lambda a: a["head"].__setitem__(
        "kind", "relay")))
    _check(ctx, "wit/head-kind-relay-schema", relay_head, "schema", stmt=good, acts=bag.acts)


def _never_validates(ctx, bag, statement):
    """TIP_OK never lifts an act that fails a rule before step 14 (WT-06)."""
    fx = ctx.fixtures
    revoked = fx.verdict("approve", "carol", recipient="carol", wit=True)
    ctx.negative(revoked, APPROVE, ["carol"], "revoked_key", revoked=["carol"])
    _check(ctx, "wit/never-validates-revoked", revoked, "revoked_key", stmt=statement,
           acts=bag.acts, recipient="carol")
    head, payload, sig = forge.parts(_approve(ctx))
    flipped = forge.join(head, payload, sig[:32] + bytes([sig[32] ^ 1]) + sig[33:])
    ctx.negative(flipped, APPROVE, ["alice"], "bad_signature")
    _check(ctx, "wit/never-validates-bad-sig", flipped, "bad_signature", stmt=statement,
           acts=bag.acts)

    c = chain.Chain(fx, wit=True, ctx=ctx)
    c.device_add("alice2", AB)
    c.device_add("bob2", AB)
    c.device_remove("carol", AB)
    c.device_add("alice3", AB)
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=PIN_CLASS)
    unproven = fx.verdict("approve", "dave2", recipient="dave", wit=True)
    ctx.positive(unproven, APPROVE, ["dave2"])
    _check(ctx, "wit/never-validates-unproven", unproven, "unproven_class", stmt=statement,
           acts=c.acts, cls=PIN_CLASS, recipient="dave")


def _enrolled_rows(ctx):
    fx = ctx.fixtures
    bag = Bag(ctx)
    good = fx.tip_statement(tip=bag.t[4])
    ctx.positive_statement(good)
    stale = fx.tip_statement(tip=bag.t[4], ts=base.shift(NOW, -3601))
    ctx.positive_statement(stale)
    for name, reason, kwargs in (
            ("wit/enr-relay-ok", "fixture_profile", {"tip_statement": good}),
            ("wit/enr-relay-missing", "witness_missing", {"tip_statement": None}),
            ("wit/enr-relay-stale", "stale_witness", {"tip_statement": stale})):
        ctx.writer.add(name, "enrolled", inputs.enrolled_anchor(False, reason),
                       input=inputs.enrolled_input(fx, wit=True, acts=bag.acts, **kwargs))
    ctx.writer.add("wit/enr-mode-none-supplied", "enrolled",
                   inputs.enrolled_anchor(False, "witness_unexpected"),
                   input=inputs.enrolled_input(fx, tip_statement=good))


def _witness(fx, edit):
    """WIT_ORG with `edit(witness, document)` applied, as an original lineage."""
    doc = inputs.derive(fx.wit_org, lambda d: edit(d["policy"]["witness"], d))
    return doc


def _point_of(fx, name, use):
    k = fx.key(name, use)
    return {"crv": "P-256", "kty": "EC", "x": k.x, "y": k.y}


def _policy_rows(ctx):
    fx, w = ctx.fixtures, ctx.writer

    def fold_error(name, doc, code):
        w.add(name, "fold", inputs.error_anchor(code),
              input=inputs.fold_input(inputs.original_lineage(fx, doc)))

    def swap_key(jwk):
        return lambda witness, _doc: witness.update(
            relay_pub_jwk=dict(jwk), relay_kid=keys.thumbprint(jwk["x"], jwk["y"]))

    fold_error("wit/pol-missing-witness",
               inputs.derive(fx.org, lambda d: d["policy"].pop("witness")), "policy_invalid")
    fold_error("wit/pol-mode-unknown",
               inputs.derive(fx.org, lambda d: d["policy"].__setitem__("witness", {"mode": "log"})),
               "policy_invalid")
    fold_error("wit/pol-none-extra-key",
               inputs.derive(fx.org, lambda d: d["policy"].__setitem__(
                   "witness", {"mode": "none", "relay_kid": fx.relay.kid})), "policy_invalid")
    fold_error("wit/pol-relay-missing-jwk", _witness(fx, lambda wi, d: wi.pop("relay_pub_jwk")),
               "policy_invalid")
    fold_error("wit/pol-kid-not-thumbprint",
               _witness(fx, lambda wi, d: wi.__setitem__("relay_kid", fx.key("alice").kid)),
               "policy_invalid")
    off = (fx.relay.y_int + 1).to_bytes(32, "big")
    fold_error("wit/pol-jwk-not-on-curve",
               _witness(fx, swap_key({"crv": "P-256", "kty": "EC", "x": fx.relay.x,
                                      "y": keys.b64u(off)})), "policy_invalid")
    fold_error("wit/pol-jwk-extra-member",
               _witness(fx, lambda wi, d: wi["relay_pub_jwk"].__setitem__("alg", "ES256")),
               "policy_invalid")
    fold_error("wit/pol-tip-age-59",
               _witness(fx, lambda wi, d: wi.__setitem__("max_tip_age_s", "59")),
               "policy_out_of_bounds")
    fold_error("wit/pol-tip-age-86401",
               _witness(fx, lambda wi, d: wi.__setitem__("max_tip_age_s", "86401")),
               "policy_out_of_bounds")
    for name, age in (("wit/pol-tip-age-bounds-ok", "60"),
                      ("wit/pol-tip-age-upper-bound-ok", "86400")):
        doc = _witness(fx, lambda wi, d, age=age: wi.__setitem__("max_tip_age_s", age))
        lineage = inputs.original_lineage(fx, doc)
        for jws in lineage[0]["sigs"]:
            renderrows.pos(ctx, jws)
        w.add(name, "fold", state.anchor(state.State(doc)), input=inputs.fold_input(lineage))
    fold_error("wit/pol-relay-key-is-device-key",
               _witness(fx, swap_key(_point_of(fx, "alice", "sign"))), "policy_invalid")
    fold_error("wit/pol-relay-key-is-agree-key",
               _witness(fx, swap_key(_point_of(fx, "bob", "agree"))), "policy_invalid")

    # the relay key is already present in the fold, so a device.add naming it is not on the chain
    c = chain.Chain(fx, wit=True, ctx=ctx)

    def as_relay(body):
        body["sign"] = {"x": fx.relay.x, "y": fx.relay.y}
        body["kid"] = fx.relay.kid
    c.device_add("alice2", AB, ok=False, body_edit=as_relay)
    w.add("wit/device-add-relay-key-ignored", "fold", c.expect(), input=c.fold_input())

    lineage = fx.lineage(wit=True)
    w.add("wit/relay-ok-original", "fold", state.anchor(state.State(fx.wit_org)),
          input=inputs.fold_input(lineage))
    pin = inputs.pin_line(fx.wit_org_id, fx.wit_org_id, fx.profile).decode("ascii")
    w.add("wit/genesis-check-relay-ok", "genesis-check",
          result.line({"pin": pin, "reason": "ok", "valid": True}),
          input={"acts": [], "lineage": lineage})


def _bag_row(ctx):
    fx = ctx.fixtures
    bag = Bag(ctx)
    statement = fx.tip_statement(tip=bag.t[4])
    ctx.positive_statement(statement)
    ctx.writer.add("wit/statement-in-bag-ignored", "fold", bag.chain.expect(),
                   input=bag.chain.fold_input(extra_acts=[statement]))


def _render_rows(ctx):
    """RN-04 policy lines: `Witness: none` over ORG, the relay lines over the change to relay."""
    fx = ctx.fixtures
    renderrows.genesis_row(ctx, "wit/render-genesis-witness-none", fx.org, {"document": fx.org})
    relay = fx.wit_org["policy"]["witness"]
    change = epochs.make_change(
        fx, fx.org, fx.org_id, carry=("alice", "bob", "carol"), new=(),
        edit=lambda d: d["policy"].__setitem__("witness", relay))
    renderrows.genesis_row(ctx, "wit/render-genesis-witness-relay", change,
                           {"document": change, "previous": fx.org})


def generate(ctx):
    _render_rows(ctx)
    _statement_rows(ctx)
    _enrolled_rows(ctx)
    _policy_rows(ctx)
    _bag_row(ctx)
