"""Vectors sch/*: envelope, act object and field formats (ACT-01, ACT-06 to ACT-08, ACT-13, ACT-14).

Each `check-act` row is a real act with ONE edit, signed again, so the earlier
steps of VR-02 pass and `schema` is the first failure (step 3 for the envelope,
step 5 for the act object). `receipt_id` is the payload id and `class` is null
(see lib/inputs.py). The decimal rows and the two `genesis.sign` head rows are
`fold` rows: their expectation is a fold error, which needs no state anchor.

The fold-state rows are sch/chain-primary-with-head and sch/endorse-missing-head: an
act with that one schema defect is not on the chain, so the state is the genesis
state. Not written here: sch/resolve-with-head (it needs a fork, see groups/rsv.py).
"""
from lib import base, chain, forge, inputs

_HEAD_DEFECTS = {
    "bad-char": lambda h: h[:5] + "+" + h[6:],
    "no-u": lambda h: "A" + h[1:],
    "short": lambda h: h[:-1],
    "trailing-bits": lambda h: "u" + forge.flip_spare_bits(h[1:]),
    "wrong-code": lambda h: "u" + base._b64u(b"\x13\x20" + base._unb64u(h[1:])[2:]),
}


def _set(key, value):
    return lambda p: p.__setitem__(key, value)


def _drop(key):
    return lambda p: p.pop(key)


def _act(edit):
    return forge.act_edit(edit)


def _hashstr_row(defect):
    return lambda p: p.__setitem__("inputs_hash", _HEAD_DEFECTS[defect](p["inputs_hash"]))


def _ts(text):
    return _set("ts", text)


def _check_act_rows(fx):
    bob = fx.key("bob").kid
    return (
        ("sch/act-extra-key", _act(lambda a: a.__setitem__("x", "y"))),
        ("sch/act-kid-differs-from-header", _act(lambda a: a.__setitem__("kid", bob))),
        ("sch/act-kid-missing", _act(lambda a: a.pop("kid"))),
        ("sch/act-missing-body", _act(lambda a: a.pop("body"))),
        ("sch/act-missing-head", _act(lambda a: a.pop("head"))),
        ("sch/act-missing-org", _act(lambda a: a.pop("org"))),
        ("sch/act-object-extra-key-after-method", _act(lambda a: a.__setitem__("seq", "1"))),
        ("sch/binding-mcp", _set("binding", "mcp")),
        ("sch/cost-nonzero", lambda p: p["cost"].__setitem__("usd_micros", "5")),
        ("sch/ext-extra-key", lambda p: p["ext"].__setitem__("x.other", {})),
        ("sch/ext-missing", _drop("ext")),
        ("sch/extra-top-key", _set("seq", "1")),
        ("sch/hashstr-bad-char", _hashstr_row("bad-char")),
        ("sch/hashstr-no-u", _hashstr_row("no-u")),
        ("sch/hashstr-short", _hashstr_row("short")),
        ("sch/hashstr-trailing-bits", _hashstr_row("trailing-bits")),
        ("sch/hashstr-wrong-code", _hashstr_row("wrong-code")),
        ("sch/head-has-n", _act(lambda a: a["head"].__setitem__("n", "3"))),
        ("sch/head-kind-unknown", _act(lambda a: a["head"].__setitem__("kind", "merkle"))),
        ("sch/missing-top-key", _drop("log_policy")),
        ("sch/nonce-not-hashstr", _set("nonce", "not-a-hashstr")),
        ("sch/parent-performer-absent", _drop("parent_performer_id")),
        ("sch/performer-empty", _set("performer_id", "")),
        ("sch/performer-too-long", _set("performer_id", "a" * 33)),
        ("sch/performer-uppercase", _set("performer_id", "Alice")),
        ("sch/status-not-ok", _set("status", "FAILED")),
        ("sch/ts-feb30", _ts("2026-02-30T12:00:00Z")),
        ("sch/ts-fraction", _ts("2026-11-08T11:59:00.5Z")),
        ("sch/ts-leap-second", _ts("2026-11-08T11:59:60Z")),
        ("sch/ts-lowercase-t", _ts("2026-11-08t11:59:00Z")),
        ("sch/ts-no-z", _ts("2026-11-08T11:59:00")),
        ("sch/ts-offset", _ts("2026-11-08T11:59:00+00:00")),
        ("sch/verdict-parent-nonnull", _set("parent_receipt_hash", fx.org_id)),
        ("sch/verdict-parent-performer-nonnull", _set("parent_performer_id", "alice")),
    )


DECIMALS = (
    ("sch/decimal-11-digits", "12345678901"),
    ("sch/decimal-empty", ""),
    ("sch/decimal-exponent", "1e3"),
    ("sch/decimal-leading-zero", "02"),
    ("sch/decimal-negative", "-1"),
)


def _sign_without_head(fx, jws):
    return forge.resign(fx, jws, _act(lambda a: a.pop("head")))


def _sign_with_head(fx, jws):
    return forge.resign(fx, jws, _act(
        lambda a: a.__setitem__("head", {"id": fx.org_id, "kind": "chain"})))


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    valid = fx.approve()
    for name, edit in _check_act_rows(fx):
        jws = forge.resign(fx, valid, edit)
        w.add(name, "check-act", inputs.check_anchor(jws, "schema"),
              input=inputs.check_input(fx, jws))
    # decision: parent_receipt_hash must be null (ACT-13)
    jws = forge.resign(fx, fx.decision(), _set("parent_receipt_hash", fx.org_id))
    w.add("sch/decision-parent-nonnull", "check-act", inputs.check_anchor(jws, "schema"),
          input=inputs.check_input(fx, jws, method=inputs.DECISION))

    for name, text in DECIMALS:
        doc = inputs.derive(
            fx.org, lambda d, text=text: d["policy"]["rules"]["device.remove"].__setitem__(
                "persons", text))
        w.add(name, "fold", inputs.error_anchor("policy_invalid"),
              input=inputs.fold_input(inputs.original_lineage(fx, doc)))

    # a genesis.sign over a change without head, and over an original with head, does not count
    change = inputs.change_doc(fx)
    original = inputs.original_lineage(fx, fx.org)[0]
    sigs = [fx.genesis_sign(n, change) for n in ("alice", "bob", "carol")]
    sigs[0] = _sign_without_head(fx, sigs[0])
    w.add("sch/genesis-sign-change-without-head", "fold", inputs.error_anchor("genesis_unsigned"),
          input=inputs.fold_input([original, {"doc": change, "sigs": sigs}]))
    sigs = list(original["sigs"])
    sigs[0] = _sign_with_head(fx, sigs[0])
    w.add("sch/genesis-sign-original-with-head", "fold", inputs.error_anchor("genesis_unsigned"),
          input=inputs.fold_input([{"doc": fx.org, "sigs": sigs}]))

    # a chain primary must not carry `head` (ACT-08); a counted endorsement must (FO-08)
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", ("alice", "bob"), ok=False,
                 primary_head={"id": fx.org_id, "kind": "chain"})
    w.add("sch/chain-primary-with-head", "fold", c.expect(), input=c.fold_input())
    c = chain.Chain(fx, ctx=ctx)
    c.device_add("alice2", ("alice", "bob"), ok=False, endorse_head=False)
    w.add("sch/endorse-missing-head", "fold", c.expect(), input=c.fold_input())
