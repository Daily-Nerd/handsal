"""Vectors cls/*: key classes, accepted and unproven keys (KC-01 to KC-08, FO-02).

Genesis rows are ORG with one class defect, and the code is the one the class model of
`lib/rules.genesis_classes` gives (GP-15 step 3). The act rows run on ORG, or on PINORG (ORG
plus a member `dave` whose role is listed in no rule, holding a `fixture-pin` device that the
policy lists); `dave` is the only person who can hold a pin-class key (KC-08), so a key that is
not accepted is always dave's second device `dave2` (the pattern of `vtn/*`).

Not written (the spec cannot back a vector):
- `cls/tagged-registry-no-pending` is retired: a property of the registry file at the tag (KC-02),
  proven by `check_catalog.py --final`.
- `cls/pending-class-accepted`, `cls/win-hello-biometric-only-maintainer-ok` and
  `cls/win-hello-pin-capable-maintainer-refused` are retired for the macOS-only first tag: the
  registry has no Windows class, and a tagged registry holds no `pending-spike` class (KC-02).
  The pending-class row was `plus({"class": "win-hello-hw", "user_verification": "biometric_only"})`
  with the code `class_pending`; the Windows tag restores it with the class.

No maintainer can hold a key that the policy does not accept: a genesis lists only accepted
classes (GP-20) and a maintainer's new key must be `biometric_only` (KC-08), which the one
`biometric_only` class of registry version 1 always is. The "does not count" rows therefore use
dave, who has no listed role either (FO-23 item 3); they show that the act is not on the chain,
and they cannot show acceptance as the only defect (section 14, L-registry limit).
"""
from lib import base, chain, checkrows, inputs, rules

PIN = "fixture-pin"
AB = ("alice", "bob")
BIO_PAIR = {"class": "apple-se-bio", "user_verification": "biometric_only"}
PIN_PAIR = {"class": PIN, "user_verification": "biometric_or_pin"}
APPROVE = inputs.APPROVE


def _classes(*pairs):
    def edit(doc):
        doc["policy"]["classes"] = sorted(pairs, key=lambda p: p["class"])
    return edit


def _pin_device(fx, name):
    entry = fx.device_entry(name, PIN)
    entry["label"] = "%s pin" % name
    return entry


def pinorg(fx, *, alice_pin=False):
    """PINORG (spec names): ORG, the policy lists `fixture-pin`, and `dave` (role `member`)
    holds a device of that class; `alice_pin` gives maintainer alice a second one."""
    def edit(doc):
        doc["policy"]["classes"] = [BIO_PAIR, PIN_PAIR]
        doc["members"] = sorted(doc["members"] + [{"id": "dave", "role": "member"}],
                                key=lambda m: m["id"])
        added = [_pin_device(fx, "dave")] + ([_pin_device(fx, "alice-pin")] if alice_pin else [])
        doc["devices"] = sorted(doc["devices"] + added, key=lambda d: d["kid"])
    return inputs.derive(fx.org, edit)


def _lineage(fx, doc):
    """Every listed device signs its document: a device without a counting signature is
    `genesis_unsigned` (GP-15 step 6), so a class row needs every pin device's signature too."""
    return inputs.original_lineage(fx, doc)


def _genesis_row(ctx, name, doc, code):
    """A `fold` row whose original document earns `code`; the class model must agree."""
    if code == "genesis_schema":
        if not base.check_genesis_shape(doc):
            raise AssertionError("%s: the document is schema-valid" % name)
    elif rules.genesis_classes(doc, fixture=True) != code:
        raise AssertionError("%s: the class model says %r, the row says %r"
                             % (name, rules.genesis_classes(doc, fixture=True), code))
    ctx.writer.add(name, "fold", inputs.error_anchor(code),
                   input=inputs.fold_input(_lineage(ctx.fixtures, doc)))


def _alg_member(doc):
    """KC-05: a device entry has no `alg` member, whatever its value."""
    next(d for d in doc["devices"] if d["person"] == "alice")["alg"] = "Ed25519"


def _genesis_rows(ctx):
    fx = ctx.fixtures
    def plus(pair):
        return _classes(BIO_PAIR, pair)

    rows = (
        ("cls/unknown-class-genesis", plus({"class": "yubikey-piv", "user_verification": "biometric_only"}),
         "class_unknown"),
        ("cls/test-class-listed", plus({"class": "test-sw-p256", "user_verification": "none"}),
         "class_test_only"),
        ("cls/uv-mismatch", _classes({"class": "apple-se-bio", "user_verification": "biometric_or_pin"}),
         "class_policy_mismatch"),
        ("cls/ed25519-device", _alg_member, "genesis_schema"),
    )
    for name, edit, code in rows:
        _genesis_row(ctx, name, inputs.derive(fx.org, edit), code)
    _genesis_row(ctx, "cls/role-holder-pin-genesis-refused", pinorg(fx, alice_pin=True),
                 "role_key_class")


def _on(ctx, doc, build):
    """A chain over `doc` (an original) after `build(chain)`."""
    c = chain.Chain(ctx.fixtures, ctx=ctx, doc=doc, lineage=_lineage(ctx.fixtures, doc))
    build(c)
    return c


def _dave(c, cls=PIN):
    """dave (role `member`) joins with an accepted device and a second one of class `cls`."""
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("alice", "dave", "bob"), cls=cls)


def _fold_rows(ctx, doc, rows):
    for name, build in rows:
        c = _on(ctx, doc, build)
        ctx.writer.add(name, "fold", c.expect(), input=c.fold_input())


def _dave_then(act):
    def build(c):
        _dave(c)
        act(c)
    return build


def _act_rows(ctx):
    fx = ctx.fixtures
    org = fx.org
    _fold_rows(ctx, org, (
        ("cls/unknown-class-device-add",
         lambda c: c.device_add("alice2", AB, cls="yubikey-piv", ok=False)),
        ("cls/role-holder-unaccepted-pin-class-not-on-chain",
         lambda c: c.device_add("alice-pin", AB, cls=PIN, ok=False)),
        ("cls/unproven-endorsement-ignored",
         _dave_then(lambda c: c.device_add("bob2", ("bob", "dave2"), ok=False))),
        ("cls/unproven-self-remove-ignored",
         _dave_then(lambda c: c.device_remove("dave2", ("dave2", "alice"), ok=False))),
        ("cls/unproven-vote-not-counted",
         _dave_then(lambda c: c.member_add("frank", ("alice", "dave2"), role="maintainer", ok=False))),
    ))
    _fold_rows(ctx, pinorg(fx), (
        ("cls/pin-key-never-counts", lambda c: c.device_add("X1", ("alice", "dave"), ok=False)),
        ("cls/role-holder-pin-device-add-not-on-chain",
         lambda c: c.device_add("alice-pin", AB, cls=PIN, ok=False)),
        ("cls/role-holder-pin-member-add-not-on-chain",
         lambda c: c.member_add("frank-pin", AB, role="maintainer", cls=PIN, ok=False)),
        ("cls/role-holder-biometric-member-add-ok",
         lambda c: c.member_add("frank", AB, role="maintainer")),
    ))
    c = _on(ctx, pinorg(fx), lambda c: None)
    ctx.writer.add("cls/nonrole-pin-device-ok", "fold", c.expect(), input=c.fold_input())


def _verdict_rows(ctx):
    fx = ctx.fixtures
    c = _on(ctx, fx.org, _dave)
    jws = fx.verdict("approve", "dave2", recipient="dave")
    checkrows.row(ctx, "cls/verdict-unproven", jws, "unproven_class", cls=PIN, method=APPROVE,
                  signers=["dave2"], acts=c.acts, recipient="dave")

    c = _on(ctx, fx.org, lambda c: _dave(c, cls="test-sw-p256"))
    jws = fx.verdict("approve", "dave2", recipient="dave")
    checkrows.row(ctx, "cls/test-class-key-unproven", jws, "unproven_class", cls="test-sw-p256",
                  signers=["dave2"], acts=c.acts, recipient="dave")

    # the same acts under a policy that lists the class: the key is accepted (KC-04)
    doc = inputs.derive(fx.org, _classes(BIO_PAIR, PIN_PAIR))
    lineage = _lineage(fx, doc)
    c = _on(ctx, doc, _dave)
    org_id = inputs.doc_id(doc)
    jws = fx.verdict("approve", "dave2", recipient="dave", org=org_id)
    checkrows.row(ctx, "cls/policy-swap-human", jws, "ok", cls=PIN, signers=["dave2"],
                  acts=c.acts, recipient="dave", lineage=lineage, org=org_id,
                  pin=inputs.probe_for(lineage))

    # vitni alone, given the fold `keys`, says ok for an act the checker refuses (FO-02)
    checkrows.row(ctx, "cls/vitni-ok-not-approval", fx.approve(), "stale_view", signers=["alice"],
                  synced_at=base.shift(base.NOW, -86401))


def _vitni_direct_row(ctx):
    """FO-02: the fold `keys` of this state hold no kid of `dave2`, so vitni alone answers
    `unknown_key` for dave2's verdict; both vitni binaries must say so at generation time. The
    state is the one of `fld/unaccepted-not-in-keys`, so this is a check and no vector."""
    fx = ctx.fixtures
    c = _on(ctx, fx.org, _dave)
    names = ("alice", "bob", "carol", "dave")
    if fx.keyset(names) != c.state.keys():
        raise AssertionError("the vitni key map is not the fold keys of the state")
    ctx.negative(fx.verdict("approve", "dave2", recipient="dave"), APPROVE, names, "unknown_key")


def generate(ctx):
    _genesis_rows(ctx)
    _act_rows(ctx)
    _verdict_rows(ctx)
    _vitni_direct_row(ctx)

