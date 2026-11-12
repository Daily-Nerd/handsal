"""Vectors gen/*: genesis documents and their signatures, through `fold` errors (GP-01, GP-03, GP-15).

Each row is ORG with one defect, and the expected code is the fold error. The
org id and the pin follow the document under test, so the pin checks of VR-02
step 6 pass and the genesis defect is the first failure.

The four state rows (gen/ok-3-maintainers, gen/junk-sig-ignored,
gen/duplicate-sig-same-kid-ok, gen/sig-by-unlisted-key) expect ORG's state at
position 0. gen/order-revoked-before-changed and gen/order-unauthorized-before-carry
need chain acts that revoke a carried device before a change, which belongs to the
change cluster (groups/chg_order.py).
"""
import hashlib

from lib import base, chain, forge, inputs, keys, p256, state

WRONG_PREV = base.hashstr(b"not the previous document")
UNIMPLEMENTED = base.hashstr(b"unimplemented profile")


def _device(doc, person):
    return next(d for d in doc["devices"] if d["person"] == person)


def _resort(doc):
    doc["devices"].sort(key=lambda d: d["kid"])


def _agree_equals_sign(doc):
    d = _device(doc, "alice")
    d["agree"] = dict(d["sign"])


def _unaccepted_class(doc):
    _device(doc, "alice")["class"] = "fixture-pin"


def _person_unlisted(doc):
    _device(doc, "alice")["person"] = "zed"


def _duplicate_agree(doc):
    _device(doc, "bob")["agree"] = dict(_device(doc, "alice")["agree"])


def _duplicate_kid(doc):
    alice, bob = _device(doc, "alice"), _device(doc, "bob")
    bob["sign"], bob["kid"] = dict(alice["sign"]), alice["kid"]
    _resort(doc)


def _duplicate_member(doc):
    doc["members"].insert(0, dict(doc["members"][0]))


def _off_curve(doc):
    d = _device(doc, "alice")
    y = int.from_bytes(base._unb64u(d["sign"]["y"]), "big") + 1
    bad = (int.from_bytes(base._unb64u(d["sign"]["x"]), "big"), y)
    if p256.on_curve(bad):
        raise AssertionError("the edited point is on the curve")
    d["sign"]["y"] = keys.b64u(y.to_bytes(32, "big"))
    d["kid"] = keys.thumbprint(d["sign"]["x"], d["sign"]["y"])
    _resort(doc)


def _wrong_kid(doc):
    _device(doc, "alice")["kid"] = keys.b64u(hashlib.sha256(b"wrong kid").digest())
    _resort(doc)


def _no_device(doc):
    doc["devices"].remove(_device(doc, "alice"))


def _role_unlisted(doc):
    doc["members"][0]["role"] = "lead"


def _too_large(doc):
    doc["members"], doc["devices"] = inputs.synthetic_members(13)


def _set(key, value):
    return lambda d: d.__setitem__(key, value)


def _classes(doc):
    doc["policy"]["classes"].append({"class": "unknown-class", "user_verification": "biometric_only"})
    doc["profile"] = base.hashstr(b"unimplemented profile 2")


ORIGINAL_ROWS = (
    ("gen/agree-equals-sign", _agree_equals_sign, "genesis_key_invalid"),
    ("gen/device-not-accepted-class", _unaccepted_class, "genesis_schema"),
    ("gen/device-person-unlisted", _person_unlisted, "genesis_schema"),
    ("gen/duplicate-agree-key", _duplicate_agree, "duplicate_key"),
    ("gen/duplicate-kid-across-persons", _duplicate_kid, "duplicate_key"),
    ("gen/duplicate-member-id", _duplicate_member, "genesis_schema"),
    ("gen/extra-key", _set("extra", "x"), "genesis_schema"),
    ("gen/key-not-on-curve", _off_curve, "genesis_key_invalid"),
    ("gen/kid-not-thumbprint", _wrong_kid, "genesis_key_invalid"),
    ("gen/member-no-device", _no_device, "genesis_schema"),
    ("gen/member-role-unlisted", _role_unlisted, "policy_invalid"),
    ("gen/missing-key", lambda d: d.pop("name"), "genesis_schema"),
    ("gen/name-25", _set("name", "n" * 25), "genesis_schema"),
    ("gen/org-nonnull-original", lambda d: d.__setitem__("org", base.hashstr(b"some org")),
     "genesis_schema"),
    ("gen/order-policy-before-device-class", lambda d: d["policy"].pop("classes"),
     "policy_invalid"),
    ("gen/order-profile-before-class", _classes, "profile_mismatch"),
    ("gen/order-profile-before-fixture-key",
     _set("profile", base.hashstr(b"unimplemented profile 3")), "profile_mismatch"),
    ("gen/profile-mismatch", _set("profile", UNIMPLEMENTED), "profile_mismatch"),
    ("gen/render-too-large", _too_large, "genesis_render_too_large"),
    ("gen/unsorted-devices", lambda d: d["devices"].reverse(), "doc_not_sorted"),
    ("gen/unsorted-members", lambda d: d["members"].reverse(), "doc_not_sorted"),
    ("gen/unsorted-roles", lambda d: d["policy"].__setitem__("roles", ["member", "maintainer"]),
     "doc_not_sorted"),
    ("gen/v-wrong", _set("v", "handsal-genesis/2"), "genesis_schema"),
    ("gen/zero-members", _set("members", []), "genesis_schema"),
)


def _sig_rows(fx):
    """Signature rows: (name, alice's signature or None for none)."""
    sign = fx.genesis_sign("alice", fx.org)

    def edit(mutate):
        return forge.resign(fx, sign, mutate)

    bob = fx.key("bob").kid
    return (
        ("gen/missing-maintainer-sig", None),
        ("gen/sig-over-other-doc", fx.genesis_sign("alice", fx.wit_org)),
        ("gen/sig-parent-nonnull-ignored",
         edit(lambda p: p.__setitem__("parent_receipt_hash", fx.org_id))),
        ("gen/sig-performer-mismatch-ignored",
         edit(lambda p: p.__setitem__("performer_id", "bob"))),
        ("gen/sign-act-kid-differs-unsigned",
         edit(forge.act_edit(lambda a: a.__setitem__("kid", bob)))),
        ("gen/sign-body-not-empty-unsigned",
         edit(forge.act_edit(lambda a: a.__setitem__("body", {"x": "y"})))),
    )


def _change_rows(fx):
    """Change rows: (name, edit of the change document, signers of the change)."""
    def more_members(doc):
        members, devices = inputs.synthetic_members(13)
        doc["members"] = sorted(doc["members"] + members, key=lambda m: m["id"])
        doc["devices"] = sorted(doc["devices"] + devices, key=lambda d: d["kid"])

    return (
        ("gen/order-schema-before-lineage",
         lambda d: (d["members"].reverse(), d.__setitem__("prev", WRONG_PREV)),
         ("alice", "bob", "carol")),
        ("gen/order-lineage-before-unsigned", _set("prev", WRONG_PREV), ()),
        ("gen/order-unsigned-before-head", _set("head", base.hashstr(b"unknown head")),
         ("alice", "bob")),
        ("gen/order-lineage-before-render",
         lambda d: (more_members(d), d.__setitem__("prev", WRONG_PREV)), ()),
    )


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    _state_rows(ctx)
    for name, edit, code in ORIGINAL_ROWS:
        doc = inputs.derive(fx.org, edit)
        signers = [] if name == "gen/render-too-large" else None
        w.add(name, "fold", inputs.error_anchor(code),
              input=inputs.fold_input(inputs.original_lineage(fx, doc, signers)))

    # a change-shaped document alone in the lineage has no original before it
    alone = inputs.change_doc(fx)
    w.add("gen/prev-nonnull-no-lineage", "fold", inputs.error_anchor("lineage_broken"),
          input=inputs.fold_input(inputs.original_lineage(fx, alone)))

    for name, alice_sig in _sig_rows(fx):
        sigs = [fx.genesis_sign(n, fx.org) for n in ("bob", "carol")]
        if alice_sig is not None:
            sigs.insert(0, alice_sig)
        w.add(name, "fold", inputs.error_anchor("genesis_unsigned"),
              input=inputs.fold_input([{"doc": fx.org, "sigs": sigs}]))

    original = inputs.original_lineage(fx, fx.org)[0]
    codes = {"gen/order-schema-before-lineage": "doc_not_sorted",
             "gen/order-lineage-before-unsigned": "lineage_broken",
             "gen/order-unsigned-before-head": "genesis_unsigned",
             "gen/order-lineage-before-render": "lineage_broken"}
    for name, edit, signers in _change_rows(fx):
        change = inputs.change_doc(fx, edit=edit)
        sigs = [fx.genesis_sign(n, change) for n in signers]
        w.add(name, "fold", inputs.error_anchor(codes[name]),
              input=inputs.fold_input([original, {"doc": change, "sigs": sigs}]))


def _state_rows(ctx):
    """ORG's genesis state, reached with different signature sets (GP-03, GP-15)."""
    fx, w = ctx.fixtures, ctx.writer
    names = ("alice", "bob", "carol")

    def positives(sigs_by_name):
        for name, jws in sigs_by_name:
            ctx.positive(jws, chain.GENESIS_SIGN, [name])

    good = [(n, fx.genesis_sign(n, fx.org)) for n in names]
    second_alice = fx.genesis_sign("alice", fx.org, ts=base.shift(base.NOW, -3600))
    head, payload, sig = forge.parts(good[0][1])
    junk = forge.join(head, payload, bytes([sig[0] ^ 1]) + sig[1:])
    dave = fx.genesis_sign("dave", fx.org)
    rows = (
        ("gen/ok-3-maintainers", good, []),
        ("gen/junk-sig-ignored", good, [junk]),
        ("gen/duplicate-sig-same-kid-ok", good + [("alice", second_alice)], []),
        ("gen/sig-by-unlisted-key", good + [("dave", dave)], []),
    )
    for name, valid, extra in rows:
        positives(valid)
        lineage = [{"doc": fx.org, "sigs": [j for _n, j in valid] + extra}]
        w.add(name, "fold", state.anchor(state.State(fx.org)), input=inputs.fold_input(lineage))
