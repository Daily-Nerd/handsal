"""Vectors pol/*: the policy of a genesis document, through `fold` errors (GP-02, GP-15 step 3).

Each row is ORG, or a change of ORG, with one policy defect. The org id and the
pin follow the document under test, so the pin checks pass and the policy code
is the fold error. The three bound classes keep their order: a malformed field
is `policy_invalid`, a violated bound `policy_out_of_bounds`, and an unreachable
rule `policy_unreachable`.

pol/org3-2-of-3-ok is the one state row: ORG as it is. A document without `policy` is `policy_invalid`:
GP-01 leaves the presence of `policy` to GP-02.
"""
from lib import chain, inputs, state


def _rule(rule, **fields):
    return lambda d: d["policy"]["rules"][rule].update(fields)


def _fresh(key, value):
    return lambda d: d["policy"]["freshness"].__setitem__(key, value)


def _drop_rule(rule):
    return lambda d: d["policy"]["rules"].pop(rule)


def _only(persons):
    """Keep only the named persons (members and their devices)."""
    def edit(doc):
        doc["members"] = [m for m in doc["members"] if m["id"] in persons]
        doc["devices"] = [e for e in doc["devices"] if e["person"] in persons]
    return edit


def _spare_per_rule(doc):
    """chain.resolve is held by two `lead` members, so persons 2 leaves no spare."""
    doc["policy"]["roles"] = ["lead", "maintainer", "member"]
    for member in doc["members"]:
        member["role"] = "lead" if member["id"] in ("alice", "bob") else "maintainer"
    for rule in doc["policy"]["rules"].values():
        rule["roles"] = ["lead", "maintainer"]
    doc["policy"]["rules"]["chain.resolve"]["roles"] = ["lead"]


def _classes(edit):
    return lambda d: edit(d["policy"]["classes"])


ROWS = (
    ("pol/device-remove-keys-form",
     lambda d: d["policy"]["rules"].__setitem__("device.remove", {"keys": "2",
                                                                 "roles": ["maintainer"]}),
     "policy_invalid"),
    ("pol/duplicate-class-entry", _classes(lambda c: c.append(dict(c[0]))), "policy_invalid"),
    ("pol/empty-accepted-classes", _classes(lambda c: c.clear()), "policy_invalid"),
    ("pol/empty-from", _rule("member.add", roles=[]), "policy_invalid"),
    ("pol/extra-policy-key", lambda d: d["policy"].__setitem__("x", "y"), "policy_invalid"),
    ("pol/max-validity-over-30d", _fresh("max_validity_s", "2592001"), "policy_out_of_bounds"),
    ("pol/max-view-age-too-large", _fresh("max_view_age_s", "2592001"), "policy_out_of_bounds"),
    ("pol/max-view-age-too-small", _fresh("max_view_age_s", "59"), "policy_out_of_bounds"),
    ("pol/missing-freshness", lambda d: d["policy"].pop("freshness"), "policy_invalid"),
    ("pol/missing-policy", lambda d: d.pop("policy"), "policy_invalid"),
    ("pol/missing-quorum-rule-device-remove-other", _drop_rule("device.remove"), "policy_invalid"),
    ("pol/missing-quorum-rule-genesis-change", _drop_rule("genesis.change"), "policy_invalid"),
    ("pol/missing-quorum-rule-member-add", _drop_rule("member.add"), "policy_invalid"),
    ("pol/missing-rule-chain-resolve", _drop_rule("chain.resolve"), "policy_invalid"),
    ("pol/persons-16-out-of-bounds", _rule("chain.resolve", persons="16"), "policy_out_of_bounds"),
    ("pol/persons-equals-role-holders-refused", _rule("device.remove", persons="3"),
     "policy_unreachable"),
    ("pol/persons-one-refused", _rule("device.remove", persons="1"), "policy_out_of_bounds"),
    ("pol/rule-role-unlisted", _rule("chain.resolve", roles=["unlisted"]), "policy_invalid"),
    ("pol/single-person-org-unreachable", _only({"alice"}), "policy_unreachable"),
    ("pol/skew-3601", _fresh("clock_skew_s", "3601"), "policy_out_of_bounds"),
    ("pol/spare-counted-per-rule-roles", _spare_per_rule, "policy_unreachable"),
    ("pol/threshold-unreachable", _rule("device.remove", persons="4"), "policy_unreachable"),
    ("pol/threshold-zero", _rule("device.remove", persons="0"), "policy_out_of_bounds"),
    ("pol/two-person-org-refused", _only({"alice", "bob"}), "policy_unreachable"),
    ("pol/v-wrong", lambda d: d["policy"].__setitem__("v", "handsal-policy/2"), "policy_invalid"),
)

CHANGE_ROWS = (
    ("pol/change-removing-spare-refused", _only({"alice", "bob"}), "policy_unreachable"),
    ("pol/persons-one-in-change-refused", _rule("member.add", persons="1"),
     "policy_out_of_bounds"),
)


def generate(ctx):
    fx, w = ctx.fixtures, ctx.writer
    for name, edit, code in ROWS:
        doc = inputs.derive(fx.org, edit)
        w.add(name, "fold", inputs.error_anchor(code),
              input=inputs.fold_input(inputs.original_lineage(fx, doc)))
    original = inputs.original_lineage(fx, fx.org)[0]
    for name, edit, code in CHANGE_ROWS:
        change = inputs.change_doc(fx, edit=edit)
        sigs = [fx.genesis_sign(fx.name_of_kid(d["kid"]), change) for d in change["devices"]]
        w.add(name, "fold", inputs.error_anchor(code),
              input=inputs.fold_input([original, {"doc": change, "sigs": sigs}]))

    # three maintainers, every rule `persons "2"`: reachable, so ORG's own state (GP-02)
    lineage = inputs.original_lineage(fx, fx.org)
    for entry, jws in zip(fx.org["devices"], lineage[0]["sigs"]):
        ctx.positive(jws, chain.GENESIS_SIGN, [fx.name_of_kid(entry["kid"])])
    w.add("pol/org3-2-of-3-ok", "fold", state.anchor(state.State(fx.org)),
          input=inputs.fold_input(lineage))
