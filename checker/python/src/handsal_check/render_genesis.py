"""Genesis rendering (RN-04, RN-08, RN-10) and the size bound of GP-15 step 5.

An original renders in full: every member, every device (full kid, class on its own line, label,
agree thumbprint) and the whole policy, the witness included. A change renders as a difference from
the document it replaces: `Org name` and `Profile` (as an original opens), `Previous`, the full `Head`, the members and devices added or removed, the
roles changed, the full policy, and what stayed. Carried devices are byte-identical (GP-20), so
there is no "devices changed" section; a section with no entry is not written.

`render_size` is the fold's check: the document's own `genesis.sign` render must fit in 72 lines
(`genesis_render_too_large`). It calls `render` below, which calls `render.frame`, the one owner of
what fits, so the fold and the signer can never disagree. It reads a document that already passed
GP-15 steps 1 to 4 (and a `previous` that passed them in its own turn): it validates nothing.
"""
from . import emit, encoding, errors, genesis, render
from .render import GENESIS_SIGN, hash12

_WIDEST_PERFORMER = "p" * 32   # placeholders with the widest shape: the size depends on content, not on them
_PLACEHOLDER_KID = "k" * 43
_PLACEHOLDER_TS = "2000-01-01T00:00:00Z"


def _device_lines(device):
    return ["  - %s of %s" % (device["kid"], device["person"]), "    Class: " + device["class"],
            "    Label: " + device["label"],
            "    Agree: " + encoding.thumbprint(device["agree"]["x"], device["agree"]["y"])]


def _policy_lines(policy):
    out = ["Policy:", "  Roles: " + ",".join(policy["roles"])]
    for name in sorted(policy["rules"]):
        rule = policy["rules"][name]
        out.append("  Rule %s: %s of %s" % (name, rule["persons"], ",".join(rule["roles"])))
    for entry in policy["classes"]:
        out.append("  Class %s: %s" % (entry["class"], entry["user_verification"]))
    freshness = policy["freshness"]
    out += ["  Clock skew: %s s" % freshness["clock_skew_s"], "  Max validity: %s s" % freshness["max_validity_s"],
            "  Max view age: %s s" % freshness["max_view_age_s"]]
    witness = policy["witness"]
    if witness["mode"] == "none":
        out.append("  Witness: none")
    else:
        out += ["  Witness: relay", "  Relay key: " + witness["relay_kid"],
                "  Max tip age: %s s" % witness["max_tip_age_s"]]
    return out


def _members(doc):
    return {member["id"]: member["role"] for member in doc["members"]}


def _devices(doc):
    return {device["kid"]: device for device in doc["devices"]}


def _difference(doc, previous):
    """The sets a change is read from: members added and removed, roles changed, devices added,
    removed and carried."""
    before, after = _members(previous), _members(doc)
    added = [m for m in doc["members"] if m["id"] not in before]
    removed = [m for m in previous["members"] if m["id"] not in after]
    changed = [(m["id"], before[m["id"]], m["role"]) for m in doc["members"]
               if m["id"] in before and before[m["id"]] != m["role"]]
    old, new = _devices(previous), _devices(doc)
    return (added, removed, changed, [d for d in doc["devices"] if d["kid"] not in old],
            [d for d in previous["devices"] if d["kid"] not in new], [d for d in doc["devices"] if d["kid"] in old])


def _policy_differs(doc, previous):
    return emit.emit_subset(doc["policy"]) != emit.emit_subset(previous["policy"])


def summary(doc, previous):
    """Line 1 of the `genesis.sign` over `doc` (RN-03): an original, or a change against `previous`."""
    name, digest = render.cut12(doc["name"]), hash12(genesis.doc_hash(doc))
    if previous is None:
        return "Sign genesis of %s (%s): %d members, %d devices" % (name, digest, len(doc["members"]), len(doc["devices"]))
    added, removed, changed, dev_added, dev_removed, _ = _difference(doc, previous)
    return "Change %s (%s): +%d/-%d dev, %d mem, policy %s" % (
        name, digest, len(dev_added), len(dev_removed), len(added) + len(removed) + len(changed),
        "NEW" if _policy_differs(doc, previous) else "same")


def _section(title, entries):
    return [title] + entries if entries else []


def lines(doc, previous):
    """The method lines of the `genesis.sign` over `doc` (RN-04, RN-10)."""
    if previous is None:
        out = ["Org name: " + doc["name"], "Profile: " + doc["profile"], "Members:"]
        out += ["  - %s %s" % (m["id"], m["role"]) for m in doc["members"]]
        out.append("Devices:")
        for device in doc["devices"]:
            out += _device_lines(device)
        return out + _policy_lines(doc["policy"]) + ["Document hash: " + hash12(genesis.doc_hash(doc))]
    added, removed, changed, dev_added, dev_removed, carried = _difference(doc, previous)
    out = ["Org name: " + doc["name"], "Profile: " + doc["profile"], "Previous: " + hash12(doc["prev"]),
           "Head: " + doc["head"]]
    out += _section("Members added:", ["  - %s %s" % (m["id"], m["role"]) for m in added])
    out += _section("Members removed:", ["  - %s %s" % (m["id"], m["role"]) for m in removed])
    out += _section("Role changed:", ["  - %s %s -> %s" % entry for entry in changed])
    out += _section("Devices added:", [line for d in dev_added for line in _device_lines(d)])
    out += _section("Devices removed:", ["  - %s of %s" % (d["kid"], d["person"]) for d in dev_removed])
    out += _policy_lines(doc["policy"])
    unchanged = len(doc["members"]) - len(added) - len(changed)
    return out + ["Unchanged: %d devices, %d members" % (len(carried), unchanged)]


def render_document(doc, previous, *, org, performer, kid, ts, head):
    """The whole render of the `genesis.sign` over `doc`: line 1, header, `lines`, `Signed at`, and
    for a change the `Head` line (`head` is the signed head id, None for an original). `previous` is None for
    an original."""
    return render.frame(first=summary(doc, previous), method=GENESIS_SIGN, org=org, performer=performer, kid=kid,
                        body=lines(doc, previous), ts=ts, expires=None, parent=None,
                        head=head, sender=False)


def render_size(doc, previous):
    """GP-15 step 5: `genesis_render_too_large` when the signed render of `doc` is over 72 lines."""
    try:
        render_document(doc, previous, org=genesis.doc_hash(doc), performer=_WIDEST_PERFORMER,
                        kid=_PLACEHOLDER_KID, ts=_PLACEHOLDER_TS, head=doc.get("head"))
    except errors.Refused:   # `frame` refuses for one reason only: more than 72 lines
        raise errors.Refused("genesis_render_too_large") from None
