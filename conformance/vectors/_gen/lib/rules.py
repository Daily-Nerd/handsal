"""The rules of FO-22 and FO-23 that the generator model can evaluate (CF-06).

`Chain` records the acts a vector author calls valid (`ok=True` or `valid=True`), and nothing
else judges them, so a claim that contradicts the spec would ship as an anchor. These checks
refuse such a claim when the bag is built, against the state at the act's parent `S_P`. Each
function states the one rule it owns and raises `Refused` with the requirement id.

`genesis_classes` is the same kind of model for the class half of a genesis document (GP-15
step 3).

Not checked here: proof of possession and every signature-level rule (the vitni cross-check
and the shape tests own them), `chain.resolve` (FO-25) and the genesis change (GP-19).
"""
import json
from pathlib import Path

REGISTRY = Path(__file__).resolve().parents[4] / "spec" / "registry.json"


class Refused(ValueError):
    """The author's claim contradicts a rule of the spec."""


def _registry():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def _uv(cls):
    """KC-08: the registry `user_verification` of a class, whether or not a policy lists it."""
    reg = _registry()
    for entry in reg["key_classes"] + reg["fixture_only"]:
        if entry["id"] == cls:
            return entry["user_verification"]
    raise Refused("KC-08: unknown class %s" % cls)


def genesis_classes(doc, *, fixture, reg=None):
    """GP-15 step 3, the class half: the first code `doc` earns from KC-01 to KC-08, else None.

    Each code is tried over the whole document before the next, in the order of GP-15: a
    policy class outside the registry (the `fixture_only` list counts only under the fixture
    profile, GP-18), a pending one, the test one, a pair that differs from the registry, then a
    listed device of a class the policy does not list (`genesis_schema`, GP-20), then a role
    holder whose device class is not `biometric_only` (KC-08). `reg` is the registry the model reads
    (default: the shipped one); a tagged registry has no pending class, so a test passes one that does.
    """
    reg = reg or _registry()
    known = {e["id"]: e for e in reg["key_classes"] + (reg["fixture_only"] if fixture else [])}
    pairs = doc["policy"]["classes"]
    tests = (
        ("class_unknown", lambda p: p["class"] not in known),
        ("class_pending", lambda p: known[p["class"]]["status"] == "pending-spike"),
        ("class_test_only", lambda p: known[p["class"]]["status"] == "test-only"),
        ("class_policy_mismatch",
         lambda p: p["user_verification"] != known[p["class"]]["user_verification"]),
    )
    for code, bad in tests:
        if any(bad(p) for p in pairs):
            return code
    listed = {p["class"] for p in pairs}
    if any(d["class"] not in listed for d in doc["devices"]):
        return "genesis_schema"
    holders = {r for rule in doc["policy"]["rules"].values() for r in rule["roles"]}
    role = {m["id"]: m["role"] for m in doc["members"]}
    if any(role[d["person"]] in holders and known[d["class"]]["user_verification"] != "biometric_only"
           for d in doc["devices"]):
        return "role_key_class"
    return None


def _live(st, kid):
    """The person of `kid` when the key is active and accepted in `st` (KC-04), else None."""
    for person, devices in st.devices.items():
        d = devices.get(kid)
        if d is not None:
            return person if d["status"] == "active" and d["accepted"] else None
    return None


def role_holder(st, person):
    """KC-08: the member's role is listed in `roles` of any rule of the epoch policy."""
    role = st.members.get(person)
    return role is not None and any(role in r["roles"] for r in st.policy["rules"].values())


def quorum(st, rule, kids):
    """FO-23: the primary key is live, and `rule` has at least Q persons with a listed role."""
    if _live(st, kids[0]) is None:
        raise Refused("FO-23: the primary signer is not active and accepted in S_P")
    r = st.policy["rules"][rule]
    counted = {p for p in (_live(st, k) for k in kids) if p is not None and st.members[p] in r["roles"]}
    if len(counted) < int(r["persons"]):
        raise Refused("FO-22: quorum, %d of %s persons counted" % (len(counted), r["persons"]))


def _role_class(st, person, role, cls):
    holder = role in {x for r in st.policy["rules"].values() for x in r["roles"]}
    if holder and _uv(cls) != "biometric_only":
        raise Refused("KC-08: class %s for role holder %s" % (cls, person))


def device_add(st, person, cls, kids):
    """FO-22 `device.add`: a member, an allowed class, consent, then the quorum."""
    if person not in st.members:
        raise Refused("FO-22: %s is not a member in S_P" % person)
    _role_class(st, person, st.members[person], cls)
    own = [k for k in st.devices.get(person, {}) if _live(st, k)]
    if own and not any(k in own for k in kids):
        raise Refused("FO-22: consent, no active key of %s signed" % person)
    quorum(st, "device.remove", kids)


def device_remove(st, person, kid, kids):
    """FO-22 `device.remove`: the target is an active device of the person in S_P."""
    d = st.devices.get(person, {}).get(kid)
    if d is None or d["status"] != "active":
        raise Refused("FO-22: target is not an active device of %s in S_P" % person)
    quorum(st, "device.remove", kids)


def member_add(st, member, role, cls, kids, earlier):
    """FO-22 `member.add`: an unused id, a listed role, an allowed class, then the quorum."""
    if member in st.members or member in earlier:
        raise Refused("FO-22: member id %s is not unused" % member)
    if role not in st.policy["roles"]:
        raise Refused("FO-22: role %s is not listed in policy roles" % role)
    _role_class(st, member, role, cls)
    quorum(st, "member.add", kids)
