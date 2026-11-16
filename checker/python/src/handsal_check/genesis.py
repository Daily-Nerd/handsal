"""Genesis document validation (GP-01, GP-15 steps 1 to 3, GP-18, GP-20, KC-05, KC-08).

`check_document` judges one document by itself, in the order GP-15 fixes, and
returns the profile kind it runs under. Everything that needs another document,
a signature or an act (links, possession, head, authority, carried devices,
render size) is a later step owned elsewhere.

  step 1, structure   `genesis_schema`, then `doc_not_sorted`, then
                      `genesis_key_invalid`, then `duplicate_key`; each pass
                      covers the whole document before the next begins
  step 2, profile     `profile_mismatch`, `fixture_profile` (`profiles`)
  step 3, policy      `policy.validate` (its codes), then a listed device of a
                      class the policy does not accept (`genesis_schema`), then
                      `role_key_class`, then `fixture_key`

A document is original iff `prev` is null: then `org` is null and `head` is
absent. Otherwise it is a change: `org` and `head` are hashstrs. The `policy`
member is not part of the step 1 key check: a document without one is
`policy_invalid` (step 3), as GP-02 says. A value outside the canonical subset
(a number, a boolean, a non-ASCII string, nesting over MAX_DEPTH, size over
MAX_PAYLOAD) is `genesis_schema`, so every later check can rely on strings,
lists, objects and null.
"""
from collections import namedtuple

from . import devicekey, emit, encoding, errors, policy, schema

Context = namedtuple("Context", "reg profiles allow_fixture")

VERSION = "handsal-genesis/1"
BASE_KEYS = {"devices", "members", "name", "org", "prev", "profile", "v"}
DEVICE_KEYS = {"agree", "class", "kid", "label", "person", "sign"}


def doc_hash(doc):
    """hashstr(JCS(doc)): the document hash, the org id of an original, and a change's `prev`."""
    return encoding.hashstr(emit.emit_subset(doc))


def _schema():
    return errors.Refused("genesis_schema")


def _is_point_shape(point):
    return (type(point) is dict and set(point) == {"x", "y"}
            and type(point["x"]) is str and type(point["y"]) is str)


def check_shape(doc):
    if type(doc) is not dict:
        raise _schema()
    try:
        emit.emit_subset(doc)
    except emit.EmitError:
        raise _schema() from None
    if set(doc) - {"policy", "head"} != BASE_KEYS or doc["v"] != VERSION:
        raise _schema()
    if not schema.is_org_name(doc["name"]) or not schema.is_hashstr(doc["profile"]):
        raise _schema()
    original = doc["prev"] is None
    if original:
        if doc["org"] is not None or "head" in doc:
            raise _schema()
    elif not (schema.is_hashstr(doc["prev"]) and schema.is_hashstr(doc["org"])
              and schema.is_hashstr(doc.get("head"))):
        raise _schema()
    members, devices = doc["members"], doc["devices"]
    if type(members) is not list or not members or type(devices) is not list or not devices:
        raise _schema()
    for member in members:
        if (type(member) is not dict or set(member) != {"id", "role"}
                or not schema.is_member_id(member["id"]) or not schema.is_role_id(member["role"])):
            raise _schema()
    ids = [m["id"] for m in members]
    if len(set(ids)) != len(ids):
        raise _schema()
    for device in devices:
        if type(device) is not dict or set(device) != DEVICE_KEYS:
            raise _schema()
        if (type(device["class"]) is not str or type(device["kid"]) is not str
                or not schema.is_label(device["label"]) or device["person"] not in ids
                or not _is_point_shape(device["sign"]) or not _is_point_shape(device["agree"])):
            raise _schema()
    if {d["person"] for d in devices} != set(ids):
        raise _schema()


def _ascending(values):
    return all(a <= b for a, b in zip(values, values[1:]))


def _policy_lists(pol):
    """Every list of the policy that one byte form depends on, when it is well formed enough to
    be ordered. A malformed policy is `policy_invalid` later, never `doc_not_sorted`."""
    if type(pol) is not dict:
        return
    classes = pol.get("classes")
    if type(classes) is list and all(type(c) is dict and type(c.get("class")) is str for c in classes):
        yield [c["class"] for c in classes]
    roles = pol.get("roles")
    if type(roles) is list and all(type(r) is str for r in roles):
        yield roles
    relays = pol.get("relays")
    if type(relays) is list and all(type(r) is str for r in relays):
        yield relays
    rules = pol.get("rules")
    if type(rules) is dict:
        for rule in rules.values():
            rule_roles = rule.get("roles") if type(rule) is dict else None
            if type(rule_roles) is list and all(type(r) is str for r in rule_roles):
                yield rule_roles


def _check_sorted(doc):
    lists = [[m["id"] for m in doc["members"]], [d["kid"] for d in doc["devices"]]]
    lists.extend(_policy_lists(doc.get("policy")))
    if not all(_ascending(values) for values in lists):
        raise errors.Refused("doc_not_sorted")


def _check_keys(doc):
    for device in doc["devices"]:
        if devicekey.defect(device["kid"], device["sign"], device["agree"]) is not None:
            raise errors.Refused("genesis_key_invalid")
    devices = doc["devices"]
    kids = [d["kid"] for d in devices]
    agrees = [(d["agree"]["x"], d["agree"]["y"]) for d in devices]
    if len(set(kids)) != len(kids) or len(set(agrees)) != len(agrees):
        raise errors.Refused("duplicate_key")


def _check_devices_against_policy(doc, ctx, fixture):
    pol = doc["policy"]
    accepted = {entry["class"] for entry in pol["classes"]}
    if any(device["class"] not in accepted for device in doc["devices"]):
        raise _schema()
    holder_roles = set()
    for rule in pol["rules"].values():
        holder_roles.update(rule["roles"])
    holders = {m["id"] for m in doc["members"] if m["role"] in holder_roles}
    for device in doc["devices"]:
        if device["person"] in holders:
            cls = ctx.reg.lookup_class(device["class"], fixture)
            if cls.user_verification != "biometric_only":
                raise errors.Refused("role_key_class")


def _check_fixture_keys(doc, version):
    kids = [device["kid"] for device in doc["devices"]]
    witness = doc["policy"]["witness"]
    if witness["mode"] == "relay":
        kids.append(witness["relay_kid"])
    if any(version.is_fixture_kid(kid) for kid in kids):
        raise errors.Refused("fixture_key")


def _check_structure(doc):
    """GP-15 step 1: the whole document, in the order the codes are listed."""
    check_shape(doc)
    _check_sorted(doc)
    _check_keys(doc)


def _check_content(doc, ctx, fixture, version):
    """GP-15 step 3: policy, devices against it, and (under the production profile) the fixture keys `version` lists."""
    policy.validate(doc.get("policy"), doc["members"], doc["devices"], ctx.reg, fixture)
    _check_devices_against_policy(doc, ctx, fixture)
    if not fixture:
        _check_fixture_keys(doc, version)


def check_document(doc, ctx, previous=None):
    """Return the `Profile` of `doc` if it is valid by itself, else raise Refused.

    `previous` is the `Profile` of the document before it in the lineage (None for the original);
    `ctx.allow_fixture` is false for the production build (CF-08).
    """
    _check_structure(doc)
    profile = ctx.profiles.check_document(doc["profile"], previous, ctx.allow_fixture)
    _check_content(doc, ctx, profile.fixture, profile.version)
    return profile


def check_alone(doc, ctx):
    """GP-15 steps 1 and 3 over `doc` alone, for a renderer that holds a document and no lineage (RN-09).

    Step 2 and the lineage steps belong to the fold, so an unimplemented profile is no defect here. Step 3
    is checked under the profile the document names: strict (fixture keys refused) unless it names a
    fixture profile or none this checker implements.
    """
    _check_structure(doc)
    profile = ctx.profiles.resolve(doc["profile"])
    strict = profile is not None and not profile.fixture
    _check_content(doc, ctx, not strict, profile.version if strict else None)


def check_link(doc, previous, original_org):
    """GP-15 step 4 for a document that passed steps 1 to 3: `lineage_broken` unless it fits.

    `previous` is the lineage document before it, or None for the first. The first must be an
    original (`prev` null). Every later one names the document before it in `prev` and the
    original's org id in `org`, so a lineage is one chain from the original to the pinned one.
    """
    if previous is None:
        if doc["prev"] is not None:
            raise errors.Refused("lineage_broken")
        return
    if doc["prev"] != doc_hash(previous) or doc["org"] != original_org:
        raise errors.Refused("lineage_broken")
