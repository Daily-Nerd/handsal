"""Policy validation (GP-02, KC-02, KC-03, KC-07, WT-01), GP-15 step 3 up to the class codes.

One entry point, `validate`, running the checks in the order GP-15 fixes, each
pass over the whole policy before the next begins:

  1. shape                        `policy_invalid` (`relays` and the witness shape included)
  2. bounds                       `policy_out_of_bounds` (`relays` longer than the registry allows included)
  3. a spare person per rule      `policy_unreachable`
  4. classes, one code per pass   `class_unknown`, `class_pending`, `class_test_only`,
                                  `class_policy_mismatch`

Bounds are the registry's constants; this module names none. The policy is
data: nothing here names a class, a role or a threshold. Sortedness of the
lists is judged earlier, by the document (`doc_not_sorted`, GP-01), because one
document has one byte form.
"""
from . import errors, schema, witness_policy

TOP_KEYS = {"classes", "freshness", "relays", "roles", "rules", "v", "witness"}
FRESHNESS_KEYS = ("clock_skew_s", "max_validity_s", "max_view_age_s")
RULE_NAMES = {"chain.resolve", "device.remove", "genesis.change", "member.add"}
VERSION = "handsal-policy/1"


def _invalid():
    return errors.Refused("policy_invalid")


def _role_list(value, listed=None):
    if type(value) is not list or not value or not all(schema.is_role_id(r) for r in value):
        raise _invalid()
    if len(set(value)) != len(value):
        raise _invalid()
    if listed is not None and not set(value) <= set(listed):
        raise _invalid()


def _relays(value):
    """`relays` (GP-02): a list of distinct `hostname` values. The order is the document's (GP-01)."""
    if type(value) is not list or not all(schema.is_hostname(host) for host in value):
        raise _invalid()
    if len(set(value)) != len(value):
        raise _invalid()


def _shape(pol, members):
    if type(pol) is not dict or set(pol) != TOP_KEYS or pol["v"] != VERSION:
        raise _invalid()
    _role_list(pol["roles"])
    _relays(pol["relays"])
    classes = pol["classes"]
    if type(classes) is not list or not classes:
        raise _invalid()
    for entry in classes:
        if (type(entry) is not dict or set(entry) != {"class", "user_verification"}
                or type(entry["class"]) is not str or type(entry["user_verification"]) is not str):
            raise _invalid()
    if len({entry["class"] for entry in classes}) != len(classes):
        raise _invalid()
    freshness = pol["freshness"]
    if type(freshness) is not dict or set(freshness) != set(FRESHNESS_KEYS):
        raise _invalid()
    if not all(schema.is_decimal(freshness[key]) for key in FRESHNESS_KEYS):
        raise _invalid()
    rules = pol["rules"]
    if type(rules) is not dict or set(rules) != RULE_NAMES:
        raise _invalid()
    for rule in rules.values():
        if type(rule) is not dict or set(rule) != {"persons", "roles"} or not schema.is_decimal(rule["persons"]):
            raise _invalid()
        _role_list(rule["roles"], pol["roles"])
    if not {m["role"] for m in members} <= set(pol["roles"]):
        raise _invalid()


def _bounds(pol, reg):
    for key in FRESHNESS_KEYS:
        if not reg.number(key, "min") <= int(pol["freshness"][key]) <= reg.number(key, "max"):
            raise errors.Refused("policy_out_of_bounds")
    low, high = reg.number("persons", "min"), reg.number("persons", "max")
    for rule in pol["rules"].values():
        if not low <= int(rule["persons"]) <= high:
            raise errors.Refused("policy_out_of_bounds")
    if not reg.number("relays", "min") <= len(pol["relays"]) <= reg.number("relays", "max"):
        raise errors.Refused("policy_out_of_bounds")
    witness_policy.bounds(pol["witness"], reg)


def _spare_person(pol, members):
    for rule in pol["rules"].values():
        holders = sum(1 for m in members if m["role"] in rule["roles"])
        if int(rule["persons"]) >= holders:
            raise errors.Refused("policy_unreachable")


def _class_codes(pol, reg, fixture):
    entries = [(entry, reg.lookup_class(entry["class"], fixture)) for entry in pol["classes"]]
    if any(cls is None for _, cls in entries):
        raise errors.Refused("class_unknown")
    if any(cls.status == "pending-spike" for _, cls in entries):
        raise errors.Refused("class_pending")
    if any(cls.status == "test-only" for _, cls in entries):
        raise errors.Refused("class_test_only")
    if any(entry["user_verification"] != cls.user_verification for entry, cls in entries):
        raise errors.Refused("class_policy_mismatch")


def validate(pol, members, devices, reg, fixture):
    """Return if `pol` is a valid policy for a document with these `members` (`{id, role}`) and
    `devices` (genesis entries), under the profile kind (`fixture` true for the fixture profile).
    Otherwise raise Refused with the first code in GP-15 order."""
    _shape(pol, members)
    witness_policy.shape(pol["witness"], devices)
    _bounds(pol, reg)
    _spare_person(pol, members)
    _class_codes(pol, reg, fixture)
