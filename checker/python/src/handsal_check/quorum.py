"""Quorum: counted signatures, persons, consent and the body conditions of a chain primary (FO-13,
FO-22, FO-23, KC-04, KC-08, SG-09).

`check_primary` decides whether the primary `group`, whose parent is the node `parent`, is valid
against the state at that parent, and returns the state after it, or None (the act is ignored,
FO-06). In order, cheapest first:
  1. the link rules (FO-04) and the closed body (ACT-09);
  2. the body conditions against `S_P` (FO-22 table, KC-08, FO-07 uniqueness, SG-09);
  3. the primary signature, verified against the keys of `S_P`;
  4. the proof of possession of a new key (FO-07);
  5. counted signatures: the primary and every endorsement that passes FO-08, verified, whose
     person holds a role listed in the rule of the method; at least `persons` distinct persons;
  6. consent on `device.add`: a verified signature by a key of the target person, when that person
     has a usable key.

The fold names no role, threshold, class or duration (FO-13): every number and list is read from the
epoch policy. The effect of a valid act is a function of its method and body only, so no output
reads which signatures an act carries beyond this test (FO-23, surplus).
"""
from . import bodies, chain, endorse, errors, state as state_module
from .state import State

DEVICE_ADD = "local:handsal.device.add"
DEVICE_REMOVE = "local:handsal.device.remove"
MEMBER_ADD = "local:handsal.member.add"
# FO-22: the rule of the policy that governs each method
RULE = {DEVICE_ADD: "device.remove", DEVICE_REMOVE: "device.remove", MEMBER_ADD: "member.add",
        chain.RESOLVE: "chain.resolve"}


def verified_signatures(epoch, group, state):
    """`((person, kid), {endorsement id: (person, kid)})` of the signatures on `group` that verify
    against the keys of `S_P`: its primary, and every endorsement that passes FO-08 (FO-21: one valid
    copy suffices). None if the primary itself does not verify."""
    keys = state.keys_map()
    if not endorse.verified(epoch, group, keys):
        return None
    endorsements = {}
    for endorsement in epoch.bag.endorsements_of(group.act):
        if endorse.verified(epoch, endorsement, keys):
            endorsements[endorsement.act.id] = (endorsement.act.performer, endorsement.act.kid)
    return (group.act.performer, group.act.kid), endorsements


def signatures(epoch, group, state):
    """`[(person, kid)]` of every verified signature on `group` against `S_P`, or None."""
    found = verified_signatures(epoch, group, state)
    if found is None:
        return None
    primary, endorsements = found
    return [primary] + list(endorsements.values())


def counted_persons(epoch, rule, state, signed, unclean=frozenset()):
    """The distinct persons of `signed` that count under `rule`: their role is listed in it (FO-23
    item 3) and their key is not in `unclean` (item 4, resolves only)."""
    _, roles = epoch.rule(rule)
    return {person for person, kid in signed if state.members.get(person) in roles and kid not in unclean}


def class_allowed(epoch, role, cls):
    """KC-08: a role holder's device class has registry `user_verification` `biometric_only`."""
    if role not in epoch.holder_roles:
        return True
    entry = epoch.profile.version.reg.lookup_class(cls, epoch.fixture)
    return entry is not None and entry.user_verification == "biometric_only"


def _introduced_ok(epoch, state, role, entry):
    """The new device `entry` (`class`, `kid`, `sign`, `agree`) may enter: its class suits the role,
    its keys are fresh, and under a production profile it is no fixture key (GP-18)."""
    if not class_allowed(epoch, role, entry["class"]):
        return False
    if not epoch.fixture and epoch.profile.version.is_fixture_kid(entry["kid"]):
        return False
    return endorse.fresh_key(epoch, state, entry["kid"], entry["sign"], entry["agree"])


def _device_add(epoch, act, state):
    body = act.body
    person = body["person"]
    if person not in state.members or body["link_code_hash"] in state.link_codes:
        return None
    if not _introduced_ok(epoch, state, state.members[person], body):
        return None
    device = state_module.new_device(body, body["class"] in epoch.accepted_classes)
    return state.with_device(body["kid"], device).with_link_code(body["link_code_hash"])


def _member_add(epoch, act, state):
    body = act.body
    member, entry = body["member"], body["device"]
    if member in state.members or member in epoch.earlier.members or body["link_code_hash"] in state.link_codes:
        return None
    if not _introduced_ok(epoch, state, body["role"], entry):
        return None
    device = state_module.new_device({**entry, "person": member}, entry["class"] in epoch.accepted_classes)
    return state.with_member(member, body["role"]).with_device(entry["kid"], device).with_link_code(
        body["link_code_hash"])


def _device_remove(epoch, act, state):
    device = state.devices.get(act.body["kid"])
    if device is None or device.person != act.body["person"] or device.status != "active":
        return None
    return state.with_removed(act.body["kid"])


_EFFECT = {DEVICE_ADD: _device_add, DEVICE_REMOVE: _device_remove, MEMBER_ADD: _member_add}


def introduced(act):
    """`(person, kid, sign)` of the key an introducing act brings, or None for a removal."""
    if act.method == DEVICE_ADD:
        return act.body["person"], act.body["kid"], act.body["sign"]
    if act.method == MEMBER_ADD:
        return act.body["member"], act.body["device"]["kid"], act.body["device"]["sign"]
    return None


def check_primary(epoch, group, parent):
    """The `State` after the primary `group` at the node `parent`, or None if it is not valid there."""
    act, state = group.act, parent.state
    if not chain.linked(act, parent):
        return None
    try:
        bodies.validate(act.method, act.body, epoch.profile.version.reg, epoch.fixture, epoch.roles)
    except errors.Refused:
        return None
    after = _EFFECT[act.method](epoch, act, state)
    if after is None:
        return None
    signed = signatures(epoch, group, state)
    if signed is None:
        return None
    new_key = introduced(act)
    if new_key is not None and not endorse.possession(epoch, group, state, *new_key):
        return None
    rule = RULE[act.method]
    if len(counted_persons(epoch, rule, state, signed)) < epoch.rule(rule)[0]:
        return None
    if act.method == DEVICE_ADD and state.usable_devices(act.body["person"]):
        if act.body["person"] not in {person for person, _ in signed}:
            return None
    return after
