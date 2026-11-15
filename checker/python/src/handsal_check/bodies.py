"""Body validation per method (ACT-09, ACT-10, ACT-11), for the lifecycle, verdict, decision,
endorse and `chain.resolve` bodies.

The registry holds every closed body schema and `schema.check` reads it, so a
body has one definition. This module runs that check and then the few rules the
registry cannot express:
- an introduced device (`device.add`, `member.add`): its class is in the
  registry for the profile, and its keys are valid (`devicekey`, ACT-11);
- `member.add`: the role is one the epoch policy lists;
- `chain.resolve`: `choose` is one of `candidates`.
Every defect is `body_schema` except the ACT-07 forms (hashstr, member id),
which are `schema` (one defect, one code). Whether a class is *accepted*, a key
is already present or a role-holder rule holds is the fold's business (KC-04,
FO-07, KC-08), not the body's.
"""
from . import devicekey, errors, schema


def _refuse():
    return errors.Refused("body_schema")


def _no_extra_rule(body, reg, fixture, roles):
    pass


def _device_rule(entry, reg, fixture):
    if reg.lookup_class(entry["class"], fixture) is None:
        raise _refuse()
    if devicekey.defect(entry["kid"], entry["sign"], entry["agree"]) is not None:
        raise _refuse()


def _device_add(body, reg, fixture, roles):
    _device_rule(body, reg, fixture)


def _member_add(body, reg, fixture, roles):
    if roles is None:
        raise ValueError("member.add needs the epoch policy roles")
    if body["role"] not in roles:
        raise _refuse()
    _device_rule(body["device"], reg, fixture)


def _resolve(body, reg, fixture, roles):
    if body["choose"] not in body["candidates"]:
        raise _refuse()


_SEMANTICS = {
    "local:handsal.genesis.sign": _no_extra_rule,
    "local:handsal.device.add": _device_add,
    "local:handsal.device.remove": _no_extra_rule,
    "local:handsal.member.add": _member_add,
    "local:handsal.chain.resolve": _resolve,
    "local:handsal.act.endorse": _no_extra_rule,
    "local:handsal.request.approve": _no_extra_rule,
    "local:handsal.request.reject": _no_extra_rule,
    "local:handsal.request.needs-info": _no_extra_rule,
    "local:handsal.decision": _no_extra_rule,
}


def validate(method, body, reg, fixture=False, roles=None):
    """Return if `body` is a valid body of `method`, else raise Refused.

    `fixture` says whether the fixture profile is in force (fixture-only classes exist);
    `roles` is the epoch policy's role list, required for `member.add`.
    An unknown method is a KeyError: callers judge `method_unknown` first.
    """
    node = {"code": "body_schema", **reg.methods[method].body}
    schema.check(node, body, reg, "body_schema")
    _SEMANTICS[method](body, reg, fixture, roles)
