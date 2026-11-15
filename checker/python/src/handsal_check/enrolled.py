"""The `enrolled` predicate (GP-13): this machine holds a valid administrator-written pin for `org`, its
evidence folds, and `device_kid` names an active accepted device of that org, freshly viewed.

`parse_input` turns the command JSON into an `Input` or raises `Malformed`. `run` evaluates the steps in
order and returns `{enrolled, reason}` for the first failure, `{true, "ok"}` if there is none:

  1 to 3  the pin checks of VR-02 step 6, (a) to (h), with their codes     (`pinned.fold`)
  4       the fold succeeds, else its error code, `fork` included (`epoch_superseded` where `next` is "yes",
          a fork being a verdict about an open tip)                        (`pinned.fold`)
  5       `device_kid` is a device in the state (`local_key_unknown`), active (`local_key_not_active`)
          and accepted (`local_class_not_accepted`)
  6       the view is fresh (VR-12: `epoch_superseded` first), then the witness of the policy's mode
          (WT-04, WT-05, WT-10), both in `rules_time.act_free_view`, which `head` calls too
  7       the pin's `spec` is not a fixture profile (`fixture_profile`, GP-18)

It does not prove that the key is on this machine or that a person is present: `device_kid` is the
caller's word, and presence is proven per act by `check-act`. A verifier that cannot answer is the reason
`verifier_unavailable`, as for `check-act` and `fold`: never a pass.

`pin`, `now` and the store's content (`acts`, `lineage`, `next`, `synced_at`, `tip_statement`) are inputs of the
conformance build only (CF-08, CF-09): with `conformance_build=False` an input that carries any is
`malformed_input` and the build fills them in-process (`Input._replace`), the store's failure as `store_reason`,
which `pinned.fold` answers at VR-02 step 6 (f).
"""
from collections import namedtuple

from . import errors, foldcmd, pinfile, pinned, render_genesis, rules_time, schema, verifier

Input = namedtuple("Input", "acts device_kid lineage next now org pin synced_at tip_statement store_reason")


def _malformed():
    return errors.Malformed()


def _get(value, key, kind):
    """`value[key]`, which must be present and of exactly the type `kind`."""
    if key not in value or type(value[key]) is not kind:
        raise _malformed()
    return value[key]


def parse_input(value, conformance_build=True):
    """The `Input` of the command JSON `value` (GP-13), or raise Malformed."""
    if type(value) is not dict:
        raise _malformed()
    for key in ("pin", "now"):
        if (key in value) != conformance_build:   # required here, refused in production
            raise _malformed()
    acts, lineage = foldcmd.read_chain(value, conformance_build)
    device_kid, org = (_get(value, key, str) for key in ("device_kid", "org"))
    if not schema.is_hashstr(org):
        raise _malformed()
    synced_at, next_, tip_statement = foldcmd.read_view(value, conformance_build)
    now = pin = None
    if conformance_build:
        now = _get(value, "now", str)
        if not schema.is_time(now):
            raise _malformed()
        pin = pinfile.Probe.from_json(value["pin"])
    return Input(acts, device_kid, lineage, next_, now, org, pin, synced_at, tip_statement, None)


def _result(enrolled, reason):
    return {"enrolled": enrolled, "reason": reason}


def _device(state, kid):
    """Step 5: the device `kid` of `state` must be active and accepted."""
    device = state.devices.get(kid)
    if device is None:
        raise errors.Refused("local_key_unknown")
    if device.status != "active":
        raise errors.Refused("local_key_not_active")
    if not device.accepted:
        raise errors.Refused("local_class_not_accepted")


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{enrolled, reason}` of `inp`. `vitni` is the verifier (CF-05); `allow_fixture` is false for
    the production build (CF-08)."""
    vitni = verifier.Memoized(vitni)
    try:
        pin, epochs, node = pinned.fold(inp.pin, inp.org, inp.lineage, inp.acts, reg, profiles, allow_fixture,
                                        vitni, render_size, inp.next, inp.store_reason)
        _device(node.state, inp.device_kid)
        rules_time.act_free_view(epochs[-1], pin, node, inp, vitni)
        if profiles.kind(pin.spec) == "fixture":
            raise errors.Refused("fixture_profile")
    except errors.Refused as err:
        return _result(False, err.code)
    except verifier.VerifierUnavailable:
        return _result(False, "verifier_unavailable")
    return _result(True, "ok")
