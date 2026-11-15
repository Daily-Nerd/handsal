"""The `head` command (VR-19): the head (ACT-08) a producer of an act names, so it need not rebuild the chain.

`parse_input` turns the command JSON into an `Input` or raises `Malformed`: the inputs of `enrolled` (GP-13)
without `device_kid`, so `production.fill` serves it unchanged. `run` evaluates the steps in order and returns
`{head, reason}` for the first failure (`head` null), `{head: {id, kind: "chain"}, reason: "ok"}` if there is none:

  1 to 3  the pin checks of VR-02 step 6, (a) to (h), with their codes, the store reason at (f) in production
                                                                          (`pinned.folded`)
  4       the fold succeeds, else its error code, `fork` included (`epoch_superseded` where `next` is "yes",
          a fork being a verdict about an open tip)                        (`pinned.tip`)
  5       the act-free view of VR-12 then the witness of the policy's mode (`rules_time.act_free_view`)

`ok` names the tip of the pinned epoch's accepted chain: the receipt id of its last primary, or the current
genesis document hash where the chain is empty (ACT-08, position 0). These are `check-act`'s steps 6 and 14 with
the act removed, so the equality of I12 holds by construction and a test over the `check-act` worlds keeps it. No
fixture step and no new reason code: the conformance build answers under the fixture profile and the production
build refuses it at step 6 (f), and `head` proves nothing about a person.

`pin`, `now` and the store's content (`acts`, `lineage`, `next`, `synced_at`, `tip_statement`) are inputs of the
conformance build only (CF-08, CF-09): with `conformance_build=False` an input that carries any is
`malformed_input` and the build fills them in-process (`Input._replace`), the store's failure as `store_reason`.
"""
from collections import namedtuple

from . import errors, foldcmd, pinfile, pinned, render_genesis, rules_time, schema, verifier

Input = namedtuple("Input", "acts lineage next now org pin synced_at tip_statement store_reason")


def _malformed():
    return errors.Malformed()


def parse_input(value, conformance_build=True):
    """The `Input` of the command JSON `value` (VR-19), or raise Malformed."""
    if type(value) is not dict:
        raise _malformed()
    for key in ("pin", "now"):
        if (key in value) != conformance_build:   # required here, refused in production
            raise _malformed()
    acts, lineage = foldcmd.read_chain(value, conformance_build)
    org = value.get("org")
    if type(org) is not str or not schema.is_hashstr(org):
        raise _malformed()
    synced_at, next_, tip_statement = foldcmd.read_view(value, conformance_build)
    now = pin = None
    if conformance_build:
        now = value["now"]
        if type(now) is not str or not schema.is_time(now):
            raise _malformed()
        pin = pinfile.Probe.from_json(value["pin"])
    return Input(acts, lineage, next_, now, org, pin, synced_at, tip_statement, None)


def _result(found, reason):
    return {"head": None if found is None else {"id": found, "kind": "chain"}, "reason": reason}


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `{head, reason}` of `inp`. `vitni` is the verifier (CF-05); `allow_fixture` is false for the production
    build (CF-08)."""
    vitni = verifier.Memoized(vitni)
    try:
        pin, epochs = pinned.folded(inp.pin, inp.org, inp.lineage, inp.acts, reg, profiles, allow_fixture,
                                    vitni, render_size, inp.store_reason)
        epoch, node = pinned.tip(epochs, inp.next)
        rules_time.act_free_view(epoch, pin, node, inp, vitni)
    except errors.Refused as err:
        return _result(None, err.code)
    except verifier.VerifierUnavailable:
        return _result(None, "verifier_unavailable")
    return _result(node.id, "ok")
