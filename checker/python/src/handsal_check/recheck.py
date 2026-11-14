"""`recheck-act` (VR-17): the time-free half of `check-act`, for an act a consumer stored.

A consumer keeps the full JWS of every act it accepted (VR-14) and runs this command at read time, so that
"this stored act is a human decision" rests on evidence an agent cannot mint (a signature by a key the
pinned fold gave a person) and not on an editable record of an earlier answer.

`parse_input` reads the inputs of `check-act` without the four that name a moment: `now`, `synced_at`, `seen`
and `tip_statement` are `malformed_input` in both builds, so a caller cannot think a clock or a store was
used. `pin` is an input of the conformance build only, as for `check-act` (CF-08).

`run` is `pipeline.judge` with the other `locate` and the other steps:

  1 to 6   the act by itself, the pin and the fold, exactly as `check-act` (a fork or later acts beyond the
           act's head do not stop it)
  head     the act's own `head` must be a position of the accepted chain, else `stale_view`; the state of that
           node is the state judged. Nothing newer is read.
  7 to 12  `rules.TIME_FREE`, the steps `check-act` runs, unchanged
  16       `rules.proven`: the key is accepted in that state

Not run: 13 time (`now`, expiry), 14 view and witness, 15 `duplicate_receipt`. The answer names what it
does not prove (`NOT_PROVEN`) and carries `rechecked`, never `valid`: a consumer that swaps one command for the
other reads no `valid` and fails closed.
"""
from collections import namedtuple

from . import checkact, errors, pipeline, render_genesis, rules

Input = namedtuple("Input", checkact.ACT_FIELDS)

TIMED_INPUTS = ("now", "seen", "synced_at", "tip_statement")

# What a `rechecked:true` leaves open (VR-17, section 14 L9). One list, sorted, in every answer.
NOT_PROVEN = ("expiry", "freshness", "order_of_arrival", "replay", "revocation_after_head")


def parse_input(value, conformance_build=True):
    """The `Input` of the command JSON `value` (VR-17), or raise Malformed."""
    if type(value) is not dict or any(key in value for key in TIMED_INPUTS):
        raise errors.Malformed()
    if ("pin" in value) != conformance_build:   # required here, refused in production
        raise errors.Malformed()
    return Input(**checkact.parse_act_fields(value, conformance_build))


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The `recheck-act` result for `inp`: `rechecked:true` with `ok`, or the first failing step."""
    got = pipeline.judge(inp, reg, profiles, allow_fixture, vitni, render_size,
                         locate=pipeline.head, steps=rules.RECHECK_STEPS)
    return {"class": got.cls, "not_proven": list(NOT_PROVEN), "reason": got.reason, "receipt_id": got.receipt,
            "rechecked": got.reason == "ok"}
