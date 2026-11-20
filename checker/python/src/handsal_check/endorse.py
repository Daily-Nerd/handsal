"""Verified texts, possession proofs and key uniqueness (FO-07, FO-08, FO-21, SG-09).

`verified` is the one test of whether a signature is real: some text of the group verifies with
vitni against the entry of its own signer in the state at the parent of the act the signature belongs
to, and S is low (VR-04). The state is that of the parent, so a removal only affects later positions
(FO-05). Each text is asked with the one entry `keys_for` gives for its own `(performer, kid)`, which
vitni reads and nothing else, so a question stays one entry whatever the size of the state. A signer with no entry
is not asked at all: its answer is `unknown_key` whatever the text.

`possession` is the proof of possession of FO-07: an endorsement of the introducing act, signed by
the new key, whose `performer_id` is the new key's person (ACT-13), verified against the parent state
plus the new key as active. It never counts toward a quorum.

`fresh_key` is the uniqueness rule of FO-07: the new kid and points equal no kid, signing or
agreement key of any device of the parent state (removed ones included), of any earlier epoch, or of
the epoch's relay key.
"""
from . import state as state_module
from . import verifier


def verified(epoch, group, keys_for):
    """True iff a text of `group` verifies with vitni against `keys_for(performer, kid)` of its own signer,
    and has a low S. `keys_for` is `State.keys_for` of the state at the parent, or the possession source."""
    method = group.act.method
    return any(verifier.is_low_s(copy.signature) and _answers_ok(epoch, copy, keys_for(copy.performer, copy.kid), method)
               for copy in group.copies)


def _answers_ok(epoch, copy, keys, method):
    """True iff vitni answers `ok` to `copy` under `keys`. Empty `keys` is never asked: vitni answers `unknown_key`
    to it (CONTRACT section 7 step 3), or refuses the text earlier (steps 1 and 2), and no step before the
    signature check can answer `ok`, so the answer is known and no question is spent on it."""
    return bool(keys) and epoch.vitni.verify(copy.jws, keys, method) == "ok"


def possessed(epoch, endorsement, state, person, kid, sign):
    """True iff the endorsement group `endorsement` is a proof of possession by the new key `kid` of `person`: it is
    signed by that key, names that person as performer, and verifies against the parent state plus the new key as
    active. It reads the memo of `epoch` and the group, so one text can be judged alone."""
    own = {person: {kid: verifier.key_entry(sign, "active")}}

    def keys_for(owner, key):
        return own if (owner, key) == (person, kid) else state.keys_for(owner, key)

    return (endorsement.act.kid == kid and endorsement.act.performer == person
            and verified(epoch, endorsement, keys_for))


def possession(epoch, group, state, person, kid, sign):
    """True iff the introducing act `group` has a proof of possession by the new key `kid` of `person`."""
    return any(possessed(epoch, endorsement, state, person, kid, sign)
               for endorsement in epoch.bag.endorsements_of(group.act))


def fresh_key(epoch, state, kid, sign, agree):
    """True iff the new `kid`, `sign` and `agree` (the point objects) are used by no device or relay key: each is
    asked of the state's own kids and points and of the earlier epochs' by membership, nothing is built."""
    # No relay means nothing to collide with. A kid or a point is never None, so (None, None) matches neither test.
    relay_kid, relay_point = epoch.relay if epoch.relay is not None else (None, None)
    if kid in state.devices or kid in epoch.earlier.kids or kid == relay_kid:
        return False
    return not any(pt in state.points or pt in epoch.earlier.points or pt == relay_point
                   for pt in (state_module.point(sign), state_module.point(agree)))
