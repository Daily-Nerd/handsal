"""Verified texts, possession proofs and key uniqueness (FO-07, FO-08, FO-21, SG-09).

`verified` is the one test of whether a signature is real: some text of the group verifies with
vitni against the entry of its own signer in the state at the parent of the act the signature belongs
to, and S is low (VR-04). The state is that of the parent, so a removal only affects later positions
(FO-05). Each text is asked with the one entry `keys_for` gives for its own `(performer, kid)`, which
vitni reads and nothing else, so a question stays one entry whatever the size of the state.

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
    return any(verifier.is_low_s(copy.signature)
               and epoch.vitni.verify(copy.jws, keys_for(copy.performer, copy.kid), method) == "ok"
               for copy in group.copies)


def possession(epoch, group, state, person, kid, sign):
    """True iff the introducing act `group` has a proof of possession by the new key `kid` of `person`."""
    own = {person: {kid: verifier.key_entry(sign, "active")}}

    def keys_for(owner, key):
        return own if (owner, key) == (person, kid) else state.keys_for(owner, key)

    for endorsement in epoch.bag.endorsements_of(group.act):
        if (endorsement.act.kid == kid and endorsement.act.performer == person
                and verified(epoch, endorsement, keys_for)):
            return True
    return False


def fresh_key(epoch, state, kid, sign, agree):
    """True iff the new `kid`, `sign` and `agree` (the point objects) are used by no device or relay key."""
    used_kids = set(state.devices) | epoch.earlier.kids
    used_points = set(epoch.earlier.points)
    for device in state.devices.values():
        used_points.update((device.sign, device.agree))
    if epoch.relay is not None:
        used_kids.add(epoch.relay[0])
        used_points.add(epoch.relay[1])
    new_points = {state_module.point(sign), state_module.point(agree)}
    return kid not in used_kids and not new_points & used_points
