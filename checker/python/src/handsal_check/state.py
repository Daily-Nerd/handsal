"""The state at one node of an epoch (FO-26 `S_n`): members, devices, used link codes.

A state is a value: every change returns a new one, so the state of a node is never altered by a
later act. A removed device keeps its entry with status `removed` (FO-03). `accepted` is KC-04: the
device class is listed in the epoch policy `classes`; it is fixed when the device enters the state.

`keys_map` is the one projection of `devices` to the vitni `keys` map (FO-02): exactly the accepted
devices, `active` when active and `revoked` when removed. A person with no accepted device has no
entry. The `keys` output reads it whole. `keys_for` is that projection narrowed to one signer, what each fold
question carries; `has_entry` says whether a kid has an entry at all.
"""
from collections import namedtuple

from . import verifier

Device = namedtuple("Device", "person cls label sign agree status accepted")   # sign, agree: (x, y)


def point(obj):
    return (obj["x"], obj["y"])


def point_obj(pt):
    return {"x": pt[0], "y": pt[1]}


def new_device(entry, accepted):
    """An active `Device` from a genesis entry or an introducing body (`class`, `label`, `sign`, `agree`)."""
    return Device(entry["person"], entry["class"], entry["label"], point(entry["sign"]),
                  point(entry["agree"]), "active", accepted)


class State:
    __slots__ = ("members", "devices", "link_codes")

    def __init__(self, members, devices, link_codes=frozenset()):
        self.members = members          # {member id: role}
        self.devices = devices          # {kid: Device}
        self.link_codes = link_codes    # link_code_hash of every primary on the path

    @classmethod
    def from_document(cls, doc, accepted_classes):
        members = {m["id"]: m["role"] for m in doc["members"]}
        devices = {d["kid"]: new_device(d, d["class"] in accepted_classes) for d in doc["devices"]}
        return cls(members, devices)

    def with_member(self, member, role):
        return State({**self.members, member: role}, self.devices, self.link_codes)

    def with_device(self, kid, device):
        return State(self.members, {**self.devices, kid: device}, self.link_codes)

    def with_removed(self, kid):
        return self.with_device(kid, self.devices[kid]._replace(status="removed"))

    def with_link_code(self, code):
        return State(self.members, self.devices, self.link_codes | {code})

    def _entry(self, device):
        """The vitni `keys` entry `device` projects to, or None when it projects to none (not accepted, KC-04)."""
        if not device.accepted:
            return None
        return verifier.key_entry(point_obj(device.sign), "active" if device.status == "active" else "revoked")

    def keys_map(self):
        out = {}
        for kid, device in self.devices.items():
            entry = self._entry(device)
            if entry is not None:
                out.setdefault(device.person, {})[kid] = entry
        return out

    def keys_for(self, person, kid):
        """`keys_map` narrowed to the one entry vitni reads for a text signed by `kid` of `person`:
        `{person: {kid: entry}}`, or `{}` when the map has no such entry. One lookup, whatever the number of
        devices. Narrowing gives the verdict of the whole map because vitni resolves `keys[performer_id][kid]` and
        nothing else (CONTRACT section 7); the checker reads `kid` byte-exact from the header (`jws._HEADER`) and
        `performer_id` with the strict payload parser, which refuses a duplicate member. If either reading is
        relaxed, narrowing is no longer sound."""
        device = self.devices.get(kid)
        entry = None if device is None or device.person != person else self._entry(device)
        return {} if entry is None else {person: {kid: entry}}

    def has_entry(self, kid):
        """True iff `kid` has an entry in `keys_map`, under any person: an accepted device of this state."""
        device = self.devices.get(kid)
        return device is not None and self._entry(device) is not None

    def usable_devices(self, person):
        """The kids of `person` that are active and accepted in this state."""
        return [kid for kid, d in self.devices.items() if d.person == person and d.status == "active" and d.accepted]
