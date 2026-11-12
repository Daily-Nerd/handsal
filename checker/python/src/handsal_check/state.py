"""The state at one node of an epoch (FO-26 `S_n`): members, devices, used link codes.

A state is a value: every change returns a new one, so the state of a node is never altered by a
later act. A removed device keeps its entry with status `removed` (FO-03). `accepted` is KC-04: the
device class is listed in the epoch policy `classes`; it is fixed when the device enters the state.

`keys_map` is the one projection of `devices` to the vitni `keys` map (FO-02): exactly the accepted
devices, `active` when active and `revoked` when removed. A person with no accepted device has no
entry. Every verification, and the `keys` output, reads it.
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

    def keys_map(self):
        out = {}
        for kid, device in self.devices.items():
            if device.accepted:
                status = "active" if device.status == "active" else "revoked"
                out.setdefault(device.person, {})[kid] = verifier.key_entry(point_obj(device.sign), status)
        return out

    def usable_devices(self, person):
        """The kids of `person` that are active and accepted in this state."""
        return [kid for kid, d in self.devices.items() if d.person == person and d.status == "active" and d.accepted]
