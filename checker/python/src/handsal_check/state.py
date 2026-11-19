"""The state at one node of an epoch (FO-26 `S_n`): members, devices, used link codes.

A state is a value: every change returns a new one, so the state of a node is never altered by a
later act. Its maps are `Shared`: a change copies a constant part of a map and shares the rest with the state it
came from, so the states of a tree of N nodes hold O(N) entries and not O(N squared). A removed device keeps its
entry with status `removed` (FO-03). `accepted` is KC-04: the device class is listed in the epoch policy
`classes`; it is fixed when the device enters the state.

`keys_map` is the one projection of `devices` to the vitni `keys` map (FO-02): exactly the accepted
devices, `active` when active and `revoked` when removed. A person with no accepted device has no
entry. The `keys` output reads it whole. `keys_for` is that projection narrowed to one signer, what each fold
question carries; `has_entry` says whether a kid has an entry at all.
"""
import binascii
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


WIDTH = 64


def _slot(key):
    """The bucket of `key`: a CRC of its repr, so the bucket, and with it the order a map is read in, is the same in
    every process (the builtin is salted per process, so it is not used)."""
    return binascii.crc32(repr(key).encode()) % WIDTH


class Shared:
    """A map that is a value: `set` returns a new map that shares every bucket but one with this one, which is never
    altered. A change copies the WIDTH slots and one bucket, not the whole map: the input cap (`ijson.MAX_INPUT`)
    bounds the entries of a map, so that is a constant. Read it like a dict: `get`, `in`, `[]`, iteration, `items`,
    `values`, `len`, `==`. Keys are read in bucket order, a function of the keys only."""
    __slots__ = ("_buckets", "_len")

    def __init__(self, buckets=None, size=0):
        self._buckets = _EMPTY if buckets is None else buckets
        self._len = size

    def get(self, key, default=None):
        return self._buckets[_slot(key)].get(key, default)

    def __contains__(self, key):
        return key in self._buckets[_slot(key)]

    def __getitem__(self, key):
        return self._buckets[_slot(key)][key]

    def set(self, key, value):
        """This map with `key` bound to `value`."""
        slot = _slot(key)
        old = self._buckets[slot]
        buckets = list(self._buckets)
        buckets[slot] = {**old, key: value}
        return Shared(tuple(buckets), self._len + (key not in old))

    def __len__(self):
        return self._len

    def __iter__(self):
        for bucket in self._buckets:
            yield from bucket

    def keys(self):
        return list(self)

    def items(self):
        return [item for bucket in self._buckets for item in bucket.items()]

    def values(self):
        return [value for bucket in self._buckets for value in bucket.values()]

    def __eq__(self, other):
        return dict(self.items()) == (dict(other.items()) if hasattr(other, "items") else other)

    def __repr__(self):
        return "Shared(%r)" % dict(self.items())


_EMPTY = tuple({} for _ in range(WIDTH))


class State:
    __slots__ = ("members", "devices", "link_codes")

    def __init__(self, members, devices, link_codes=()):
        """The state of plain mappings: `members` `{member id: role}`, `devices` `{kid: Device}` and the iterable
        `link_codes` (the link_code_hash of every primary on the path). Each lands through the same `set` a
        change uses."""
        self.members, self.devices, self.link_codes = Shared(), Shared(), Shared()
        for member, role in members.items():
            self.members = self.members.set(member, role)
        for kid, device in devices.items():
            self.devices = self.devices.set(kid, device)
        for code in link_codes:
            self.link_codes = self.link_codes.set(code, True)

    def _with(self, members=None, devices=None, link_codes=None):
        """This state with the maps given replaced: no map is copied, each is shared or is the one given."""
        new = State.__new__(State)
        new.members = self.members if members is None else members
        new.devices = self.devices if devices is None else devices
        new.link_codes = self.link_codes if link_codes is None else link_codes
        return new

    @classmethod
    def from_document(cls, doc, accepted_classes):
        members = {m["id"]: m["role"] for m in doc["members"]}
        devices = {d["kid"]: new_device(d, d["class"] in accepted_classes) for d in doc["devices"]}
        return cls(members, devices)

    def with_member(self, member, role):
        return self._with(members=self.members.set(member, role))

    def with_device(self, kid, device):
        return self._with(devices=self.devices.set(kid, device))

    def with_removed(self, kid):
        return self.with_device(kid, self.devices[kid]._replace(status="removed"))

    def with_link_code(self, code):
        return self._with(link_codes=self.link_codes.set(code, True))

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
