"""The expected fold output, authored from the spec (FO-01, FO-02, FO-03, ACT-08).

A `State` is the state at one node of an epoch: it starts from a genesis document
and is edited by the effects the spec gives to valid acts (a `device.add` adds an
accepted-or-not device, a `device.remove` marks one removed, `advance` moves the
tip). It never judges an act: a vector author states which acts are valid and
applies exactly those effects, so the anchor is independent of every checker
(CF-06). `output()` is the FO-01 object; `keys` is a projection of `devices`
computed in one function (FO-02).

Settled in the spec: a person with no accepted device has no entry in `keys`, not
even an empty object (FO-02). `tip.n` is a decimal string, like the input `at`
(FO-01, FO-16). `_tip_n` is the one place that form is written.
"""
import copy

from . import inputs, result


def _tip_n(n):
    return str(n)


class State:
    def __init__(self, doc, org=None):
        self.doc = doc
        self.policy = copy.deepcopy(doc["policy"])
        self.org = org or doc["org"] or inputs.doc_id(doc)
        self.genesis = inputs.doc_id(doc)
        self.tip_id = self.genesis
        self.n = 0
        self.members = {m["id"]: m["role"] for m in doc["members"]}  # role per person (FO-22)
        self.devices = {}
        for entry in doc["devices"]:
            self.add_device(entry["person"], entry)

    def accepted(self, cls):
        """KC-04: the class is listed in the epoch policy `classes` (GP-18 is not in play here)."""
        return cls in [c["class"] for c in self.policy["classes"]]

    def add_device(self, person, entry):
        """A device enters the state, active (FO-22 effect of device.add and member.add)."""
        for devices in self.devices.values():
            if entry["kid"] in devices:
                raise ValueError("kid already in the state: %s" % entry["kid"])
        self.devices.setdefault(person, {})[entry["kid"]] = {
            "accepted": self.accepted(entry["class"]), "agree": dict(entry["agree"]),
            "class": entry["class"], "label": entry["label"], "sign": dict(entry["sign"]),
            "status": "active"}

    def add_member(self, person, role):
        """A `member.add` creates the person (FO-10); its device follows through `add_device`."""
        self.members[person] = role

    def remove_device(self, kid):
        """The device keeps its entry with status `removed` (FO-03, FO-26)."""
        for devices in self.devices.values():
            if kid in devices:
                devices[kid]["status"] = "removed"
                return
        raise KeyError(kid)

    def advance(self, act_id):
        """A valid chain primary becomes the next node."""
        self.tip_id = act_id
        self.n += 1

    def snapshot(self):
        return copy.deepcopy(self)

    def keys(self):
        """FO-02: exactly the accepted devices; `revoked` when removed."""
        out = {}
        for person, devices in self.devices.items():
            mine = {kid: {"alg": "ES256", "crv": "P-256", "kty": "EC",
                          "status": "active" if d["status"] == "active" else "revoked",
                          "x": d["sign"]["x"], "y": d["sign"]["y"]}
                    for kid, d in devices.items() if d["accepted"]}
            if mine:  # FO-02: no accepted device, no entry (not even `{}`)
                out[person] = mine
        return out

    def output(self):
        return {"devices": copy.deepcopy(self.devices), "keys": self.keys(), "org": self.org,
                "org_name": self.doc["name"], "policy": copy.deepcopy(self.policy),
                "spec": self.doc["profile"],
                "tip": {"genesis": self.genesis, "id": self.tip_id, "n": _tip_n(self.n)}}


def anchor(state):
    """The `fold` result line of `state`."""
    return result.line(state.output())


def fork_anchor(parent, candidates):
    """The `fold` result of an unresolved fork (FO-01, FO-24): sorted candidates, no `keys`."""
    return result.line({"error": "fork", "fork": {"candidates": sorted(candidates),
                                                  "parent": parent}})
