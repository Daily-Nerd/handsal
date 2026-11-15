"""Builders for genesis documents in tests: ORG, its policy and its devices.

Built from the fixture keys only. Nothing here calls the checker's validators, so a
document is valid because of how it is built, and each test breaks exactly one thing.
"""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]


def point(name):
    return {"x": KEYS[name]["x"], "y": KEYS[name]["y"]}


def device(name, person=None, cls="apple-se-bio", label="laptop"):
    """The genesis entry of the fixture device `name` ("alice", "bob2", "alice-pin" ...)."""
    base = name.split("-")[0] if name.endswith("-pin") else name
    person = person or base.rstrip("0123456789")
    return {"agree": point(name + ".agree"), "class": cls, "kid": KEYS[name + ".sign"]["kid"],
            "label": label, "person": person, "sign": point(name + ".sign")}


def policy(persons="2", witness=None, roles=("maintainer", "member"), rule_roles=("maintainer",),
           classes=(("apple-se-bio", "biometric_only"),), relays=("r.example",)):
    rule = {"persons": persons, "roles": list(rule_roles)}
    return {
        "classes": [{"class": c, "user_verification": uv} for c, uv in classes],
        "freshness": {"clock_skew_s": "300", "max_validity_s": "604800", "max_view_age_s": "86400"},
        "relays": list(relays),
        "roles": list(roles),
        "rules": {"chain.resolve": dict(rule), "device.remove": dict(rule),
                  "genesis.change": dict(rule), "member.add": dict(rule)},
        "v": "handsal-policy/1",
        "witness": witness or {"mode": "none"},
    }


def org(profile, people=("alice", "bob", "carol"), devices=None, pol=None, name="ORG"):
    """An original document (no `head`): `people` are maintainers with one device each."""
    devices = devices if devices is not None else [device(p) for p in people]
    return {
        "devices": sorted(devices, key=lambda d: d["kid"]),
        "members": [{"id": p, "role": "maintainer"} for p in sorted(people)],
        "name": name, "org": None,
        "policy": pol or policy(),
        "prev": None, "profile": profile, "v": "handsal-genesis/1",
    }


def change(profile, org_id, prev, head, **kw):
    doc = org(profile, **kw)
    doc["org"], doc["prev"], doc["head"] = org_id, prev, head
    return doc


def relay_witness(max_tip_age="3600"):
    key = KEYS["relay-fixture"]
    return {"max_tip_age_s": max_tip_age, "mode": "relay", "relay_kid": key["kid"],
            "relay_pub_jwk": {"crv": "P-256", "kty": "EC", "x": key["x"], "y": key["y"]}}


def edit(doc, path, value=None, delete=False):
    """A deep copy of `doc` with the value at `path` replaced, or the key deleted."""
    out = copy.deepcopy(doc)
    node = out
    for step in path[:-1]:
        node = node[step]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return out
