"""Vectors rem/*: `device.remove` (FO-11, FO-22, FO-27).

Hand-reviewed heuristic rows (checked against FO-22 and FO-27):
- rem/remove-already-removed: the second removal names a device that is not active in S_P,
  so it is not on the chain; the state stays at position 1.
- rem/remove-last-device: carol keeps her entry with status `removed` and no active device.
- rem/remove-unknown-kid: the kid is no device of any person, so the act is not on the chain.
- rem/self-removal-wrong-person: `body.person` is bob but the kid is alice2's, so the body
  condition fails although two persons signed.

rem/second-person-quorum-unmet is written by groups/quorum4.py (it needs the four-maintainer ORG4).
"""
import hashlib

from lib import keys, rows
from lib.rows import AB


def _alice2(c):
    c.device_add("alice2", AB)


def _after(build, *args, **kw):
    def run(c):
        build(c)
        c.device_remove(*args, ok=False, **kw)
    return run


def _three(c):
    for name in ("alice2", "alice3", "X1"):
        c.device_add(name, AB)
    c.device_remove("alice3", ("alice2", "X1"), short=True, ok=False)


def _fresh_cannot_remove_older(c):
    for name in ("alice2", "X1", "X2"):
        c.device_add(name, AB)
    c.device_remove("alice", ("X1", "X2"), short=True, ok=False)


def _fresh_quorum_ok(c):
    c.device_add("X1", AB)
    c.device_remove("alice", ("X1", "bob"))


def _already_removed(c):
    c.device_remove("carol", AB)
    c.device_remove("carol", AB, ok=False)


def _unknown_kid(c):
    unknown = keys.b64u(hashlib.sha256(b"no such device").digest())
    c.device_remove("carol", AB, ok=False, body_edit=lambda b: b.__setitem__("kid", unknown))


def _wrong_person(c):
    c.device_add("alice2", AB)
    c.device_remove("alice2", ("alice2", "bob"), ok=False,
                    body_edit=lambda b: b.__setitem__("person", "bob"))


def _target_is_endorser(c):
    c.device_add("bob2", ("bob", "alice"))
    c.device_remove("bob2", ("alice", "bob2"))


def _two_same_person(c):
    c.device_add("alice2", AB)
    c.device_add("alice3", AB)
    c.device_remove("alice", ("alice2", "alice3"), short=True, ok=False)


ROWS = (
    ("rem/cross-person-single-sig",
     lambda c: c.device_remove("bob", ("alice",), short=True, ok=False)),
    ("rem/endorser-is-signer",
     lambda c: c.device_remove("carol", ("alice", "alice"), short=True, ok=False)),
    ("rem/fresh-key-with-senior-ok", _three),
    ("rem/fresh-keys-cannot-remove-older", _fresh_cannot_remove_older),
    ("rem/fresh-keys-quorum-path-ok", _fresh_quorum_ok),
    ("rem/remove-already-removed", _already_removed),
    ("rem/remove-last-device", lambda c: c.device_remove("carol", AB)),
    ("rem/remove-unknown-kid", _unknown_kid),
    ("rem/second-person-quorum-ok", lambda c: c.device_remove("carol", AB)),
    ("rem/self-removal-ok", _after(_alice2, "alice2", ("alice2",), short=True)),
    ("rem/self-removal-wrong-person", _wrong_person),
    ("rem/target-is-endorser", _target_is_endorser),
    ("rem/thief-phone-alone", _after(_alice2, "alice", ("alice2",), short=True)),
    ("rem/two-devices-one-person-other-target",
     _after(_alice2, "bob", ("alice", "alice2"), short=True)),
    ("rem/two-devices-same-person-ok", _two_same_person),
)


def generate(ctx):
    rows.add_rows(ctx, ROWS)
