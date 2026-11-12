"""Vectors quo/*: quorum authority and counted signatures (FO-13, FO-22, FO-23, FO-27).

Persons are counted once however many devices sign; a person with no active accepted key
has no signature; a key that is not accepted, or whose person holds no listed role, counts
for nothing; device.add also needs a key of the target person when that person has one.

quo/two-lost-persons-unreachable is the change half only (`genesis_change_unauthorized`) and
is not written yet: it needs a genesis change (see the chg groups). Its fold half, bob and
carol removed and alice alone, is quo/one-left-unreachable.
quo/policy-swap-2-vs-3 and quo/raised-floor-3-two-rejected are written by groups/quorum4.py (they need ORG4).
"""
from lib import rows
from lib.rows import AB, BC


def _two_alice(c):
    c.device_add("alice2", AB)
    c.device_add("alice3", AB)


def _consent_removed_key(c):
    c.device_add("alice2", AB)
    c.device_remove("alice", BC)
    c.device_add("X1", ("bob", "carol", "alice"), ok=False)


def _devices_not_votes(c):
    _two_alice(c)
    c.device_remove("carol", ("alice", "alice2", "alice3"), short=True, ok=False)


def _readded_by_others(c):
    c.device_remove("carol", AB)
    c.device_add("carol2", AB)
    c.device_add("alice2", ("alice", "carol2"))


def _removed_no_vote(c):
    c.device_remove("carol", AB)
    c.device_add("alice2", ("alice", "carol"), ok=False)


def _one_left(c):
    c.device_remove("carol", AB)
    c.device_remove("bob", AB)
    c.device_add("alice2", ("alice",), short=True, ok=False)


def _unaccepted_primary(c):
    rows.with_dave(c)
    c.device_add("alice2", ("dave2", "alice", "bob"), ok=False)


def _primary_without_role(c):
    c.member_add("dave", AB, role="member")
    c.device_add("dave2", ("dave", "alice", "bob"))


def _single_person(c):
    _two_alice(c)
    c.device_remove("carol", ("alice", "alice2", "alice3"), short=True, ok=False)


def _single_member_add(c):
    c.device_add("alice2", AB)
    c.member_add("dave", ("alice", "alice2"), role="member", short=True, ok=False)


def _surplus_no_role(c):
    c.member_add("dave", AB, role="member")
    c.device_add("X1", ("alice", "bob", "dave"))


def _surplus_removed_later(c):
    c.device_add("bob2", BC)
    c.device_add("X1", ("alice", "bob", "bob2"))
    c.device_remove("bob2", ("alice", "carol"))


ROWS = (
    ("quo/device-add-consent-from-removed-key-invalid", _consent_removed_key),
    ("quo/device-add-needs-own-key", lambda c: c.device_add("X1", BC, ok=False)),
    ("quo/device-add-own-key-as-endorser-ok", lambda c: c.device_add("X1", ("bob", "alice"))),
    ("quo/devices-not-votes", _devices_not_votes),
    ("quo/endorser-no-role-not-counted",
     lambda c: (c.member_add("dave", AB, role="member"),
                c.device_remove("carol", ("alice", "dave"), ok=False))),
    ("quo/last-device-readded-by-others", _readded_by_others),
    ("quo/last-device-removed-no-vote", _removed_no_vote),
    ("quo/one-left-unreachable", _one_left),
    ("quo/primary-unaccepted-key-invalid", _unaccepted_primary),
    ("quo/primary-without-role-ok", _primary_without_role),
    ("quo/remove-then-add-replaces-keys",
     lambda c: (c.device_remove("alice", BC), c.device_add("X1", BC))),
    ("quo/role-not-in-from",
     lambda c: (c.member_add("dave", AB, role="member"),
                c.device_add("X1", ("alice", "dave"), ok=False))),
    ("quo/self-removal-needs-second-person",
     lambda c: (c.device_add("alice2", AB), c.device_remove("alice2", ("alice2", "bob")))),
    ("quo/single-person-act-rejected", _single_person),
    ("quo/single-person-member-add-rejected", _single_member_add),
    ("quo/surplus-endorsement-same-output",
     lambda c: c.device_add("X1", ("alice", "bob", "carol"))),
    ("quo/surplus-no-role-ignored", _surplus_no_role),
    ("quo/surplus-removed-later-no-effect", _surplus_removed_later),
    ("quo/two-left-reachable",
     lambda c: (c.device_remove("carol", AB), c.member_add("dave", AB, role="member"))),
    ("quo/two-persons-device-add-ok", lambda c: c.device_add("X1", AB)),
)


def generate(ctx):
    rows.add_rows(ctx, ROWS)
