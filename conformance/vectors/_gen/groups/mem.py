"""Vectors mem/*: `member.add` (FO-10, FO-22 S7 and S8, FO-23).

The fold output has no member list, so a role is observed through what the member can
then do: mem/roles-from-quorum adds dave as a maintainer, and dave's signature then counts
toward a removal. mem/endorser-no-role adds dave as a plain member, whose endorsement does
not count.

Not written: mem/id-reused-across-epochs (needs a genesis change, see the chg groups).
"""
from lib import rows
from lib.rows import AB


def _roles_from_quorum(c):
    c.member_add("dave", AB, role="maintainer")
    c.device_remove("carol", ("dave", "alice"))


def _endorser_no_role(c):
    c.member_add("dave", AB, role="member")
    c.member_add("frank", ("alice", "dave"), role="member", ok=False)


def _two_devices(c):
    c.device_add("alice2", AB)
    c.member_add("dave", ("alice", "alice2"), role="member", short=True, ok=False)


ROWS = (
    ("mem/ok-2-of-3", lambda c: c.member_add("dave", AB, role="member")),
    ("mem/roles-from-quorum", _roles_from_quorum),
    ("mem/endorser-no-role", _endorser_no_role),
    ("mem/id-reused",
     lambda c: c.member_add("dave", AB, role="maintainer", member="alice", ok=False)),
    ("mem/no-pop", lambda c: c.member_add("dave", AB, role="member", pop=False, ok=False)),
    ("mem/one-of-3",
     lambda c: c.member_add("dave", ("alice",), role="member", short=True, ok=False)),
    ("mem/two-devices-one-person", _two_devices),
)


def generate(ctx):
    rows.add_rows(ctx, ROWS)
