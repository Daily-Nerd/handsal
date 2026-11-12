"""Vectors add/*: `device.add` (FO-07, FO-09, FO-22, FO-23).

Each row is a bag and the state the spec gives it. A valid act is applied; an act with
one defect sits in the bag with `ok=False` and moves nothing (FO-06). A new key's proof of
possession is an endorsement signed by that key with its person as performer (FO-07, ACT-13).

Not written: add/kid-removed-in-earlier-epoch (needs a genesis change, see the chg groups).
add/same-device-twice and add/ok-quorum-path have the same bag shape as add/ok and
add/single-signer-not-on-chain; the catalog gives each its own id.
"""
from lib import rows
from lib.rows import AB


def _ok(c):
    c.device_add("alice2", AB)


def _after_alice2(c, *args, **kw):
    c.device_add("alice2", AB)
    return c.device_add(*args, ok=False, **kw)


def _agree_reused(c):
    c.device_add("alice2", AB, ok=False,
                 body_edit=lambda b: b.__setitem__("agree", c.fx.key("carol", "agree").point()))


def _kid_reused_active(c):
    own = c.fx.key("alice")

    def edit(b):
        b["sign"], b["kid"] = own.point(), own.kid
    c.device_add("alice2", AB, ok=False, body_edit=edit)


def _kid_reused_removed(c):
    c.device_remove("carol", AB)
    c.device_add("carol", AB, ok=False)


def _signer_revoked(c):
    c.device_remove("bob", ("alice", "carol"))
    c.device_add("alice2", AB, ok=False)


def _signer_unaccepted(c):
    rows.with_dave(c)
    c.device_add("alice2", ("alice", "dave2"), ok=False)


ROWS = (
    ("add/ok", _ok),
    ("add/ok-quorum-path", _ok),
    ("add/ok-two-devices-same-person",
     lambda c: _after_alice2(c, "alice3", ("alice", "alice2"), short=True)),
    ("add/agree-reused", _agree_reused),
    ("add/cross-person", lambda c: c.device_add("bob2", ("alice", "carol"), ok=False)),
    ("add/kid-reused-active", _kid_reused_active),
    ("add/kid-reused-removed", _kid_reused_removed),
    ("add/no-pop", lambda c: c.device_add("alice2", AB, ok=False, pop=False)),
    ("add/pop-by-other-key", lambda c: c.device_add("alice2", AB, ok=False, pop_signer="bob")),
    ("add/pop-performer-mismatch",
     lambda c: c.device_add("alice2", AB, ok=False, pop_performer="bob")),
    ("add/pop-not-counted", lambda c: c.device_add("alice2", ("alice",), ok=False, short=True)),
    ("add/same-device-twice", lambda c: _after_alice2(c, "alice2", AB)),
    ("add/signer-revoked", _signer_revoked),
    ("add/signer-unaccepted-class", _signer_unaccepted),
    ("add/single-signer-not-on-chain",
     lambda c: c.device_add("alice2", ("alice",), ok=False, short=True)),
    ("add/stolen-key-alone-cannot-add",
     lambda c: _after_alice2(c, "X1", ("alice2",), short=True)),
    ("add/two-devices-one-person-other-person-target",
     lambda c: _after_alice2(c, "bob2", ("alice", "alice2"), short=True)),
)


def generate(ctx):
    rows.add_rows(ctx, ROWS)
