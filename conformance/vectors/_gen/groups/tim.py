"""Vectors tim/*: the time rules of VR-11 (policy `clock_skew_s` 300, `max_validity_s` 604800).

Each row is an approve by alice whose `ts` or `expires` is moved to the boundary under test;
the boundary itself is valid, one second beyond it is the named reason. NOW is
2026-11-08T12:00:00Z and the default `ts` is NOW minus 60 s.
"""
from lib import base, checkrows

NOW = base.NOW
TS = base.shift(NOW, -60)
ROWS = (
    ("tim/expired-at-now", "expired", {"expires": NOW}),
    ("tim/expires-before-ts", "bad_expiry", {"expires": base.shift(TS, -1)}),
    ("tim/expires-equal-ts", "bad_expiry", {"expires": TS}),
    ("tim/one-second-left-ok", "ok", {"expires": base.shift(NOW, 1)}),
    ("tim/ts-future-by-skew-ok", "ok", {"ts": base.shift(NOW, 300)}),
    ("tim/ts-future-by-skew-plus-1", "ts_in_future", {"ts": base.shift(NOW, 301)}),
    ("tim/validity-exactly-max-ok", "ok", {"expires": base.shift(TS, 604800)}),
    ("tim/validity-max-plus-1", "validity_too_long", {"expires": base.shift(TS, 604801)}),
)


def generate(ctx):
    for name, reason, kwargs in ROWS:
        checkrows.row(ctx, name, ctx.fixtures.approve(**kwargs), reason, signers=["alice"])
