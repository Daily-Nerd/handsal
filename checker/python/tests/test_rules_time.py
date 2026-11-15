"""T3.45 time rules and view rules, and the witness step (VR-11, VR-12, WT-04; VR-02 steps 13 and 14)."""
import unittest
from collections import namedtuple
from pathlib import Path

from handsal_check import encoding, errors, rules_time

from .act_builder import FakeVitni, head_of
from .checkact_world import EXPIRES, NOW, TS, Scenario, at, check
from .genesis_fixtures import policy, relay_witness
from .fold_world import World

SKEW, VALIDITY, VIEW_AGE = 300, 604800, 86400


def reason(s, act=None, **over):
    return check(s.value(act or s.verdict(), **over))["reason"]


class Time(unittest.TestCase):
    def test_ts_exactly_skew_ahead_is_valid_one_more_is_in_the_future(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(ts=at(-SKEW), extra={"expires": at(-3600)})), "ok")
        self.assertEqual(reason(s, s.verdict(ts=at(-SKEW - 1), extra={"expires": at(-3600)})), "ts_in_future")

    def test_expires_must_be_after_ts(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(extra={"expires": TS})), "bad_expiry")
        self.assertEqual(reason(s, s.verdict(extra={"expires": at(1800 + 1)})), "bad_expiry")

    def test_validity_is_at_most_the_policys_maximum(self):
        s = Scenario()
        from handsal_check import schema
        ts = schema.seconds(TS)
        import time
        fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        self.assertEqual(reason(s, s.verdict(extra={"expires": fmt(ts + VALIDITY)}), now=at(0)), "ok")
        self.assertEqual(reason(s, s.verdict(extra={"expires": fmt(ts + VALIDITY + 1)})), "validity_too_long")

    def test_expired_exactly_at_expires_and_valid_one_second_before(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(extra={"expires": NOW})), "expired")
        self.assertEqual(reason(s, s.verdict(extra={"expires": at(-1)})), "ok")

    def test_ts_in_the_future_comes_before_bad_expiry_before_validity_before_expired(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(ts=at(-SKEW - 1), extra={"expires": TS})), "ts_in_future")
        self.assertEqual(reason(s, s.verdict(extra={"expires": TS})), "bad_expiry")


class View(unittest.TestCase):
    def test_synced_at_ahead_of_now_by_more_than_the_skew_is_view_in_the_future(self):
        s = Scenario()
        self.assertEqual(reason(s, synced_at=at(-SKEW)), "ok")
        self.assertEqual(reason(s, synced_at=at(-SKEW - 1)), "view_in_future")

    def test_a_view_older_than_the_maximum_is_stale(self):
        s = Scenario()
        act = s.verdict(ts=at(VIEW_AGE + 2000), extra={"expires": at(-100)})
        self.assertEqual(reason(s, act, synced_at=at(VIEW_AGE)), "ok")
        self.assertEqual(reason(s, act, synced_at=at(VIEW_AGE + 1)), "stale_view")

    def test_a_head_that_is_no_position_of_the_chain_is_stale_view(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(head=head_of(encoding.hashstr(b"unknown")))), "stale_view")

    def test_a_head_older_than_the_tip_is_valid(self):
        s = Scenario()
        step = s.w.device_add("alice2", ("alice", "bob"))
        self.assertEqual(reason(s, s.verdict(), acts=step.acts), "ok")
        self.assertEqual(reason(s, s.verdict(head=head_of(step.id)), acts=step.acts), "ok")

    def test_a_head_of_another_epoch_is_stale_view(self):
        s = Scenario()
        other = World(name="OTHER")
        self.assertEqual(reason(s, s.verdict(head=head_of(other.id))), "stale_view")

    def test_time_is_judged_before_view_and_view_before_witness(self):
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(extra={"expires": NOW}), synced_at=at(-SKEW - 1)), "expired")
        self.assertEqual(reason(s, s.verdict(head=head_of(encoding.hashstr(b"x"))), tip_statement="junk"), "stale_view")


class Superseded(unittest.TestCase):
    """VR-12's first rule: a store that holds a valid successor of the pin cannot see what the new epoch removed,
    whatever the age of its view, so `epoch_superseded` comes before the age rules, in every witness mode."""

    def test_next_yes_is_epoch_superseded_and_next_no_is_the_view_as_before(self):   # VR-12 S5
        s = Scenario()
        self.assertEqual(reason(s, next="yes"), "epoch_superseded")
        self.assertEqual(reason(s, next="no"), "ok")

    def test_it_comes_before_view_in_the_future_stale_view_and_a_head_that_is_no_position(self):   # VR-12, order
        s = Scenario()
        self.assertEqual(reason(s, next="yes", synced_at=at(VIEW_AGE + 1)), "epoch_superseded")
        self.assertEqual(reason(s, next="yes", synced_at=at(-SKEW - 1)), "epoch_superseded")
        self.assertEqual(reason(s, s.verdict(head=head_of(encoding.hashstr(b"x"))), next="yes"), "epoch_superseded")
        self.assertEqual(reason(s, s.verdict(head=head_of(encoding.hashstr(b"x"))), next="no"), "stale_view")

    def test_the_time_rules_of_step_13_still_come_first(self):   # VR-02 step 13 before step 14
        s = Scenario()
        self.assertEqual(reason(s, s.verdict(extra={"expires": NOW}), next="yes"), "expired")

    def test_it_comes_before_the_witness_in_every_mode(self):   # VR-12, WT-07
        w = World(pol=policy(witness=relay_witness("3600")))
        s = Scenario(w)
        self.assertEqual(reason(s), "witness_missing")
        self.assertEqual(reason(s, next="yes"), "epoch_superseded")
        none = Scenario()
        self.assertEqual(reason(none, tip_statement="garbage", next="no"), "witness_unexpected")
        self.assertEqual(reason(none, tip_statement="garbage", next="yes"), "epoch_superseded")


class Witness(unittest.TestCase):
    def test_mode_none_rejects_any_statement(self):
        s = Scenario()
        self.assertEqual(reason(s, tip_statement="garbage"), "witness_unexpected")

    def test_mode_relay_needs_a_statement_and_vr_12_still_runs(self):
        w = World(pol=policy(witness=relay_witness("3600")))
        s = Scenario(w)
        self.assertEqual(reason(s), "witness_missing")
        self.assertEqual(reason(s, s.verdict(head=head_of(encoding.hashstr(b"x")))), "stale_view")

    def test_the_witness_comes_before_duplicate_receipt(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(reason(s, act, tip_statement="garbage", seen=[act.id]), "witness_unexpected")


class ActFreeView(unittest.TestCase):
    """SH5: the view rules that need no act and then the witness, in one function: `enrolled` step 6 and `head` step 5
    call it, and `check-act` keeps its own step 14 (the head rule sits between the age and the witness there)."""

    Pin = namedtuple("Pin", "org genesis")
    Inp = namedtuple("Inp", "now synced_at next tip_statement")

    def setUp(self):
        w = World(pol=policy(witness=relay_witness("3600")))
        self.epoch, self.pin = w.epoch(), self.Pin(w.org, w.id)
        self.node = self.epoch.root
        self.none = World().epoch()

    def call(self, epoch=None, tip_statement=None, **over):
        fields = dict(now=NOW, synced_at=NOW, next="no", tip_statement=tip_statement)
        fields.update(over)
        return rules_time.act_free_view(epoch or self.none, self.pin, self.node, self.Inp(**fields), FakeVitni())

    def reason(self, **kw):
        try:
            self.call(**kw)
        except errors.Refused as err:
            return err.code
        return "ok"

    def test_a_fresh_view_with_no_witness_is_ok(self):
        self.assertEqual(self.reason(), "ok")

    def test_the_rules_of_vr_12_come_in_order(self):
        self.assertEqual(self.reason(next="yes", synced_at=at(VIEW_AGE + 1)), "epoch_superseded")
        self.assertEqual(self.reason(synced_at=at(-SKEW - 1)), "view_in_future")
        self.assertEqual(self.reason(synced_at=at(VIEW_AGE + 1)), "stale_view")
        self.assertEqual(self.reason(synced_at=at(VIEW_AGE)), "ok")
        self.assertEqual(self.reason(synced_at=at(-SKEW)), "ok")

    def test_the_witness_of_the_epochs_mode_follows(self):
        self.assertEqual(self.reason(tip_statement="garbage"), "witness_unexpected")
        self.assertEqual(self.reason(epoch=self.epoch), "witness_missing")

    def test_the_view_rules_come_before_the_witness(self):
        self.assertEqual(self.reason(epoch=self.epoch, synced_at=at(VIEW_AGE + 1)), "stale_view")
        self.assertEqual(self.reason(tip_statement="garbage", next="yes"), "epoch_superseded")

    def test_the_two_act_free_callers_own_neither_the_view_rules_nor_the_witness(self):   # SH5: one owner
        src = Path(__file__).resolve().parents[1] / "src" / "handsal_check"
        for name in ("enrolled.py", "head.py"):
            text = (src / name).read_text()
            self.assertIn("rules_time.act_free_view(", text, name)
            for call in ("witness.check(", "fresh_view("):
                self.assertNotIn(call, text, (name, call))


if __name__ == "__main__":
    unittest.main()
