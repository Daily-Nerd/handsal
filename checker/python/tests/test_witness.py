"""T3.39 and T3.40 the witness (WT-03 to WT-10): mode `none`, then mode `relay` in the order of WT-05.

Steps 1 to 6a (T3.39): missing, malformed, key, signature, org, epoch, superseded. Steps 7 to 9 (T3.40):
future, stale, behind. Each defect is the only one in its test, and each pair of adjacent steps has an
ordering test, so the first failure wins and no step reads a field before the signature vouches for it.
"""
import unittest

from handsal_check import encoding, errors, verifier, witness

from .act_builder import BAD, HIGH, FakeVitni
from .fold_world import World
from .genesis_fixtures import KEYS, policy, relay_witness
from .witness_fixtures import RELAY_KID, statement

NOW = "2026-11-08T12:00:00Z"
MAX_AGE = 3600
SKEW = 300


def fresh_ts(delta=60):
    """`ts` that many seconds before NOW."""
    import calendar
    import time
    t = calendar.timegm(time.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ")) - delta
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Fixture:
    def __init__(self, age=str(MAX_AGE)):
        self.w = World(pol=policy(witness=relay_witness(age)))
        self.epoch = self.w.epoch()
        self.none = World().epoch()
        self.org = self.w.org
        self.genesis = self.w.id

    def statement(self, **over):
        fields = dict(epoch=self.genesis, tip=self.genesis, org=self.org, ts=fresh_ts())
        fields.update(over)
        return statement(**fields)

    def context(self, positions=None, now=NOW, epoch=None):
        return witness.Context(epoch or self.epoch, self.org, self.genesis, now,
                               frozenset([self.genesis]) if positions is None else positions)


F = Fixture()


def check(text, ctx=None, vitni=None):
    try:
        witness.check(text, ctx or F.context(), vitni or FakeVitni())
    except errors.Refused as err:
        return err.code
    return None


class ModeNone(unittest.TestCase):
    def ctx(self):
        return witness.Context(F.none, F.org, F.genesis, NOW, frozenset())

    def test_null_is_fine(self):
        self.assertIsNone(check(None, self.ctx()))

    def test_any_statement_is_unexpected_and_is_not_parsed(self):
        for text in (F.statement().jws, "garbage", "", "a.b.c"):
            self.assertEqual(check(text, self.ctx()), "witness_unexpected", text)

    def test_the_verifier_is_never_asked(self):
        vitni = FakeVitni()
        check(F.statement().jws, self.ctx(), vitni)
        self.assertEqual(vitni.calls, [])


class RelayOrder(unittest.TestCase):
    def test_a_good_statement_passes(self):
        self.assertIsNone(check(F.statement().jws))

    def test_1_a_missing_statement(self):
        self.assertEqual(check(None), "witness_missing")

    def test_2_a_malformed_statement(self):
        self.assertEqual(check("junk"), "witness_malformed")
        self.assertEqual(check(F.statement(next="maybe").jws), "witness_malformed")

    def test_3_the_header_kid_must_be_the_relays(self):
        other = F.statement(kid=KEYS["bob.sign"]["kid"])
        self.assertEqual(check(other.jws), "witness_key_mismatch")

    def test_4_a_bad_signature(self):
        self.assertEqual(check(F.statement(sig=BAD).jws), "witness_bad_signature")

    def test_4_a_high_s_signature_is_a_bad_signature_though_vitni_accepts_it(self):
        self.assertEqual(check(F.statement(sig=HIGH).jws), "witness_bad_signature")

    def test_4_vitni_is_asked_with_the_pinned_relay_key_and_method(self):
        vitni = FakeVitni()
        text = F.statement().jws
        check(text, vitni=vitni)
        key = KEYS["relay-fixture"]
        self.assertEqual(vitni.calls, [(text, '{"relay": {"%s": {"alg": "ES256", "crv": "P-256", "kty": "EC", '
                                              '"status": "active", "x": "%s", "y": "%s"}}}' % (RELAY_KID, key["x"], key["y"]),
                                        "local:handsal.relay.tip")])

    def test_4_a_verifier_that_cannot_answer_is_not_a_pass(self):
        from .act_builder import Unavailable
        with self.assertRaises(verifier.VerifierUnavailable):
            witness.check(F.statement().jws, F.context(), Unavailable())

    def test_5_the_org_must_be_the_pins(self):
        self.assertEqual(check(F.statement(org=encoding.hashstr(b"other")).jws), "witness_org_mismatch")

    def test_6_the_epoch_must_be_the_pins_genesis(self):
        self.assertEqual(check(F.statement(epoch=encoding.hashstr(b"newer")).jws), "witness_epoch_mismatch")

    def test_6a_a_superseded_epoch(self):
        self.assertEqual(check(F.statement(next="yes").jws), "witness_superseded")

    def test_each_adjacent_pair_returns_the_earlier_code(self):
        wrong_org, wrong_epoch = encoding.hashstr(b"other"), encoding.hashstr(b"newer")
        pairs = [
            ("malformed before key", F.statement(kid=KEYS["bob.sign"]["kid"], next="maybe"), "witness_malformed"),
            ("key before signature", F.statement(kid=KEYS["bob.sign"]["kid"], sig=BAD), "witness_key_mismatch"),
            ("signature before org", F.statement(org=wrong_org, sig=BAD), "witness_bad_signature"),
            ("org before epoch", F.statement(org=wrong_org, epoch=wrong_epoch), "witness_org_mismatch"),
            ("epoch before superseded", F.statement(epoch=wrong_epoch, next="yes"), "witness_epoch_mismatch"),
        ]
        for label, act, expected in pairs:
            self.assertEqual(check(act.jws), expected, label)

    def test_superseded_is_judged_before_the_time_checks(self):
        old = F.statement(next="yes", ts=fresh_ts(MAX_AGE + 1000))
        self.assertEqual(check(old.jws), "witness_superseded")

    def test_no_field_of_an_unsigned_statement_decides_before_the_signature(self):
        # a forged statement with the wrong org and a bad signature is `bad_signature`, never `org_mismatch`
        forged = F.statement(org=encoding.hashstr(b"other"), epoch=encoding.hashstr(b"x"), next="yes", sig=BAD)
        self.assertEqual(check(forged.jws), "witness_bad_signature")

    def test_the_successor_is_never_looked_for_in_the_bag(self):
        # the context carries no bag at all: a `no` statement for the pinned epoch passes (WT-10)
        self.assertIsNone(check(F.statement(next="no").jws))


class RelayTime(unittest.TestCase):
    def test_7_a_statement_exactly_skew_ahead_is_valid_one_more_is_in_the_future(self):
        self.assertIsNone(check(F.statement(ts=fresh_ts(-SKEW)).jws))
        self.assertEqual(check(F.statement(ts=fresh_ts(-SKEW - 1)).jws), "witness_in_future")

    def test_8_exactly_the_maximum_age_is_valid_one_more_is_stale(self):
        self.assertIsNone(check(F.statement(ts=fresh_ts(MAX_AGE)).jws))
        self.assertEqual(check(F.statement(ts=fresh_ts(MAX_AGE + 1)).jws), "stale_witness")

    def test_9_a_tip_that_is_not_a_position_of_the_chain_is_behind(self):
        self.assertEqual(check(F.statement(tip=encoding.hashstr(b"t5")).jws), "behind_witness")

    def test_9_a_tip_older_than_the_consumers_is_valid(self):
        ahead = frozenset([F.genesis, encoding.hashstr(b"t1"), encoding.hashstr(b"t2")])
        self.assertIsNone(check(F.statement(tip=F.genesis).jws, F.context(positions=ahead)))

    def test_9_the_tip_may_be_any_position_of_the_chain_not_only_the_last(self):
        t1 = encoding.hashstr(b"t1")
        self.assertIsNone(check(F.statement(tip=t1).jws, F.context(positions=frozenset([F.genesis, t1]))))

    def test_the_time_steps_run_in_order(self):
        junk = encoding.hashstr(b"junk")
        self.assertEqual(check(F.statement(ts=fresh_ts(-SKEW - 1), tip=junk).jws), "witness_in_future")
        self.assertEqual(check(F.statement(ts=fresh_ts(MAX_AGE + 1), tip=junk).jws), "stale_witness")

    def test_a_statement_never_adds_acceptance_only_a_refusal(self):
        # no input of the statement changes the return value on success: it is None, never a verdict
        self.assertIsNone(witness.check(F.statement().jws, F.context(), FakeVitni()))

    def test_the_max_tip_age_is_the_policys(self):
        short = Fixture("60")
        ok = short.statement(ts=fresh_ts(60))
        stale = short.statement(ts=fresh_ts(61))
        self.assertIsNone(check(ok.jws, short.context()))
        self.assertEqual(check(stale.jws, short.context()), "stale_witness")


if __name__ == "__main__":
    unittest.main()
