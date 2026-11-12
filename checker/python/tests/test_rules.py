"""T3.42 check-act pipeline from the fold on (VR-01, VR-02 steps 6 (i) to 10 and 16): the input, the fold,
`org_mismatch`, vitni verify with the right keys map, `high_s`, `unproven_class`, and `class`."""
import unittest

from handsal_check import encoding, rules, verifier

from .act_builder import BAD, HIGH, FakeVitni, Unavailable, kid_of
from .checkact_world import ALL, APPROVE, Scenario, Stub, check, dave_world
from .genesis_fixtures import KEYS


def ok(receipt):
    return {"class": "apple-se-bio", "reason": "ok", "receipt_id": receipt, "valid": True}


class Valid(unittest.TestCase):
    def test_a_fully_checked_approve_is_valid_with_its_class(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(check(s.value(act)), ok(act.id))

    def test_the_rules_module_names_every_step_from_7_on(self):
        self.assertEqual([step.__name__ for step in rules.STEPS], ["org", "relay", "verify", "low_s", "identity",
                         "request", "inputs", "outputs", "time", "view", "witness", "duplicate", "proven"])


class Fold(unittest.TestCase):
    def test_a_fold_error_is_the_reason_and_class_is_null(self):
        s = Scenario()
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        act = s.verdict()
        self.assertEqual(check(s.value(act)), {"class": None, "reason": "genesis_unsigned", "receipt_id": act.id, "valid": False})

    def test_a_verifier_that_cannot_answer_in_the_fold_is_verifier_unavailable(self):
        s = Scenario()
        act = s.verdict()
        got = check(s.value(act), Unavailable())
        self.assertEqual((got["reason"], got["valid"], got["class"]), ("verifier_unavailable", False, None))

    def test_a_frozen_bag_is_fork_and_it_precedes_vitni(self):
        s = Scenario()
        c1 = s.w.device_add("alice2", ("alice", "bob"))
        c2 = s.w.device_add("alice3", ("alice", "carol"))
        act = s.verdict(sig=BAD)
        vitni = FakeVitni()
        got = check(s.value(act, acts=c1.acts + c2.acts), vitni)
        self.assertEqual((got["reason"], got["class"]), ("fork", None))
        self.assertEqual([c for c in vitni.calls if c[2] == APPROVE], [])   # vitni was never asked about the act


class OrgMismatch(unittest.TestCase):
    def test_the_acts_org_must_be_the_pins_and_class_is_filled_from_step_7(self):
        s = Scenario()
        act = s.verdict(org=encoding.hashstr(b"other org"))
        self.assertEqual(check(s.value(act)), {**ok(act.id), "reason": "org_mismatch", "valid": False})


class Verify(unittest.TestCase):
    def test_four_reasons_pass_through_unchanged(self):
        s = Scenario()
        act = s.verdict()
        for reason in ("unknown_key", "revoked_key", "bad_signature", "context_mismatch"):
            self.assertEqual(check(s.value(act), Stub(reason))["reason"], reason)

    def test_every_other_reason_is_verifier_unexpected(self):
        s = Scenario()
        act = s.verdict()
        for reason in ("malformed", "header_key_material", "alg_not_allowed", "non_canonical_payload", "anything"):
            self.assertEqual(check(s.value(act), Stub(reason))["reason"], "verifier_unexpected", reason)

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable_with_the_class(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict()), Unavailable())["reason"], "verifier_unavailable")

    def test_vitni_is_pinned_to_the_expected_method_and_gets_the_fold_keys(self):
        s = Scenario()
        stub = Stub("ok")
        check(s.value(s.verdict()), stub)
        keys, method = stub.calls[-1]
        self.assertEqual(method, APPROVE)
        self.assertEqual(set(keys), {"alice", "bob", "carol"})
        self.assertEqual(keys["alice"][kid_of("alice")]["status"], "active")

    def test_a_signature_by_a_non_member_is_unknown_key_and_class_null(self):
        s = Scenario()
        act = s.verdict(signer="dave")
        got = check(s.value(act), FakeVitni())
        self.assertEqual((got["reason"], got["class"]), ("unknown_key", None))

    def test_a_bad_signature_is_bad_signature(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(sig=BAD)))["reason"], "bad_signature")

    def test_the_expected_method_is_what_vitni_pins(self):
        s = Scenario()
        got = check(s.value(s.verdict("reject"), expect_method=APPROVE))
        self.assertEqual(got["reason"], "context_mismatch")

    def test_an_unaccepted_key_is_still_verified_with_a_one_entry_map_keyed_by_its_person(self):
        w, step = dave_world()
        s = Scenario(w, ALL + ("dave",))
        act = s.verdict(signer="dave2", extra={"recipient": "dave"})
        stub = Stub("ok")
        got = check(s.value(act, acts=step.acts, recipient="dave"), stub)
        keys, _ = stub.calls[-1]
        self.assertEqual(list(keys), ["dave"])
        self.assertEqual(list(keys["dave"]), [kid_of("dave2")])
        self.assertEqual(keys["dave"][kid_of("dave2")]["status"], "active")
        self.assertEqual((got["reason"], got["class"]), ("unproven_class", "fixture-pin"))

    def test_an_unaccepted_key_with_a_bad_signature_is_bad_signature_never_unproven_class(self):
        w, step = dave_world()
        s = Scenario(w, ALL + ("dave",))
        act = s.verdict(signer="dave2", sig=BAD, extra={"recipient": "dave"})
        self.assertEqual(check(s.value(act, acts=step.acts, recipient="dave"))["reason"], "bad_signature")

    def test_a_revoked_unaccepted_key_is_offered_as_revoked(self):
        w, step = dave_world()
        removal = w.device_remove("dave2", ("alice", "bob"), parent=step)
        s = Scenario(w, ALL + ("dave",))
        act = s.verdict(signer="dave2", extra={"recipient": "dave"})
        stub = Stub("ok")
        check(s.value(act, acts=step.acts + removal.acts, recipient="dave"), stub)
        self.assertEqual(stub.calls[-1][0]["dave"][kid_of("dave2")]["status"], "revoked")

    def test_a_removed_key_is_revoked_key(self):
        s = Scenario()
        removal = s.w.device_remove("carol", ("alice", "bob"))
        act = s.verdict(signer="carol", extra={"recipient": "carol"})
        got = check(s.value(act, acts=removal.acts, recipient="carol"))
        self.assertEqual((got["reason"], got["class"]), ("revoked_key", "apple-se-bio"))


class LowS(unittest.TestCase):
    def test_a_high_s_signature_vitni_accepts_is_high_s(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(sig=HIGH)))["reason"], "high_s")

    def test_vitni_reasons_come_before_high_s(self):
        s = Scenario()
        self.assertEqual(check(s.value(s.verdict(sig=HIGH)), Stub("bad_signature"))["reason"], "bad_signature")


class Proven(unittest.TestCase):
    def test_an_accepted_key_is_ok(self):
        s = Scenario()
        self.assertTrue(check(s.value(s.verdict()))["valid"])

    def test_unproven_class_only_for_an_otherwise_perfect_act(self):
        w, step = dave_world()
        s = Scenario(w, ALL + ("dave",))
        act = s.verdict(signer="dave2", extra={"recipient": "dave"}, outputs_hash=encoding.hashstr(b"x"))
        self.assertEqual(check(s.value(act, acts=step.acts, recipient="dave"))["reason"], "outputs_mismatch")


if __name__ == "__main__":
    unittest.main()
