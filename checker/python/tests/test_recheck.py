"""`recheck-act` (VR-17): the time-free half of `check-act`, for an act a consumer stored.

The rule it protects: a consumer decides that a stored act is a human decision only from evidence an agent
cannot mint. The stored act is the full JWS, and this command re-verifies it at read time. It shares one
implementation of the time-free steps with `check-act` (`rules.TIME_FREE`), so the two cannot disagree about
the signature, the key, or the request. It runs no step that reads the verifier's moment: no `now`, no
freshness, no expiry, no tip-based revocation, no `seen`, no witness.
"""
import unittest

from handsal_check import encoding, errors, profiles, rules
from handsal_check import recheck as recheck_module

from .act_builder import BAD, HIGH, FakeVitni, Unavailable, head_of
from .checkact_world import ALL, APPROVE, Scenario, at, b64, check, dave_world, outputs, probe_for
from .fold_world import World
from .genesis_fixtures import policy

NOT_PROVEN = ["expiry", "freshness", "order_of_arrival", "replay", "revocation_after_head"]
TIMED_KEYS = ("next", "now", "seen", "synced_at", "tip_statement")


def recheck_value(value):
    """The `recheck-act` input of a `check-act` input: the same keys without the four that name a moment."""
    return {k: v for k, v in value.items() if k not in TIMED_KEYS}


def rc(value, vitni=None):
    inp = recheck_module.parse_input(recheck_value(value))
    return recheck_module.run(inp, profiles.load(), True, vitni or FakeVitni())



def good(receipt, cls="apple-se-bio"):
    return {"class": cls, "not_proven": NOT_PROVEN, "reason": "ok", "receipt_id": receipt, "rechecked": True}


def bad(reason, receipt, cls="apple-se-bio"):
    return {"class": cls, "not_proven": NOT_PROVEN, "reason": reason, "receipt_id": receipt, "rechecked": False}


class Output(unittest.TestCase):
    def test_a_stored_verdict_rechecks_with_its_class_and_names_what_it_does_not_prove(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(rc(s.value(act)), good(act.id))

    def test_the_result_has_no_valid_key_so_it_cannot_be_read_as_a_check_act_answer(self):
        s = Scenario()
        self.assertNotIn("valid", rc(s.value(s.verdict())))

    def test_not_proven_is_the_one_list_the_module_exports(self):
        self.assertEqual(list(recheck_module.NOT_PROVEN), NOT_PROVEN)

    def test_a_decision_rechecks_too(self):
        s = Scenario()
        act = s.decision()
        self.assertEqual(rc(s.decision_value(act)), good(act.id))


class Input(unittest.TestCase):
    def malformed(self, value, conformance_build=True):
        with self.assertRaises(errors.Malformed):
            recheck_module.parse_input(value, conformance_build)

    def test_the_keys_that_name_a_moment_or_a_view_are_refused_in_both_builds(self):   # VR-17 S11, S17
        s = Scenario()
        full = s.value(s.verdict())
        base = recheck_value(full)
        recheck_module.parse_input(base)       # the reduced input is well formed
        for key in TIMED_KEYS:
            self.malformed({**base, key: full[key]})
            self.malformed({**{k: v for k, v in base.items() if k != "pin"}, key: full[key]}, False)

    def test_the_conformance_build_requires_pin_and_the_production_build_refuses_it(self):
        s = Scenario()
        base = recheck_value(s.value(s.verdict()))
        self.malformed({k: v for k, v in base.items() if k != "pin"})
        self.malformed(base, conformance_build=False)

    def test_the_other_required_inputs_are_those_of_check_act(self):
        s = Scenario()
        base = recheck_value(s.value(s.verdict()))
        for key in ("acts", "expect_method", "jws", "lineage", "org", "recipient", "request_b64",
                    "request_id"):
            self.malformed({k: v for k, v in base.items() if k != key})
        self.malformed({**base, "relay": "r.example"})   # VR-08: a relay input is refused in both builds

    def test_a_decision_needs_its_content_and_words(self):
        s = Scenario()
        base = recheck_value(s.decision_value(s.decision()))
        recheck_module.parse_input(base)
        for key in ("action", "consumer", "decision_b64", "subject"):
            self.malformed({k: v for k, v in base.items() if k != key})


class TimeFree(unittest.TestCase):
    """What the verifier's moment never changes: the same act, the same bag, whatever has happened since."""

    def test_an_expired_act_rechecks_while_check_act_says_expired(self):
        s = Scenario()
        act = s.verdict()
        later = s.value(act, now=at(-10 * 86400), synced_at=at(-10 * 86400))
        self.assertEqual(check(later)["reason"], "expired")
        self.assertEqual(rc(later), good(act.id))

    def test_an_act_from_the_future_rechecks(self):
        s = Scenario()
        act = s.verdict(ts=at(-10 ** 6), extra={"expires": at(-10 ** 6 - 3600)})
        self.assertEqual(check(s.value(act))["reason"], "ts_in_future")
        self.assertEqual(rc(s.value(act)), good(act.id))

    def test_an_act_checked_before_is_not_a_duplicate(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(check(s.value(act, seen=[act.id]))["reason"], "duplicate_receipt")
        self.assertEqual(rc(s.value(act, seen=[act.id])), good(act.id))

    def test_a_key_removed_after_the_acts_head_still_rechecks(self):
        # L1 and VR-12: `check-act` judges the key at the tip, the recheck at the act's own head.
        s = Scenario()
        add = s.w.device_add("alice2", ("alice", "bob"))
        remove = s.w.device_remove("alice", ("bob", "carol"), parent=add)
        act = s.verdict(head=head_of(add.id))
        value = s.value(act, acts=add.acts + remove.acts)
        self.assertEqual(check(value)["reason"], "revoked_key")
        self.assertEqual(rc(value), good(act.id))

    def test_a_key_not_yet_active_at_the_acts_head_is_unknown_key(self):
        s = Scenario()
        add = s.w.device_add("alice2", ("alice", "bob"))
        act = s.verdict(signer="alice2")                       # head: the root, before alice2 existed
        value = s.value(act, acts=add.acts)
        self.assertTrue(check(value)["valid"])                  # active at the tip
        self.assertEqual(rc(value), bad("unknown_key", act.id, None))   # the state at the head has no such device

    def test_a_key_active_at_the_head_rechecks_when_the_head_is_after_its_add(self):
        s = Scenario()
        add = s.w.device_add("alice2", ("alice", "bob"))
        act = s.verdict(signer="alice2", head=head_of(add.id))
        self.assertEqual(rc(s.value(act, acts=add.acts)), good(act.id))

    def test_a_fork_after_the_head_does_not_change_the_state_at_it(self):
        s = Scenario()
        c1 = s.w.device_add("alice2", ("alice", "bob"))
        c2 = s.w.device_add("alice3", ("alice", "carol"))
        act = s.verdict()                                       # head: the root, the fork parent
        value = s.value(act, acts=c1.acts + c2.acts)
        self.assertEqual(check(value)["reason"], "fork")
        self.assertEqual(rc(value), good(act.id))

    def test_a_head_beyond_the_fork_parent_is_not_on_the_accepted_chain(self):
        s = Scenario()
        c1 = s.w.device_add("alice2", ("alice", "bob"))
        c2 = s.w.device_add("alice3", ("alice", "carol"))
        act = s.verdict(head=head_of(c1.id))
        self.assertEqual(rc(s.value(act, acts=c1.acts + c2.acts))["reason"], "stale_view")


class Refusals(unittest.TestCase):
    def test_a_head_that_is_no_position_is_stale_view_with_class_null(self):
        s = Scenario()
        act = s.verdict(head=head_of(encoding.hashstr(b"no such node")))
        self.assertEqual(rc(s.value(act)), bad("stale_view", act.id, None))

    def test_a_bad_signature(self):
        s = Scenario()
        act = s.verdict(sig=BAD)
        self.assertEqual(rc(s.value(act)), bad("bad_signature", act.id))

    def test_a_high_s_signature(self):
        s = Scenario()
        act = s.verdict(sig=HIGH)
        self.assertEqual(rc(s.value(act)), bad("high_s", act.id))

    def test_other_requests_bytes(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(rc(s.value(act, request_b64=b64(b"other request")))["reason"], "inputs_mismatch")

    def test_another_recipient_relay_or_org(self):
        s = Scenario()
        act = s.verdict()
        self.assertEqual(rc(s.value(act, recipient="bob"))["reason"], "request_mismatch")
        self.assertEqual(rc(s.value(s.verdict(extra={"relay": "other.example"})))["reason"], "relay_mismatch")
        self.assertEqual(rc(s.value(act, request_id="req-00000002"))["reason"], "request_mismatch")

    def test_a_chain_act_is_not_rechecked(self):
        s = Scenario()
        add = s.w.device_add("alice2", ("alice", "bob"))
        got = rc(s.value(add.primary, expect_method=APPROVE))
        self.assertEqual((got["reason"], got["rechecked"], got["class"]), ("chain_method", False, None))

    def test_a_key_that_is_not_accepted_is_unproven_class(self):
        w, add = dave_world()
        s = Scenario(w, ALL + ("dave",))
        act = s.verdict(signer="dave2", head=head_of(add.id), extra={"recipient": "dave"})
        got = rc(s.value(act, acts=add.acts, recipient="dave"))
        self.assertEqual((got["reason"], got["rechecked"]), ("unproven_class", False))

    def test_a_fold_error_is_the_reason_and_class_is_null(self):
        s = Scenario()
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        act = s.verdict()
        self.assertEqual(rc(s.value(act)), bad("genesis_unsigned", act.id, None))

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable(self):
        s = Scenario()
        act = s.verdict()
        got = rc(s.value(act), Unavailable())
        self.assertEqual((got["reason"], got["rechecked"], got["class"]), ("verifier_unavailable", False, None))

    def test_the_pin_is_checked_like_check_act(self):
        s = Scenario()
        act = s.verdict()
        wrong = {**s.value()["pin"], "owner_ok": False, "reason": "pin_owner"}
        self.assertEqual(rc(s.value(act, pin=wrong))["reason"], "pin_owner")


class SharedImplementation(unittest.TestCase):
    """VR-17: `check-act` is the time-free steps and then the timed ones. One list holds the first part."""

    def test_the_steps_are_one_list_cut_in_two(self):
        names = lambda steps: [step.__name__ for step in steps]
        self.assertEqual(names(rules.TIME_FREE), ["org", "relay", "verify", "low_s", "identity", "request",
                                                  "inputs", "outputs"])
        self.assertEqual(names(rules.TIMED), ["time", "view", "witness", "duplicate"])
        self.assertEqual(rules.STEPS, rules.TIME_FREE + rules.TIMED + (rules.proven,))
        self.assertEqual(rules.RECHECK_STEPS, rules.TIME_FREE + (rules.proven,))

    def test_a_timed_step_is_never_run(self):
        s = Scenario()
        for step in rules.RECHECK_STEPS:
            self.assertNotIn(step, rules.TIMED)

    def test_both_commands_give_the_same_reason_for_every_time_free_defect(self):
        s = Scenario()
        cases = {
            "bad_signature": s.value(s.verdict(sig=BAD)),
            "high_s": s.value(s.verdict(sig=HIGH)),
            "org_mismatch": s.value(s.verdict(org=encoding.hashstr(b"other org"))),
            "relay_mismatch": s.value(s.verdict(extra={"relay": "other.example"})),
            "request_mismatch": s.value(s.verdict(), recipient="bob"),
            "inputs_mismatch": s.value(s.verdict(), request_b64=b64(b"other")),
            "identity_mismatch": s.value(s.verdict(extra={"recipient": "bob"}), recipient="bob"),
            "outputs_mismatch": s.value(s.verdict(outputs_hash=outputs("reject"))),
            "ok": s.value(s.verdict()),
        }
        for want, value in cases.items():
            self.assertEqual(check(value)["reason"], want, want)
            self.assertEqual(rc(value)["reason"], want, want)

    def test_the_head_state_is_the_tip_state_when_the_head_is_the_tip(self):
        s = Scenario()
        add = s.w.device_add("alice2", ("alice", "bob"))
        act = s.verdict(signer="alice2", head=head_of(add.id))
        value = s.value(act, acts=add.acts)
        self.assertEqual(check(value)["class"], rc(value)["class"])


class AcrossEpochs(unittest.TestCase):
    """VR-17: a head is a position in its own epoch, and the lineage proves which epoch that is, so the same
    answer holds after a genesis change. Per epoch, the chain the lineage proves is the path to the head H of
    the next change; a key removed by a later epoch does not change an earlier epoch's act."""

    def after_change(self, w, head, **over):
        """A scenario whose lineage continues with a change at `head`, pinned at the change."""
        s = Scenario(w)
        doc = w.change_doc(head)
        s.lineage = [s.lineage[0], {"doc": doc, "sigs": w.sigs(doc, ALL)}]
        return s, doc, {"pin": probe_for(doc, w.id), **over}

    def test_an_act_of_an_earlier_epoch_rechecks_after_the_change(self):
        w = World()
        s, doc, extra = self.after_change(w, w.id)
        act = s.verdict()
        value = s.value(act, **extra)
        self.assertEqual(rc(value), good(act.id))
        self.assertEqual(check(value)["reason"], "stale_view")   # to act on now, the head must be in the current epoch

    def test_a_head_on_the_path_to_the_change_is_in_its_epoch(self):
        w = World()
        add = w.device_add("alice2", ("alice", "bob"))
        s, doc, extra = self.after_change(w, add.id)
        act = s.verdict(signer="alice2", head=head_of(add.id))
        self.assertEqual(rc(s.value(act, acts=add.acts, **extra)), good(act.id))

    def test_the_key_is_examined_in_the_state_at_the_head_of_its_own_epoch(self):
        w = World()
        add = w.device_add("alice2", ("alice", "bob"))
        s, doc, extra = self.after_change(w, add.id)
        act = s.verdict(signer="alice2")                      # head: the root, before alice2 was added
        self.assertEqual(rc(s.value(act, acts=add.acts, **extra))["reason"], "unknown_key")

    def test_a_head_past_the_change_is_on_no_chain_the_lineage_proves(self):
        w = World()
        add = w.device_add("alice2", ("alice", "bob"))
        s, doc, extra = self.after_change(w, w.id)           # the change is at the root, the add is beside it
        act = s.verdict(signer="alice2", head=head_of(add.id))
        self.assertEqual(rc(s.value(act, acts=add.acts, **extra))["reason"], "stale_view")

    def test_a_key_removed_by_a_later_epoch_does_not_change_an_earlier_act(self):
        w = World()
        s, doc, extra = self.after_change(w, w.id)
        w2 = World()
        w2.doc, w2.id, w2.org = doc, __import__("handsal_check.genesis", fromlist=["x"]).doc_hash(doc), w.id
        removal = w2.device_remove("alice", ("bob", "carol"))
        old = s.verdict()
        now = s.verdict(head=head_of(removal.id))   # a head after the removal, in epoch 2
        self.assertEqual(check(s.value(now, acts=removal.acts, **extra))["reason"], "revoked_key")   # removed in epoch 2
        self.assertEqual(rc(s.value(old, acts=removal.acts, **extra)), good(old.id))
        self.assertEqual(rc(s.value(now, acts=removal.acts, **extra))["reason"], "revoked_key")
        self.assertEqual(rc(s.value(s.verdict(head=head_of(w2.id)), acts=removal.acts, **extra))["reason"], "ok")

    def test_the_relay_is_read_from_the_policy_of_the_heads_own_epoch(self):   # VR-08, VR-17 S16
        w = World()
        s = Scenario(w)
        doc = w.change_doc(w.id, pol=policy(relays=("s.example",)))
        s.lineage = [s.lineage[0], {"doc": doc, "sigs": w.sigs(doc, ALL)}]
        extra = {"pin": probe_for(doc, w.id)}
        act = s.verdict()   # names r.example, signed in epoch 0 whose policy lists it
        self.assertEqual(rc(s.value(act, **extra)), good(act.id))
        self.assertEqual(check(s.value(act, **extra))["reason"], "relay_mismatch")   # step 8 reads epoch 1: `s.example` only
        tip = s.verdict(head=head_of(__import__("handsal_check.genesis", fromlist=["x"]).doc_hash(doc)))
        self.assertEqual(rc(s.value(tip, **extra))["reason"], "relay_mismatch")   # epoch 1 lists s.example only


if __name__ == "__main__":
    unittest.main()
