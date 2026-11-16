"""T3.54 the `enrolled` predicate (GP-13): seven steps in order, first failure wins.

1 to 3 the pin checks of VR-02 step 6 (a) to (h); 4 the fold; 5 the device (`local_key_unknown`,
`local_key_not_active`, `local_class_not_accepted`); 6 the view (VR-12) then the witness (WT-04, WT-05,
WT-10); 7 the pin's `spec` is not the fixture profile. Each defect is the only one in its test, each pair
of adjacent steps has an ordering test, and `enrolled:true` is only reachable under the production
profile, so the positive path builds a production world with an empty fixture kid list.
"""
import unittest

from handsal_check import enrolled, errors, genesis, profiles, registry

from .act_builder import BAD, FakeVitni, Unavailable, kid_of
from .checkact_world import NOW, Scenario, at, dave_world, probe_for
from .fold_world import World
from .genesis_fixtures import policy, relay_witness
from .witness_fixtures import statement
from .profile_sets import production_of, without_fixture_kids

REG = registry.load()
FIXTURE = profiles.load()
PRODUCTION_ONLY = without_fixture_kids(profiles.load())   # no kid is a fixture kid


def production_world(**kw):
    """A world whose document names the production profile; the id and so every act follow from it."""
    w = World(**kw)
    w.doc["profile"] = production_of(FIXTURE)
    w.id = w.org = genesis.doc_hash(w.doc)
    return w


def value(s, device="alice", **over):
    data = {"acts": [], "device_kid": kid_of(device), "lineage": s.lineage, "now": NOW, "org": s.w.id,
            "next": "no", "pin": probe_for(s.w.doc, s.w.id), "synced_at": NOW, "tip_statement": None}
    data.update(over)
    return data


def run(data, vitni=None, production=False, profs=None):
    """The `enrolled` result. `production` runs the build that refuses the fixture profile."""
    inp = enrolled.parse_input(data, conformance_build=True)
    return enrolled.run(inp, profs or (PRODUCTION_ONLY if production else FIXTURE), not production,
                        vitni or FakeVitni())


def relay_scenario(age="3600"):
    w = production_world(pol=policy(witness=relay_witness(age)))
    return Scenario(w)


def stmt(s, **over):
    fields = dict(epoch=s.w.id, tip=s.w.id, org=s.w.org, ts=at(60))
    fields.update(over)
    return statement(**fields).jws


def reason(data, **kw):
    got = run(data, **kw)
    return got["enrolled"], got["reason"]


class Positive(unittest.TestCase):
    def test_everything_valid_under_the_production_profile_is_enrolled(self):
        s = Scenario(production_world())
        self.assertEqual(run(value(s), production=True), {"enrolled": True, "reason": "ok"})

    def test_a_relay_witness_with_a_fresh_statement_is_enrolled(self):
        s = relay_scenario()
        self.assertEqual(run(value(s, tip_statement=stmt(s)), production=True), {"enrolled": True, "reason": "ok"})

    def test_the_result_has_exactly_two_keys(self):
        s = Scenario(production_world())
        self.assertEqual(set(run(value(s), production=True)), {"enrolled", "reason"})

    def test_the_device_is_not_proven_to_be_on_this_machine(self):
        # bob's kid on alice's machine: GP-13 says enrolled does not prove presence
        s = Scenario(production_world())
        self.assertEqual(run(value(s, device="bob"), production=True), {"enrolled": True, "reason": "ok"})


class FixtureProfile(unittest.TestCase):
    def test_everything_valid_under_the_fixture_profile_is_fixture_profile(self):   # step 7
        s = Scenario()
        self.assertEqual(reason(value(s)), (False, "fixture_profile"))

    def test_the_production_build_refuses_it_at_the_pin(self):   # step 3 (f), before any fold
        s = Scenario()
        vitni = FakeVitni()
        self.assertEqual(reason(value(s), vitni=vitni, production=True, profs=FIXTURE), (False, "fixture_profile"))
        self.assertEqual(vitni.calls, [])


class PinChecks(unittest.TestCase):
    """Steps 1 to 3 are `pinfile.check`; the codes and their order are pinned there. Here: they are first."""

    def test_an_owner_failure_is_the_probes_reason(self):
        s = Scenario(production_world())
        pin = {**probe_for(s.w.doc, s.w.id), "owner_ok": False, "reason": "pin_owner"}
        self.assertEqual(reason(value(s, pin=pin), production=True), (False, "pin_owner"))

    def test_a_missing_pin_is_pin_missing(self):
        s = Scenario(production_world())
        pin = {**probe_for(s.w.doc, s.w.id), "bytes_b64": "", "owner_ok": False, "reason": "pin_missing"}
        self.assertEqual(reason(value(s, pin=pin), production=True), (False, "pin_missing"))

    def test_the_wsl2_probe_is_pin_probe_unprotected(self):
        s = Scenario(production_world())
        pin = {**probe_for(s.w.doc, s.w.id), "bytes_b64": "", "owner_ok": False, "reason": "pin_probe_unprotected"}
        self.assertEqual(reason(value(s, pin=pin), production=True), (False, "pin_probe_unprotected"))

    def test_another_orgs_pin_is_pin_org_mismatch(self):
        s = Scenario(production_world())
        other = Scenario(production_world(name="OTHER"))
        self.assertEqual(reason(value(s, pin=probe_for(other.w.doc, other.w.id)), production=True),
                         (False, "pin_org_mismatch"))

    def test_a_pin_of_another_genesis_is_genesis_pin_mismatch(self):
        s = Scenario(production_world())
        earlier = production_world(name="EARLIER")
        pin = probe_for(earlier.doc, s.w.id)
        self.assertEqual(reason(value(s, pin=pin), production=True), (False, "genesis_pin_mismatch"))

    def test_the_pin_checks_come_before_the_fold(self):
        s = Scenario(production_world())
        s.lineage = [{"doc": s.w.doc, "sigs": []}]   # the fold would say genesis_unsigned
        pin = {**probe_for(s.w.doc, s.w.id), "owner_ok": False, "reason": "pin_owner"}
        self.assertEqual(reason(value(s, pin=pin), production=True), (False, "pin_owner"))


class Fold(unittest.TestCase):
    def test_a_fold_error_is_the_reason(self):   # step 4
        s = Scenario(production_world())
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        self.assertEqual(reason(value(s), production=True), (False, "genesis_unsigned"))

    def test_a_frozen_bag_is_fork(self):
        s = Scenario(production_world())
        c1 = s.w.device_add("alice2", ("alice", "bob"))
        c2 = s.w.device_add("alice3", ("alice", "carol"))
        self.assertEqual(reason(value(s, acts=c1.acts + c2.acts), production=True), (False, "fork"))

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s), vitni=Unavailable(), production=True), (False, "verifier_unavailable"))

    def test_the_fold_comes_before_the_device_steps(self):
        s = Scenario(production_world())
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        self.assertEqual(reason(value(s, device_kid="A" * 43), production=True), (False, "genesis_unsigned"))


class Device(unittest.TestCase):
    def test_a_kid_that_is_no_device_is_local_key_unknown(self):   # step 5
        s = Scenario(production_world())
        data = value(s, device_kid="A" * 43)
        self.assertEqual(reason(data, production=True), (False, "local_key_unknown"))

    def test_a_removed_device_is_local_key_not_active(self):
        w = production_world(extra=("bob2",))
        s = Scenario(w, ("alice", "bob", "carol", "bob2"))
        removal = w.device_remove("bob2", ("bob", "alice"))
        self.assertEqual(reason(value(s, device="bob2", acts=removal.acts), production=True),
                         (False, "local_key_not_active"))

    def test_a_device_of_a_class_the_policy_does_not_accept_is_local_class_not_accepted(self):
        # under the fixture profile `fixture-pin` is a usable class the policy does not list; under the
        # production profile no such class can be introduced, so this step runs before step 7 here
        w, step = dave_world()
        s = Scenario(w, ("alice", "bob", "carol", "dave"))
        self.assertEqual(reason(value(s, device="dave2", acts=step.acts)), (False, "local_class_not_accepted"))

    def test_the_device_steps_come_before_the_view(self):
        s = Scenario(production_world())
        data = value(s, device_kid="A" * 43, synced_at=at(10 ** 7))
        self.assertEqual(reason(data, production=True), (False, "local_key_unknown"))


class View(unittest.TestCase):
    def test_a_stale_view_is_stale_view(self):   # step 6, VR-12
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, synced_at=at(86401)), production=True), (False, "stale_view"))

    def test_exactly_the_max_view_age_is_valid(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, synced_at=at(86400)), production=True), (True, "ok"))

    def test_a_view_from_the_future_beyond_the_skew_is_view_in_future(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, synced_at=at(-301)), production=True), (False, "view_in_future"))

    def test_the_view_rules_come_before_the_witness(self):
        s = relay_scenario()
        self.assertEqual(reason(value(s, synced_at=at(86401)), production=True), (False, "stale_view"))


class Superseded(unittest.TestCase):
    """GP-13 step 6 and VR-12: a machine whose store holds a valid successor of its pin is not enrolled."""

    def test_next_yes_is_epoch_superseded_and_next_no_is_enrolled(self):   # GP-13 S9
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, next="yes"), production=True), (False, "epoch_superseded"))
        self.assertEqual(reason(value(s, next="no"), production=True), (True, "ok"))

    def test_it_is_the_first_rule_of_the_view_and_comes_before_the_witness(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, next="yes", synced_at=at(86401)), production=True),
                         (False, "epoch_superseded"))
        self.assertEqual(reason(value(s, next="yes", synced_at=at(-301)), production=True),
                         (False, "epoch_superseded"))
        self.assertEqual(reason(value(s, next="yes", tip_statement="whatever"), production=True),
                         (False, "epoch_superseded"))
        relay = relay_scenario()
        self.assertEqual(reason(value(relay, next="yes"), production=True), (False, "epoch_superseded"))

    def test_the_pin_the_fold_and_the_device_come_before_it(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, next="yes", device_kid="A" * 43), production=True),
                         (False, "local_key_unknown"))

    def test_a_fork_at_a_superseded_pin_is_epoch_superseded_and_the_other_fold_errors_come_first(self):   # GP-13 step 4
        s = Scenario(production_world())
        c1 = s.w.device_add("alice2", ("alice", "bob"))
        c2 = s.w.device_add("alice3", ("alice", "carol"))
        acts = c1.acts + c2.acts
        self.assertEqual(reason(value(s, acts=acts, next="yes"), production=True), (False, "epoch_superseded"))
        self.assertEqual(reason(value(s, acts=acts, next="no"), production=True), (False, "fork"))
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        self.assertEqual(reason(value(s, next="yes"), production=True), (False, "genesis_unsigned"))

    def test_a_removed_key_with_a_stale_view_is_still_local_key_not_active(self):   # SH5: step 5 before step 6
        s = Scenario(production_world())
        gone = s.w.device_remove("alice", ("bob", "carol"))
        self.assertEqual(reason(value(s, acts=gone.acts, synced_at=at(86401)), production=True),
                         (False, "local_key_not_active"))
        self.assertEqual(reason(value(s, acts=gone.acts), production=True), (False, "local_key_not_active"))
        self.assertEqual(reason(value(s, device="bob", acts=gone.acts, synced_at=at(86401)), production=True),
                         (False, "stale_view"))

    def test_the_fixture_profile_comes_after_it(self):   # step 7 after step 6
        s = Scenario()
        self.assertEqual(reason(value(s, next="no")), (False, "fixture_profile"))
        self.assertEqual(reason(value(s, next="yes")), (False, "epoch_superseded"))


class Witness(unittest.TestCase):
    def test_mode_relay_without_a_statement_is_witness_missing(self):
        s = relay_scenario()
        self.assertEqual(reason(value(s), production=True), (False, "witness_missing"))

    def test_mode_none_with_any_text_is_witness_unexpected(self):
        s = Scenario(production_world())
        self.assertEqual(reason(value(s, tip_statement="whatever"), production=True), (False, "witness_unexpected"))

    def test_a_stale_statement_is_stale_witness(self):
        s = relay_scenario("3600")
        self.assertEqual(reason(value(s, tip_statement=stmt(s, ts=at(3601))), production=True),
                         (False, "stale_witness"))

    def test_a_statement_that_a_successor_replaced_is_witness_superseded(self):
        s = relay_scenario()
        self.assertEqual(reason(value(s, tip_statement=stmt(s, next="yes")), production=True),
                         (False, "witness_superseded"))

    def test_a_statement_whose_tip_is_not_on_the_chain_is_behind_witness(self):
        s = relay_scenario()
        other = production_world(name="OTHER")
        self.assertEqual(reason(value(s, tip_statement=stmt(s, tip=other.id)), production=True),
                         (False, "behind_witness"))

    def test_a_bad_statement_signature_is_witness_bad_signature(self):
        s = relay_scenario()
        bad = statement(epoch=s.w.id, tip=s.w.id, org=s.w.org, ts=at(60), sig=BAD).jws
        self.assertEqual(reason(value(s, tip_statement=bad), production=True), (False, "witness_bad_signature"))

    def test_the_witness_comes_before_the_fixture_profile_step(self):
        w = World(pol=policy(witness=relay_witness()))   # fixture profile, relay mode, no statement
        s = Scenario(w)
        self.assertEqual(reason(value(s)), (False, "witness_missing"))


class Input(unittest.TestCase):
    def setUp(self):
        self.s = Scenario(production_world())
        self.good = value(self.s)

    def parse(self, data, conformance=True):
        return enrolled.parse_input(data, conformance_build=conformance)

    def test_the_keys_of_gp_13_parse(self):
        got = self.parse(self.good)
        self.assertEqual(got.device_kid, self.good["device_kid"])
        self.assertEqual((got.now, got.synced_at, got.org), (NOW, NOW, self.s.w.id))

    def test_every_required_key_is_required(self):
        for key in self.good:
            data = {k: v for k, v in self.good.items() if k != key}
            with self.assertRaises(errors.Malformed, msg=key):
                self.parse(data)

    def test_every_key_has_a_type(self):
        for key, bad in (("acts", {}), ("acts", [5]), ("device_kid", 5), ("lineage", "x"), ("lineage", [{"doc": 1}]),
                         ("now", 5), ("now", "not a time"), ("org", "not a hashstr"), ("org", None),
                         ("pin", "x"), ("synced_at", 5), ("synced_at", "x"), ("tip_statement", 5), ("next", 5),
                         ("next", None), ("next", "maybe")):
            with self.assertRaises(errors.Malformed, msg=(key, bad)):
                self.parse({**self.good, key: bad})

    def test_the_input_is_not_an_object(self):
        with self.assertRaises(errors.Malformed):
            self.parse([])

    def test_the_production_build_takes_neither_pin_nor_now_nor_the_stores_five_keys(self):   # CF-08, CF-09
        supplied = ("pin", "now", "acts", "lineage", "next", "synced_at", "tip_statement")
        production = {k: v for k, v in self.good.items() if k not in supplied}
        got = self.parse(production, conformance=False)
        self.assertEqual((got.pin, got.now, got.next, got.synced_at, got.tip_statement, got.store_reason),
                         (None, None, None, None, None, None))
        self.assertEqual((got.acts, got.lineage), ([], []))   # placeholders: the production `fill` replaces them
        for key in supplied:
            with self.assertRaises(errors.Malformed, msg=key):
                self.parse({**production, key: self.good[key]}, conformance=False)

    def test_the_conformance_build_requires_both(self):
        for key in ("pin", "now"):
            with self.assertRaises(errors.Malformed, msg=key):
                self.parse({k: v for k, v in self.good.items() if k != key})


if __name__ == "__main__":
    unittest.main()
