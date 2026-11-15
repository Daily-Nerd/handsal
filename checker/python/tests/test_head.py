"""T15.2 the `head` command (VR-19): the head a producer of an act names (ACT-08), over the one store read.

Steps, first failure wins: 1 to 3 the pin checks of VR-02 step 6 (a) to (h); 4 the fold (`fork`, or
`epoch_superseded` where `next` is "yes"); 5 the act-free view (VR-12) then the witness (WT-04, WT-05, WT-10).
Output `{"head": {"id": T, "kind": "chain"}, "reason": "ok"}` or `{"head": null, "reason": R}`. Each code has its own
test, each pair of adjacent steps an ordering test, and the SH6 property at the end holds the equality with
`check-act` (I12) over every world this file builds.
"""
import unittest

from handsal_check import checkact, encoding, errors, head, registry

from .act_builder import FakeVitni, Unavailable, head_of
from .checkact_world import NOW, Scenario, at, probe_for
from .fold_world import World
from .store_world import later_world
from .test_enrolled import FIXTURE, PRODUCTION_ONLY, production_world, relay_scenario, stmt

REG = registry.load()
ALL = ("alice", "bob", "carol")
AB = ("alice", "bob")
SKEW, VIEW_AGE = 300, 86400


def value(s, **over):
    """The conformance input of `head` for the scenario `s`: the inputs of `enrolled` without `device_kid`."""
    data = {"acts": [], "lineage": s.lineage, "next": "no", "now": NOW, "org": s.w.id,
            "pin": probe_for(s.w.doc, s.w.id), "synced_at": NOW, "tip_statement": None}
    data.update(over)
    return data


def run(data, vitni=None, profs=None, allow_fixture=True, production=False):
    """The `head` result of the conformance input `data`. `production` runs the build that refuses the fixture
    profile and has no fixture kid (a relay world needs it: its relay key is not a fixture kid there)."""
    inp = head.parse_input(data, conformance_build=True)
    if production:
        profs, allow_fixture = PRODUCTION_ONLY, False
    return head.run(inp, REG, profs or FIXTURE, allow_fixture, vitni or FakeVitni())


def answer(data, **kw):   # `(head, reason)`
    got = run(data, **kw)
    return got["head"], got["reason"]


def at_head(node_id):
    return head_of(node_id)


def chain_of(w, count):
    """`count` valid primaries, each the child of the one before: the steps, the first at the root."""
    steps, parent = [], None
    for name in ("alice2", "bob2", "alice3", "bob3")[:count]:
        parent = w.device_add(name, AB, parent)
        steps.append(parent)
    return steps


def acts_of(steps):
    return [text for step in steps for text in step.acts]


class Output(unittest.TestCase):
    def test_the_head_of_a_chain_is_the_tip_in_the_exact_act_form(self):   # VR-19 S1
        s = Scenario()
        steps = chain_of(s.w, 3)
        got = run(value(s, acts=acts_of(steps)))
        self.assertEqual(got, {"head": {"id": steps[-1].id, "kind": "chain"}, "reason": "ok"})
        self.assertEqual(list(got), ["head", "reason"])
        self.assertEqual(set(got["head"]), {"id", "kind"})   # no `n` to strip and no `kind` to add

    def test_an_empty_chain_answers_the_genesis_document_hash(self):   # VR-19 S1, ACT-08 position 0
        s = Scenario()
        self.assertEqual(run(value(s)), {"head": {"id": s.w.id, "kind": "chain"}, "reason": "ok"})

    def test_a_refusal_is_a_null_head_and_the_code(self):
        s = Scenario()
        self.assertEqual(run(value(s, next="yes")), {"head": None, "reason": "epoch_superseded"})

    def test_the_result_has_exactly_two_keys(self):
        s = Scenario()
        self.assertEqual(set(run(value(s))), {"head", "reason"})
        self.assertEqual(set(run(value(s, next="yes"))), {"head", "reason"})

    def test_a_fork_lifted_by_a_resolve_answers_the_tip_of_the_chosen_branch(self):   # VR-19 S1
        s = Scenario()
        c1, c2 = s.w.device_add("alice2", AB), s.w.device_add("alice3", ("alice", "carol"))
        resolve = s.w.resolve(AB, [c1, c2], c1, [c2])
        acts = c1.acts + c2.acts + resolve.acts
        self.assertEqual(answer(value(s, acts=c1.acts + c2.acts)), (None, "fork"))
        self.assertEqual(answer(value(s, acts=acts)), ({"id": c1.id, "kind": "chain"}, "ok"))

    def test_the_fixture_profile_is_answered_by_the_conformance_build(self):   # VR-19, SH3: no fixture step
        s = Scenario()
        self.assertEqual(answer(value(s))[1], "ok")
        self.assertEqual(answer(value(s), profs=FIXTURE, allow_fixture=True)[1], "ok")

    def test_the_production_build_refuses_the_fixture_profile_at_the_pin(self):   # VR-19, VR-02 step 6
        s = Scenario()
        self.assertEqual(answer(value(s), profs=PRODUCTION_ONLY, allow_fixture=False), (None, "fixture_profile"))

    def test_a_production_profile_world_is_answered_in_the_production_build(self):
        s = Scenario(production_world())
        self.assertEqual(answer(value(s), profs=PRODUCTION_ONLY, allow_fixture=False),
                         ({"id": s.w.id, "kind": "chain"}, "ok"))


class TwoEpochs(unittest.TestCase):
    """A lineage of two epochs and a pin at the last: the head is a position of the last, never of the path of the
    earlier one (VR-19 S6)."""

    def setUp(self):
        self.w = World()
        self.a = self.w.device_add("alice2", AB)
        self.doc = self.w.change_doc(self.a.id)
        self.lineage = [{"doc": self.w.doc, "sigs": self.w.sigs(self.w.doc, ALL)},
                        {"doc": self.doc, "sigs": self.w.sigs(self.doc, ALL)}]
        self.later = later_world(self.w, self.doc)

    def data(self, acts, **over):
        s = Scenario(self.later)
        return value(s, acts=acts, lineage=self.lineage, org=self.w.id, pin=probe_for(self.doc, self.w.id), **over)

    def test_the_head_is_in_the_last_epoch(self):
        b = self.later.device_add("bob2", AB)
        self.assertEqual(answer(self.data(self.a.acts + b.acts)), ({"id": b.id, "kind": "chain"}, "ok"))

    def test_a_last_epoch_with_no_act_answers_its_document_hash_not_the_earlier_tip(self):
        self.assertEqual(answer(self.data(self.a.acts)), ({"id": self.later.id, "kind": "chain"}, "ok"))

    def test_the_earlier_epochs_own_chain_never_decides_the_head(self):
        b = self.later.device_add("bob2", AB)
        got = run(self.data(self.a.acts + b.acts))
        self.assertNotIn(got["head"]["id"], (self.w.id, self.a.id))


class PinChecks(unittest.TestCase):
    """Steps 1 to 3 are `pinfile.check`; here only that `head` answers its codes first."""

    def test_the_probes_reason_is_the_answer(self):
        s = Scenario()
        for reason in ("pin_missing", "pin_owner", "pin_probe_unavailable", "pin_probe_unprotected"):
            pin = {**probe_for(s.w.doc, s.w.id), "bytes_b64": "", "owner_ok": False, "reason": reason}
            self.assertEqual(answer(value(s, pin=pin)), (None, reason))

    def test_another_orgs_pin_is_pin_org_mismatch(self):
        s, other = Scenario(), Scenario(World(name="OTHER"))
        self.assertEqual(answer(value(s, pin=probe_for(other.w.doc, other.w.id))), (None, "pin_org_mismatch"))

    def test_a_pin_of_another_genesis_is_genesis_pin_mismatch(self):
        s, earlier = Scenario(), World(name="EARLIER")
        self.assertEqual(answer(value(s, pin=probe_for(earlier.doc, s.w.id))), (None, "genesis_pin_mismatch"))

    def test_a_lineage_that_is_not_the_pins_is_lineage_broken(self):
        s, other = Scenario(), Scenario(World(name="OTHER"))
        self.assertEqual(answer(value(s, lineage=other.lineage)), (None, "lineage_broken"))

    def test_the_pin_checks_come_before_the_fold_the_view_and_the_witness(self):
        s = Scenario()
        s.lineage = [{"doc": s.w.doc, "sigs": []}]   # the fold would say genesis_unsigned
        pin = {**probe_for(s.w.doc, s.w.id), "owner_ok": False, "reason": "pin_owner"}
        self.assertEqual(answer(value(s, pin=pin, next="yes", synced_at=at(VIEW_AGE + 1), tip_statement="x")),
                         (None, "pin_owner"))


class Fold(unittest.TestCase):
    def test_a_fold_error_is_the_reason(self):
        s = Scenario()
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        self.assertEqual(answer(value(s)), (None, "genesis_unsigned"))

    def test_a_frozen_bag_is_fork_and_has_no_head(self):   # VR-19 S2
        s = Scenario()
        c1, c2 = s.w.device_add("alice2", AB), s.w.device_add("alice3", ("alice", "carol"))
        self.assertEqual(answer(value(s, acts=c1.acts + c2.acts)), (None, "fork"))

    def test_a_fork_where_next_is_yes_is_epoch_superseded(self):   # VR-19 S2, VR-12
        s = Scenario()
        c1, c2 = s.w.device_add("alice2", AB), s.w.device_add("alice3", ("alice", "carol"))
        self.assertEqual(answer(value(s, acts=c1.acts + c2.acts, next="yes")), (None, "epoch_superseded"))

    def test_the_other_fold_errors_keep_their_place_where_next_is_yes(self):
        s = Scenario()
        s.lineage = [{"doc": s.w.doc, "sigs": []}]
        self.assertEqual(answer(value(s, next="yes")), (None, "genesis_unsigned"))

    def test_a_verifier_that_cannot_answer_is_verifier_unavailable(self):
        s = Scenario()
        self.assertEqual(answer(value(s), vitni=Unavailable()), (None, "verifier_unavailable"))


class View(unittest.TestCase):
    def test_next_yes_is_epoch_superseded_and_comes_first_of_the_view(self):   # VR-19 S2, VR-12
        s = Scenario()
        self.assertEqual(answer(value(s, next="yes")), (None, "epoch_superseded"))
        self.assertEqual(answer(value(s, next="yes", synced_at=at(VIEW_AGE + 1))), (None, "epoch_superseded"))
        self.assertEqual(answer(value(s, next="yes", synced_at=at(-SKEW - 1))), (None, "epoch_superseded"))
        self.assertEqual(answer(value(s, next="yes", tip_statement="junk")), (None, "epoch_superseded"))

    def test_a_view_older_than_the_maximum_is_stale_view(self):   # VR-19 S3
        s = Scenario()
        self.assertEqual(answer(value(s, synced_at=at(VIEW_AGE + 1))), (None, "stale_view"))

    def test_a_view_exactly_the_maximum_old_is_ok(self):   # VR-19 S3 control
        s = Scenario()
        self.assertEqual(answer(value(s, synced_at=at(VIEW_AGE)))[1], "ok")

    def test_a_view_ahead_of_now_by_more_than_the_skew_is_view_in_the_future(self):   # VR-19 S3
        s = Scenario()
        self.assertEqual(answer(value(s, synced_at=at(-SKEW - 1))), (None, "view_in_future"))
        self.assertEqual(answer(value(s, synced_at=at(-SKEW)))[1], "ok")

    def test_the_view_comes_before_the_witness(self):
        s = relay_scenario()
        self.assertEqual(answer(value(s, synced_at=at(VIEW_AGE + 1)), production=True), (None, "stale_view"))


class Witness(unittest.TestCase):
    def test_mode_none_with_a_statement_is_witness_unexpected(self):   # VR-19 S4
        s = Scenario()
        self.assertEqual(answer(value(s, tip_statement="garbage")), (None, "witness_unexpected"))

    def test_mode_relay_without_a_statement_is_witness_missing(self):   # VR-19 S4
        s = relay_scenario()
        self.assertEqual(answer(value(s), production=True), (None, "witness_missing"))

    def test_mode_relay_with_a_good_statement_is_ok(self):   # VR-19 S4 control
        s = relay_scenario()
        self.assertEqual(answer(value(s, tip_statement=stmt(s)), production=True), ({"id": s.w.id, "kind": "chain"}, "ok"))

    def test_a_statement_that_names_a_position_the_view_does_not_hold_is_behind_witness(self):   # WT-05 step 9
        s = relay_scenario()
        self.assertEqual(answer(value(s, tip_statement=stmt(s, tip=encoding.hashstr(b"elsewhere"))), production=True), (None, "behind_witness"))

    def test_a_statement_that_closes_the_epoch_is_witness_superseded(self):   # WT-10
        s = relay_scenario()
        self.assertEqual(answer(value(s, tip_statement=stmt(s, next="yes")), production=True), (None, "witness_superseded"))


class Input(unittest.TestCase):
    def malformed(self, data, conformance_build=True):
        with self.assertRaises(errors.Malformed):
            head.parse_input(data, conformance_build)

    def test_a_valid_input_parses(self):
        head.parse_input(value(Scenario()), conformance_build=True)

    def test_every_key_of_the_conformance_build_is_required(self):   # VR-19, S5
        for key in ("acts", "lineage", "next", "now", "org", "pin", "synced_at", "tip_statement"):
            data = value(Scenario())
            del data[key]
            with self.subTest(key=key):
                self.malformed(data)

    def test_next_must_be_yes_or_no(self):
        for bad in ("maybe", None, True, 1):
            with self.subTest(bad=bad):
                self.malformed(value(Scenario(), next=bad))

    def test_org_must_be_a_hashstr(self):
        for bad in ("short", None, 5, "A" * 44):
            with self.subTest(bad=bad):
                self.malformed(value(Scenario(), org=bad))

    def test_the_input_is_an_object(self):
        self.malformed([])
        self.malformed("x")

    def test_the_production_input_is_org_alone(self):   # VR-19, CF-08
        s = Scenario()
        inp = head.parse_input({"org": s.w.id}, conformance_build=False)
        self.assertEqual((inp.org, inp.pin, inp.now, inp.acts, inp.lineage), (s.w.id, None, None, [], []))

    def test_the_production_input_refuses_every_state_key(self):   # VR-19 S7
        s = Scenario()
        extra = {"acts": [], "lineage": s.lineage, "next": "no", "now": NOW, "pin": probe_for(s.w.doc, s.w.id),
                 "synced_at": NOW, "tip_statement": None}
        for key, item in extra.items():
            with self.subTest(key=key):
                self.malformed({"org": s.w.id, key: item}, conformance_build=False)

    def test_the_production_input_needs_an_org(self):
        self.malformed({}, conformance_build=False)
        self.malformed({"org": "x"}, conformance_build=False)


# ---- SH6: the equality with `check-act` (I12), over every world below

def decision_for(s, node_id, **over):
    return s.decision_value(s.decision(head=at_head(node_id), **over))


def worlds():
    """`(name, scenario, input overrides, vitni, production)`: every kind of view this file knows. Where `head` has
    none, the decision names the root, a position every refusal below leaves in place."""
    out = []

    def add(name, s, vitni=None, production=False, **over):
        out.append((name, s, over, vitni, production))

    s = Scenario()
    steps = chain_of(s.w, 3)
    add("tip of three", s, acts=acts_of(steps))
    add("older head still ok", s, acts=acts_of(steps[:2]))
    add("root only", Scenario())
    s = Scenario()
    c1, c2 = s.w.device_add("alice2", AB), s.w.device_add("alice3", ("alice", "carol"))
    add("fork", s, acts=c1.acts + c2.acts)
    add("fork superseded", s, acts=c1.acts + c2.acts, next="yes")
    resolve = s.w.resolve(AB, [c1, c2], c1, [c2])
    add("resolved fork", s, acts=c1.acts + c2.acts + resolve.acts)
    add("superseded", Scenario(), next="yes")
    add("stale", Scenario(), synced_at=at(VIEW_AGE + 1))
    add("stale and superseded", Scenario(), synced_at=at(VIEW_AGE + 1), next="yes")
    add("exact age", Scenario(), synced_at=at(VIEW_AGE))
    add("in the future", Scenario(), synced_at=at(-SKEW - 1))
    add("exact skew", Scenario(), synced_at=at(-SKEW))
    add("none with a statement", Scenario(), tip_statement="garbage")
    relay = relay_scenario()
    add("relay missing", relay, production=True)
    add("relay ok", relay, tip_statement=stmt(relay), production=True)
    add("relay behind", relay, tip_statement=stmt(relay, tip=encoding.hashstr(b"elsewhere")), production=True)
    add("relay stale witness", relay, tip_statement=stmt(relay, ts=at(7200)), production=True)
    add("relay superseded statement", relay, tip_statement=stmt(relay, next="yes"), production=True)
    add("relay stale view", relay, tip_statement=stmt(relay), synced_at=at(VIEW_AGE + 1), production=True)
    s = Scenario()
    s.lineage = [{"doc": s.w.doc, "sigs": []}]
    add("unsigned genesis", s)
    add("verifier down", Scenario(), vitni=Unavailable())
    other = Scenario(World(name="OTHER"))
    add("lineage broken", Scenario(), lineage=other.lineage)
    gone = Scenario()
    add("pin missing", gone, pin={**probe_for(gone.w.doc, gone.w.id), "bytes_b64": "", "owner_ok": False,
                                    "reason": "pin_missing"})
    add("pin of another org", gone, pin=probe_for(other.w.doc, other.w.id))
    return out


def two_epoch_world(next_="no", synced_at=NOW):
    w = World()
    a = w.device_add("alice2", AB)
    doc = w.change_doc(a.id)
    later = later_world(w, doc)
    b = later.device_add("bob2", AB)
    s = Scenario(later)
    lineage = [{"doc": w.doc, "sigs": w.sigs(w.doc, ALL)}, {"doc": doc, "sigs": w.sigs(doc, ALL)}]
    return s, w, dict(acts=a.acts + b.acts, lineage=lineage, org=w.id, pin=probe_for(doc, w.id), next=next_,
                      synced_at=synced_at)


class Equality(unittest.TestCase):
    """I12 (VR-19 S8): for every world, `head` answers `ok` with T and `check-act` of an otherwise perfect decision
    that names T passes steps 6 and 14, or `head` answers a code R and `check-act` of that decision answers R."""

    def agree(self, name, s, head_over, vitni=None, production=False):
        inp = value(s, **head_over)
        got = run(inp, vitni=vitni, production=production)
        named = got["head"]["id"] if got["head"] else s.w.id
        data = s.decision_value(s.decision(head=at_head(named), org=inp["org"]), org=inp["org"],
                                **{k: v for k, v in inp.items() if k not in ("org",)})
        profs, fixture = (PRODUCTION_ONLY, False) if production else (FIXTURE, True)
        checked = checkact.run(checkact.parse_input(data), REG, profs, fixture, vitni or FakeVitni())
        if got["head"] is None:
            self.assertEqual(checked["reason"], got["reason"], name)
        else:
            self.assertEqual((got["reason"], checked["reason"]), ("ok", "ok"), name)
        return got

    def test_head_and_check_act_agree_over_every_check_act_world(self):   # SH6, VR-19 S8
        seen = set()
        for name, s, head_over, vitni, production in worlds():
            with self.subTest(world=name):
                seen.add(self.agree(name, s, head_over, vitni, production)["reason"])
        s, _, over = two_epoch_world()
        with self.subTest(world="two epochs"):
            got = self.agree("two epochs", s, over)
            self.assertEqual(got["reason"], "ok")
        for name, extra in (("two epochs superseded", dict(next_="yes")),
                            ("two epochs stale", dict(synced_at=at(VIEW_AGE + 1)))):
            with self.subTest(world=name):
                s, _, over = two_epoch_world(**extra)
                seen.add(self.agree(name, s, over)["reason"])
        # the worlds reach both outcomes and the codes of the view, the witness and the fold
        self.assertTrue({"ok", "fork", "epoch_superseded", "stale_view", "view_in_future", "witness_missing",
                         "witness_unexpected", "behind_witness", "witness_superseded", "stale_witness",
                         "genesis_unsigned", "verifier_unavailable", "lineage_broken", "pin_missing",
                         "pin_org_mismatch"} <= seen, seen)

    def test_the_older_head_check_act_accepts_is_not_what_head_answers(self):   # VR-19 which head: the tip
        s = Scenario()
        steps = chain_of(s.w, 2)
        data = value(s, acts=acts_of(steps))
        self.assertEqual(run(data)["head"]["id"], steps[-1].id)
        older = s.decision_value(s.decision(head=at_head(steps[0].id)), acts=acts_of(steps))
        self.assertEqual(checkact.run(checkact.parse_input(older), REG, FIXTURE, True, FakeVitni())["reason"], "ok")


if __name__ == "__main__":
    unittest.main()
