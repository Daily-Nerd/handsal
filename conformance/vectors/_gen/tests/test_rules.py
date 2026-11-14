"""The generator model refuses an authorial `ok` or `valid` claim that the spec's rules contradict.

`Chain` records the acts a vector author calls valid; nothing else judges them. The rules of
FO-22 and FO-23 that the model can evaluate are checked here, against the state at the act's
parent: quorum, consent on `device.add`, the target of a removal, a new member, key classes.
"""
import unittest

from lib import base, chain, inputs, rules

FX = base.Fixtures(base.fixture_profile())


def _pending_registry():
    """The shipped registry plus a class that is `pending-spike`: the first tag ships none (KC-02)."""
    reg = rules._registry()
    reg["key_classes"].append({"alg": "ES256", "hardware_bound": True, "id": "later-hw",
                               "per_signature_user_verification": True, "status": "pending-spike",
                               "user_verification": None})
    return reg


PENDING_REG = _pending_registry()
AB, AC, BC = ("alice", "bob"), ("alice", "carol"), ("bob", "carol")


class Consent(unittest.TestCase):
    """FO-22 consent on `device.add`."""

    def setUp(self):
        self.c = chain.Chain(FX)

    def test_an_add_beside_an_active_device_needs_a_key_of_that_person(self):
        with self.assertRaisesRegex(rules.Refused, "consent"):
            self.c.device_add("bob2", AC)

    def test_the_persons_own_key_as_primary_or_endorser_gives_consent(self):
        self.c.device_add("bob2", BC)
        self.c.device_add("alice2", ("bob", "alice"))

    def test_a_removed_key_gives_no_consent(self):
        self.c.device_add("alice2", AB)
        self.c.device_remove("alice", BC)
        with self.assertRaisesRegex(rules.Refused, "consent"):
            self.c.device_add("alice3", ("bob", "carol", "alice"))

    def test_a_person_without_an_active_device_needs_no_consent(self):
        self.c.device_remove("carol", AB)
        self.c.device_add("carol2", AB)

    def test_consent_is_read_at_the_acts_parent_not_at_the_tip(self):
        first = self.c.device_add("alice2", AB)
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "consent"):  # carol is active at `first`
            self.c.device_add("carol2", AB, ok=False, valid=True, parent=first)
        self.c.device_add("carol2", AB)  # and has none at the tip

    def test_an_act_declared_not_ok_is_never_checked(self):
        self.c.device_add("bob2", AC, ok=False)


class StateAt(unittest.TestCase):
    """`Chain.state_at(built)`: the state after any act the author called valid."""

    def test_it_gives_the_state_after_an_applied_and_an_off_tip_act(self):
        c = chain.Chain(FX)
        first = c.device_add("alice2", AB)
        side = c.device_add("bob2", BC, ok=False, valid=True, parent=None)
        self.assertEqual(c.state_at(first).n, 1)
        self.assertIn(FX.key("bob2").kid, c.state_at(side).devices["bob"])
        self.assertNotIn(FX.key("bob2").kid, c.state_at(first).devices["bob"])
        self.assertEqual(c.state_at(None).n, 0)

    def test_an_act_declared_not_ok_has_no_state(self):
        c = chain.Chain(FX)
        gone = c.device_add("alice2", AB, ok=False)
        with self.assertRaises(KeyError):
            c.state_at(gone)


class Quorum(unittest.TestCase):
    def setUp(self):
        self.c = chain.Chain(FX)

    def test_two_devices_of_one_person_are_one_person(self):
        self.c.device_add("alice2", AB)
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            self.c.device_add("alice3", ("alice", "alice2", "dave"))

    def test_a_signer_not_in_the_state_does_not_count(self):
        with self.assertRaisesRegex(rules.Refused, "signer"):
            self.c.device_add("alice2", ("carol2", "alice"))

    def test_a_removed_signer_does_not_count(self):
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "signer"):
            self.c.device_remove("bob", ("carol", "alice"))

    def test_a_person_without_a_listed_role_is_not_counted(self):
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            self.c.device_add("alice2", ("alice", "dave"))

    def test_the_primary_signer_need_not_hold_a_role(self):
        self.c.member_add("dave", AB, role="member")
        self.c.device_add("alice2", ("dave", "alice", "bob"))

    def test_the_rule_is_the_policys_persons(self):
        from lib import epochs
        c = epochs.original_chain(FX, epochs.org4(FX))
        with self.assertRaisesRegex(rules.Refused, "quorum"):
            c.device_add("alice2", AB)
        c.device_add("alice2", ("alice", "bob", "carol"))


class Targets(unittest.TestCase):
    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_removal_needs_an_active_device_of_the_person(self):
        self.c.device_remove("carol", AB)
        with self.assertRaisesRegex(rules.Refused, "target"):
            self.c.device_remove("carol", AB)

    def test_a_removal_of_a_key_the_state_does_not_hold_is_refused(self):
        with self.assertRaisesRegex(rules.Refused, "target"):
            self.c.device_remove("alice2", BC)

    def test_a_device_add_needs_a_member(self):
        with self.assertRaisesRegex(rules.Refused, "member"):
            self.c.device_add("dave", AB)

    def test_a_member_add_needs_an_unused_id(self):
        self.c.member_add("dave", AB, role="member")
        with self.assertRaisesRegex(rules.Refused, "unused"):
            self.c.member_add("dave2", AB, role="member", member="dave")

    def test_a_member_add_needs_a_listed_role(self):
        with self.assertRaisesRegex(rules.Refused, "role"):
            self.c.member_add("dave", AB, role="admin")

    def test_a_member_id_of_an_earlier_epoch_is_not_unused(self):
        from lib import epochs, inputs
        change = epochs.make_change(FX, FX.org, FX.org_id, carry=("alice", "bob"),
                                    new=("frank",))
        sigs = epochs.sign_change(FX, change)
        lineage = FX.lineage() + [{"doc": change, "sigs": sigs}]
        c = chain.Chain(FX, doc=change, lineage=lineage)
        with self.assertRaisesRegex(rules.Refused, "unused"):
            c.member_add("carol2", ("alice", "bob"), role="maintainer", member="carol")
        self.assertIsNotNone(inputs.doc_id(change))


class Classes(unittest.TestCase):
    """KC-08: a role holder's key must be of a biometric-only class."""

    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_pin_class_key_for_a_role_holder_is_refused(self):
        with self.assertRaisesRegex(rules.Refused, "class"):
            self.c.device_add("alice2", AB, cls="fixture-pin")

    def test_a_pin_class_key_for_a_member_without_a_listed_role_is_allowed(self):
        self.c.member_add("dave", AB, role="member")
        self.c.device_add("dave2", ("alice", "dave", "bob"), cls="fixture-pin")


class MemberAddClass(unittest.TestCase):
    """KC-08 reads the class of a `member.add` device the same way as a `device.add` one."""

    def setUp(self):
        self.c = chain.Chain(FX)

    def test_a_pin_class_device_for_a_new_maintainer_is_refused(self):
        with self.assertRaisesRegex(rules.Refused, "class"):
            self.c.member_add("frank", AB, role="maintainer", cls="fixture-pin")

    def test_a_pin_class_device_for_a_new_member_without_a_listed_role_is_allowed(self):
        self.c.member_add("frank", AB, role="member", cls="fixture-pin")
        device = next(iter(self.c.state.devices["frank"].values()))
        self.assertEqual(device["class"], "fixture-pin")
        self.assertFalse(device["accepted"])

    def test_the_class_reaches_the_act_body(self):
        built = self.c.member_add("frank", AB, role="member", cls="fixture-pin")
        import json
        from lib import forge
        body = json.loads(forge.parts(built.acts[0])[1])["ext"]["dev.handsal/act"]["body"]
        self.assertEqual(body["device"]["class"], "fixture-pin")


def _doc(edit):
    return inputs.derive(FX.org, edit)


def _classes(*pairs):
    def edit(doc):
        doc["policy"]["classes"] = [{"class": c, "user_verification": uv} for c, uv in pairs]
    return edit


def _holds(person, name, cls):
    """`name`'s device (class `cls`) is listed in the document under `person`."""
    def edit(doc):
        entry = FX.device_entry(name, cls)
        entry["person"] = person
        doc["devices"] = sorted(doc["devices"] + [entry], key=lambda d: d["kid"])
    return edit


PIN_PAIR = ("fixture-pin", "biometric_or_pin")
BIO_PAIR = ("apple-se-bio", "biometric_only")


class GenesisClasses(unittest.TestCase):
    """GP-15 step 3, the class half: the first code a document earns from KC-01 to KC-08."""

    def code(self, *edits, fixture=True, reg=None):
        def edit(doc):
            for one in edits:
                one(doc)
        return rules.genesis_classes(_doc(edit), fixture=fixture, reg=reg)

    def test_org_has_no_class_defect(self):
        self.assertIsNone(rules.genesis_classes(FX.org, fixture=True))

    def test_a_class_outside_the_registry_is_class_unknown(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, ("yubikey-piv", "biometric_only"))), "class_unknown")

    def test_a_pending_class_is_class_pending(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, ("later-hw", "biometric_only")), reg=PENDING_REG),
                         "class_pending")

    def test_the_shipped_registry_has_no_pending_class_so_the_windows_class_is_unknown(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, ("win-hello-hw", "biometric_only"))), "class_unknown")

    def test_the_test_class_is_class_test_only(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, ("test-sw-p256", "none"))), "class_test_only")

    def test_a_pair_that_differs_from_the_registry_is_class_policy_mismatch(self):
        self.assertEqual(self.code(_classes(("apple-se-bio", "biometric_or_pin"))), "class_policy_mismatch")

    def test_the_codes_come_in_the_order_of_gp_15_wherever_the_defects_sit(self):
        mismatch, test_only = ("apple-se-bio", "biometric_or_pin"), ("test-sw-p256", "none")
        pending, unknown = ("later-hw", "biometric_only"), ("yubikey-piv", "biometric_only")
        for want, pairs in (("class_test_only", (mismatch, test_only)),
                            ("class_pending", (test_only, pending)),
                            ("class_unknown", (pending, unknown))):
            self.assertEqual(self.code(_classes(*pairs), reg=PENDING_REG), want)

    def test_a_device_of_a_class_the_policy_does_not_list_is_genesis_schema(self):
        self.assertEqual(self.code(_holds("dave", "dave", "fixture-pin"), _members_dave()), "genesis_schema")

    def test_a_role_holder_with_a_pin_class_device_is_role_key_class(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, PIN_PAIR), _holds("alice", "alice-pin", "fixture-pin")),
                         "role_key_class")

    def test_a_member_without_a_listed_role_may_hold_a_listed_pin_class_device(self):
        self.assertIsNone(self.code(_classes(BIO_PAIR, PIN_PAIR), _members_dave(),
                                    _holds("dave", "dave", "fixture-pin")))

    def test_a_fixture_only_class_is_unknown_under_a_production_profile(self):
        self.assertEqual(self.code(_classes(BIO_PAIR, PIN_PAIR), fixture=False), "class_unknown")
        self.assertIsNone(self.code(_classes(BIO_PAIR, PIN_PAIR), fixture=True))


def _members_dave():
    def edit(doc):
        doc["members"] = sorted(doc["members"] + [{"id": "dave", "role": "member"}], key=lambda m: m["id"])
    return edit


if __name__ == "__main__":
    unittest.main()
