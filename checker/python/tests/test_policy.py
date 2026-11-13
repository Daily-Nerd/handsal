"""T3.16 policy validation (GP-02, KC-02, KC-03, KC-07): codes and the order GP-15 step 3 fixes."""
import json
import unittest

from handsal_check import coredata, errors, ijson, policy, registry

from .genesis_fixtures import device, edit, policy as make_policy, relay_witness

REG = registry.load()


def registry_with_pending_class():
    """The shipped registry plus one class whose status is `pending-spike`. The first tag ships none
    (KC-02, macOS only), so the one rule that reads the status is proven on a registry built here."""
    doc = ijson.loads(coredata.read_checked(coredata.REGISTRY))
    doc["key_classes"].append({"alg": "ES256", "hardware_bound": True, "id": "later-hw",
                               "per_signature_user_verification": True, "status": "pending-spike",
                               "user_verification": None})
    return registry.Registry(doc)


PENDING_REG = registry_with_pending_class()
THREE = ["alice", "bob", "carol"]


def members(people=THREE, role="maintainer"):
    return [{"id": p, "role": role} for p in people]


def devices(people=THREE):
    return [device(p) for p in people]


def run(pol, people=THREE, fixture=True, member_list=None, reg=REG):
    try:
        policy.validate(pol, member_list or members(people), devices(people), reg, fixture)
    except errors.Refused as err:
        return err.code
    return None


class Valid(unittest.TestCase):
    def test_org3_two_of_three(self):
        self.assertIsNone(run(make_policy()))

    def test_relay_witness(self):
        self.assertIsNone(run(make_policy(witness=relay_witness())))

    def test_persons_up_to_the_spare_rule(self):
        self.assertIsNone(run(make_policy("3"), people=["alice", "bob", "carol", "dave"]))


class ShapeIsPolicyInvalid(unittest.TestCase):
    def test_not_an_object(self):
        for bad in (None, [], "policy", 5):
            self.assertEqual(run(bad), "policy_invalid", bad)

    def test_missing_and_extra_top_keys(self):
        for key in ("classes", "freshness", "roles", "rules", "v", "witness"):
            self.assertEqual(run(edit(make_policy(), [key], delete=True)), "policy_invalid", key)
        self.assertEqual(run(edit(make_policy(), ["extra"], "x")), "policy_invalid")

    def test_wrong_v(self):
        self.assertEqual(run(edit(make_policy(), ["v"], "handsal-policy/2")), "policy_invalid")

    def test_freshness_shape_and_decimals(self):
        p = make_policy()
        self.assertEqual(run(edit(p, ["freshness", "clock_skew_s"], delete=True)), "policy_invalid")
        self.assertEqual(run(edit(p, ["freshness", "x"], "1")), "policy_invalid")
        for bad in ("02", "-1", "", "1e3", "12345678901", 300, None):
            self.assertEqual(run(edit(p, ["freshness", "clock_skew_s"], bad)), "policy_invalid", bad)

    def test_rules_are_exactly_the_four(self):
        p = make_policy()
        for key in ("chain.resolve", "device.remove", "genesis.change", "member.add"):
            self.assertEqual(run(edit(p, ["rules", key], delete=True)), "policy_invalid", key)
        self.assertEqual(run(edit(p, ["rules", "x.y"], {"persons": "2", "roles": ["maintainer"]})),
                         "policy_invalid")

    def test_rule_shape(self):
        p = make_policy()
        self.assertEqual(run(edit(p, ["rules", "device.remove"], {"keys": "2", "roles": ["maintainer"]})),
                         "policy_invalid")                       # the old design form
        self.assertEqual(run(edit(p, ["rules", "member.add", "roles"], [])), "policy_invalid")
        self.assertEqual(run(edit(p, ["rules", "member.add", "roles"], ["maintainer", "maintainer"])),
                         "policy_invalid")
        self.assertEqual(run(edit(p, ["rules", "member.add", "roles"], ["lead"])), "policy_invalid")
        self.assertEqual(run(edit(p, ["rules", "member.add", "persons"], "02")), "policy_invalid")
        self.assertEqual(run(edit(p, ["rules", "member.add", "persons"], 2)), "policy_invalid")

    def test_roles_list(self):
        p = make_policy()
        self.assertEqual(run(edit(p, ["roles"], [])), "policy_invalid")
        self.assertEqual(run(edit(p, ["roles"], ["maintainer", "maintainer", "member"])), "policy_invalid")
        self.assertEqual(run(edit(p, ["roles"], ["Maintainer"])), "policy_invalid")

    def test_a_member_role_must_be_listed(self):
        self.assertEqual(run(make_policy(roles=("lead", "member"), rule_roles=("lead",))),
                         "policy_invalid")

    def test_classes_list(self):
        p = make_policy()
        self.assertEqual(run(edit(p, ["classes"], [])), "policy_invalid")
        dup = [{"class": "apple-se-bio", "user_verification": "biometric_only"}] * 2
        self.assertEqual(run(edit(p, ["classes"], dup)), "policy_invalid")
        self.assertEqual(run(edit(p, ["classes", 0, "x"], "y")), "policy_invalid")
        self.assertEqual(run(edit(p, ["classes", 0, "user_verification"], delete=True)), "policy_invalid")
        self.assertEqual(run(edit(p, ["classes", 0, "class"], 5)), "policy_invalid")
        self.assertEqual(run(edit(p, ["classes", 0, "user_verification"], None)), "policy_invalid")

    def test_witness_shape_is_policy_invalid(self):
        self.assertEqual(run(edit(make_policy(), ["witness"], {"mode": "relays"})), "policy_invalid")


class BoundsArePolicyOutOfBounds(unittest.TestCase):
    def test_persons(self):
        for bad in ("0", "1", "16", "999999999"):
            self.assertEqual(run(make_policy(bad)), "policy_out_of_bounds", bad)

    def test_persons_bound_in_a_single_rule(self):
        p = make_policy()
        self.assertEqual(run(edit(p, ["rules", "chain.resolve", "persons"], "16")), "policy_out_of_bounds")
        self.assertEqual(run(edit(p, ["rules", "device.remove", "persons"], "1")), "policy_out_of_bounds")

    def test_freshness_bounds(self):
        p = make_policy()
        cases = (("clock_skew_s", "3601"), ("max_validity_s", "59"), ("max_validity_s", "2592001"),
                 ("max_view_age_s", "59"), ("max_view_age_s", "2592001"))
        for key, bad in cases:
            self.assertEqual(run(edit(p, ["freshness", key], bad)), "policy_out_of_bounds", (key, bad))
        for key, ok in (("clock_skew_s", "0"), ("clock_skew_s", "3600"), ("max_validity_s", "60"),
                        ("max_validity_s", "2592000"), ("max_view_age_s", "60"), ("max_view_age_s", "2592000")):
            self.assertIsNone(run(edit(p, ["freshness", key], ok)), (key, ok))

    def test_witness_tip_age(self):
        self.assertEqual(run(make_policy(witness=relay_witness("59"))), "policy_out_of_bounds")
        self.assertEqual(run(make_policy(witness=relay_witness("86401"))), "policy_out_of_bounds")
        self.assertIsNone(run(make_policy(witness=relay_witness("60"))))
        self.assertIsNone(run(make_policy(witness=relay_witness("86400"))))

    def test_invalid_is_reported_before_out_of_bounds(self):
        p = edit(make_policy("1"), ["v"], "nope")
        self.assertEqual(run(p), "policy_invalid")
        p = edit(make_policy("16"), ["freshness", "clock_skew_s"], "02")
        self.assertEqual(run(p), "policy_invalid")


class Reachability(unittest.TestCase):
    def test_persons_must_be_smaller_than_the_role_holders(self):
        self.assertEqual(run(make_policy("3")), "policy_unreachable")             # three holders, Q 3
        self.assertEqual(run(make_policy("4")), "policy_unreachable")
        self.assertEqual(run(make_policy("2"), people=["alice", "bob"]), "policy_unreachable")
        self.assertEqual(run(make_policy("2"), people=["alice"]), "policy_unreachable")

    def test_each_rule_counts_its_own_role_holders(self):
        two_leads = [{"id": "alice", "role": "lead"}, {"id": "bob", "role": "lead"},
                     {"id": "carol", "role": "maintainer"}, {"id": "dave", "role": "maintainer"}]
        p = make_policy(roles=("lead", "maintainer"))
        p["rules"]["chain.resolve"]["roles"] = ["lead"]
        self.assertEqual(run(p, people=["alice", "bob", "carol", "dave"], member_list=two_leads),
                         "policy_unreachable")

    def test_a_non_role_holder_is_not_counted(self):
        people = ["alice", "bob", "carol", "dave"]
        ml = members(THREE) + [{"id": "dave", "role": "member"}]
        self.assertEqual(run(make_policy("3"), people=people, member_list=ml), "policy_unreachable")
        self.assertIsNone(run(make_policy("2"), people=people, member_list=ml))

    def test_bounds_are_reported_before_reachability(self):
        self.assertEqual(run(make_policy("16")), "policy_out_of_bounds")
        p = edit(make_policy("3"), ["rules", "member.add", "persons"], "1")
        self.assertEqual(run(p), "policy_out_of_bounds")


class Classes(unittest.TestCase):
    def test_unknown_class(self):
        p = make_policy(classes=(("apple-se-bio", "biometric_only"), ("yubikey-piv", "biometric_only")))
        self.assertEqual(run(p), "class_unknown")

    def test_fixture_only_class_is_unknown_under_production(self):
        p = make_policy(classes=(("apple-se-bio", "biometric_only"), ("fixture-pin", "biometric_or_pin")))
        self.assertEqual(run(p, fixture=False), "class_unknown")
        self.assertIsNone(run(p, fixture=True))

    def test_pending_class_cannot_be_listed(self):
        p = make_policy(classes=(("apple-se-bio", "biometric_only"), ("later-hw", "biometric_only")))
        self.assertEqual(run(p, reg=PENDING_REG), "class_pending")

    def test_the_windows_class_is_not_in_the_first_tag(self):
        """T7.7: the class returns with a registry version bump in the Windows tag; until then a
        policy that lists it names a class the registry does not have."""
        p = make_policy(classes=(("apple-se-bio", "biometric_only"), ("win-hello-hw", "biometric_only")))
        self.assertEqual(run(p), "class_unknown")
        self.assertEqual(json.loads(coredata.read_checked(coredata.REGISTRY))["key_classes"].__len__(), 2)

    def test_test_only_class_cannot_be_listed(self):
        p = make_policy(classes=(("apple-se-bio", "biometric_only"), ("test-sw-p256", "none")))
        self.assertEqual(run(p), "class_test_only")

    def test_user_verification_must_equal_the_registry_value(self):
        self.assertEqual(run(make_policy(classes=(("apple-se-bio", "biometric_or_pin"),))), "class_policy_mismatch")
        self.assertEqual(run(make_policy(classes=(("apple-se-bio", "none"),))), "class_policy_mismatch")
        self.assertEqual(run(make_policy(classes=(("apple-se-bio", "fingerprint"),))), "class_policy_mismatch")

    def test_unknown_before_pending_before_test_only_before_mismatch(self):
        everything = (("apple-se-bio", "none"), ("later-hw", "biometric_only"), ("test-sw-p256", "none"),
                      ("yubikey-piv", "none"))
        p = make_policy(classes=tuple(sorted(everything)))
        self.assertEqual(run(p, reg=PENDING_REG), "class_unknown")
        p = make_policy(classes=tuple(sorted(everything[:3])))
        self.assertEqual(run(p, reg=PENDING_REG), "class_pending")
        p = make_policy(classes=(("apple-se-bio", "none"), ("test-sw-p256", "none")))
        self.assertEqual(run(p), "class_test_only")

    def test_unreachable_is_reported_before_class_codes(self):
        p = make_policy("3", classes=(("apple-se-bio", "biometric_only"), ("yubikey-piv", "none")))
        self.assertEqual(run(p), "policy_unreachable")


if __name__ == "__main__":
    unittest.main()
