"""T3.16 genesis document validation (GP-01, GP-02, GP-15 steps 1 to 3, GP-18, KC-05, KC-08, ACT-11).

Rows follow the `gen/*`, `pol/*`, `cls/role-holder-*` and `fix/*` ids that need no
signature and no lineage: the checks of a single document, in the order GP-15 fixes.
"""
import unittest

from handsal_check import encoding, errors, genesis, profiles, registry

from . import p256_helper
from .genesis_fixtures import KEYS, change, device, edit, org, policy, relay_witness
from .profile_sets import fixture_of, production_of

REG = registry.load()
PROFILES = profiles.load()
FIX = fixture_of(PROFILES)
PROD = production_of(PROFILES)
H = encoding.hashstr(b"previous")
H2 = encoding.hashstr(b"org")


def ctx(allow_fixture=True):
    return genesis.Context(PROFILES, allow_fixture)


def run(doc, allow_fixture=True, previous=None):
    """The code `check_document` refuses `doc` with, else the kind of its profile. `previous` is the profile hash of the document before it."""
    try:
        got = genesis.check_document(doc, ctx(allow_fixture), None if previous is None else PROFILES.resolve(previous))
        return "fixture" if got.fixture else "production"
    except errors.Refused as err:
        return err.code


def doc(**kw):
    return org(FIX, **kw)


class Valid(unittest.TestCase):
    def test_org_original(self):
        self.assertEqual(run(doc()), "fixture")

    def test_change_shape(self):
        self.assertEqual(run(change(FIX, H2, H, H2)), "fixture")

    def test_a_production_document_with_unlisted_keys(self):
        people = ["alice", "bob", "carol"]
        devices = [p256_helper.production_device(p, p) for p in people]
        self.assertEqual(run(org(PROD, devices=devices), allow_fixture=False), "production")

    def test_doc_hash_is_the_hashstr_of_the_canonical_bytes(self):
        from handsal_check import emit
        d = doc()
        self.assertEqual(genesis.doc_hash(d), encoding.hashstr(emit.emit_subset(d)))
        self.assertNotEqual(genesis.doc_hash(d), genesis.doc_hash(doc(name="OTHER")))

    def test_pin_class_is_fine_for_a_member_who_is_not_a_role_holder(self):
        # cls/nonrole-pin-device-ok: dave has role member and holds a fixture-pin device
        pol = policy(classes=(("apple-se-bio", "biometric_only"), ("fixture-pin", "biometric_or_pin")))
        devices = [device("alice"), device("bob"), device("carol"),
                   device("dave", cls="fixture-pin")]
        d = doc(devices=devices, pol=pol)
        d["members"] = sorted(d["members"] + [{"id": "dave", "role": "member"}], key=lambda m: m["id"])
        self.assertEqual(run(d), "fixture")


class Step1Structure(unittest.TestCase):
    def test_not_an_object_or_not_in_the_canonical_subset(self):
        for bad in (None, [], "doc", 5):
            self.assertEqual(run(bad), "genesis_schema", bad)
        self.assertEqual(run(edit(doc(), ["name"], 5)), "genesis_schema")
        self.assertEqual(run(edit(doc(), ["name"], True)), "genesis_schema")

    def test_extra_and_missing_keys(self):
        self.assertEqual(run(edit(doc(), ["extra"], "x")), "genesis_schema")
        for key in ("devices", "members", "name", "org", "prev", "profile", "v"):
            self.assertEqual(run(edit(doc(), [key], delete=True)), "genesis_schema", key)

    def test_wrong_v(self):
        self.assertEqual(run(edit(doc(), ["v"], "handsal-genesis/2")), "genesis_schema")

    def test_name_limits(self):
        self.assertEqual(run(doc(name="x" * 25)), "genesis_schema")
        self.assertEqual(run(doc(name="")), "genesis_schema")
        self.assertEqual(run(doc(name="café")), "genesis_schema")
        self.assertEqual(run(doc(name="x" * 24)), "fixture")

    def test_original_shape(self):
        self.assertEqual(run(edit(doc(), ["org"], H2)), "genesis_schema")         # org set, prev null
        self.assertEqual(run(edit(doc(), ["head"], H)), "genesis_schema")         # head on an original
        self.assertEqual(run(edit(doc(), ["head"], None)), "genesis_schema")

    def test_change_shape(self):
        good = change(FIX, H2, H, H2)
        self.assertEqual(run(edit(good, ["head"], delete=True)), "genesis_schema")
        self.assertEqual(run(edit(good, ["head"], "nope")), "genesis_schema")
        self.assertEqual(run(edit(good, ["head"], None)), "genesis_schema")
        self.assertEqual(run(edit(good, ["org"], None)), "genesis_schema")
        self.assertEqual(run(edit(good, ["org"], "nope")), "genesis_schema")
        self.assertEqual(run(edit(good, ["prev"], "nope")), "genesis_schema")

    def test_profile_must_be_a_hashstr(self):
        self.assertEqual(run(edit(doc(), ["profile"], "nope")), "genesis_schema")
        self.assertEqual(run(edit(doc(), ["profile"], None)), "genesis_schema")

    def test_members(self):
        d = doc()
        self.assertEqual(run(edit(d, ["members"], [])), "genesis_schema")
        self.assertEqual(run(edit(d, ["members"], "x")), "genesis_schema")
        dup = d["members"] + [dict(d["members"][0])]
        self.assertEqual(run(edit(d, ["members"], dup)), "genesis_schema")
        self.assertEqual(run(edit(d, ["members", 0, "extra"], "x")), "genesis_schema")
        self.assertEqual(run(edit(d, ["members", 0, "id"], "Alice")), "genesis_schema")
        self.assertEqual(run(edit(d, ["members", 0, "role"], "Maintainer")), "genesis_schema")

    def test_a_member_without_a_device(self):
        d = doc()
        d["devices"] = [e for e in d["devices"] if e["person"] != "carol"]
        self.assertEqual(run(d), "genesis_schema")

    def test_a_device_for_a_person_who_is_not_a_member(self):
        d = doc()
        d["devices"] = sorted(d["devices"] + [device("dave")], key=lambda e: e["kid"])
        self.assertEqual(run(d), "genesis_schema")

    def test_no_devices(self):
        self.assertEqual(run(edit(doc(), ["devices"], [])), "genesis_schema")

    def test_device_entry_is_closed(self):
        d = doc()
        self.assertEqual(run(edit(d, ["devices", 0, "alg"], "ES256")), "genesis_schema")   # KC-05
        for key in ("agree", "class", "kid", "label", "person", "sign"):
            self.assertEqual(run(edit(d, ["devices", 0, key], delete=True)), "genesis_schema", key)
        self.assertEqual(run(edit(d, ["devices", 0, "label"], 'a"b')), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "label"], "")), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "person"], "Bob")), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "class"], 5)), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "kid"], 5)), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "sign"], "x")), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "agree", "z"], "x")), "genesis_schema")
        self.assertEqual(run(edit(d, ["devices", 0, "agree", "x"], 5)), "genesis_schema")

    def test_devices_unsorted(self):
        d = doc()
        d["devices"] = list(reversed(d["devices"]))
        self.assertEqual(run(d), "doc_not_sorted")

    def test_members_unsorted(self):
        d = doc()
        d["members"] = list(reversed(d["members"]))
        self.assertEqual(run(d), "doc_not_sorted")

    def test_policy_roles_unsorted(self):
        self.assertEqual(run(doc(pol=policy(roles=("member", "maintainer")))), "doc_not_sorted")

    def test_policy_classes_unsorted(self):
        pol = policy(classes=(("fixture-pin", "biometric_or_pin"), ("apple-se-bio", "biometric_only")))
        self.assertEqual(run(doc(pol=pol)), "doc_not_sorted")

    def test_policy_relays_unsorted(self):   # GP-01: `relays` is a sorted list of the policy
        self.assertEqual(run(doc(pol=policy(relays=("s.example", "r.example")))), "doc_not_sorted")
        self.assertEqual(run(doc(pol=policy(relays=("r.example", "s.example")))), "fixture")

    def test_relays_unsorted_is_judged_in_step_1_before_the_policy_codes(self):
        pol = policy(relays=("s.example", "r.example"))
        pol["v"] = "handsal-policy/2"
        self.assertEqual(run(doc(pol=pol)), "doc_not_sorted")

    def test_rule_roles_unsorted(self):
        pol = policy(rule_roles=("member", "maintainer"))
        self.assertEqual(run(doc(pol=pol)), "doc_not_sorted")

    def test_a_malformed_policy_is_not_sorted_here_it_is_policy_invalid_later(self):
        self.assertEqual(run(edit(doc(), ["policy"], delete=True)), "policy_invalid")
        self.assertEqual(run(edit(doc(), ["policy"], "x")), "policy_invalid")
        self.assertEqual(run(edit(doc(), ["policy", "roles"], "x")), "policy_invalid")

    def test_key_defects(self):
        d = doc()
        y = encoding.b64u_decode(d["devices"][0]["sign"]["y"])
        off = encoding.b64u_encode(y[:-1] + bytes([y[-1] ^ 1]))
        cases = {
            "agree equals sign": edit(d, ["devices", 0, "agree"], dict(d["devices"][0]["sign"])),
            "kid not thumbprint": edit(d, ["devices", 0, "kid"], KEYS["dave.sign"]["kid"]),
            "off the curve": edit(d, ["devices", 0, "sign", "y"], off),
            "x 31 bytes": edit(d, ["devices", 0, "sign", "x"],
                               encoding.b64u_encode(encoding.b64u_decode(d["devices"][0]["sign"]["x"])[1:])),
            "agree off the curve": edit(d, ["devices", 0, "agree", "y"], off),
        }
        for label, bad in cases.items():
            self.assertEqual(run(bad), "genesis_key_invalid", label)

    def test_duplicates(self):
        d = doc()
        # same kid and keys for two persons (devices stay sorted, so no sort defect)
        alice = next(e for e in d["devices"] if e["person"] == "alice")
        twin = dict(alice, person="bob")
        d_kid = edit(d, ["devices"], sorted(d["devices"] + [twin], key=lambda e: e["kid"]))
        self.assertEqual(run(d_kid), "duplicate_key")
        # same agree key, different signing keys
        bob = next(e for e in d["devices"] if e["person"] == "bob")
        shared = edit(d, ["devices"], [dict(e, agree=dict(alice["agree"])) if e is bob else e
                                       for e in d["devices"]])
        self.assertEqual(run(shared), "duplicate_key")

    def test_step_1_order_schema_sorted_key_duplicate(self):
        d = doc()
        # unsorted members and an extra key: schema first
        both = edit(d, ["extra"], "x")
        both["members"] = list(reversed(both["members"]))
        self.assertEqual(run(both), "genesis_schema")
        # unsorted devices and a bad key: sorted first
        bad_and_unsorted = edit(d, ["devices", 0, "agree"], dict(d["devices"][0]["sign"]))
        bad_and_unsorted["devices"] = list(reversed(bad_and_unsorted["devices"]))
        self.assertEqual(run(bad_and_unsorted), "doc_not_sorted")
        # a key defect and a duplicate: key first
        alice = next(e for e in d["devices"] if e["person"] == "alice")
        twin = dict(alice, person="bob", agree=dict(alice["sign"]))
        both_key_dup = edit(d, ["devices"], sorted(d["devices"] + [twin], key=lambda e: e["kid"]))
        self.assertEqual(run(both_key_dup), "genesis_key_invalid")


class Step2Profile(unittest.TestCase):
    def test_unimplemented_profile(self):
        self.assertEqual(run(org(encoding.hashstr(b"another"))), "profile_mismatch")

    def test_fixture_profile_refused_where_the_build_refuses_it(self):
        self.assertEqual(run(doc(), allow_fixture=False), "fixture_profile")

    def test_a_lineage_mixing_the_two(self):
        self.assertEqual(run(doc(), previous=PROD), "fixture_profile")
        self.assertEqual(run(org(PROD), previous=FIX), "fixture_profile")

    def test_structure_is_reported_before_the_profile(self):
        d = org(encoding.hashstr(b"another"), name="x" * 25)
        self.assertEqual(run(d), "genesis_schema")

    def test_profile_is_reported_before_class_codes(self):
        pol = policy(classes=(("apple-se-bio", "biometric_only"), ("yubikey-piv", "none")))
        self.assertEqual(run(org(encoding.hashstr(b"another"), pol=pol)), "profile_mismatch")

    def test_profile_is_reported_before_a_fixture_key(self):
        self.assertEqual(run(org(encoding.hashstr(b"another"))), "profile_mismatch")


class Step3PolicyAndDevices(unittest.TestCase):
    def test_policy_codes_pass_through(self):
        self.assertEqual(run(doc(pol=policy("3"))), "policy_unreachable")
        self.assertEqual(run(doc(pol=policy("1"))), "policy_out_of_bounds")
        self.assertEqual(run(doc(pol=edit(policy(), ["freshness"], delete=True))), "policy_invalid")
        self.assertEqual(run(doc(pol=policy(classes=(("apple-se-bio", "none"),)))), "class_policy_mismatch")

    def test_a_member_role_the_policy_does_not_list(self):
        d = doc()
        d["members"][0]["role"] = "admin"
        self.assertEqual(run(d), "policy_invalid")

    def test_a_listed_device_whose_class_the_policy_does_not_accept(self):
        pol = policy(classes=(("apple-se-bio", "biometric_only"),))
        devices = [device("alice"), device("bob"), device("carol", cls="fixture-pin")]
        self.assertEqual(run(doc(devices=devices, pol=pol)), "genesis_schema")
        unknown = [device("alice"), device("bob"), device("carol", cls="yubikey-piv")]
        self.assertEqual(run(doc(devices=unknown, pol=pol)), "genesis_schema")

    def test_policy_is_reported_before_the_device_class(self):
        pol = edit(policy(), ["classes"], delete=True)
        self.assertEqual(run(doc(devices=[device("alice", cls="x")], pol=pol, people=["alice"])),
                         "policy_invalid")
        devices = [device("alice"), device("bob"), device("carol", cls="yubikey-piv")]
        self.assertEqual(run(doc(devices=devices, pol=edit(policy(), ["classes"], delete=True))),
                         "policy_invalid")

    def test_role_holder_with_a_pin_class_device(self):
        pol = policy(classes=(("apple-se-bio", "biometric_only"), ("fixture-pin", "biometric_or_pin")))
        devices = [device("alice"), device("bob"), device("carol"), device("alice-pin", cls="fixture-pin")]
        self.assertEqual(run(doc(devices=devices, pol=pol)), "role_key_class")

    def test_fixture_key_under_a_production_profile(self):
        self.assertEqual(run(org(PROD), allow_fixture=False), "fixture_key")

    def test_a_fixture_relay_kid_under_a_production_profile(self):
        devices = [p256_helper.production_device(p, p) for p in ("alice", "bob", "carol")]
        pol = policy(witness=relay_witness())
        self.assertEqual(run(org(PROD, devices=devices, pol=pol), allow_fixture=False), "fixture_key")

    def test_a_relay_that_is_not_a_fixture_key_is_fine_under_production(self):
        devices = [p256_helper.production_device(p, p) for p in ("alice", "bob", "carol")]
        relay = p256_helper.public_point(0x1234567)
        pol = policy(witness={"max_tip_age_s": "3600", "mode": "relay",
                              "relay_kid": encoding.thumbprint(relay["x"], relay["y"]),
                              "relay_pub_jwk": {"crv": "P-256", "kty": "EC", **relay}})
        self.assertEqual(run(org(PROD, devices=devices, pol=pol), allow_fixture=False), "production")

    def test_pin_class_under_production_is_class_unknown(self):
        pol = policy(classes=(("apple-se-bio", "biometric_only"), ("fixture-pin", "biometric_or_pin")))
        devices = [p256_helper.production_device(p, p) for p in ("alice", "bob", "carol")]
        self.assertEqual(run(org(PROD, devices=devices, pol=pol), allow_fixture=False), "class_unknown")


class Step4Links(unittest.TestCase):
    """GP-07, GP-15 step 4: `lineage_broken`. A link is judged on documents that passed steps 1 to 3."""

    def link(self, document, previous, original_org):
        try:
            genesis.check_link(document, previous, original_org)
        except errors.Refused as err:
            return err.code
        return None

    def test_the_first_document_must_be_an_original(self):
        original = doc()
        self.assertIsNone(self.link(original, None, genesis.doc_hash(original)))
        chg = change(FIX, H2, H, H2)
        self.assertEqual(self.link(chg, None, H2), "lineage_broken")

    def test_a_change_names_the_previous_document_and_the_original_org(self):
        original = doc()
        org_id = genesis.doc_hash(original)
        good = change(FIX, org_id, genesis.doc_hash(original), H)
        self.assertIsNone(self.link(good, original, org_id))
        self.assertEqual(self.link(edit(good, ["prev"], H2), original, org_id), "lineage_broken")
        self.assertEqual(self.link(edit(good, ["org"], H2), original, org_id), "lineage_broken")

    def test_a_second_original_in_the_lineage_is_broken(self):
        original = doc()
        self.assertEqual(self.link(doc(name="SECOND"), original, genesis.doc_hash(original)), "lineage_broken")

    def test_each_link_is_to_the_document_before_it_not_the_original(self):
        original = doc()
        org_id = genesis.doc_hash(original)
        second = change(FIX, org_id, genesis.doc_hash(original), H, name="SECOND")
        third = change(FIX, org_id, genesis.doc_hash(original), H, name="THIRD")   # skips `second`
        self.assertIsNone(self.link(second, original, org_id))
        self.assertEqual(self.link(third, second, org_id), "lineage_broken")


if __name__ == "__main__":
    unittest.main()
