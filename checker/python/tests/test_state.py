"""The projection of a state to the vitni `keys` map (FO-02), whole and narrowed to one signer.

`keys_map` is the one owner of the projection. `keys_for` and `has_entry` are the same projection read at one
`(person, kid)` or one kid, in one lookup, so a question to the verifier carries the entry it reads and nothing else.
"""
import pathlib
import random
import re
import unittest

from handsal_check import state, verifier

from .act_builder import kid_of
from .genesis_fixtures import point
from .shared_reads import Reads

PERSONS = ("alice", "bob", "carol", "nobody")


def device(name, person, status="active", accepted=True):
    return state.Device(person, "apple-se-bio", "phone", state.point(point(name + ".sign")),
                        state.point(point(name + ".agree")), status, accepted)


def devices():
    """Active, removed, unaccepted and another person's devices: every row of the projection."""
    return {kid_of("alice"): device("alice", "alice"),
            kid_of("bob"): device("bob", "bob"),
            kid_of("carol"): device("carol", "carol"),
            kid_of("bob2"): device("bob2", "bob", status="removed"),
            kid_of("alice2"): device("alice2", "alice", accepted=False),
            kid_of("alice3"): device("alice3", "alice", status="removed", accepted=False)}


def narrow(keys, person, kid):
    """`keys` cut to the one entry `(person, kid)` names, written from the definition: the entry, or nothing."""
    entry = keys.get(person, {}).get(kid)
    return {} if entry is None else {person: {kid: entry}}


class Narrowed(unittest.TestCase):
    def setUp(self):
        self.state = state.State({"alice": "maintainer", "bob": "maintainer", "carol": "maintainer"}, devices())
        self.kids = list(self.state.devices) + [kid_of("dave"), "k" * 43]

    def test_keys_for_is_keys_map_cut_to_one_entry_for_every_person_and_kid(self):
        full = self.state.keys_map()
        for person in PERSONS:
            for kid in self.kids:
                with self.subTest(person=person, kid=kid[:6]):
                    self.assertEqual(self.state.keys_for(person, kid), narrow(full, person, kid))

    def test_a_kid_that_is_absent_or_under_another_person_or_unaccepted_has_no_entry(self):
        self.assertEqual(self.state.keys_for("alice", kid_of("dave")), {})
        self.assertEqual(self.state.keys_for("bob", kid_of("alice")), {})     # alice's kid, asked for bob
        self.assertEqual(self.state.keys_for("alice", kid_of("alice2")), {})  # not accepted (KC-04)
        self.assertEqual(self.state.keys_for("alice", kid_of("alice3")), {})  # not accepted and removed
        self.assertEqual(self.state.keys_for("nobody", kid_of("alice")), {})

    def test_a_removed_device_is_revoked_exactly_as_keys_map_has_it(self):
        got = self.state.keys_for("bob", kid_of("bob2"))
        self.assertEqual(got["bob"][kid_of("bob2")]["status"], "revoked")
        self.assertEqual(got, {"bob": {kid_of("bob2"): self.state.keys_map()["bob"][kid_of("bob2")]}})
        self.assertEqual(self.state.keys_for("bob", kid_of("bob"))["bob"][kid_of("bob")]["status"], "active")

    def test_the_answer_is_a_new_object_each_time(self):
        first = self.state.keys_for("alice", kid_of("alice"))
        first["alice"][kid_of("alice")]["status"] = "changed"
        self.assertEqual(self.state.keys_for("alice", kid_of("alice"))["alice"][kid_of("alice")]["status"], "active")
        self.assertEqual(self.state.keys_map()["alice"][kid_of("alice")]["status"], "active")

    def test_has_entry_is_whether_some_person_has_the_kid_in_keys_map(self):
        full = self.state.keys_map()
        for kid in self.kids:
            with self.subTest(kid=kid[:6]):
                self.assertEqual(self.state.has_entry(kid), any(kid in entries for entries in full.values()))
        self.assertTrue(self.state.has_entry(kid_of("bob2")))      # removed: revoked, still an entry
        self.assertFalse(self.state.has_entry(kid_of("alice2")))   # unaccepted

    def test_one_reading_is_one_lookup_and_walks_no_device(self):
        big = state.State({}, devices())
        with Reads() as reads:
            for ask in (lambda: big.keys_for("bob", kid_of("bob")), lambda: big.keys_for("bob", kid_of("dave")),
                        lambda: big.keys_for("alice", kid_of("bob")), lambda: big.has_entry(kid_of("bob")),
                        lambda: big.has_entry(kid_of("dave"))):
                reads.reset()
                ask()
                self.assertEqual(reads.walked, 0)
                self.assertLessEqual(reads.looked, 1)

    def test_keys_map_is_unchanged_in_what_it_holds(self):
        want = {"alice": {kid_of("alice"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("alice")].sign), "active")},
                "bob": {kid_of("bob"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("bob")].sign), "active"),
                        kid_of("bob2"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("bob2")].sign), "revoked")},
                "carol": {kid_of("carol"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("carol")].sign), "active")}}
        self.assertEqual(self.state.keys_map(), want)


def changed_buckets(before, after):
    """How many buckets of a `Shared` the map `after` does not share with the map `before`."""
    return sum(1 for old, new in zip(before._buckets, after._buckets) if old is not new)


class SharedMap(unittest.TestCase):
    """`state.Shared` is a map that is a value: it reads as a dict, a `set` returns a new map and leaves the old one
    as it was."""

    @staticmethod
    def keys():
        return ["k%d" % i for i in range(40)] + [(i, 7 * i) for i in range(40)] + [kid_of("alice"), kid_of("bob2")]

    def test_it_agrees_with_a_dict_under_random_sets_and_reads(self):
        keys = self.keys()
        for seed in range(8):
            rng = random.Random(seed)
            shared, model, versions = state.Shared(), {}, []
            for step in range(300):
                key = rng.choice(keys)
                value = rng.randint(0, 9)
                shared, model = shared.set(key, value), {**model, key: value}
                versions.append((shared, dict(model)))
                probe = rng.choice(keys)
                self.assertEqual(shared.get(probe), model.get(probe))
                self.assertEqual(shared.get(probe, "none"), model.get(probe, "none"))
                self.assertEqual(probe in shared, probe in model)
                self.assertEqual(len(shared), len(model))
                if probe in model:
                    self.assertEqual(shared[probe], model[probe])
                else:
                    with self.assertRaises(KeyError):
                        shared[probe]
            self.assertEqual(sorted(map(repr, shared)), sorted(map(repr, model)))
            self.assertEqual(sorted(map(repr, shared.items())), sorted(map(repr, model.items())))
            self.assertEqual(sorted(shared.values()), sorted(model.values()))
            self.assertEqual(shared, model)
            self.assertEqual(model, shared)
            self.assertNotEqual(shared, {**model, "extra": 1})
            self.assertNotEqual(shared.set("extra", 1), model)
            for old, want in versions:   # a later set never changes an earlier map
                self.assertEqual(old, want)
                self.assertEqual(len(old), len(want))

    def test_setting_a_key_to_the_value_it_has_changes_nothing_that_can_be_read(self):
        shared = state.Shared().set("a", 1)
        again = shared.set("a", 1)
        self.assertEqual(again, shared)
        self.assertEqual(len(again), 1)

    def test_the_empty_map_is_empty(self):
        empty = state.Shared()
        self.assertEqual(len(empty), 0)
        self.assertEqual(list(empty), [])
        self.assertEqual(empty, {})
        self.assertNotIn("a", empty)


class SharedState(unittest.TestCase):
    """A change to a state copies a constant part of it: every bucket but the one the change lands in is the parent's
    own, whatever the size of the state."""

    @staticmethod
    def synthetic(i):
        return state.Device("p%d" % (i % 5), "apple-se-bio", "phone", (i, i), (i, -i), "active", True)

    def test_each_device_added_replaces_one_bucket_of_the_devices_and_shares_the_rest(self):
        current = state.State({"alice": "maintainer"}, {})
        for i in range(2000):
            following = current.with_device("kid%d" % i, self.synthetic(i))
            self.assertEqual(changed_buckets(current.devices, following.devices), 1, msg=i)
            self.assertIs(following.members, current.members)
            self.assertIs(following.link_codes, current.link_codes)
            current = following
        self.assertEqual(len(current.devices), 2000)

    def test_a_removal_replaces_one_bucket_of_the_devices(self):
        current = state.State({}, {"kid%d" % i: self.synthetic(i) for i in range(500)})
        removed = current.with_removed("kid7")
        self.assertEqual(changed_buckets(current.devices, removed.devices), 1)
        self.assertEqual(current.devices["kid7"].status, "active")
        self.assertEqual(removed.devices["kid7"].status, "removed")

    def test_a_link_code_replaces_one_bucket_of_the_link_codes_and_a_member_one_of_the_members(self):
        current = state.State({"m%d" % i: "member" for i in range(300)}, {}, ["c%d" % i for i in range(300)])
        coded = current.with_link_code("fresh")
        self.assertEqual(changed_buckets(current.link_codes, coded.link_codes), 1)
        self.assertIn("fresh", coded.link_codes)
        self.assertNotIn("fresh", current.link_codes)
        self.assertIs(coded.devices, current.devices)
        member = current.with_member("new", "member")
        self.assertEqual(changed_buckets(current.members, member.members), 1)
        self.assertEqual(member.members.get("new"), "member")
        self.assertIsNone(current.members.get("new"))

    def test_a_state_built_from_plain_mappings_holds_what_they_hold(self):
        built = state.State({"alice": "maintainer"}, devices(), ["x", "y"])
        self.assertEqual(built.members, {"alice": "maintainer"})
        self.assertEqual(built.devices, devices())
        self.assertEqual(built.link_codes, {"x": True, "y": True})


class SharedOrder(unittest.TestCase):
    """Where a key lives, and so the order a map is read in, is a function of the key and nothing else: the same in
    every process, and the same for two maps built from the same keys in another order."""

    def test_the_bucket_of_a_key_is_fixed_by_the_key(self):
        self.assertEqual(state._slot("alice"), 38)
        self.assertEqual(state._slot((1, 2)), 53)
        self.assertEqual(state._slot("uEiA53OC7"), 20)
        self.assertEqual(state.WIDTH, 64)

    def test_two_maps_of_the_same_keys_in_another_order_hold_each_key_in_the_same_bucket(self):
        keys = ["k%d" % i for i in range(100)] + [(i, i) for i in range(100)]
        forward, backward = state.Shared(), state.Shared()
        for key in keys:
            forward = forward.set(key, 1)
        for key in reversed(keys):
            backward = backward.set(key, 1)
        self.assertEqual([set(b) for b in forward._buckets], [set(b) for b in backward._buckets])
        self.assertEqual(forward, backward)
        self.assertEqual([state._slot(k) for k in forward], sorted(state._slot(k) for k in forward))

    def test_the_module_makes_no_call_of_the_builtin_hash(self):
        source = pathlib.Path(state.__file__).read_text()
        self.assertIsNone(re.search(r"(?<![\w.])hash\(", source))
        self.assertIn("binascii", source)


if __name__ == "__main__":
    unittest.main()
