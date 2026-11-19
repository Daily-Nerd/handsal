"""The projection of a state to the vitni `keys` map (FO-02), whole and narrowed to one signer.

`keys_map` is the one owner of the projection. `keys_for` and `has_entry` are the same projection read at one
`(person, kid)` or one kid, in one lookup, so a question to the verifier carries the entry it reads and nothing else.
"""
import unittest

from handsal_check import state, verifier

from .act_builder import kid_of
from .genesis_fixtures import point

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


class Lookups(dict):
    """A devices mapping that records how it was read."""

    def __init__(self, *args):
        super().__init__(*args)
        self.looked, self.walked = 0, 0

    def get(self, *args):
        self.looked += 1
        return super().get(*args)

    def __getitem__(self, key):
        self.looked += 1
        return super().__getitem__(key)

    def __contains__(self, key):
        self.looked += 1
        return super().__contains__(key)

    def __iter__(self):
        self.walked += 1
        return super().__iter__()

    def items(self):
        self.walked += 1
        return super().items()

    def values(self):
        self.walked += 1
        return super().values()

    def keys(self):
        self.walked += 1
        return super().keys()


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
        seen = Lookups(devices())
        big = state.State({}, seen)
        for ask in (lambda: big.keys_for("bob", kid_of("bob")), lambda: big.keys_for("bob", kid_of("dave")),
                    lambda: big.keys_for("alice", kid_of("bob")), lambda: big.has_entry(kid_of("bob")),
                    lambda: big.has_entry(kid_of("dave"))):
            seen.looked = seen.walked = 0
            ask()
            self.assertEqual(seen.walked, 0)
            self.assertLessEqual(seen.looked, 1)

    def test_keys_map_is_unchanged_in_what_it_holds(self):
        want = {"alice": {kid_of("alice"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("alice")].sign), "active")},
                "bob": {kid_of("bob"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("bob")].sign), "active"),
                        kid_of("bob2"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("bob2")].sign), "revoked")},
                "carol": {kid_of("carol"): verifier.key_entry(state.point_obj(self.state.devices[kid_of("carol")].sign), "active")}}
        self.assertEqual(self.state.keys_map(), want)


if __name__ == "__main__":
    unittest.main()
