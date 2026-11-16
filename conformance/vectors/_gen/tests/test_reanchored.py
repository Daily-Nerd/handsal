"""T16.12 (d): four vectors that already exist are anchored to the editions, not to "the" profile.

The answers do not change. What changes is what the vector says it is: a hash that is in no catalog entry (GP-22 S2),
a lineage of two implemented hashes of different kinds (GP-24 S9), a pin whose `spec` is an implemented hash that is
not the last document's (GP-05 S3). Each test states the property through the set of supported profiles, which is the
two profiles of the current core and every entry of `profiles/catalog.json`, so it holds the same after the
founding release and after a second edition.
"""
import base64
import json
import unittest

import generate
from lib import base
from tests import catalog


def supported():
    """The profile hashes an implementation of this tree implements: the current core's two, and the catalog's."""
    found = {base.fixture_profile(), base.production_profile()}
    path = generate.CONFORMANCE.parent / "profiles" / "catalog.json"
    if path.is_file():
        for row in json.loads(path.read_text(encoding="utf-8")):
            found.update((row["production"], row["fixture"]))
    return found


def profiles(vector):
    return [entry["doc"]["profile"] for entry in vector["input"]["lineage"]]


class Chg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_modules(["chg_auth"], ["chg"])

    def test_the_middle_hash_is_in_no_catalog_entry_and_the_first_failing_document_wins(self):   # GP-22 S2, GP-23 S6
        vector = self.v["chg/profile-unimplemented-in-middle"]
        first, middle, last = profiles(vector)
        self.assertTrue(base.is_hashstr(middle))
        self.assertNotIn(middle, supported())
        self.assertIn(first, supported())
        self.assertIn(last, supported(), "the last document names an implemented profile: the middle one alone fails")
        self.assertEqual(catalog.anchor_code(vector), "profile_mismatch")
        self.assertEqual(catalog.catalog_code("chg/profile-unimplemented-in-middle"), "profile_mismatch")


class Gen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("gen", ["gen"])

    def test_the_hash_is_well_formed_and_in_no_catalog_entry(self):   # GP-22 S2
        vector = self.v["gen/profile-mismatch"]
        (named,) = profiles(vector)
        self.assertTrue(base.is_hashstr(named))
        self.assertNotIn(named, supported())
        self.assertEqual(catalog.anchor_code(vector), "profile_mismatch")


class Fix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("fix", ["fix"])

    def test_a_fixture_original_and_a_production_change_name_two_implemented_profiles(self):   # GP-24 S9
        vector = self.v["fix/mixed-profile-lineage"]
        self.assertEqual(profiles(vector), [base.fixture_profile(), base.production_profile()])
        for named in profiles(vector):
            self.assertIn(named, supported())
        self.assertEqual(catalog.anchor_code(vector), "fixture_profile")


class Pin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = catalog.generate_group("pin", ["pin"])

    def test_the_pin_names_an_implemented_profile_that_is_not_the_last_documents(self):   # GP-05 S3
        vector = self.v["pin/spec-not-last-profile"]
        spec = json.loads(base64.b64decode(vector["input"]["pin"]["bytes_b64"]))["spec"]
        last = profiles(vector)[-1]
        self.assertIn(spec, supported())
        self.assertNotEqual(spec, last)
        self.assertEqual(catalog.anchor_code(vector), "pin_spec_mismatch")


if __name__ == "__main__":
    unittest.main()
