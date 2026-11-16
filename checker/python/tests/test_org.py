"""T3.17 org id derivation (GP-01, GP-04, GP-05)."""
import hashlib
import unittest

from handsal_check import emit, encoding, genesis, org, profiles

from .genesis_fixtures import org as make_org
from .profile_sets import fixture_of

PROFILES = profiles.load()


class OrgId(unittest.TestCase):
    def test_org_id_is_the_hash_of_the_original_document(self):
        doc = make_org(fixture_of(PROFILES))
        self.assertEqual(org.org_id(doc), encoding.hashstr(emit.emit_subset(doc)))
        self.assertEqual(org.org_id(doc), genesis.doc_hash(doc))

    def test_the_org_id_is_not_in_the_documents_own_bytes_but_in_every_later_one(self):
        original = make_org(fixture_of(PROFILES))
        self.assertIsNone(original["org"])
        self.assertNotIn(org.org_id(original).encode(), emit.emit_subset(original))

    def test_digest_hex_is_the_sha256_inside_the_id(self):
        doc = make_org(fixture_of(PROFILES))
        digest = hashlib.sha256(emit.emit_subset(doc)).hexdigest()
        self.assertEqual(org.digest_hex(org.org_id(doc)), digest)
        self.assertEqual(len(digest), 64)

    def test_pin_filename_is_lowercase_hex_and_dot_pin(self):
        doc = make_org(fixture_of(PROFILES))
        name = org.pin_filename(org.org_id(doc))
        self.assertEqual(name, hashlib.sha256(emit.emit_subset(doc)).hexdigest() + ".pin")
        self.assertEqual(name, name.lower())

    def test_two_documents_two_names(self):
        a = org.pin_filename(org.org_id(make_org(fixture_of(PROFILES), name="A")))
        b = org.pin_filename(org.org_id(make_org(fixture_of(PROFILES), name="B")))
        self.assertNotEqual(a, b)

    def test_a_value_that_is_not_an_org_id_is_a_caller_bug(self):
        for bad in ("nope", None, 5, encoding.hashstr(b"x")[:-1]):
            with self.assertRaises(ValueError):
                org.digest_hex(bad)


if __name__ == "__main__":
    unittest.main()
