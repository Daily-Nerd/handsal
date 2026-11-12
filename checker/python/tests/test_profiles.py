"""T3.19 profiles (CF-01, GP-07, GP-18): the two hashes, what is implemented, fixture kids."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from handsal_check import coredata, encoding, errors, profiles

ROOT = Path(__file__).resolve().parents[3]
KEYS = json.loads((ROOT / "conformance" / "fixtures" / "keys.json").read_text())["keys"]


def tools_manifest():
    spec = importlib.util.spec_from_file_location("tools_manifest", ROOT / "tools" / "manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILES = profiles.load()


def code_of(call, *args):
    try:
        call(*args)
    except errors.Refused as err:
        return err.code
    return None


class Hashes(unittest.TestCase):
    def test_equal_to_the_release_tool_computation(self):
        manifest = tools_manifest()
        self.assertEqual(PROFILES.production, manifest.production_profile(ROOT))
        self.assertEqual(PROFILES.fixture, manifest.fixture_profile(ROOT))

    def test_the_two_differ_and_are_hashstrs(self):
        self.assertNotEqual(PROFILES.production, PROFILES.fixture)
        self.assertTrue(encoding.is_hashstr(PROFILES.production))
        self.assertTrue(encoding.is_hashstr(PROFILES.fixture))

    def test_a_changed_manifest_entry_changes_both_hashes(self):
        manifest = coredata.load_manifest()
        manifest["spec/profile.md"] = encoding.EMPTY_HASH
        self.assertNotEqual(profiles.profile_hash("production", manifest), PROFILES.production)
        self.assertNotEqual(profiles.profile_hash("fixture", manifest), PROFILES.fixture)

    def test_unknown_kind_is_a_bug(self):
        with self.assertRaises(ValueError):
            profiles.profile_hash("staging", coredata.load_manifest())


class Kinds(unittest.TestCase):
    def test_kind_of_a_profile_hash(self):
        self.assertEqual(PROFILES.kind(PROFILES.production), "production")
        self.assertEqual(PROFILES.kind(PROFILES.fixture), "fixture")
        self.assertIsNone(PROFILES.kind(encoding.hashstr(b"another profile")))
        self.assertIsNone(PROFILES.kind(None))
        self.assertIsNone(PROFILES.kind(5))

    def test_implemented(self):
        self.assertTrue(PROFILES.implemented(PROFILES.production))
        self.assertTrue(PROFILES.implemented(PROFILES.fixture))
        self.assertFalse(PROFILES.implemented(encoding.EMPTY_HASH))


class DocumentProfile(unittest.TestCase):
    """GP-15 step 2 for one document: profile_mismatch, then fixture_profile."""

    def check(self, profile, first_kind, allow_fixture):
        return code_of(PROFILES.check_document, profile, first_kind, allow_fixture)

    def test_unimplemented_is_profile_mismatch(self):
        self.assertEqual(self.check(encoding.EMPTY_HASH, None, True), "profile_mismatch")
        self.assertEqual(self.check("nope", None, False), "profile_mismatch")

    def test_production_original_everywhere(self):
        for allow in (False, True):
            self.assertIsNone(self.check(PROFILES.production, None, allow))

    def test_fixture_original_only_where_allowed(self):
        self.assertIsNone(self.check(PROFILES.fixture, None, True))
        self.assertEqual(self.check(PROFILES.fixture, None, False), "fixture_profile")

    def test_a_lineage_that_mixes_the_two_is_fixture_profile(self):
        self.assertEqual(self.check(PROFILES.production, "fixture", True), "fixture_profile")
        self.assertEqual(self.check(PROFILES.fixture, "production", True), "fixture_profile")
        self.assertIsNone(self.check(PROFILES.production, "production", True))
        self.assertIsNone(self.check(PROFILES.fixture, "fixture", True))

    def test_mismatch_is_judged_before_mixing(self):
        self.assertEqual(self.check(encoding.EMPTY_HASH, "fixture", False), "profile_mismatch")

    def test_the_kind_helper_returns_the_kind_on_success(self):
        self.assertEqual(PROFILES.check_document(PROFILES.fixture, None, True), "fixture")
        self.assertEqual(PROFILES.check_document(PROFILES.production, None, True), "production")


class FixtureKids(unittest.TestCase):
    def test_listed_kids(self):
        listed = json.loads((ROOT / "conformance/fixtures/fixture-kids.json").read_text())
        for kid in listed:
            self.assertTrue(PROFILES.is_fixture_kid(kid))
        self.assertEqual(len(PROFILES.fixture_kids), len(listed))

    def test_every_fixture_sign_key_and_the_relay_key_is_listed(self):
        for name, key in KEYS.items():
            if "kid" in key:
                self.assertTrue(PROFILES.is_fixture_kid(key["kid"]), name)

    def test_other_kids_are_not(self):
        self.assertFalse(PROFILES.is_fixture_kid(encoding.b64u_encode(bytes(32))))
        self.assertFalse(PROFILES.is_fixture_kid(None))
        self.assertFalse(PROFILES.is_fixture_kid(["x"]))

    def test_a_tampered_kid_list_is_refused_at_load(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        data = tmp / "data"
        shutil.copytree(coredata.DATA_DIR, data)
        path = data / coredata.FIXTURE_KIDS
        path.write_bytes(path.read_bytes().replace(b"04kif0", b"04kif1", 1))
        with self.assertRaises(coredata.CoreDataError):
            profiles.load(data)


if __name__ == "__main__":
    unittest.main()
