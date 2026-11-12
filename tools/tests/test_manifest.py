"""The core manifest and the two profile hashes (CF-01, GP-18).

Expected values are computed here with hashlib and json only, so the tests
do not lean on the code they check.
"""
import base64
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402

CORE = [
    "conformance/CONTRACT.md",
    "conformance/fixtures/fixture-kids.json",
    "conformance/fixtures/keys.json",
    "spec/profile.md",
    "spec/registry.json",
]


def hashstr(raw):
    digest = b"\x12\x20" + hashlib.sha256(raw).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def expected(root, kind):
    core = {p: hashstr((Path(root) / p).read_bytes()) for p in CORE}
    doc = json.dumps({"core": core, "kind": kind}, sort_keys=True, separators=(",", ":"))
    return hashstr(doc.encode("ascii"))


def copy_core(dst):
    for rel in CORE:
        target = Path(dst) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)


class CoreManifest(unittest.TestCase):
    def test_lists_exactly_the_core_files(self):
        self.assertEqual(sorted(manifest.core_manifest(ROOT)), CORE)

    def test_entry_is_hashstr_of_raw_bytes(self):
        core = manifest.core_manifest(ROOT)
        for rel in CORE:
            self.assertEqual(core[rel], hashstr((ROOT / rel).read_bytes()), rel)

    def test_lists_no_vector_file(self):
        self.assertFalse([p for p in manifest.core_manifest(ROOT) if "/vectors/" in p])


class ProfileHashes(unittest.TestCase):
    def test_match_independent_computation(self):
        self.assertEqual(manifest.production_profile(ROOT), expected(ROOT, "production"))
        self.assertEqual(manifest.fixture_profile(ROOT), expected(ROOT, "fixture"))

    def test_are_canonical_and_distinct(self):
        prod, fix = manifest.production_profile(ROOT), manifest.fixture_profile(ROOT)
        for h in (prod, fix):
            self.assertEqual(len(h), 47)
            self.assertTrue(h.startswith("uEi"))
        self.assertNotEqual(prod, fix)

    def test_default_root_is_the_repo(self):
        self.assertEqual(manifest.production_profile(), manifest.production_profile(ROOT))
        self.assertEqual(manifest.fixture_profile(), manifest.fixture_profile(ROOT))

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            manifest.profile_hash("staging", ROOT)


class Isolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        copy_core(self.tmp)

    def hashes(self):
        return manifest.production_profile(self.tmp), manifest.fixture_profile(self.tmp)

    def test_vectors_do_not_move_the_hashes(self):
        before = self.hashes()
        vectors = Path(self.tmp) / "conformance" / "vectors" / "jcs"
        vectors.mkdir(parents=True)
        (vectors / "a.json").write_text('{"id":"jcs/a"}')
        self.assertEqual(self.hashes(), before)
        (vectors / "a.json").write_text('{"id":"jcs/b"}')
        self.assertEqual(self.hashes(), before)

    def test_every_core_file_moves_both_hashes(self):
        base = self.hashes()
        for rel in CORE:
            path = Path(self.tmp) / rel
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            changed = self.hashes()
            self.assertNotEqual(changed[0], base[0], rel)
            self.assertNotEqual(changed[1], base[1], rel)
            path.write_bytes(original)
        self.assertEqual(self.hashes(), base)

    def test_missing_core_file_fails_loudly(self):
        (Path(self.tmp) / "spec" / "registry.json").unlink()
        with self.assertRaises(manifest.ManifestError):
            manifest.core_manifest(self.tmp)


if __name__ == "__main__":
    unittest.main()
