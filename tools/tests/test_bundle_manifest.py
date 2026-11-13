"""The bundle manifest (CF-01): the core plus every vector file, separate from the profile hashes.

Expected values are computed here with hashlib and json only.
"""
import base64
import contextlib
import hashlib
import io
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
    "spec/profile-interfaces.md",
    "spec/profile.md",
    "spec/registry.json",
]
# computed with openssl from the files by tools/repin.py, the one place the pins live
_PINS = json.loads((ROOT / "conformance" / "pins.json").read_text(encoding="utf-8"))
REAL_PROFILES = (_PINS["production_profile"], _PINS["fixture_profile"])


def hashstr(raw):
    digest = b"\x12\x20" + hashlib.sha256(raw).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def make_tree(dst):
    dst = Path(dst)
    for rel in CORE:
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    vdir = dst / "conformance" / "vectors"
    (vdir / "_gen").mkdir(parents=True)
    (vdir / "a.one.json").write_text('{"name":"a/one"}')
    (vdir / "b.two.json").write_text('{"name":"b/two"}')
    (vdir / "_gen" / "tool.py").write_text("generator, not a vector")
    (dst / "spec").mkdir(exist_ok=True)


def independent_bundle(root):
    root = Path(root)
    files = {p: hashstr((root / p).read_bytes()) for p in CORE}
    for path in sorted((root / "conformance" / "vectors").iterdir()):
        if path.is_file():
            files["conformance/vectors/" + path.name] = hashstr(path.read_bytes())
    doc = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return files, hashstr(doc.encode("ascii"))


class Bundle(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        make_tree(self.tmp)

    def test_files_are_the_core_plus_every_vector_file_and_no_generator_file(self):
        files = manifest.bundle_files(self.tmp)
        self.assertEqual(sorted(files), sorted(independent_bundle(self.tmp)[0]))
        self.assertNotIn("conformance/vectors/_gen/tool.py", files)

    def test_bundle_hash_matches_independent_computation(self):
        self.assertEqual(manifest.bundle_hash(self.tmp), independent_bundle(self.tmp)[1])

    def test_one_vector_byte_moves_the_bundle_hash(self):
        before = manifest.bundle_hash(self.tmp)
        (self.tmp / "conformance/vectors/a.one.json").write_text('{"name":"a/onf"}')
        self.assertNotEqual(manifest.bundle_hash(self.tmp), before)

    def test_vectors_leave_the_profile_hashes_alone(self):
        before = (manifest.production_profile(self.tmp), manifest.fixture_profile(self.tmp))
        (self.tmp / "conformance/vectors/c.three.json").write_text("{}")
        self.assertEqual(
            (manifest.production_profile(self.tmp), manifest.fixture_profile(self.tmp)), before)

    def test_a_core_byte_moves_the_bundle_hash(self):
        before = manifest.bundle_hash(self.tmp)
        with open(self.tmp / "spec/profile.md", "ab") as fh:
            fh.write(b"\n")
        self.assertNotEqual(manifest.bundle_hash(self.tmp), before)


class CheckMode(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        make_tree(self.tmp)
        manifest.write_bundle_manifest(self.tmp)

    def check(self):
        return manifest.check_bundle_manifest(self.tmp)

    def test_written_file_carries_the_bundle_hash_and_every_file_hash_and_no_profile_hash(self):
        doc = json.loads((self.tmp / "spec/MANIFEST.json").read_text())
        files, bundle = independent_bundle(self.tmp)
        self.assertEqual(doc, {"bundle": bundle, "files": files})
        text = (self.tmp / "spec/MANIFEST.json").read_text()
        for profile in (manifest.production_profile(self.tmp), manifest.fixture_profile(self.tmp)):
            self.assertNotIn(profile, text)

    def test_fresh_manifest_passes(self):
        self.assertEqual(self.check(), [])

    def test_tampered_vector_byte_fails_and_names_the_file(self):
        path = self.tmp / "conformance/vectors/b.two.json"
        path.write_bytes(path.read_bytes().replace(b"two", b"twp"))
        problems = self.check()
        self.assertEqual(len(problems), 1)
        self.assertIn("conformance/vectors/b.two.json", problems[0])

    def test_added_and_removed_vector_fail(self):
        (self.tmp / "conformance/vectors/c.new.json").write_text("{}")
        (self.tmp / "conformance/vectors/a.one.json").unlink()
        problems = "\n".join(self.check())
        self.assertIn("c.new.json", problems)
        self.assertIn("a.one.json", problems)

    def test_a_core_change_fails(self):
        with open(self.tmp / "conformance/CONTRACT.md", "ab") as fh:
            fh.write(b"x")
        self.assertTrue(any("CONTRACT.md" in p for p in self.check()))

    def test_a_hand_edited_bundle_hash_fails_even_when_every_file_matches(self):
        path = self.tmp / "spec/MANIFEST.json"
        doc = json.loads(path.read_text())
        doc["bundle"] = doc["bundle"][:-1] + ("A" if doc["bundle"][-1] != "A" else "B")
        path.write_text(json.dumps(doc))
        self.assertTrue(any("bundle" in p for p in self.check()))

    def test_missing_or_malformed_manifest_fails_loudly(self):
        path = self.tmp / "spec/MANIFEST.json"
        path.write_text("not json")
        with self.assertRaises(manifest.ManifestError):
            self.check()
        path.unlink()
        with self.assertRaises(manifest.ManifestError):
            self.check()

    def test_write_is_deterministic(self):
        first = (self.tmp / "spec/MANIFEST.json").read_bytes()
        manifest.write_bundle_manifest(self.tmp)
        self.assertEqual((self.tmp / "spec/MANIFEST.json").read_bytes(), first)

    def test_cli_exit_codes(self):
        argv = ["--check", "--root", str(self.tmp)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manifest.main(argv), 0)
            (self.tmp / "conformance/vectors/c.new.json").write_text("{}")
            self.assertEqual(manifest.main(argv), 1)


class RealTree(unittest.TestCase):
    def test_the_profile_hashes_are_unchanged(self):
        self.assertEqual(
            (manifest.production_profile(), manifest.fixture_profile()), REAL_PROFILES)

    def test_the_committed_manifest_matches_the_tree(self):
        self.assertEqual(manifest.check_bundle_manifest(ROOT), [])


if __name__ == "__main__":
    unittest.main()
