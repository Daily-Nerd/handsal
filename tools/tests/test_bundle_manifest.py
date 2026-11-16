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
    "spec/profile-checks.md",
    "spec/profile-interfaces.md",
    "spec/profile-part3.md",
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
    vectors = root / "conformance" / "vectors"
    for path in sorted(vectors.rglob("*")):
        rel = path.relative_to(vectors).as_posix()
        if path.is_file() and rel.split("/")[0] != "_gen":
            files["conformance/vectors/" + rel] = hashstr(path.read_bytes())
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


class OwnerSigned(unittest.TestCase):
    """The production-key vectors sit in `conformance/vectors/prod/` (CF-08). The bundle hash covers them."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        make_tree(self.tmp)

    def add_prod(self, text="{}"):
        prod = self.tmp / "conformance" / "vectors" / "prod"
        prod.mkdir(exist_ok=True)
        (prod / "fix.prodk-a.json").write_text(text)

    def test_a_vector_in_the_owner_signed_directory_is_listed_with_its_hash(self):
        self.add_prod("{}")
        files = manifest.bundle_files(self.tmp)
        self.assertEqual(files["conformance/vectors/prod/fix.prodk-a.json"], hashstr(b"{}"))

    def test_one_byte_of_an_owner_signed_vector_moves_the_bundle_hash(self):
        self.add_prod("{}")
        before = manifest.bundle_hash(self.tmp)
        self.add_prod('{"a":1}')
        self.assertNotEqual(manifest.bundle_hash(self.tmp), before)

    def test_a_missing_owner_signed_directory_is_no_error_before_the_owner_step(self):
        self.assertFalse((self.tmp / "conformance/vectors/prod").exists())
        self.assertNotIn("conformance/vectors/prod", " ".join(manifest.bundle_files(self.tmp)))

    def test_a_set_kept_under_a_label_directory_is_covered_by_the_bundle(self):
        """The bundle covers every vector file the tree ships, wherever it sits: the set of one edition under
        `prod/<label>/` is as much a part of it as a file directly in `prod/`."""
        before = manifest.bundle_hash(self.tmp)
        nested = self.tmp / "conformance" / "vectors" / "prod" / "edition-1"
        nested.mkdir(parents=True)
        (nested / "fix.prodk-a.json").write_text("{}")
        files = manifest.bundle_files(self.tmp)
        self.assertEqual(files["conformance/vectors/prod/edition-1/fix.prodk-a.json"], hashstr(b"{}"))
        self.assertNotEqual(manifest.bundle_hash(self.tmp), before)
        (nested / "fix.prodk-a.json").write_text('{"a":1}')
        self.assertEqual(manifest.bundle_files(self.tmp)["conformance/vectors/prod/edition-1/fix.prodk-a.json"],
                         hashstr(b'{"a":1}'))
        self.assertEqual(sorted(manifest.bundle_files(self.tmp)), sorted(independent_bundle(self.tmp)[0]))

    def test_only_the_generator_directory_is_left_out_whatever_its_depth(self):
        deep = self.tmp / "conformance" / "vectors" / "_gen" / "lib" / "deeper"
        deep.mkdir(parents=True)
        (deep / "x.json").write_text("{}")
        other = self.tmp / "conformance" / "vectors" / "elsewhere"
        other.mkdir()
        (other / "x.json").write_text("{}")
        files = manifest.bundle_files(self.tmp)
        self.assertNotIn("conformance/vectors/_gen/lib/deeper/x.json", files)
        self.assertIn("conformance/vectors/elsewhere/x.json", files)

    def test_one_predicate_says_what_is_a_vector_path(self):
        """The tag run recomputes the bundle from a git tree, so it asks the same question of a path."""
        yes = ("conformance/vectors/a.one.json", "conformance/vectors/prod/x.json",
               "conformance/vectors/prod/edition-1/x.json")
        no = ("conformance/vectors/_gen/x.json", "conformance/vectors/_gen/lib/x.json", "conformance/vectors",
              "conformance/vectors_gen/x.json", "spec/x.json", "conformance/pins.json")
        self.assertEqual([manifest.is_vector_path(p) for p in yes], [True] * len(yes))
        self.assertEqual([manifest.is_vector_path(p) for p in no], [False] * len(no))


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
