"""T4.6: `tools/artifact_hashes.py` prints the SHA-256 of each artifact (SG-15, T7.3)."""
import contextlib
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import artifact_hashes as ah  # noqa: E402

PIN = json.loads((ROOT / "checker/python/packaging/interpreter.json").read_text())


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ah.main(argv)
    return code, out.getvalue(), err.getvalue()


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_a_file_prints_its_sha256_and_name_in_sha256sum_form(self):
        (self.tmp / "a.bin").write_bytes(b"abc")
        code, out, _ = run([str(self.tmp / "a.bin")])
        self.assertEqual(code, 0)
        self.assertEqual(out, "%s  a.bin\n" % hashlib.sha256(b"abc").hexdigest())

    def test_several_files_print_in_the_order_given(self):
        (self.tmp / "b").write_bytes(b"2")
        (self.tmp / "a").write_bytes(b"1")
        _, out, _ = run([str(self.tmp / "b"), str(self.tmp / "a")])
        self.assertEqual([line.split("  ")[1] for line in out.splitlines()], ["b", "a"])

    def test_an_unreadable_file_is_exit_2_with_nothing_on_stdout(self):
        code, out, err = run([str(self.tmp / "nope")])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("nope", err)


class Build(unittest.TestCase):
    def test_the_default_prints_the_zipapp_the_launcher_and_the_pinned_archives(self):
        code, out, _ = run([])
        self.assertEqual(code, 0)
        lines = [line.split("  ") for line in out.splitlines()]
        names = [name for _, name in lines]
        self.assertEqual(names[:2], ["handsal-check.pyz", "handsal-check"])
        for _, name in lines:
            self.assertTrue(name)
        for entry in PIN["platforms"].values():
            self.assertIn("%s  %s" % (entry["archive"]["sha256"], entry["archive"]["file"]), out.splitlines())
        for digest, _ in lines:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_the_upstream_notices_archive_is_not_a_published_artifact(self):
        """The installer never reads the `.tar.zst`; the packed licences archive (pack_licenses.py) is the artifact."""
        _, out, _ = run([])
        self.assertNotIn("zst", out)

    def test_two_runs_print_the_same_text(self):
        self.assertEqual(run([])[1], run([])[1])

    def test_the_printed_launcher_hash_is_the_hash_of_the_macos_launcher_text(self):
        sys.path.insert(0, str(ROOT / "checker/python/packaging"))
        import launcher  # noqa: E402
        _, out, _ = run([])
        expected = hashlib.sha256(launcher.render_macos().encode("ascii")).hexdigest()
        self.assertIn("%s  handsal-check\n" % expected, out)


PLATFORM = "macos-arm64"
INSTALL_LIB = ROOT / "tools" / "install" / "install-lib.sh"


def fake_pin(interpreter_bytes):
    """The real pin with the arm64 archive row pointing at `interpreter_bytes` (the real archive is not in the tree)."""
    pin = json.loads(json.dumps(PIN))
    pin["platforms"][PLATFORM]["archive"]["sha256"] = hashlib.sha256(interpreter_bytes).hexdigest()
    return pin


class BuildInto(unittest.TestCase):
    """The zipapp and the launcher are built in one place, for the printed lines and for the release directory."""

    def test_it_writes_the_zipapp_and_the_launcher_that_the_default_run_prints_the_hashes_of(self):
        with tempfile.TemporaryDirectory() as tmp:
            ah.build_into(tmp)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["handsal-check", "handsal-check.pyz"])
            _, out, _ = run([])
            for name in ("handsal-check.pyz", "handsal-check"):
                self.assertIn("%s  %s\n" % (hashlib.sha256((Path(tmp) / name).read_bytes()).hexdigest(), name), out)

    def test_the_launcher_is_executable_so_the_directory_can_be_published_as_it_is(self):
        with tempfile.TemporaryDirectory() as tmp:
            ah.build_into(tmp)
            self.assertTrue((Path(tmp) / "handsal-check").stat().st_mode & 0o100)


class Release(unittest.TestCase):
    """T7.3: the lines to publish for the tag are the installer's closed list, checked against this tree."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.dir = self.tmp / "A"
        self.dir.mkdir()
        self.interpreter = b"pretend interpreter archive"
        self.pin = fake_pin(self.interpreter)
        row = self.pin["platforms"][PLATFORM]
        build_zipapp, launcher = ah._load("build_zipapp"), ah._load("launcher")
        build_zipapp.build(build_zipapp.SRC, self.dir / "handsal-check.pyz")
        (self.dir / "handsal-check").write_bytes(launcher.render_macos().encode("ascii"))
        (self.dir / "vitni-verify").write_bytes(b"vitni build")
        (self.dir / "handsal-pin").write_bytes(b"pin helper build")
        (self.dir / row["archive"]["file"]).write_bytes(self.interpreter)
        (self.dir / row["packed_licenses"]["file"]).write_bytes(b"packed licences")
        self.names = ["vitni-verify", "handsal-pin", "handsal-check", "handsal-check.pyz",
                      row["archive"]["file"], row["packed_licenses"]["file"]]

    def release(self):
        return ah.release_lines(self.dir, PLATFORM, self.pin)

    def test_it_prints_the_six_artifacts_in_the_order_the_installer_checks_them(self):
        lines = self.release()
        self.assertEqual([line.split("  ")[1].strip() for line in lines], self.names)
        for line, name in zip(lines, self.names):
            self.assertEqual(line, "%s  %s\n" % (hashlib.sha256((self.dir / name).read_bytes()).hexdigest(), name))

    def test_a_missing_artifact_is_an_error(self):
        (self.dir / "handsal-pin").unlink()
        with self.assertRaisesRegex(ah.ReleaseError, "handsal-pin"):
            self.release()

    def test_a_file_that_is_not_on_the_closed_list_is_an_error_so_it_is_never_published_by_accident(self):
        (self.dir / "handsal-sign").write_bytes(b"signer")
        with self.assertRaisesRegex(ah.ReleaseError, "handsal-sign"):
            self.release()

    def test_a_symlink_is_not_an_artifact(self):
        (self.dir / "vitni-verify").unlink()
        (self.dir / "vitni-verify").symlink_to(self.dir / "handsal-pin")
        with self.assertRaisesRegex(ah.ReleaseError, "vitni-verify"):
            self.release()

    def test_a_zipapp_that_this_tree_does_not_build_is_refused(self):
        with open(self.dir / "handsal-check.pyz", "ab") as handle:
            handle.write(b"x")
        with self.assertRaisesRegex(ah.ReleaseError, "handsal-check.pyz"):
            self.release()

    def test_a_launcher_that_this_tree_does_not_render_is_refused(self):
        (self.dir / "handsal-check").write_bytes(b"#!/bin/sh\n")
        with self.assertRaisesRegex(ah.ReleaseError, "handsal-check"):
            self.release()

    def test_an_interpreter_archive_that_is_not_the_pinned_one_is_refused(self):
        row = self.pin["platforms"][PLATFORM]["archive"]["file"]
        (self.dir / row).write_bytes(b"another archive")
        with self.assertRaisesRegex(ah.ReleaseError, "pinned"):
            self.release()

    def test_a_platform_the_pin_does_not_hold_is_an_error(self):
        with self.assertRaisesRegex(ah.ReleaseError, "platform"):
            ah.release_lines(self.dir, "macos-sparc", self.pin)

    def test_a_wrong_artifact_exits_1_and_a_wrong_directory_exits_2(self):
        with open(self.dir / "handsal-check.pyz", "ab") as handle:
            handle.write(b"x")
        with self.assertRaises(ah.ReleaseError) as caught:
            self.release()
        self.assertEqual(caught.exception.code, 1)
        (self.dir / "handsal-pin").unlink()
        with self.assertRaises(ah.ReleaseError) as caught:
            self.release()
        self.assertEqual(caught.exception.code, 2)

    def test_the_command_prints_nothing_on_stdout_when_it_refuses(self):
        (self.dir / "handsal-pin").unlink()
        code, out, err = run(["--release", str(self.dir), "--platform", PLATFORM])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("handsal-pin", err)

    def test_the_closed_list_is_the_one_the_installer_checks(self):
        """The tool and tools/install/install-lib.sh each name the six artifacts; this ties the two together."""
        text = INSTALL_LIB.read_text(encoding="utf-8")
        loop = re.search(r"for _name in ([^;]+); do\n\s+verify_one", text)
        self.assertIsNotNone(loop)
        words = loop.group(1).split()
        self.assertEqual(words[:4], list(ah.FIXED_ARTIFACTS))
        self.assertEqual(words[4:], ['"$_interpreter"', '"$_licenses"'])
        self.assertIn('"cpython-*-$_triple-install_only.tar.gz"', text)
        self.assertIn('"handsal-python-licenses-*-$_triple.tar.gz"', text)
        for platform, row in PIN["platforms"].items():
            self.assertRegex(row["archive"]["file"], r"^cpython-.*-install_only\.tar\.gz$")
            self.assertRegex(row["packed_licenses"]["file"], r"^handsal-python-licenses-.*\.tar\.gz$")

    def test_the_pinned_file_names_match_the_installer_globs_for_each_macos_platform(self):
        import fnmatch
        triples = {"macos-arm64": "aarch64-apple-darwin", "macos-x86_64": "x86_64-apple-darwin"}
        for platform, triple in triples.items():
            row = PIN["platforms"][platform]
            self.assertTrue(fnmatch.fnmatch(row["archive"]["file"], "cpython-*-%s-install_only.tar.gz" % triple))
            self.assertTrue(fnmatch.fnmatch(row["packed_licenses"]["file"], "handsal-python-licenses-*-%s.tar.gz" % triple))


if __name__ == "__main__":
    unittest.main()
