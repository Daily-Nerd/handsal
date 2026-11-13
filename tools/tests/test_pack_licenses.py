"""`tools/pack_licenses.py` repacks the interpreter's licence texts into a form a stock macOS reads (SG-15).

The notices archive of python-build-standalone is `.tar.zst`; stock macOS `tar` has no zstd and the installer's
`PATH` is fixed, so the installer must never read it. The packaging step reads it once, on the builder's machine,
and writes `python/licenses/` into a gzip tar whose bytes depend only on the texts (two builders, one hash).
"""
import contextlib
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import pack_licenses as pl  # noqa: E402

PIN = json.loads((ROOT / "checker/python/packaging/interpreter.json").read_text())


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = pl.main(argv)
    return code, out.getvalue(), err.getvalue()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def tree(self, name="tree", files=None):
        root = self.tmp / name
        for rel, text in (files or {"LICENSE.cpython.txt": "cpython", "LICENSE.zlib.txt": "zlib"}).items():
            path = root / "python" / "licenses" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def members(self, archive):
        with tarfile.open(archive, "r:gz") as tar:
            return tar.getmembers()


class PackTree(Tmp):
    def test_the_archive_holds_only_python_licenses_in_sorted_order(self):
        out = self.tmp / "out.tar.gz"
        pl.pack_tree(self.tree(), out)
        self.assertEqual([m.name for m in self.members(out)],
                         ["python", "python/licenses", "python/licenses/LICENSE.cpython.txt",
                          "python/licenses/LICENSE.zlib.txt"])

    def test_every_member_is_root_owned_with_no_time_and_fixed_modes(self):
        out = self.tmp / "out.tar.gz"
        pl.pack_tree(self.tree(), out)
        for m in self.members(out):
            self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, "", "", 0), m.name)
            self.assertEqual(m.mode, 0o755 if m.isdir() else 0o644, m.name)

    def test_the_bytes_do_not_depend_on_the_builder(self):
        """Two builders, different mtimes, modes and output names: one hash (the second-device comparison)."""
        a = self.tree("a")
        b = self.tree("b")
        for path in (b / "python" / "licenses").iterdir():
            path.chmod(0o600)
            path.touch()
        pl.pack_tree(a, self.tmp / "one.tar.gz")
        pl.pack_tree(b, self.tmp / "two.tar.gz")
        self.assertEqual((self.tmp / "one.tar.gz").read_bytes(), (self.tmp / "two.tar.gz").read_bytes())

    def test_the_gzip_header_names_no_file_and_holds_no_time(self):
        out = self.tmp / "out.tar.gz"
        pl.pack_tree(self.tree(), out)
        head = out.read_bytes()[:10]
        self.assertEqual(head[:4], b"\x1f\x8b\x08\x00")  # magic, deflate, no flags (no name)
        self.assertEqual(head[4:8], b"\x00\x00\x00\x00")  # no mtime

    def test_the_contents_round_trip(self):
        out = self.tmp / "out.tar.gz"
        pl.pack_tree(self.tree(), out)
        with tarfile.open(out, "r:gz") as tar:
            self.assertEqual(tar.extractfile("python/licenses/LICENSE.zlib.txt").read(), b"zlib")

    def test_a_symlink_is_refused(self):
        root = self.tree()
        (root / "python" / "licenses" / "link").symlink_to("/etc/passwd")
        with self.assertRaises(pl.PackError) as ctx:
            pl.pack_tree(root, self.tmp / "out.tar.gz")
        self.assertIn("link", str(ctx.exception))
        self.assertFalse((self.tmp / "out.tar.gz").exists())

    def test_an_entry_outside_python_licenses_is_refused(self):
        root = self.tree()
        (root / "python" / "PYTHON.json").write_text("{}")
        with self.assertRaises(pl.PackError):
            pl.pack_tree(root, self.tmp / "out.tar.gz")

    def test_no_licence_text_is_refused(self):
        root = self.tmp / "empty"
        (root / "python" / "licenses").mkdir(parents=True)
        with self.assertRaises(pl.PackError):
            pl.pack_tree(root, self.tmp / "out.tar.gz")

    def test_a_nested_directory_is_refused(self):
        root = self.tree()
        (root / "python" / "licenses" / "sub").mkdir()
        (root / "python" / "licenses" / "sub" / "x.txt").write_text("x")
        with self.assertRaises(pl.PackError):
            pl.pack_tree(root, self.tmp / "out.tar.gz")


class Pin(unittest.TestCase):
    def test_every_platform_names_its_packed_archive(self):
        triples = {"macos-arm64": "aarch64-apple-darwin", "macos-x86_64": "x86_64-apple-darwin",
                   "windows-x64": "x86_64-pc-windows-msvc"}
        for name, entry in PIN["platforms"].items():
            self.assertEqual(entry["packed_licenses"]["file"],
                             "handsal-python-licenses-%s+%s-%s.tar.gz" % (PIN["cpython"], PIN["release"], triples[name]),
                             name)

    def test_the_macos_names_match_what_the_installer_looks_for(self):
        install = (ROOT / "tools/install/install-lib.sh").read_text()
        self.assertTrue('"handsal-python-licenses-*-$_triple.tar.gz"' in install, "the installer looks for another name")
        for name, triple in (("macos-arm64", "aarch64-apple-darwin"), ("macos-x86_64", "x86_64-apple-darwin")):
            self.assertRegex(PIN["platforms"][name]["packed_licenses"]["file"],
                             r"^handsal-python-licenses-[^/*]+-%s\.tar\.gz$" % triple)

    def test_the_installer_reads_no_zstd(self):
        text = (ROOT / "tools/install/install-lib.sh").read_text()
        self.assertFalse("zst" in text, "install-lib.sh names zstd")


class Pack(Tmp):
    """`pack` checks the pinned hash of the notices archive, then unpacks it with the injected function."""

    def entry(self, archive):
        return {"notices": {"file": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
                "packed_licenses": {"file": "handsal-python-licenses-test.tar.gz"}}

    def fake_unpack(self, calls):
        def unpack(archive, dest):
            calls.append(archive)
            shutil.copytree(self.tree("src") / "python", dest / "python")
        return unpack

    def test_a_notices_archive_that_is_not_the_pinned_one_is_refused_before_unpacking(self):
        archive = self.tmp / "n.tar.zst"
        archive.write_bytes(b"not the pinned bytes")
        entry = self.entry(archive)
        archive.write_bytes(b"changed")
        calls = []
        with self.assertRaises(pl.PackError) as ctx:
            pl.pack(archive, entry, self.tmp / "out", unpack=self.fake_unpack(calls))
        self.assertIn("pinned", str(ctx.exception))
        self.assertEqual(calls, [])
        self.assertFalse((self.tmp / "out").exists())

    def test_the_pinned_archive_is_unpacked_and_packed_under_the_pinned_name(self):
        archive = self.tmp / "n.tar.zst"
        archive.write_bytes(b"zst bytes")
        calls = []
        path = pl.pack(archive, self.entry(archive), self.tmp / "out", unpack=self.fake_unpack(calls))
        self.assertEqual(path, self.tmp / "out" / "handsal-python-licenses-test.tar.gz")
        self.assertEqual(calls, [archive])
        self.assertEqual(len(self.members(path)), 4)

    def test_the_unpacked_scratch_tree_is_removed(self):
        archive = self.tmp / "n.tar.zst"
        archive.write_bytes(b"zst bytes")
        seen = []

        def unpack(a, dest):
            seen.append(dest)
            shutil.copytree(self.tree("src") / "python", dest / "python")
        pl.pack(archive, self.entry(archive), self.tmp / "out", unpack=unpack)
        self.assertFalse(seen[0].exists())

    def test_a_failed_unpack_leaves_no_output(self):
        archive = self.tmp / "n.tar.zst"
        archive.write_bytes(b"zst bytes")

        def unpack(a, dest):
            raise pl.PackError("boom")
        with self.assertRaises(pl.PackError):
            pl.pack(archive, self.entry(archive), self.tmp / "out", unpack=unpack)
        self.assertEqual(list((self.tmp / "out").glob("*")) if (self.tmp / "out").exists() else [], [])


class Main(Tmp):
    def test_an_unknown_platform_is_exit_2_with_nothing_on_stdout(self):
        code, out, err = run(["--platform", "plan9", str(self.tmp / "n"), str(self.tmp / "out")])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("plan9", err)

    def test_a_missing_archive_is_exit_2_with_nothing_on_stdout(self):
        code, out, _ = run(["--platform", "macos-arm64", str(self.tmp / "nope"), str(self.tmp / "out")])
        self.assertEqual((code, out), (2, ""))

    def test_the_wrong_number_of_arguments_is_exit_2(self):
        self.assertEqual(run([])[0], 2)


class EndToEnd(Tmp):
    """The real `tar` and a real zstd, as the packaging machine has them. A builder without zstd fails here, loudly:
    the packaging step needs it, and a test that skipped would hide that."""

    def test_a_real_zst_archive_is_repacked_and_its_hash_is_printed(self):
        src = self.tree("src", {"LICENSE.cpython.txt": "cpython", "LICENSE.zlib.txt": "zlib"})
        (src / "python" / "PYTHON.json").write_text("{}")
        archive = self.tmp / "notices.tar.zst"
        subprocess.run(["tar", "--zstd", "-cf", str(archive), "-C", str(src), "python"], check=True)
        entry = {"notices": {"file": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
                 "packed_licenses": {"file": "handsal-python-licenses-x.tar.gz"}}
        out = pl.pack(archive, entry, self.tmp / "out")
        names = [m.name for m in self.members(out)]
        self.assertEqual(names, ["python", "python/licenses", "python/licenses/LICENSE.cpython.txt",
                                 "python/licenses/LICENSE.zlib.txt"])
        again = pl.pack(archive, entry, self.tmp / "out2")
        self.assertEqual(out.read_bytes(), again.read_bytes())
        # stock tools only: gzip and tar with no zstd read it
        subprocess.run(["gzip", "-t", str(out)], check=True)

    def test_a_missing_zstd_is_named_not_swallowed(self):
        archive = self.tmp / "n.tar.zst"
        archive.write_bytes(b"x")
        with self.assertRaises(pl.PackError) as ctx:
            pl.unpack_notices(archive, self.tmp / "dest", which=lambda name: None)
        self.assertIn("zstd", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
