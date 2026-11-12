"""T4.6: `tools/artifact_hashes.py` prints the SHA-256 of each artifact (SG-15, T7.3)."""
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
            for key in ("archive", "notices"):
                self.assertIn("%s  %s" % (entry[key]["sha256"], entry[key]["file"]), out.splitlines())
        for digest, _ in lines:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_two_runs_print_the_same_text(self):
        self.assertEqual(run([])[1], run([])[1])

    def test_the_printed_launcher_hash_is_the_hash_of_the_macos_launcher_text(self):
        sys.path.insert(0, str(ROOT / "checker/python/packaging"))
        import launcher  # noqa: E402
        _, out, _ = run([])
        expected = hashlib.sha256(launcher.render_macos().encode("ascii")).hexdigest()
        self.assertIn("%s  handsal-check\n" % expected, out)


if __name__ == "__main__":
    unittest.main()
