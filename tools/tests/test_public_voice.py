import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import check_public_voice as gate

TOOL = Path(gate.__file__).resolve()

# Violating samples are assembled at runtime so this file stays clean.
EM_DASH = chr(0x2014)
COAUTHOR = "Co-Auth" + "ored-By: Someone <a@b.c>"
GENERATED = "Generated" + " with a tool"
SESSION_URL = "https://" + "cla" + "ude.ai/code/session_abc"
ROBOT = chr(0x1F916)
REQUEST_ID = "q" + "-" + "0123456789ab"
AI_NAME = "Cla" + "ude"


class GateCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.repo = base / "repo"
        self.repo.mkdir()
        outside = base / "outside"
        outside.mkdir()
        self.terms = outside / "terms.txt"
        self.terms.write_text("# synthetic list\nzorbl\n=wibble\n\n", encoding="utf-8")

    def write(self, name, text):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def run_gate(self, *paths, terms=None):
        argv = ["--terms", str(terms or self.terms)]
        argv += [str(p) for p in (paths or [self.repo])]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = gate.main(argv)
        return code, out.getvalue()


class CleanTree(GateCase):
    def test_clean_tree_exits_zero(self):
        self.write("a.md", "plain text, a comma, (parentheses).\n")
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)

    def test_dot_directory_name_is_not_attribution(self):
        self.write(".gitignore", ".claude/\n")
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)

    def test_whole_word_term_does_not_match_inside_a_longer_word(self):
        self.write("a.md", "unwibbled and wibbles and awibble\n")
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)

    def test_ignored_directories_are_skipped(self):
        self.write(".git/x.txt", "a" + EM_DASH + "b\n")
        self.write("__pycache__/x.txt", "a" + EM_DASH + "b\n")
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)

    def test_binary_file_is_skipped(self):
        (self.repo / "b.bin").write_bytes(b"\x00\x01" + EM_DASH.encode("utf-8"))
        code, out = self.run_gate()
        self.assertEqual(code, 0, out)


class Violations(GateCase):
    def expect_hit(self, text, label, line=1):
        self.write("doc.md", "ok line\n" * (line - 1) + text + "\n")
        code, out = self.run_gate()
        self.assertEqual(code, 1, out)
        self.assertIn("doc.md:%d" % line, out)
        self.assertIn(label, out)

    def test_em_dash(self):
        self.expect_hit("a " + EM_DASH + " b", "em-dash", line=3)

    def test_coauthor_trailer(self):
        self.expect_hit(COAUTHOR, "attribution")

    def test_generated_with(self):
        self.expect_hit(GENERATED, "attribution")

    def test_session_url(self):
        self.expect_hit(SESSION_URL, "attribution")

    def test_robot_marker(self):
        self.expect_hit(ROBOT + " done", "attribution")

    def test_ai_name_as_a_word(self):
        self.expect_hit("written by " + AI_NAME, "attribution")

    def test_request_id_shape(self):
        self.expect_hit("see " + REQUEST_ID, "request-id")

    def test_internal_term_substring_any_case(self):
        self.expect_hit("the ZORBLing thing", "internal-name")

    def test_internal_term_whole_word(self):
        self.expect_hit("the Wibble here", "internal-name")

    def test_every_hit_is_reported(self):
        self.write("a.md", "x" + EM_DASH + "\n" + REQUEST_ID + "\n")
        self.write("sub/b.md", "zorbl\n")
        code, out = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(len(out.strip().splitlines()), 3, out)


class Usage(GateCase):
    def test_terms_file_is_required(self):
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()):
                gate.main([str(self.repo)])
        self.assertEqual(cm.exception.code, 2)

    def test_missing_terms_file_fails_closed(self):
        code, _ = self.run_gate(terms=self.terms.parent / "nope.txt")
        self.assertEqual(code, 2)

    def test_empty_terms_file_fails_closed(self):
        empty = self.terms.parent / "empty.txt"
        empty.write_text("# nothing\n", encoding="utf-8")
        code, _ = self.run_gate(terms=empty)
        self.assertEqual(code, 2)

    def test_terms_file_inside_scanned_tree_is_refused(self):
        inside = self.write("terms.txt", "zorbl\n")
        code, out = self.run_gate(terms=inside)
        self.assertEqual(code, 2, out)

    def test_missing_scan_path_fails_closed(self):
        code, _ = self.run_gate(self.repo / "nope")
        self.assertEqual(code, 2)


class Subprocess(GateCase):
    def test_exit_code_through_the_real_entry_point(self):
        self.write("a.md", "x" + EM_DASH + "y\n")
        r = subprocess.run(
            [sys.executable, "-I", str(TOOL), "--terms", str(self.terms), str(self.repo)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.md:1", r.stdout)


if __name__ == "__main__":
    unittest.main()
