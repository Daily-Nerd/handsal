"""T15.10: the evidence note of a PRODK run (T8.6) is written from the run, not from the first run's wording.

`prodk_evidence.py` turns the public report of `make_prodk.py` into the vault note. These tests run it on a
made-up report: no key, no signing. What belongs to one release (the task row, the proof line, the commit, the
branch, the date, the profile) comes in with the run, and a note from an earlier run is never overwritten.
"""
import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

import prodk_evidence

GEN = Path(__file__).resolve().parents[1]
REPORT = {
    "created_utc": "2026-12-01T09:30:00Z",
    "production_profile": "uEiExampleExampleExampleExampleExampleExample0",
    "python": "3.13.7",
    "pid": 4242,
    "people": {"alice": "kidAlice", "bob": "kidBob", "carol": "kidCarol"},
    "files": {"fix.prodk-fold-ok.json": "a" * 64, "enr.prodk-fixture-kid-unknown.json": "b" * 64},
    "files_scanned": 1500,
    "scan_roots": ["/repo/conformance", "/repo/spec"],
    "scalars_held": 3,
}
COMMIT = "0123456789abcdef0123456789abcdef01234567"
HARNESS = "6 vectors, 0 not passing"
PROOF = "RESULT: final proof passed (after the PRODK run), commit 0123456"


class Rendered(unittest.TestCase):
    def render(self, **kw):
        args = dict(report=REPORT, commit=COMMIT, branch="release/prodk", harness=HARNESS, proof=PROOF, task=None)
        args.update(kw)
        return prodk_evidence.render(**args)

    def test_it_holds_the_public_values_of_this_run(self):
        text = self.render()
        for want in (REPORT["production_profile"], "kidAlice", "kidBob", "kidCarol", "a" * 64, "b" * 64,
                     "2026-12-01T09:30:00Z", COMMIT, "release/prodk", HARNESS, PROOF, "1500", "3.13.7", "4242"):
            self.assertIn(want, text)

    def test_the_date_of_the_note_is_the_day_of_the_signing(self):
        self.assertRegex(self.render(), r"(?m)^date: 2026-12-01$")

    def test_the_task_row_is_what_the_run_was_given_and_absent_when_it_was_given_none(self):
        self.assertNotRegex(self.render(), r"(?m)^task:")
        self.assertRegex(self.render(task="T8.6"), r"(?m)^task: T8\.6$")
        self.assertRegex(self.render(task="T9.1"), r"(?m)^task: T9\.1$")

    def test_no_row_or_release_of_an_earlier_run_is_written_into_the_note(self):
        text = self.render(task="T8.6")
        for old in ("T7.2", "v0.1.0", "final-proof.sh", "uEiBlrx"):
            self.assertNotIn(old, text)
        source = (GEN / "prodk_evidence.py").read_text(encoding="utf-8")
        for old in ("T7.2", "v0.1.0", "final-proof.sh"):
            self.assertNotIn(old, source)

    def test_the_note_says_the_vectors_are_not_committed_because_the_run_never_commits(self):
        self.assertIn("not committed", self.render())

    def test_the_note_has_the_frontmatter_of_a_vault_evidence_note(self):
        head = self.render().split("---\n")[1]
        self.assertEqual(sorted(re.findall(r"(?m)^(\w+):", head)), ["change", "date", "project", "status", "type"])
        self.assertIn('project: "[[handsal]]"', head)

    def test_it_has_no_em_dash_and_is_small(self):
        text = self.render()
        self.assertNotIn(chr(0x2014), text)
        self.assertLess(len(text.encode("utf-8")), 150 * 1024)

    def test_the_limits_of_the_promise_are_stated(self):
        text = self.render()
        for phrase in ("What cannot be guaranteed", "freed process memory", "swap"):
            self.assertIn(phrase, text)

    def test_values_that_would_break_the_note_are_refused(self):
        for key, bad in (("task", "T8.6\nstatus: x"), ("task", "a b"), ("task", ""), ("branch", "a\nb"), ("branch", "a`b"),
                         ("commit", "abc"), ("commit", COMMIT + "\n"), ("harness", "x\ny"), ("proof", "x\ny")):
            with self.subTest(key=key, value=bad):
                with self.assertRaises(prodk_evidence.EvidenceError):
                    self.render(**{key: bad})


BAD_REPORTS = (
    ("created_utc", 20261201),
    ("created_utc", "tomorrow"),
    ("created_utc", None),
    ("production_profile", "a`b"),
    ("production_profile", "a\nb"),
    ("production_profile", 7),
    ("python", ["3"]),
    ("pid", "4242"),
    ("pid", True),
    ("people", ["alice"]),
    ("people", {"alice": 5}),
    ("people", {"alice": "k\nx"}),
    ("files", {"f.json": "xyz"}),
    ("files", {"f.json": 5}),
    ("files", ["f.json"]),
    ("files_scanned", "1500"),
    ("scalars_held", 1.5),
    ("scan_roots", "/repo"),
    ("scan_roots", [3]),
    ("scan_roots", ["a`b"]),
)


class ReportShape(unittest.TestCase):
    """The report comes from make_prodk.py, but the note is a public-facing file: its shape is checked once, at the
    boundary, and a wrong field is a refusal that names it, not a traceback."""

    def test_each_wrong_field_is_an_evidence_error_naming_it(self):
        for key, bad in BAD_REPORTS:
            with self.subTest(key=key, value=bad):
                report = dict(REPORT)
                report[key] = bad
                with self.assertRaises(prodk_evidence.EvidenceError) as ctx:
                    prodk_evidence.render(report, COMMIT, "b", HARNESS, PROOF)
                self.assertIn(key, str(ctx.exception))

    def test_the_command_line_exits_2_with_a_message_and_no_traceback(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for key, bad in BAD_REPORTS:
            with self.subTest(key=key, value=bad):
                report = dict(REPORT)
                report[key] = bad
                path = Path(tmp.name) / "r.json"
                path.write_text(json.dumps(report), encoding="utf-8")
                out = Path(tmp.name) / "note.md"
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    status = prodk_evidence.main([str(path), str(out), "--commit", COMMIT, "--branch", "b",
                                                  "--harness", HARNESS, "--proof", PROOF])
                self.assertEqual(status, 2)
                self.assertIn(key, err.getvalue())
                self.assertFalse(out.exists())


class CommandLine(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.report = self.tmp / "report.json"
        self.report.write_text(json.dumps(REPORT), encoding="utf-8")
        self.out = self.tmp / "note.md"

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = prodk_evidence.main(argv)
        return status, out.getvalue(), err.getvalue()

    def argv(self, *extra):
        return [str(self.report), str(self.out), "--commit", COMMIT, "--branch", "release/prodk", "--harness", HARNESS,
                "--proof", PROOF] + list(extra)

    def test_it_writes_the_note(self):
        status, _out, err = self.run_main(self.argv("--task", "T8.6"))
        self.assertEqual((status, err), (0, ""))
        text = self.out.read_text(encoding="utf-8")
        self.assertIn("kidAlice", text)
        self.assertRegex(text, r"(?m)^task: T8\.6$")

    def test_the_note_of_an_earlier_run_is_a_refusal_not_an_overwrite(self):
        self.out.write_text("the note of an earlier run\n", encoding="utf-8")
        status, out, err = self.run_main(self.argv())
        self.assertEqual((status, out), (2, ""))
        self.assertIn(str(self.out), err)
        self.assertIn("earlier run", err)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "the note of an earlier run\n")

    def test_a_missing_or_garbled_report_is_a_refusal_and_writes_nothing(self):
        self.report.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.run_main(self.argv())[0], 2)
        self.report.unlink()
        self.assertEqual(self.run_main(self.argv())[0], 2)
        self.assertFalse(self.out.exists())

    def test_a_report_without_the_fields_of_a_run_is_a_refusal(self):
        self.report.write_text(json.dumps({"created_utc": "2026-12-01T09:30:00Z"}), encoding="utf-8")
        status, _out, err = self.run_main(self.argv())
        self.assertEqual(status, 2)
        self.assertIn("report", err)
        self.assertFalse(self.out.exists())

    def test_usage_errors_exit_2(self):
        for argv in ([], [str(self.report)], self.argv("--nope"), self.argv("--task")):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_main(argv)[0], 2)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
