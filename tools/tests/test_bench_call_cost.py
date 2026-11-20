"""The call-cost benchmark (`tools/bench_call_cost.py`): its rows, its CPU gate and its counts.

A store of a few real `device.add` steps is generated once, outside the repository, by the tool itself. The gate is
the phase-1 CPU threshold of each command with a zero-cost verifier (N=1000 at most 1.5 s, N=3000 at most 5 s); here
it is exercised at a small N with a clock the test controls, so it is the gate that is tested and not the machine.
"""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import bench_call_cost as bench  # noqa: E402

STEPS = 3


def run(*argv):
    """`(exit status, the JSON rows printed)` of one run of the tool in this process."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = bench.main([str(part) for part in argv])
    return status, [json.loads(line) for line in out.getvalue().splitlines()]


class Clock:
    """A clock that moves `step` seconds on every reading."""

    def __init__(self, step):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


class Rows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = str(Path(cls.tmp.name) / "store.json")
        made = subprocess.run([sys.executable, "-I", str(TOOLS / "bench_call_cost.py"), "gen", str(STEPS), cls.store],
                              capture_output=True, text=True, check=False)
        if made.returncode != 0:
            raise AssertionError(made.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def measure(self, *extra, n=STEPS):
        return run("measure", self.store, n, *extra)

    def test_the_refused_item_is_a_row_of_its_own(self):
        self.assertEqual(bench.CASES, ("admit", "pool", "compact", "admit-refused"))
        status, rows = self.measure("--mode", "stub", "--reps", 1)
        self.assertEqual(status, 0)
        by_case = {row["cmd"]: row for row in rows}
        self.assertEqual(sorted(by_case), sorted(bench.CASES))
        self.assertEqual(by_case["admit"]["reason"], "ok")
        self.assertNotEqual(by_case["admit-refused"]["reason"], "ok")   # a verdict refused the item
        self.assertIsNotNone(by_case["admit-refused"]["reason"])

    def test_the_refused_row_is_refused_by_the_verdict_on_the_items_primary_alone(self):
        stored = bench.load(self.store, STEPS)
        item = stored["steps"][STEPS][0]
        refusing = bench.Refusing(bench.Stub(), {item})
        keys = {"alice": {}}
        self.assertEqual(refusing.verify(item, keys, "m"), "bad_signature")
        self.assertEqual(refusing.verify(stored["steps"][0][0], keys, "m"), "ok")

    def test_a_row_over_its_limit_fails_the_run_and_one_within_it_does_not(self):
        with mock.patch.object(bench, "LIMITS", {STEPS: 1.5}):
            with mock.patch.object(bench, "CLOCK", Clock(0.001)):
                status, rows = self.measure("--mode", "stub", "--reps", 1)
            self.assertEqual(status, 0)
            self.assertTrue(all(row["within"] for row in rows), rows)
            self.assertEqual({row["limit_s"] for row in rows}, {1.5})
            with mock.patch.object(bench, "CLOCK", Clock(10.0)):
                status, rows = self.measure("--mode", "stub", "--reps", 1)
            self.assertEqual(status, 1)
            self.assertFalse(any(row["within"] for row in rows), rows)

    def test_a_size_without_a_limit_has_no_gate(self):
        with mock.patch.object(bench, "CLOCK", Clock(10.0)):
            status, rows = self.measure("--mode", "stub", "--reps", 1)
        self.assertEqual(status, 0)
        self.assertTrue(all("limit_s" not in row and "within" not in row for row in rows), rows)

    def test_the_phase_one_thresholds_are_the_gate(self):
        self.assertEqual(bench.LIMITS, {1000: 1.5, 3000: 5.0})

    def test_the_counted_run_sees_one_round_and_no_single_question_per_call(self):
        status, rows = self.measure("--mode", "count", "--reps", 1)
        self.assertEqual(status, 0)
        by_case = {row["cmd"]: row for row in rows}
        for case, unique in (("admit", 3 * STEPS + 6), ("pool", 3 * STEPS + 3), ("compact", 3 * STEPS + 3)):
            with self.subTest(case=case):
                self.assertEqual((by_case[case]["rounds"], by_case[case]["singles"], by_case[case]["q_unique"]),
                                 (1, 0, unique))
        self.assertEqual((by_case["admit-refused"]["rounds"], by_case["admit-refused"]["singles"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
