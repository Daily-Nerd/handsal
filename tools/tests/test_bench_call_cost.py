"""The call-cost benchmark (`tools/bench_call_cost.py`): its rows, its CPU gate and its counts.

A store of a few real `device.add` steps is generated once, outside the repository, by the tool itself. The gate is
the CPU threshold of each command with a zero-cost verifier (N=1000 at most 1.5 s, N=3000 at most 5 s); here
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
# the questions that reach the verifier at N steps: every kept signature (three acts a step and three of the
# document), and admit asks three more, the item's acts
UNIQUE = {"admit": 3 * STEPS + 6, "pool": 3 * STEPS + 3, "compact": 3 * STEPS + 3}


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
        self.assertEqual(bench.CASES, tuple(bench.commands.admission_handlers(bench.BUILD)) + ("admit-refused",))
        status, rows = self.measure("--mode", "stub", "--reps", 1)
        self.assertEqual(status, 0)
        by_case = {row["cmd"]: row for row in rows}
        self.assertEqual(sorted(by_case), sorted(bench.CASES))
        self.assertEqual(by_case["admit"]["reason"], "ok")
        self.assertNotEqual(by_case["admit-refused"]["reason"], "ok")   # a verdict refused the item
        self.assertIsNotNone(by_case["admit-refused"]["reason"])

    def test_every_command_of_the_servers_table_is_a_case_with_an_input_and_a_row(self):
        table = bench.commands.admission_handlers(bench.commands.Build(conformance=False, allow_fixture=True))
        self.assertEqual(set(table), set(bench.COMMANDS))
        self.assertEqual(set(bench.inputs_at(bench.load(self.store, STEPS), STEPS)), set(table))
        status, rows = self.measure("--mode", "stub", "--reps", 1)
        self.assertEqual(status, 0)
        self.assertEqual({row["cmd"] for row in rows} - {"admit-refused"}, set(table))
        self.assertEqual({row["reason"] for row in rows if row["cmd"] != "admit-refused"}, {"ok"})

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

    def test_the_thresholds_are_the_gate(self):
        self.assertEqual(bench.LIMITS, {1000: 1.5, 3000: 5.0})

    def test_a_verifier_with_no_process_has_no_rounds_and_no_singles(self):
        # the stub answers each question in this process: nothing was spawned, so nothing is a round or a single
        status, rows = self.measure("--mode", "count", "--reps", 1)
        self.assertEqual(status, 0)
        by_case = {row["cmd"]: row for row in rows}
        for case, unique in UNIQUE.items():
            with self.subTest(case=case):
                self.assertEqual((by_case[case]["rounds"], by_case[case]["singles"], by_case[case]["q_unique"]),
                                 (0, 0, unique))
        self.assertEqual((by_case["admit-refused"]["rounds"], by_case["admit-refused"]["singles"]), (0, 0))

    def test_the_widest_keys_are_measured_the_same_whether_a_question_is_asked_singly_or_in_a_round(self):
        tally, keys = bench.Tally(), {"kid": {"alg": "ES256", "x": "a", "y": "b"}}
        counting = bench.Counting(bench.Stub(), tally)
        counting.verify("jws", keys, "m")
        single = tally.widest
        tally.reset()
        counting.verify_many([bench.verifier.question("jws", keys, "m")])
        self.assertEqual(tally.widest, single)
        self.assertEqual(single, len(bench.verifier.question("jws", keys, "m").keys))


FAKE_BATCH = """import json, sys
data = json.loads(sys.stdin.read())
if sys.argv[-1] != "verify-batch":
    print('{"error":"unsupported_command"}')
else:
    print(json.dumps({"results": [{"reason": "ok", "valid": True} for _ in data["questions"]]}))
"""


class ScriptedClock:
    """A clock that returns the given readings in order."""

    def __init__(self, *readings):
        self.readings = iter(readings)

    def __call__(self):
        return next(self.readings)


class BatchMode(unittest.TestCase):
    """`measure --mode batch`: the questions of a call go to a `VitniBatch`, and c is what one question costs over
    the cost of the checker alone: (batch wall minus stub wall) / unique questions."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = str(Path(cls.tmp.name) / "store.json")
        cls.fake = Path(cls.tmp.name) / "fake_vitni.py"
        cls.fake.write_text(FAKE_BATCH)
        made = subprocess.run([sys.executable, "-I", str(TOOLS / "bench_call_cost.py"), "gen", str(STEPS), cls.store],
                              capture_output=True, text=True, check=False)
        if made.returncode != 0:
            raise AssertionError(made.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def measure(self, *extra, commands=",".join(bench.CASES)):
        return run("measure", self.store, STEPS, "--mode", "batch", "--reps", 1, "--commands", commands,
                   "--vitni", sys.executable, "--vitni", self.fake, *extra)

    def test_every_call_is_one_batch_round_and_no_single_spawn(self):
        status, rows = self.measure()
        self.assertEqual(status, 0)
        by_case = {row["cmd"]: row for row in rows}
        self.assertEqual(sorted(by_case), sorted(bench.CASES))
        for case, unique in UNIQUE.items():
            with self.subTest(case=case):
                row = by_case[case]
                self.assertEqual((row["mode"], row["rounds"], row["singles"], row["q_unique"], row["reason"]),
                                 ("batch", 1, 0, unique, "ok" if case == "admit" else row["reason"]))
        refused = by_case["admit-refused"]
        self.assertEqual((refused["rounds"], refused["singles"]), (1, 0))   # the refusal does not turn the round into spawns
        self.assertNotEqual(refused["reason"], "ok")

    def test_c_is_the_batch_wall_less_the_stub_wall_per_unique_question(self):
        with mock.patch.object(bench, "CLOCK", ScriptedClock(0.0, 7.0, 10.0, 11.0, 20.0, 21.0)):   # timed: the batch, the stub, the counted run
            status, rows = self.measure(commands="admit")
        self.assertEqual(status, 0)
        (row,) = rows
        self.assertEqual((row["wall_s"], row["stub_wall_s"]), (7.0, 1.0))
        self.assertEqual(row["c_s"], round(6.0 / row["q_unique"], 6))

    def test_the_row_has_the_schema_of_a_measured_row_and_c(self):
        _, rows = self.measure(commands="pool")
        self.assertEqual(set(rows[0]), {"n", "cmd", "mode", "wall_s", "walls", "stub_wall_s", "c_s", "q_total", "q_unique",
                                        "rounds", "singles", "failed", "memos", "builds", "epochs", "max_keys_bytes", "reason",
                                        "peak_rss_mib"})

    def test_the_batch_has_no_cpu_gate(self):
        with mock.patch.object(bench, "LIMITS", {STEPS: 0.0}):
            status, rows = self.measure()
        self.assertEqual(status, 0)
        self.assertTrue(all("within" not in row for row in rows))

    FLAKY = ("import json, os, sys\ndata = json.loads(sys.stdin.read())\nmark = sys.argv[1]\n"
             "first = not os.path.exists(mark)\nopen(mark, 'a').close()\n"
             "if first:\n    sys.exit(3)\n"
             "ok = {'reason': 'ok', 'valid': True}\n"
             "print(json.dumps(ok if sys.argv[-1] == 'verify' else {'results': [ok for _ in data['questions']]}))\n")

    def flaky(self, mode, *clock):
        """`measure` over a vitni that gives no answer to its first process and every answer after it."""
        script, mark = Path(self.tmp.name) / "flaky_vitni.py", Path(self.tmp.name) / "seen"
        script.write_text(self.FLAKY)
        mark.unlink(missing_ok=True)
        with mock.patch.object(bench, "CLOCK", ScriptedClock(*clock)):
            return run("measure", self.store, STEPS, "--mode", mode, "--reps", 2, "--commands", "pool",
                       "--vitni", sys.executable, "--vitni", script, "--vitni", mark)

    def test_a_timed_run_that_failed_fails_the_benchmark_even_when_the_counted_run_answers(self):
        # batch: two timed runs, two stub runs, then the counted run; the first timed run gets no answer and is the slow one
        status, rows = self.flaky("batch", 0, 10, 20, 21, 30, 31, 40, 41, 50, 51)
        self.assertEqual(status, 1)
        self.assertGreater(rows[0]["failed"], 0)

    def test_a_failed_run_that_is_not_the_fastest_still_fails_a_counted_benchmark(self):
        status, rows = self.flaky("real", 0, 10, 20, 21)   # the failed run is the slow one, so it is not the best
        self.assertEqual(status, 1)
        self.assertGreater(rows[0]["failed"], 0)

    def test_a_vitni_that_cannot_batch_is_a_loud_failure_not_a_measurement(self):
        old = Path(self.tmp.name) / "old_vitni.py"
        old.write_text("import sys\nsys.stdin.read()\nprint('{\"error\":\"unsupported_command\"}')\n")
        status, rows = run("measure", self.store, STEPS, "--mode", "batch", "--reps", 1, "--commands", "pool",
                           "--vitni", sys.executable, "--vitni", old)
        self.assertEqual(status, 1)
        self.assertGreater(rows[0]["failed"], 0)


LOGGING = """import json, sys
data = json.loads(sys.stdin.read())
command = sys.argv[-1]
ok = {"reason": "ok", "valid": True}
if command == "verify":
    count, out = 1, ok
elif command == "verify-batch":
    count, out = len(data["questions"]), {"results": [ok for _ in data["questions"]]}
else:
    sys.exit(3)
with open(sys.argv[1], "a") as log:
    log.write("%s %d\\n" % (command, count))
print(json.dumps(out))
"""


class CountsAreProcesses(unittest.TestCase):
    """The counts describe what reached the verifier's process: how many processes were asked and how many questions
    each carried, whatever the class of the verifier. A vitni that logs each of its own invocations is the witness."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = str(Path(cls.tmp.name) / "store.json")
        cls.fake = Path(cls.tmp.name) / "logging_vitni.py"
        cls.fake.write_text(LOGGING)
        cls.log = Path(cls.tmp.name) / "spawns.log"
        made = subprocess.run([sys.executable, "-I", str(TOOLS / "bench_call_cost.py"), "gen", str(STEPS), cls.store],
                              capture_output=True, text=True, check=False)
        if made.returncode != 0:
            raise AssertionError(made.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def measured(self, mode, case):
        """`(the row, [(command, questions) of each process the vitni saw])` of one case in `mode`."""
        self.log.unlink(missing_ok=True)
        status, rows = run("measure", self.store, STEPS, "--mode", mode, "--reps", 1, "--commands", case,
                           "--vitni", sys.executable, "--vitni", self.fake, "--vitni", self.log)
        self.assertEqual(status, 0)
        seen = [(line.split()[0], int(line.split()[1])) for line in self.log.read_text().splitlines()]
        return rows[0], seen

    def test_a_vitni_asked_one_process_per_question_reports_a_single_for_each(self):
        for case in bench.CASES:
            with self.subTest(case=case):
                row, seen = self.measured("real", case)
                self.assertGreater(len(seen), 1)
                self.assertEqual({command for command, _ in seen}, {"verify"})
                self.assertEqual((row["rounds"], row["singles"]), (0, len(seen)))
                self.assertEqual(row["q_unique"], sum(count for _, count in seen))

    def test_a_batching_vitni_reports_a_round_for_each_process_and_the_questions_it_carried(self):
        for case in bench.CASES:
            with self.subTest(case=case):
                row, seen = self.measured("batch", case)
                # batch times the call without the counters, then counts one run: two runs reach the vitni
                self.assertEqual(len(seen) % 2, 0)
                run_seen = seen[len(seen) // 2:]
                self.assertEqual(seen[:len(seen) // 2], run_seen)
                self.assertEqual({command for command, _ in run_seen}, {"verify-batch"})
                self.assertEqual((row["rounds"], row["singles"]), (len(run_seen), 0))
                self.assertEqual(row["q_unique"], sum(count for _, count in run_seen))

    def test_a_round_of_more_questions_than_a_process_takes_is_several_processes(self):
        with mock.patch.object(bench.verifier, "BATCH_LIMIT", 4):
            row, seen = self.measured("batch", "compact")
        run_seen = seen[len(seen) // 2:]
        self.assertGreater(len(run_seen), 1)
        self.assertEqual(row["rounds"], len(run_seen))
        self.assertEqual(row["q_unique"], sum(count for _, count in run_seen))


CAP = 40000   # bytes: a handful of steps, so the test is quick; the real cap is the one of CF-11


class Bound(unittest.TestCase):
    """`bound`: the largest admit-closed store under a byte cap, and what a call over it costs (stub verifier)."""

    SCHEMA = {"cmd", "mode", "cap_bytes", "store_bytes", "steps", "kept_sigs", "s_min", "q_unique", "wall_best_s",
              "wall_worst_s", "peak_rss_mib", "reason"}

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = str(Path(cls.tmp.name) / "bound.json")
        cls.status, cls.rows = run("bound", cls.out, "--mode", "stub", "--cap", CAP, "--reps", 3)
        cls.store = json.loads(Path(cls.out).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_it_reports_each_command_in_one_fixed_schema(self):
        self.assertEqual(self.status, 0)
        self.assertEqual([row["cmd"] for row in self.rows], list(bench.commands.admission_handlers(bench.BUILD)))
        for row in self.rows:
            self.assertEqual(set(row), self.SCHEMA)
            self.assertEqual(row["mode"], "stub")
            self.assertEqual(row["cap_bytes"], CAP)

    def test_the_store_and_the_item_are_within_the_byte_cap_and_the_next_step_would_not_be(self):
        row = self.rows[0]
        steps = self.store["steps"]
        self.assertGreaterEqual(row["steps"], 2)
        self.assertEqual(len(steps), row["steps"] + 1)   # the item is the step after the store
        snap = {"acts": [act for step in steps for act in step], "docs": self.store["docs"], "org": self.store["org"]}
        self.assertEqual(row["store_bytes"], bench.snapshot_bytes(snap))
        self.assertLessEqual(row["store_bytes"], CAP)
        self.assertGreater(row["store_bytes"] + bench.step_bytes(steps[-1]), CAP)   # one more step does not fit

    def test_kept_signatures_and_the_smallest_text_are_those_of_the_store(self):
        row = self.rows[0]
        texts = [act for step in self.store["steps"][:row["steps"]] for act in step]
        texts += [sig for entry in self.store["docs"] for sig in entry["sigs"]]
        self.assertEqual(row["kept_sigs"], len(texts))
        self.assertEqual(row["kept_sigs"], 3 * row["steps"] + 3)
        self.assertEqual(row["s_min"], min(len(text) for text in texts))

    def test_each_kept_signature_is_one_question_and_admit_asks_three_more(self):
        by_cmd = {row["cmd"]: row for row in self.rows}
        kept = by_cmd["compact"]["kept_sigs"]
        self.assertEqual((by_cmd["compact"]["q_unique"], by_cmd["pool"]["q_unique"], by_cmd["admit"]["q_unique"]),
                         (kept, kept, kept + 3))
        self.assertEqual({row["reason"] for row in self.rows}, {"ok"})

    def test_the_walls_and_the_memory_are_measured(self):
        for row in self.rows:
            self.assertGreater(row["wall_best_s"], 0)
            self.assertGreaterEqual(row["wall_worst_s"], row["wall_best_s"])
            self.assertGreater(row["peak_rss_mib"], 1)

    def test_the_default_cap_is_the_one_an_act_group_is_admitted_under(self):
        self.assertEqual(bench.default_cap(), 14680064)

    def test_it_refuses_a_second_mode_an_existing_file_and_a_path_inside_the_repo(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            run("bound", str(Path(self.tmp.name) / "x.json"), "--mode", "batch")
        self.assertNotEqual(caught.exception.code, 0)   # argparse: the batch mode is the next task's
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            run("bound", self.out, "--mode", "stub", "--cap", CAP)
        self.assertEqual(caught.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            run("bound", str(ROOT / "bound-store.json"), "--mode", "stub", "--cap", CAP)
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((ROOT / "bound-store.json").exists())


if __name__ == "__main__":
    unittest.main()
