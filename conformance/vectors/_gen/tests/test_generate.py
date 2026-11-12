"""T2.8 generator driver (CF-06, CF-07).

The driver owns three things: which group modules run (an explicit registry),
that every vector goes through one writer (so names are unique across groups
and, with the id list, restricted to the shipping set), and the proof that a
rerun is byte-identical.
"""
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

import generate
from lib import base, vitni

GEN = Path(__file__).resolve().parents[1]
ROOT = GEN.parents[2]


def _group(fn):
    return types.SimpleNamespace(generate=fn)


def _fixed(ctx):
    ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")


def _other(ctx):
    ctx.writer.add("key/one", "kid", '{"kid":"k"}', input={"x": "a", "y": "b"})


class Building(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_runs_every_registered_group_in_order_and_returns_names(self):
        names = generate.run(self.dir / "out", registry=[_group(_fixed), _group(_other)])
        self.assertEqual(names, ["jcs/one", "key/one"])
        self.assertEqual(sorted(p.name for p in (self.dir / "out").iterdir()),
                         ["jcs.one.json", "key.one.json"])

    def test_same_name_in_two_groups_is_refused(self):
        with self.assertRaises(Exception):
            generate.run(self.dir / "out", registry=[_group(_fixed), _group(_fixed)])

    def test_name_outside_the_shipping_ids_is_refused(self):
        with self.assertRaises(Exception):
            generate.run(self.dir / "out", registry=[_group(_fixed)], known_ids=["key/one"])

    def test_context_gives_the_fixture_profile_from_the_manifest(self):
        seen = []
        generate.run(self.dir / "out", registry=[_group(lambda c: seen.append(c.fixtures.profile))])
        self.assertEqual(seen, [base.fixture_profile()])

    def test_stale_vector_files_are_removed_not_left_behind(self):
        out = self.dir / "out"
        out.mkdir()
        (out / "jcs.gone.json").write_text("{}\n")
        generate.run(out, registry=[_group(_fixed)])
        self.assertEqual([p.name for p in out.iterdir()], ["jcs.one.json"])

    def test_other_files_in_the_directory_are_kept(self):
        out = self.dir / "out"
        out.mkdir()
        (out / "README.txt").write_text("keep\n")
        generate.run(out, registry=[_group(_fixed)])
        self.assertTrue((out / "README.txt").exists())


class Reproducibility(unittest.TestCase):
    def test_deterministic_stub_is_reproducible(self):
        self.assertEqual(generate.check_reproducible(registry=[_group(_fixed)]), [])

    def test_nondeterministic_stub_is_caught(self):
        def noisy(ctx):
            ctx.writer.add("jcs/noisy", "subset", '{"canonical":true,"reason":"ok"}',
                           input_hex=os.urandom(8).hex())
        diff = generate.check_reproducible(registry=[_group(noisy)])
        self.assertEqual(diff, ["differs jcs.noisy.json"])

    def test_compare_reports_missing_extra_and_changed(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            (Path(a) / "x.json").write_text("1")
            (Path(a) / "same.json").write_text("s")
            (Path(b) / "same.json").write_text("s")
            (Path(b) / "y.json").write_text("2")
            (Path(a) / "z.json").write_text("a")
            (Path(b) / "z.json").write_text("b")
            self.assertEqual(generate.compare_dirs(a, b),
                             ["missing y.json", "extra x.json", "differs z.json"])


class CrossCheckWiring(unittest.TestCase):
    """Positive acts are recorded by the driver and judged by both vitni binaries (CF-06)."""

    class Fake:
        def __init__(self):
            self.calls = []

        def positive(self, jws, keys, policy):
            self.calls.append((jws, keys, policy))

    def positive_group(self, out):
        def gen(ctx):
            jws = ctx.fixtures.approve()
            ctx.positive(jws, "local:handsal.request.approve", ["alice"])
            out.append(jws)
            ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")
        return _group(gen)

    def test_positive_goes_to_the_crosscheck_with_keys_and_policy(self):
        fake, seen = self.Fake(), []
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[self.positive_group(seen)], crosscheck=fake)
        fx = base.Fixtures(base.fixture_profile())
        self.assertEqual(fake.calls, [(seen[0], fx.keyset(["alice"]),
                                       base.vitni_policy("local:handsal.request.approve"))])

    def test_a_tip_statement_goes_to_the_crosscheck_with_the_one_entry_relay_keys(self):
        """WT-05 step 4: keys `{"relay": {relay_kid: ...}}`, method `local:handsal.relay.tip`."""
        fake, seen = self.Fake(), []

        def gen(ctx):
            jws = ctx.fixtures.tip_statement()
            ctx.positive_statement(jws)
            seen.append(jws)
            ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[_group(gen)], crosscheck=fake, stats=stats)
        fx = base.Fixtures(base.fixture_profile())
        relay = fx.relay
        want_keys = {"relay": {relay.kid: dict(relay.jwk(), alg="ES256", status="active")}}
        self.assertEqual(fake.calls, [(seen[0], want_keys,
                                       base.vitni_policy("local:handsal.relay.tip"))])
        self.assertEqual(stats["positives"], 1)

    class FakeNegative(Fake):
        def __init__(self, reason):
            super().__init__()
            self.reason = reason

        def negative(self, jws, keys, policy):
            self.calls.append((jws, keys, policy))
            return self.reason

    def negative_group(self, expected):
        def gen(ctx):
            jws = ctx.fixtures.approve()
            ctx.negative(jws, "local:handsal.request.approve", ["alice"], expected,
                         revoked=["alice"])
            ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")
        return _group(gen)

    def test_negative_asks_vitni_with_the_revoked_keys_and_accepts_its_verdict(self):
        fake = self.FakeNegative("bad_signature")
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[self.negative_group("bad_signature")],
                         crosscheck=fake)
        fx = base.Fixtures(base.fixture_profile())
        self.assertEqual(fake.calls[0][1], fx.keyset(["alice"], revoked=["alice"]))

    def test_a_negative_statement_is_judged_under_the_relay_keys(self):
        fake = self.FakeNegative("bad_signature")

        def gen(ctx):
            ctx.negative_statement(ctx.fixtures.tip_statement(), "bad_signature")
            ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[_group(gen)], crosscheck=fake)
        self.assertEqual(list(fake.calls[0][1]), ["relay"])
        self.assertEqual(fake.calls[0][2], base.vitni_policy("local:handsal.relay.tip"))
        fake = self.FakeNegative("high_s")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(vitni.VitniAbort):
                generate.run(Path(d) / "out", registry=[_group(gen)], crosscheck=fake)

    def test_negative_aborts_when_vitni_says_another_reason(self):
        fake = self.FakeNegative("malformed")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(vitni.VitniAbort):
                generate.run(Path(d) / "out", registry=[self.negative_group("bad_signature")],
                             crosscheck=fake)

    def test_negative_without_a_crosscheck_is_counted_not_judged(self):
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[self.negative_group("x")], stats=stats)
        self.assertEqual(stats, {"positives": 0, "negatives": 1})

    def test_the_same_positive_is_judged_once(self):
        fake, stats = self.Fake(), {}

        def gen(ctx):
            jws = ctx.fixtures.approve()
            for _ in range(3):
                ctx.positive(jws, "local:handsal.request.approve", ["alice"])
            ctx.writer.add("jcs/one", "subset", '{"canonical":true,"reason":"ok"}', input_raw="{}")
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[_group(gen)], crosscheck=fake, stats=stats)
        self.assertEqual((len(fake.calls), stats["positives"]), (1, 1))

    def test_without_a_crosscheck_positives_are_counted_for_the_report(self):
        stats = {}
        with tempfile.TemporaryDirectory() as d:
            generate.run(Path(d) / "out", registry=[self.positive_group([])], stats=stats)
        self.assertEqual(stats, {"positives": 1, "negatives": 0})

    def test_one_vitni_binary_alone_is_refused(self):
        for args in (["--vitni-go", "/x"], ["--vitni-ts", "/x"]):
            self.assertEqual(generate.main(["--check"] + args), 2)

    def test_an_unrunnable_binary_aborts_the_run_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            code = generate.main(["--out", d, "--vitni-go", "/nonexistent/go",
                                  "--vitni-ts", "/nonexistent/ts"])
        self.assertEqual(code, 1)


class IsolatedScript(unittest.TestCase):
    def test_driver_runs_as_a_script_under_isolated_mode(self):
        """-I drops the script directory from sys.path; discover hides that (see run.py)."""
        proc = subprocess.run([sys.executable, "-I", str(GEN / "generate.py"), "--help"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--vitni-go", proc.stdout)


class Registry(unittest.TestCase):
    def test_every_module_in_groups_is_registered_and_the_reverse(self):
        import groups
        on_disk = sorted(p.stem for p in (GEN / "groups").glob("*.py") if p.stem != "__init__")
        self.assertEqual(sorted(groups.REGISTRY), on_disk)

    def test_each_registered_module_has_generate(self):
        for module in generate.load_registry():
            self.assertTrue(callable(module.generate))


class RealRun(unittest.TestCase):
    """The real registry, run in two processes with different hash seeds."""

    def run_once(self, out, seed):
        env = dict(os.environ, PYTHONHASHSEED=str(seed))
        proc = subprocess.run(
            [sys.executable, "-P", "-s", str(GEN / "generate.py"), "--out", str(out)],
            env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_two_processes_with_different_hash_seeds_agree(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.run_once(a, 1)
            self.run_once(b, 2)
            self.assertEqual(generate.compare_dirs(a, b), [])
            self.assertTrue(list(Path(a).glob("*.json")))

    def test_committed_vectors_equal_a_fresh_run(self):
        self.assertEqual(generate.check_dir(ROOT / "conformance" / "vectors"), [])

    def test_ids_come_from_the_shipping_list(self):
        ids = json.loads((ROOT / "conformance" / "vector-ids.json").read_text())["ids"]
        self.assertEqual(generate.shipping_ids(), frozenset(ids))


if __name__ == "__main__":
    unittest.main()
