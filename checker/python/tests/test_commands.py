"""The batch seam of `admit`, `pool` and `compact` (`commands.per_batch`): one verifier round per call, the same bytes.

`per_batch` finds the questions of a call by running the call's own handler over a memo that answers `ok` and
records, asks them in one round, and lets the speculative output stand only if every answer was `ok`. These tests
hold it to the invariant that makes that safe: the bytes are the bytes `per_call` (one question at a time) gives, for
every vector of the three commands, for generated stores, and for a verifier that cannot answer some or all
questions. The cost tests count rounds and unique questions at a verifier with a real batch round (`BatchStub`).
"""
import io
import json
import zlib
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import admit, commands, compact, core, errors, pool, state, verifier

from .act_builder import BAD, FakeVitni, with_signature
from .es256_vitni import Es256Vitni
from .fold_world import World
from .genesis_fixtures import point
from .linear_world import MAX, acts_of, chain as linear_chain, top
from .store_world import ALL, BatchStub, entry, opened, random_store, snap_of

BUILD = commands.Build(conformance=True, allow_fixture=True)
VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"
CAP = 100   # a memo no test here fills
NOBODY = point("alice-pin.agree")   # a point no device has: the whole traversal answers no
KEYS = {"alice": {"k" * 43: {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active", "x": "a", "y": "b"}}}


def batched(vitni):
    """The table of the three commands as the builds make it."""
    return commands.admission(BUILD, vitni)


def one_at_a_time(vitni):
    """The same three handlers under `per_call`: the oracle the seam must equal."""
    return {name: commands.per_call(vitni, handler) for name, handler in commands.admission_handlers(BUILD).items()}


def ask(table, command, value):
    out = io.BytesIO()
    core.run(table, [command], io.BytesIO(json.dumps(value).encode()), out)
    return out.getvalue()


def snapshot_of(w, below, **extra):
    return {"acts": acts_of(below), "docs": [entry(w.doc, w.sigs(w.doc, ALL))], "org": w.id, **extra}


def linear_inputs(n):
    """`{command: input}` of a store of `n` linear steps that every verifier answer on is `ok`: admit-closed."""
    w = World()
    below = linear_chain(w, n)
    item = top(w, below)
    return {"admit": snapshot_of(w, below, item={"act": item.primary.jws, "sigs": item.acts[1:]}),
            "pool": snapshot_of(w, below, agree=NOBODY),   # in no pool: the whole traversal
            "compact": snapshot_of(w, below)}


class Toy:
    """A handler that asks its memo the questions of `value` (texts) one by one and answers what it saw."""

    def __init__(self, stop_at_ok=False, until_bad=False):
        self.runs, self.stop_at_ok, self.until_bad = 0, stop_at_ok, until_bad

    def __call__(self, value, memo):
        self.runs += 1
        seen = []
        for text in value:
            if text == "malformed":
                raise errors.Malformed()
            seen.append(memo.verify(text, KEYS, "m"))
            if self.stop_at_ok and seen[-1] == "ok" or self.until_bad and seen[-1] != "ok":
                break
        return seen


class Verdict(verifier.Verifier):
    def __init__(self, table):
        self.table = table

    def verify(self, jws, keys, method):
        if self.table[jws] is None:
            raise verifier.VerifierUnavailable("down on " + jws)
        return self.table[jws]


class PerBatch(unittest.TestCase):
    """The strategy on a handler of known questions."""

    def command(self, handler, vitni, verdicts=None):
        return commands.per_batch(vitni, handler, verdicts).handler

    def test_a_command_over_a_handler_is_not_raw(self):
        self.assertFalse(commands.per_batch(BatchStub(), Toy()).raw)

    def test_every_answer_ok_is_one_round_and_the_handler_runs_once(self):
        stub, handler = BatchStub(Verdict({"a": "ok", "b": "ok", "c": "ok"})), Toy()
        self.assertEqual(self.command(handler, stub)(["a", "b", "a", "c"]), ["ok"] * 4)
        self.assertEqual((handler.runs, stub.rounds, stub.singles), (1, 1, []))
        self.assertEqual([q.jws for q in stub.batched], ["a", "b", "c"])

    def test_a_question_the_fold_never_asks_is_never_asked(self):
        stub = BatchStub(Verdict({}))
        self.assertEqual(self.command(Toy(), stub)([]), [])
        self.assertEqual((stub.rounds, stub.singles), (0, []))

    def test_a_verdict_that_is_not_ok_runs_the_handler_again_over_the_real_answers(self):
        stub, handler = BatchStub(Verdict({"a": "ok", "b": "bad_signature"})), Toy()
        self.assertEqual(self.command(handler, stub)(["a", "b"]), ["ok", "bad_signature"])
        self.assertEqual((handler.runs, stub.rounds, stub.singles), (2, 1, []))

    def test_a_question_only_the_real_pass_asks_is_one_single_question(self):
        stub, handler = BatchStub(Verdict({"a": "bad_signature", "b": "ok"})), Toy(stop_at_ok=True)
        self.assertEqual(self.command(handler, stub)(["a", "b"]), ["bad_signature", "ok"])
        self.assertEqual((handler.runs, stub.rounds), (2, 1))   # the speculation stopped at "a": it was "ok" then
        self.assertEqual([q.jws for q in stub.singles], ["b"])

    def test_an_error_is_raised_where_the_fold_reads_it_and_nowhere_else(self):
        table = {"a": "ok", "b": None, "c": "ok"}
        stub = BatchStub(Verdict(table), fails=lambda q: q.jws == "b")
        self.assertEqual(self.command(Toy(stop_at_ok=True), stub)(["a", "b", "c"]), ["ok"])   # "b" is never read
        with self.assertRaises(verifier.VerifierUnavailable):
            self.command(Toy(), BatchStub(Verdict(table), fails=lambda q: q.jws == "b"))(["a", "b", "c"])

    def test_an_error_on_a_question_only_the_optimistic_tree_asks_changes_nothing(self):
        stub = BatchStub(Verdict({"a": "bad_signature", "b": None}), fails=lambda q: q.jws == "b")
        got = self.command(Toy(until_bad=True), stub)(["a", "b"])   # the guess asks "b" too, the real fold stops at "a"
        self.assertEqual(got, ["bad_signature"])
        self.assertEqual([q.jws for q in stub.batched], ["a", "b"])

    def test_a_round_that_fails_gives_the_error_at_the_first_question_read(self):
        stub = BatchStub(Verdict({"a": "ok"}), down=True)
        with self.assertRaises(verifier.VerifierUnavailable):
            self.command(Toy(), stub)(["a"])
        self.assertEqual((stub.rounds, stub.singles), (1, []))
        self.assertEqual(self.command(Toy(), BatchStub(Verdict({}), down=True))([]), [])   # no question: no round, no error

    def test_a_refusal_of_the_input_propagates_before_any_round(self):
        stub = BatchStub(Verdict({"a": "ok"}))
        with self.assertRaises(errors.Malformed):
            self.command(Toy(), stub)(["a", "malformed"])
        self.assertEqual(stub.rounds, 0)

    def test_verdicts_are_learned_failures_are_not_and_a_warm_call_runs_no_round(self):
        known = verifier.Verdicts(CAP)
        stub = BatchStub(Verdict({"a": "ok", "b": "bad_signature", "c": None}), fails=lambda q: q.jws == "c")
        with self.assertRaises(verifier.VerifierUnavailable):
            self.command(Toy(), stub, known)(["a", "b", "c"])
        self.assertEqual([known.get(verifier.question(j, KEYS, "m")) for j in "abc"], ["ok", "bad_signature", None])
        warm, handler = BatchStub(Verdict({})), Toy()
        self.assertEqual(self.command(handler, warm, known)(["a", "b", "a"]), ["ok", "bad_signature", "ok"])
        self.assertEqual((handler.runs, warm.rounds, warm.singles), (1, 0, []))   # all known: the one fold is the real one


class OneRound(unittest.TestCase):
    """On an admit-closed store the verifier sees one round per call, the questions the call always asked."""

    def test_every_command_asks_one_round_and_no_single_question_and_runs_the_handler_once(self):
        for n in range(1, MAX + 1):
            inputs = linear_inputs(n)
            for command, module, unique in (("admit", admit, 3 * n + 6), ("pool", pool, 3 * n + 3),
                                            ("compact", compact, 3 * n + 3)):
                with self.subTest(n=n, command=command):
                    stub = BatchStub()
                    with mock.patch.object(module, "run", wraps=module.run) as spy:
                        got = ask(batched(stub), command, inputs[command])
                    self.assertEqual(json.loads(got)["reason"], "not_in_pool" if command == "pool" else "ok")
                    self.assertEqual((stub.rounds, stub.singles, spy.call_count), (1, [], 1))
                    self.assertEqual(len(stub.batched), len(set(stub.batched)))
                    self.assertEqual(len(stub.batched), unique)

    def test_the_questions_are_the_ones_the_one_at_a_time_call_asks(self):
        for n in (1, 5, MAX):
            inputs = linear_inputs(n)
            for command in inputs:
                with self.subTest(n=n, command=command):
                    stub, single = BatchStub(), BatchStub()
                    batched_out = ask(batched(stub), command, inputs[command])
                    self.assertEqual(batched_out, ask(one_at_a_time(single), command, inputs[command]))
                    self.assertEqual(set(stub.batched), set(single.singles))
                    self.assertEqual(len(single.singles), len(set(single.singles)))   # the memo asked each once

    def test_an_item_refused_by_a_verdict_is_two_folds_in_one_round(self):
        w = World()
        below = linear_chain(w, 4)
        item = top(w, below)
        bad = with_signature(item.primary, BAD)
        value = snapshot_of(w, below, item={"act": bad.jws, "sigs": item.acts[1:]})
        stub, single = BatchStub(), BatchStub()
        with mock.patch.object(admit, "run", wraps=admit.run) as spy:
            got = ask(batched(stub), "admit", value)
        self.assertNotEqual(json.loads(got)["reason"], "ok")
        self.assertEqual((stub.rounds, spy.call_count), (1, 2))
        self.assertEqual(got, ask(one_at_a_time(single), "admit", value))


class Misses(unittest.TestCase):
    """A stored first copy that is garbage: the fold tries the next copy, a question the round did not hold."""

    def world(self):
        w = World()
        below = linear_chain(w, 3)
        twin = with_signature(below[1].primary, BAD)
        return w, below, twin

    def test_a_bad_first_twin_costs_one_single_question_per_miss_and_changes_no_byte(self):
        w, below, twin = self.world()
        acts = [twin.jws] + acts_of(below)   # the garbage copy first: the fold reads it before the real one
        value = {"acts": acts, "docs": [entry(w.doc, w.sigs(w.doc, ALL))], "org": w.id}
        missed = 0
        for command, extra in (("compact", {}), ("pool", {"agree": NOBODY})):
            with self.subTest(command=command):
                stub, single = BatchStub(), BatchStub()
                got = ask(batched(stub), command, {**value, **extra})
                self.assertEqual(got, ask(one_at_a_time(single), command, {**value, **extra}))
                self.assertEqual(json.loads(got)["reason"], "not_in_pool" if command == "pool" else "ok")
                self.assertEqual(stub.rounds, 1)
                lacking = set(single.singles) - set(stub.batched)
                self.assertEqual(sorted(q.jws for q in stub.singles), sorted(q.jws for q in lacking))
                missed += len(stub.singles)
        self.assertGreater(missed, 0)

    def test_a_miss_that_cannot_be_answered_fails_loudly_and_changes_no_byte(self):
        w, below, twin = self.world()
        real = below[1].primary.jws
        acts = [twin.jws] + acts_of(below)
        value = {"acts": acts, "docs": [entry(w.doc, w.sigs(w.doc, ALL))], "org": w.id}

        def fails(asked):   # the second copy: a question only the real pass asks, so it is never in the round
            return asked.jws == real

        stub, single = BatchStub(fails=fails), BatchStub(fails=fails)
        got = ask(batched(stub), "compact", value)
        self.assertEqual(got, ask(one_at_a_time(single), "compact", value))
        self.assertEqual(json.loads(got)["reason"], "verifier_unavailable")
        self.assertEqual(stub.rounds, 1)
        self.assertNotIn(real, [q.jws for q in stub.batched])   # the miss was not in the round
        self.assertIn(real, [q.jws for q in stub.singles])      # it was asked once, alone, and failed there


def generated_inputs(seed):
    """`[(command, input)]` over a generated store: every command, and items and points of the store and not."""
    stored = random_store(seed)
    snap = snap_of(stored.acts, stored.docs, stored.org)
    base = {"acts": list(stored.acts), "docs": list(stored.docs), "org": stored.org}
    points = set()
    for found in opened(snap).values():
        found.build()
        points |= {p for n in found.nodes.values() for d in n.state.devices.values() for p in (d.sign, d.agree)}
    out = [("compact", base)]
    out += [("pool", {**base, "agree": NOBODY})]
    out += [("pool", {**base, "agree": state.point_obj(p)}) for p in sorted(points)[:3]]
    out += [("admit", {**base, "item": {"act": text, "sigs": []}}) for text in stored.acts[:4]]
    out += [("admit", {**base, "item": {"act": text, "sigs": stored.acts[8:14]}}) for text in stored.acts[8:10]]
    return out


def unlucky(asked):
    """A fixed pseudo-random subset of questions (about one in forty) that the verifier cannot answer."""
    return zlib.crc32(repr(asked).encode()) % 41 == 0


class SameOutput(unittest.TestCase):
    """The bytes of `per_batch` are the bytes of `per_call`, whatever the verifier does."""

    def same(self, command, value, **how):
        batch, single = BatchStub(**how), BatchStub(**how)
        got = ask(batched(batch), command, value)
        self.assertEqual(got, ask(one_at_a_time(single), command, value))
        return got

    def test_every_vector_of_the_three_commands(self):
        seen = 0
        for path in sorted(p for prefix in ("adm", "kpl", "cmp") for p in VECTORS.glob(prefix + ".*.json")):
            vector = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(vector=vector["name"]):
                got = self.same(vector["command"], vector["input"], inner=Es256Vitni())
                self.assertEqual(got, vector["anchor"].encode() + b"\n")   # the stand-in is honest: the vector's own answer
                seen += 1
        self.assertGreaterEqual(seen, 50)

    def test_generated_stores_with_an_honest_verifier(self):
        seen = set()
        for seed in range(8):
            for command, value in generated_inputs(seed):
                with self.subTest(seed=seed, command=command):
                    seen.add(json.loads(self.same(command, value))["reason"])
        self.assertIn("ok", seen)
        self.assertGreater(len(seen), 3)   # refusals of several kinds were compared too

    def test_generated_stores_when_some_questions_cannot_be_answered(self):
        unanswered = answered = 0
        for seed in range(8):
            for command, value in generated_inputs(seed):
                with self.subTest(seed=seed, command=command):
                    got = self.same(command, value, fails=unlucky)
                    unanswered += b"verifier_unavailable" in got
                    answered += b"verifier_unavailable" not in got
        self.assertGreater(unanswered, 0)   # a failed question was read: the same loud answer in both
        self.assertGreater(answered, 0)     # a failed question nobody reads changed nothing

    def test_generated_stores_when_the_whole_round_fails(self):
        unanswered = 0
        for seed in range(8):
            for command, value in generated_inputs(seed):
                with self.subTest(seed=seed, command=command):
                    unanswered += b"verifier_unavailable" in self.same(command, value, down=True)
        self.assertGreater(unanswered, 0)


if __name__ == "__main__":
    unittest.main()
