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

from handsal_check import admit, commands, compact, core, errors, fold, genesis, pool, state, verifier

from .act_builder import BAD, FakeVitni, with_signature
from .es256_vitni import Es256Vitni
from .fold_world import World
from .genesis_fixtures import point
from .linear_world import MAX, acts_of, chain as linear_chain, top
from .store_world import ALL, BatchStub, entry, later_world, opened, random_store, snap_of

BUILD = commands.Build(conformance=True, allow_fixture=True)
VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"
CAP = 100   # a memo no test here fills
NOBODY = point("alice-pin.agree")   # a point no device has: the whole traversal answers no
KEYS = {"alice": {"k" * 43: {"alg": "ES256", "crv": "P-256", "kty": "EC", "status": "active", "x": "a", "y": "b"}}}


class builds:
    """A context that counts the times an act tree was really built (`fold.Epoch.build` on an epoch not yet built)."""

    def __enter__(self):
        real, count = fold.Epoch.build, self

        def build(epoch):
            if not epoch._built:
                count.n += 1
            return real(epoch)

        self.n = 0
        self.patch = mock.patch.object(fold.Epoch, "build", build)
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()


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


class Staged(unittest.TestCase):
    """Both strategies take a handler of one shape, `opened(value, memo)` giving `finish()`; a handler of any other shape
    fails loudly (a TypeError when the strategy calls what it gave), never with an answer."""

    def test_whole_gives_a_finish_that_returns_what_the_handler_found_and_asks_nothing_more(self):
        stub, handler = BatchStub(Verdict({"a": "ok"})), Toy()
        finish = commands.whole(handler)(["a"], verifier.Memoized(stub))
        self.assertEqual((handler.runs, len(stub.singles)), (1, 1))   # every question was asked by `opened`
        self.assertEqual((finish(), finish()), (["ok"], ["ok"]))
        self.assertEqual((handler.runs, len(stub.singles)), (1, 1))

    def test_a_handler_that_returns_no_finish_is_refused_by_both_strategies(self):
        for name, strategy in (("per_call", commands.per_call), ("per_batch", commands.per_batch)):
            for plain in (Toy(), lambda value, memo: None):
                with self.subTest(strategy=name), self.assertRaises(TypeError):
                    strategy(BatchStub(Verdict({"a": "ok"})), plain).handler(["a"])

    def test_per_call_runs_finish_over_the_one_memo_of_the_call(self):
        stub = BatchStub(Verdict({"a": "ok", "b": "bad_signature"}))
        got = commands.per_call(stub, commands.whole(Toy())).handler(["a", "b", "a"])
        self.assertEqual(got, ["ok", "bad_signature", "ok"])
        self.assertEqual([q.jws for q in stub.singles], ["a", "b"])


class PerBatch(unittest.TestCase):
    """The strategy on a handler of known questions."""

    def command(self, handler, vitni, verdicts=None):
        return commands.per_batch(vitni, commands.whole(handler), verdicts).handler

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
            for command, module, entry_point, unique in (("admit", admit, "opened", 3 * n + 6), ("pool", pool, "run", 3 * n + 3),
                                                         ("compact", compact, "run", 3 * n + 3)):
                with self.subTest(n=n, command=command):
                    stub = BatchStub()
                    with mock.patch.object(module, entry_point, wraps=getattr(module, entry_point)) as spy:
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

    def test_a_refused_item_costs_one_fold_in_one_round(self):
        """What a verdict on the item's own text refuses is not what the store was built from, so the store is built
        once: v0.4.2 folded it a second time (two builds) to say the same thing."""
        w = World()
        below = linear_chain(w, 4)
        item = top(w, below)
        bad = with_signature(item.primary, BAD)
        value = snapshot_of(w, below, item={"act": bad.jws, "sigs": item.acts[1:]})
        stub, single = BatchStub(), BatchStub()
        with builds() as count:
            got = ask(batched(stub), "admit", value)
        self.assertNotEqual(json.loads(got)["reason"], "ok")
        self.assertEqual((stub.rounds, count.n), (1, 1))
        self.assertEqual(got, ask(one_at_a_time(single), "admit", value))


class Refusing(verifier.Verifier):
    """`inner`, except that the texts in `refused` are answered `bad_signature` whatever the keys."""

    def __init__(self, inner, refused):
        self.inner, self.refused = inner, set(refused)

    def verify(self, jws, keys, method):
        return "bad_signature" if jws in self.refused else self.inner.verify(jws, keys, method)


class Builds(unittest.TestCase):
    """How many times the act tree of the store is built (`fold.Epoch.build` that built): once when every answer the
    store rests on is `ok`, twice when a text the store holds is not, because the state then rests on a guess."""

    def table(self, stub):
        return {**batched(stub), "agree-points": commands.per_batch(stub, commands.agree_points(BUILD))}

    def inputs(self):
        """`(the acts of the store, {command: input})` over one store of four steps and an item on it."""
        w = World()
        below = linear_chain(w, 4)
        item = top(w, below)
        store = snapshot_of(w, below)
        return below, {"admit": {**store, "item": {"act": item.primary.jws, "sigs": item.acts[1:]}},
                       "pool": {**store, "agree": NOBODY}, "compact": store, "agree-points": store}

    def test_every_answer_ok_is_one_build_and_a_stored_text_that_is_not_ok_is_two(self):
        below, inputs = self.inputs()
        stored = below[1].primary.jws
        for command, value in inputs.items():
            for refused, want in (((), 1), ((stored,), 2)):
                with self.subTest(command=command, refused=bool(refused)):
                    stub = BatchStub(Refusing(FakeVitni(), refused))
                    with builds() as count:
                        got = ask(self.table(stub), command, value)
                    self.assertEqual((count.n, stub.rounds), (want, 1))
                    single = BatchStub(Refusing(FakeVitni(), refused))
                    self.assertEqual(got, ask({**one_at_a_time(single), "agree-points": commands.per_call(
                        single, commands.agree_points(BUILD))}, command, value))


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


class Recording(verifier.Memoized):
    """A call's memo that lists every question put to it, answered from memory or not, with the text it is about."""

    def __init__(self, inner):
        super().__init__(inner)
        self.asked = []

    def verify(self, jws, keys, method):
        self.asked.append(jws)
        return super().verify(jws, keys, method)


class FinishAsksTheItem(unittest.TestCase):
    """The two-stage shape: `opened` asks about the texts the store holds, `finish` only about the texts of the item."""

    def test_admit_asks_the_item_texts_in_finish_and_only_there(self):
        for n in (1, 3):
            value = linear_inputs(n)["admit"]
            item = {value["item"]["act"], *value["item"]["sigs"]}
            with self.subTest(n=n):
                memo = Recording(BatchStub())
                finish = commands.admission_handlers(BUILD)["admit"](value, memo)
                before = list(memo.asked)
                self.assertEqual(json.loads(json.dumps(finish()))["reason"], "ok")
                after = memo.asked[len(before):]
                self.assertTrue(before and after)
                self.assertEqual(item & set(before), set())   # the store's questions are about the store's texts
                self.assertTrue(set(after) <= item, "finish asked about a text that is not the item's")
                self.assertIn(value["item"]["act"], after)

    def test_admit_asks_the_receipts_of_a_document_item_in_finish_and_only_there(self):
        value = document_input()
        memo = Recording(BatchStub())
        finish = commands.admission_handlers(BUILD)["admit"](value, memo)
        before = list(memo.asked)
        self.assertEqual(finish()["reason"], "ok")
        after = memo.asked[len(before):]
        self.assertTrue(before and after)
        self.assertEqual(set(value["item"]["sigs"]) & set(before), set())
        self.assertTrue(set(after) <= set(value["item"]["sigs"]), "finish asked about a text that is not the item's")

    def test_the_commands_that_judge_no_item_ask_nothing_in_finish(self):
        for command, value in linear_inputs(2).items():
            if command == "admit":
                continue
            with self.subTest(command=command):
                memo = Recording(BatchStub())
                finish = commands.admission_handlers(BUILD)[command](value, memo)
                before = list(memo.asked)
                out = finish()
                self.assertTrue(before)
                self.assertEqual(memo.asked, before)
                self.assertEqual(finish(), out)

    def test_agree_points_asks_nothing_in_finish(self):
        memo = Recording(BatchStub())
        finish = commands.agree_points(BUILD)(linear_inputs(2)["compact"], memo)
        before = list(memo.asked)
        finish()
        self.assertTrue(before)
        self.assertEqual(memo.asked, before)


def document_input():
    """An `admit` input whose item is a change document over a store that already holds one change, with acts in it."""
    w = World()
    first = w.change_doc(w.id, name="ONE")
    second = w.change_doc(genesis.doc_hash(first), name="TWO", prev=first)
    docs = [entry(w.doc, w.sigs(w.doc, ALL)), entry(first, w.sigs(first, ALL))]
    held = acts_of(linear_chain(later_world(w, first), 2))   # acts in the epoch of the first change: its tree has questions
    return {"acts": held, "docs": docs, "org": w.id, "item": {"doc": second, "sigs": w.sigs(second, ALL)}}


class Forcing(verifier.Verifier):
    """`inner`, except that the one question `target` is answered `bad_signature`."""

    def __init__(self, inner, target):
        self.inner, self.target = inner, target

    def verify(self, jws, keys, method):
        if verifier.question(jws, keys, method) == self.target:
            return "bad_signature"
        return self.inner.verify(jws, keys, method)


class EveryQuestion(unittest.TestCase):
    """Whatever one answer is, at whichever question, `per_batch` gives the bytes `per_call` gives.

    The honest run lists the questions a call asks. Each is then forced in turn, once to a verdict that is not `ok`
    and once to an answer that cannot be had, and the two strategies are compared on each: a handler whose `finish`
    read a state that a guess had shaped, or left something behind for a second run, differs at some index."""

    def both(self, command, value, **how):
        batch, single = BatchStub(**how), BatchStub(**how)
        got = ask(batched(batch), command, value)
        self.assertEqual(got, ask(one_at_a_time(single), command, value))
        return got

    def questions(self, command, value):
        stub = BatchStub()
        ask(one_at_a_time(stub), command, value)
        return stub.singles

    def every_index(self, command, value):
        asked = self.questions(command, value)
        self.assertGreater(len(asked), 0)
        reasons = set()
        for index, target in enumerate(asked):
            with self.subTest(command=command, index=index, of=len(asked), how="verdict"):
                reasons.add(json.loads(self.both(command, value, inner=Forcing(FakeVitni(), target)))["reason"])
            with self.subTest(command=command, index=index, of=len(asked), how="unavailable"):
                self.both(command, value, fails=lambda got, target=target: got == target)
        return reasons

    def test_every_question_of_a_small_store_for_the_three_commands(self):
        for n in (1, 2, 3):
            for command, value in linear_inputs(n).items():
                self.every_index(command, value)

    def test_every_question_of_a_change_document_over_a_stored_change(self):
        value = document_input()
        self.assertEqual(json.loads(ask(batched(BatchStub()), "admit", value))["reason"], "ok")   # honest: it is admitted
        self.assertNotEqual(self.every_index("admit", value), set())

    def test_every_question_of_a_generated_store(self):
        """One input of each command over one generated store (an item that is stored, and one that carries texts)."""
        cases = generated_inputs(0)
        picked = [cases[0], cases[1]] + [cases[5], cases[-1]]
        self.assertEqual([command for command, _ in picked], ["compact", "pool", "admit", "admit"])
        reasons = set()
        for command, value in picked:
            reasons |= self.every_index(command, value)
        self.assertGreater(len(reasons), 1)   # the forced answers moved the output to another reason


if __name__ == "__main__":
    unittest.main()
