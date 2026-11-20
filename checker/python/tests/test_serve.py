"""Serve mode: one process answers many requests, each with the bytes the one-shot command gives for the same input.

A request is a header line `<command> <length>` and `<length>` bytes. `serve` only frames: the answer to a request is
`core.run` over a table and the body, as in a one-shot call, so these tests hold the frame (what ends the stream and
what does not), the bytes (every answer equals the one-shot answer, whatever the memo holds or has dropped) and the
cost (a repeat asks nothing, a change asks only what changed).
"""
import io
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from handsal_check import commands, compact, conformance, core, ijson, server, serve, verifier

from .act_builder import FakeVitni
from .fold_world import World
from .linear_world import acts_of, chain as linear_chain
from .store_world import ALL, BatchStub, entry, random_store

SRC = Path(__file__).resolve().parents[1] / "src"
STUB = str(Path(__file__).resolve().parent / "data" / "stub_vitni.py")
UNSUPPORTED = b'{"error":"unsupported_command"}\n'
UNPARSEABLE = b'{"error":"unparseable_input"}\n'
MALFORMED = b'{"error":"malformed_input"}\n'


def frame(command, body):
    return b"%s %d\n" % (command.encode(), len(body)) + body


class Identified(BatchStub):
    """A batch verifier with an identity the test moves: `ident` is what `identity()` gives, or an exception to raise.
    `down` makes the identity check fail too, as a verifier that is no longer sound would."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.ident = 1

    def identity(self):
        if self.down:
            raise verifier.VerifierUnavailable("down")
        if isinstance(self.ident, Exception):
            raise self.ident
        return self.ident


def serving(stream, vitni=None, cap=serve.MEMO_CAP, stdin=None):
    """`(result, bytes written)` of one serve run over `stream`; the result is the exit code or the exception."""
    out = io.BytesIO()
    try:
        got = serve.run(conformance.build_commands, FakeVitni() if vitni is None else vitni,
                        io.BytesIO(stream) if stdin is None else stdin, out, cap)
    except (serve.Unframed, serve.Truncated) as err:
        got = err
    return got, out.getvalue()


def one_shot(command, body, vitni=None):
    """What a fresh process answers for `command` with `body` on stdin."""
    out = io.BytesIO()
    core.run(conformance.build_commands(FakeVitni() if vitni is None else vitni), [command], io.BytesIO(body), out)
    return out.getvalue()


def snapshot(w, acts=()):
    return {"acts": list(acts), "docs": [entry(w.doc, w.sigs(w.doc, ALL))], "org": w.id}


def body_of(value):
    return json.dumps(value).encode()


class Framing(unittest.TestCase):
    def test_an_empty_stream_and_a_stream_that_ends_between_requests_exit_zero(self):
        self.assertEqual(serving(b""), (0, b""))
        self.assertEqual(serving(frame("nope", b"{}")), (0, UNSUPPORTED))

    def test_a_header_that_is_not_a_frame_ends_the_process_and_writes_nothing_for_it(self):
        headers = {"uppercase": b"ADMIT 2\n{}", "a digit in the token": b"admit1 2\n{}", "no space": b"admit2\n{}",
                   "two spaces": b"admit  2\n{}", "a leading space": b" admit 2\n{}", "a trailing space": b"admit 2 \n{}",
                   "a carriage return": b"admit 2\r\n{}", "a leading zero": b"admit 02\n{}",
                   "a sign": b"admit +2\n{}", "a negative length": b"admit -2\n{}", "no length": b"admit \n{}",
                   "not a number": b"admit two\n{}", "no token": b" 2\n{}", "no line feed": b"admit 2",
                   "an empty line": b"\n", "binary": b"\xff\xfe 2\n{}"}
        for name, stream in headers.items():
            with self.subTest(name):
                got, out = serving(stream)
                self.assertIsInstance(got, serve.Unframed)
                self.assertEqual(out, b"")

    def test_a_malformed_header_after_good_requests_leaves_their_answers_written(self):
        got, out = serving(frame("nope", b"{}") + b"admit 02\n{}" + frame("nope", b"{}"))
        self.assertIsInstance(got, serve.Unframed)
        self.assertEqual(out, UNSUPPORTED)   # the first was answered, the third was never read

    def test_a_header_is_at_most_64_bytes_before_the_line_feed(self):
        fits = b"a" * 62 + b" 2"
        self.assertEqual(len(fits), 64)
        self.assertEqual(serving(fits + b"\n{}"), (0, UNSUPPORTED))
        got, out = serving(fits + b"0\n{}")   # 65 bytes before the line feed
        self.assertIsInstance(got, serve.Unframed)
        self.assertEqual(out, b"")
        got, out = serving(b"a" * 5000)   # a stream that is no frames is refused without reading it all
        self.assertIsInstance(got, serve.Unframed)

    def test_the_length_is_canonical_decimal_and_zero_is_a_length(self):
        self.assertEqual(serving(b"nope 0\n"), (0, UNSUPPORTED))
        self.assertEqual(serving(frame("compact", b"")), (0, UNPARSEABLE))   # an empty body is not JSON

    def test_a_body_that_ends_early_ends_the_process_and_answers_nothing(self):
        got, out = serving(b"compact 3\n{}")
        self.assertIsInstance(got, serve.Truncated)
        self.assertEqual(out, b"")

    def test_a_stream_that_ends_inside_a_discarded_body_ends_the_process(self):
        got, out = serving(b"nope 10\nabc")
        self.assertIsInstance(got, serve.Truncated)
        self.assertEqual(out, UNSUPPORTED)   # the answer was known before the body was discarded, and is not lost

    def test_an_unknown_command_discards_its_body_answers_unsupported_and_goes_on(self):
        w = World()
        value = body_of(snapshot(w))
        stream = frame("nope", b'{"acts": []}') + frame("serve", b"{}") + frame("compact", value)
        got, out = serving(stream)
        self.assertEqual(got, 0)
        self.assertEqual(out, UNSUPPORTED * 2 + one_shot("compact", value))

    def test_serve_inside_a_stream_is_an_unknown_command_with_no_special_case(self):
        self.assertEqual(serving(frame("serve", b"")), (0, UNSUPPORTED))
        self.assertNotIn("serve", conformance.build_commands(FakeVitni()))
        self.assertNotIn("serve", server.build_commands(FakeVitni()))

    def test_a_body_that_fails_the_framing_of_a_call_gets_the_one_shot_error_line_and_the_stream_goes_on(self):
        deep = b"[" * (ijson.MAX_NESTING + 1) + b"]" * (ijson.MAX_NESTING + 1)
        bodies = {"not JSON": b"{", "a duplicate member": b'{"a":1,"a":2}', "too deep": deep, "not an object": b"[]",
                  "a lone surrogate": b'"\\ud800"'}
        for name, body in bodies.items():
            with self.subTest(name):
                got, out = serving(frame("compact", body) + frame("nope", b""))
                self.assertEqual(got, 0)
                self.assertEqual(out, one_shot("compact", body) + UNSUPPORTED)
                self.assertTrue(out.startswith(UNPARSEABLE if name != "not an object" else MALFORMED), name)


class Blanks:
    """`total` blanks, made as they are read."""

    def __init__(self, total):
        self.left = total

    def read(self, size):
        got = min(size, self.left)
        self.left -= got
        return b" " * got


class Feed:
    """The stream of a request whose body is gigabytes long: a header line, the body, made as it is read, and then
    `rest`. It notes the size of each read of the body, and fails the test on a read that asks for no limit."""

    def __init__(self, header, length, rest):
        self.header, self.body, self.rest = header, Blanks(length), rest
        self.sizes, self.taken = [], 0

    def readline(self, limit=-1):
        if self.header:
            got, self.header = self.header, b""
            return got
        assert not self.body.left, "a header is read only after the whole body"
        cut = self.rest.find(b"\n") + 1 or len(self.rest)
        got, self.rest = self.rest[:cut], self.rest[cut:]
        return got

    def read(self, size=-1):
        assert size is not None and size >= 0, "a read with no limit on a body that is gigabytes long"
        if self.body.left:
            self.sizes.append(size)
            got = self.body.read(size)
            self.taken += len(got)
            return got
        got, self.rest = self.rest[:size], self.rest[size:]
        return got


class Oversize(unittest.TestCase):
    def test_a_length_over_the_limit_answers_unparseable_and_discards_exactly_that_many_bytes_in_chunks(self):
        length = 1 << 30
        feed = Feed(b"compact %d\n" % length, length, frame("nope", b"{}"))
        out = io.BytesIO()
        self.assertEqual(serve.run(conformance.build_commands, FakeVitni(), feed, out), 0)
        self.assertEqual(out.getvalue(), UNPARSEABLE + UNSUPPORTED)   # and the next header was read right after
        self.assertEqual(feed.sizes[0], ijson.MAX_INPUT + 1)   # core.run reads one byte past the limit
        self.assertLessEqual(max(feed.sizes[1:]), 65536)       # the rest is discarded in chunks
        self.assertEqual(feed.taken, length)

    def test_an_unknown_command_with_an_over_size_body_is_unsupported_and_the_body_is_discarded_in_chunks(self):
        length = ijson.MAX_INPUT + 5
        feed = Feed(b"nope %d\n" % length, length, frame("nope", b""))
        out = io.BytesIO()
        self.assertEqual(serve.run(conformance.build_commands, FakeVitni(), feed, out), 0)
        self.assertEqual(out.getvalue(), UNSUPPORTED * 2)
        self.assertLessEqual(max(feed.sizes), 65536)
        self.assertEqual(feed.taken, length)

    def test_a_body_of_exactly_the_limit_is_read_and_one_byte_more_is_not(self):
        fits = b" " * (ijson.MAX_INPUT - 2) + b"{}"
        for body, want in ((fits, MALFORMED), (b" " + fits, UNPARSEABLE)):
            got, out = serving(frame("compact", body) + frame("nope", b""))
            self.assertEqual((got, out), (0, want + UNSUPPORTED))
            self.assertEqual(out[:len(want)], one_shot("compact", body))


def request_pool():
    """`(command, body)` of valid and refused requests over a few organizations, for the property tests."""
    pool = []
    for seed in range(4):
        stored = random_store(seed)
        snap = {"acts": stored.acts, "docs": stored.docs, "org": stored.org}
        agree = {"x": stored.docs[0]["doc"]["devices"][0]["agree"]["x"], "y": stored.docs[0]["doc"]["devices"][0]["agree"]["y"]}
        for command, value in (("compact", snap), ("agree-points", snap), ("pool", {**snap, "agree": agree}),
                               ("admit", {**snap, "item": {"act": stored.acts[0], "sigs": []}}),
                               ("admit", {**snap, "item": {"doc": stored.docs[0]["doc"], "sigs": stored.docs[0]["sigs"]}}),
                               ("compact", {**snap, "docs": []}), ("agree-points", {**snap, "acts": "x"})):
            pool.append((command, body_of(value)))
    pool += [("compact", b"{"), ("pool", b"{}"), ("nope", b"{}"), ("serve", b""), ("kid", b'{"x":"AA","y":"AA"}'),
             ("subset", b'{"a":1}'), ("compact", b"[" * 70)]
    return pool


class SameBytes(unittest.TestCase):
    def sequence(self, seed, length=14):
        rng = random.Random(seed)
        pool = request_pool()
        return [rng.choice(pool) for _ in range(length)]

    def check(self, requests, vitni, cap):
        stream = b"".join(frame(command, body) for command, body in requests)
        got, out = serving(stream, vitni, cap)
        self.assertEqual(got, 0)
        want = b"".join(one_shot(command, body) for command, body in requests)
        self.assertEqual(out, want)
        self.assertEqual(out.count(b"\n"), len(requests))   # one line each

    def test_random_sequences_of_requests_answer_what_a_fresh_process_answers(self):
        for seed in range(6):
            self.check(self.sequence(seed), Identified(), serve.MEMO_CAP)

    def test_a_memo_that_evicts_all_the_time_changes_no_byte(self):
        for seed in range(4):
            self.check(self.sequence(seed + 20), Identified(), 4)

    def test_an_identity_that_changes_or_fails_between_requests_changes_no_byte(self):
        class Moving(Identified):
            def __init__(self):
                super().__init__()
                self.script = iter([1, 1, 2, verifier.VerifierUnavailable("gone"), 2, 2, 3, 3, 3,
                                    verifier.VerifierUnavailable("gone"), verifier.VerifierUnavailable("gone")])

            def identity(self):
                got = next(self.script, 3)
                if isinstance(got, Exception):
                    raise got
                return got

        for seed in range(4):
            self.check(self.sequence(seed + 40), Moving(), 8)

    def test_a_verifier_with_no_identity_never_clears_the_memo_and_changes_no_byte(self):
        for seed in range(3):
            self.check(self.sequence(seed + 60), FakeVitni(), serve.MEMO_CAP)

    def test_a_verifier_that_cannot_answer_gives_the_same_refusals_as_a_fresh_process(self):
        for seed in range(3):
            requests = self.sequence(seed + 80)
            stream = b"".join(frame(command, body) for command, body in requests)
            got, out = serving(stream, Identified(down=True), serve.MEMO_CAP)
            self.assertEqual(got, 0)
            self.assertEqual(out, b"".join(one_shot(command, body, Identified(down=True)) for command, body in requests))
            self.assertIn(b"verifier_unavailable", out)


class Warm(unittest.TestCase):
    """Cost: what a repeat or a small change asks, counted at a verifier with a real batch round."""

    def run_stream(self, requests, stub):
        marks, out = [], io.BytesIO()
        calls = mock.patch.object(compact, "run", wraps=compact.run)

        class Marking(io.BytesIO):
            def write(inner, data):
                marks.append((stub.rounds, len(stub.batched), runs.call_count))
                return super().write(data)

        marking = Marking()
        with calls as runs:
            serve.run(conformance.build_commands, stub, io.BytesIO(b"".join(frame(c, b) for c, b in requests)), marking)
        return marks, marking.getvalue()

    def store(self, steps):
        w = World()
        chain = linear_chain(w, steps + 1)
        return [body_of(snapshot(w, acts_of(chain[:n]))) for n in (steps, steps, steps + 1)]

    def test_a_repeat_runs_no_round_and_the_handler_once_and_a_small_change_asks_only_what_changed(self):
        stub, (first, repeat, grown) = Identified(), self.store(6)
        marks, out = self.run_stream([("compact", first), ("compact", repeat), ("compact", grown)], stub)
        cold, warm, changed = marks   # each: (rounds, questions asked, handler runs) when its answer was written
        self.assertEqual(cold, (1, 3 * 6 + 3, 1))   # cold: one round, every question once
        self.assertEqual((warm[0] - cold[0], warm[1] - cold[1], warm[2] - cold[2]), (0, 0, 1))   # no round, one fold
        asked = changed[1] - warm[1]
        self.assertTrue(0 < asked <= 2 + 2, asked)   # one more step: at most Q + 2 new questions
        self.assertEqual(out, one_shot("compact", first) * 2 + one_shot("compact", grown))

    def test_a_question_that_errored_in_one_request_is_asked_again_in_the_next(self):
        stub, (first, repeat, _) = Identified(), self.store(4)
        stub.fails = lambda asked: True
        marks, out = [], io.BytesIO()
        outs = []

        class Healing(io.BytesIO):
            def write(inner, data):
                outs.append(data)
                stub.fails = lambda asked: False   # the verifier recovers after the first answer
                return super().write(data)

        serve.run(conformance.build_commands, stub, io.BytesIO(frame("compact", first) + frame("compact", repeat)),
                  Healing())
        self.assertEqual(outs[0], b'{"drop":null,"reason":"verifier_unavailable"}\n')
        self.assertEqual(outs[1], one_shot("compact", repeat))
        self.assertEqual(stub.rounds, 2)   # the failed questions were never held as verdicts: the second asks them again

    def test_a_verifier_replaced_between_two_requests_answers_what_a_fresh_process_answers(self):
        stub, (first, repeat, _) = Identified(), self.store(3)
        outs = []

        class Swapping(io.BytesIO):
            def write(inner, data):
                outs.append(data)
                stub.ident = 2   # a different file now, and it no longer vouches for what the first one said
                stub.inner = _Rejecting()
                return super().write(data)

        serve.run(conformance.build_commands, stub, io.BytesIO(frame("compact", first) + frame("compact", repeat)),
                  Swapping())
        self.assertEqual(outs[0], one_shot("compact", first))
        self.assertEqual(outs[1], one_shot("compact", repeat, _Rejecting()))
        self.assertNotEqual(outs[0], outs[1])

    def test_every_failed_identity_check_empties_the_memo_not_only_the_first(self):
        stub, (first, repeat, _) = Identified(), self.store(3)
        script = iter([1, verifier.VerifierUnavailable("gone"), verifier.VerifierUnavailable("gone")])

        def identity():
            got = next(script)
            if isinstance(got, Exception):
                raise got
            return got

        stub.identity = identity   # the checks fail twice in a row while the verifier itself still answers
        marks, out = self.run_stream([("compact", first)] * 3, stub)
        self.assertEqual([mark[0] for mark in marks], [1, 2, 3])   # a round each: a failed check leaves nothing warm
        self.assertEqual(out, one_shot("compact", first) * 3)

    def test_a_verifier_that_stops_being_sound_refuses_a_call_that_needs_a_verdict_as_one_shot_does(self):
        stub, (first, repeat, _) = Identified(), self.store(3)
        outs = []

        class Breaking(io.BytesIO):
            def write(inner, data):
                outs.append(data)
                stub.down = True   # as if the file were made group-writable: the check fails, the memo is cleared
                return super().write(data)

        serve.run(conformance.build_commands, stub, io.BytesIO(frame("compact", first) + frame("compact", repeat)),
                  Breaking())
        self.assertEqual(outs[0], one_shot("compact", first))
        self.assertEqual(outs[1], b'{"drop":null,"reason":"verifier_unavailable"}\n')
        self.assertEqual(outs[1], one_shot("compact", repeat, Identified(down=True)))


class _Rejecting(verifier.Verifier):
    """A verifier that finds every signature bad."""

    def verify(self, jws, keys, method):
        return "bad_signature"


class Entry(unittest.TestCase):
    """The build's entry points: `serve` as the whole argument list, from a process and from `main`."""

    def run_main(self, args, stdin):
        code = ("import sys; sys.path.insert(0, %r); import handsal_check.conformance as c; sys.argv = ['x'] + %r; "
                "sys.exit(c.main())" % (str(SRC), args))
        return subprocess.run([sys.executable, "-I", "-c", code], input=stdin, capture_output=True, timeout=60)

    def test_the_conformance_build_serves_when_serve_is_the_whole_argument_list(self):
        got = self.run_main(["--vitni", sys.executable, "--vitni", STUB, "serve"], frame("nope", b"") * 2)
        self.assertEqual((got.returncode, got.stdout), (0, UNSUPPORTED * 2))

    def test_a_process_that_cannot_frame_its_stream_exits_nonzero_with_nothing_on_stdout(self):
        for stream in (b"admit 02\n{}", b"compact 3\n{}", b"garbage"):
            got = self.run_main(["--vitni", sys.executable, "--vitni", STUB, "serve"], stream)
            self.assertNotEqual(got.returncode, 0, stream)
            self.assertEqual(got.stdout, b"", stream)
            self.assertNotEqual(got.stderr, b"")

    def test_serve_with_anything_else_in_the_argument_list_is_not_serve_mode(self):
        got = self.run_main(["--vitni", sys.executable, "--vitni", STUB, "serve", "extra"], b"{}")
        self.assertEqual(got.stdout, UNSUPPORTED)   # one-shot: `serve` is no command

    def test_the_server_build_serves_and_answers_what_its_one_shot_build_answers(self):
        w = World()
        value = body_of(snapshot(w))
        requests = [("compact", value), ("pool", b"{}"), ("nope", b"{}"), ("agree-points", value), ("admit", b"x")]
        out = io.BytesIO()
        stream = io.BytesIO(b"".join(frame(c, b) for c, b in requests))
        self.assertEqual(server.main(["serve"], stream, out), 0)
        want = b""
        for command, body in requests:
            one = io.BytesIO()
            server.main([command], io.BytesIO(body), one)
            want += one.getvalue()
        self.assertEqual(out.getvalue(), want)

    def test_both_builds_make_the_table_with_the_memo_the_process_owns(self):
        seen = []
        real = commands.admission

        def spy(*args, **kw):
            seen.append(kw.get("verdicts"))
            return real(*args, **kw)

        with mock.patch.object(commands, "admission", spy):
            serve.run(server.build_commands, FakeVitni(), io.BytesIO(b""), io.BytesIO(), 7)
            serve.run(conformance.build_commands, FakeVitni(), io.BytesIO(b""), io.BytesIO(), 9)
        self.assertEqual([type(v) for v in seen], [verifier.Verdicts, verifier.Verdicts])
        self.assertEqual([v.cap for v in seen], [7, 9])
        self.assertEqual(serve.MEMO_CAP, 262144)


if __name__ == "__main__":
    unittest.main()
