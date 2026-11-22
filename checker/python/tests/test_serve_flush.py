"""Serve mode answers an over-limit request as soon as the limit is passed, not when its body has been read to the end.

A client that sends its whole body before it reads anything can stall once the pipes are full. `core.run` refuses a
body after reading one byte more than the input limit, so the refusal is known at that moment and has to be on stdout
before the rest of the body is read, or both sides wait for each other.
"""
import unittest

from handsal_check import conformance, ijson, serve

from .act_builder import FakeVitni


class Out:
    """A stdout that keeps what was written apart from what was flushed: a reader of the pipe sees only the latter."""

    def __init__(self):
        self.pending, self.flushed = b"", b""

    def write(self, data):
        self.pending += data
        return len(data)

    def flush(self):
        self.flushed += self.pending
        self.pending = b""


class Stalls:
    """A request header, `ijson.MAX_INPUT + 1` body bytes, and then nothing more until the answer is read. The read
    that would block raises instead, after noting what a reader of stdout could see at that moment."""

    def __init__(self, out, command, announced):
        self.out, self.header, self.before_stall = out, b"%s %d\n" % (command, announced), ijson.MAX_INPUT + 1
        self.seen_at_stall = None

    def readline(self, limit=-1):
        got, self.header = self.header, b""
        return got

    def read(self, size=-1):
        if self.before_stall:
            got = min(size, self.before_stall)
            self.before_stall -= got
            return b" " * got
        if self.seen_at_stall is None:
            self.seen_at_stall = self.out.flushed
        raise BlockingIOError("the client sends the rest only after it has read the answer")


class FlushBeforeDrain(unittest.TestCase):
    def stalled(self, command):
        out = Out()
        feed = Stalls(out, command, ijson.MAX_INPUT + 1000)
        with self.assertRaises(BlockingIOError):
            serve.run(conformance.build_commands, FakeVitni(), feed, out)
        return feed.seen_at_stall

    def test_an_over_limit_answer_is_on_stdout_before_the_rest_of_the_body_is_read(self):
        self.assertEqual(self.stalled(b"compact"), b'{"error":"unparseable_input"}\n')

    def test_an_unknown_command_is_answered_before_its_body_is_read(self):
        self.assertEqual(self.stalled(b"nope"), b'{"error":"unsupported_command"}\n')
