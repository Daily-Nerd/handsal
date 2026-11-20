"""`core.run`: the one place a command's input is framed (CF-03). The command is judged first, then the size, then the
JSON; and the size is judged on at most one byte more than the limit, so an input of any length is refused without
being held in memory.
"""
import io
import unittest

from handsal_check import core, ijson


class Unbounded(io.RawIOBase):
    """A stream that never ends. A read that asks for no limit would never return, so it fails the test instead."""

    def __init__(self):
        self.asked = []

    def readable(self):
        return True

    def read(self, size=-1):
        self.asked.append(size)
        if size is None or size < 0:
            raise AssertionError("read() with no limit on a stream that does not end")
        return b" " * size


UNSUPPORTED = b'{"error":"unsupported_command"}\n'


def table():
    calls = []

    def handler(value):
        calls.append(value)
        return {"seen": value}

    return {"echo": core.Command(handler, False), "bytes": core.Command(lambda raw: {"n": len(raw)}, True)}, calls


def run(commands, argv, stdin):
    out = io.BytesIO()
    core.run(commands, argv, stdin if not isinstance(stdin, bytes) else io.BytesIO(stdin), out)
    return out.getvalue()


class BoundedRead(unittest.TestCase):
    def test_an_input_of_exactly_the_limit_is_read_and_one_byte_more_is_unparseable(self):
        commands, calls = table()
        fits = b" " * (ijson.MAX_INPUT - 2) + b"{}"
        self.assertEqual(run(commands, ["echo"], fits), b'{"seen":{}}\n')
        self.assertEqual(run(commands, ["echo"], b" " + fits), b'{"error":"unparseable_input"}\n')
        self.assertEqual(calls, [{}])   # the handler never saw the larger one

    def test_a_raw_command_is_judged_by_the_same_size(self):
        commands, _ = table()
        self.assertEqual(run(commands, ["bytes"], b"x" * ijson.MAX_INPUT), b'{"n":%d}\n' % ijson.MAX_INPUT)
        self.assertEqual(run(commands, ["bytes"], b"x" * (ijson.MAX_INPUT + 1)), b'{"error":"unparseable_input"}\n')

    def test_an_unknown_command_with_an_over_size_body_is_unsupported_command(self):
        commands, calls = table()
        self.assertEqual(run(commands, ["nope"], b" " * (ijson.MAX_INPUT + 1)), b'{"error":"unsupported_command"}\n')
        self.assertEqual(run(commands, [], b" " * (ijson.MAX_INPUT + 1)), b'{"error":"unsupported_command"}\n')
        self.assertEqual(calls, [])

    def test_a_stream_that_does_not_end_is_refused_after_one_byte_more_than_the_limit(self):
        commands, calls = table()
        stream = Unbounded()
        self.assertEqual(run(commands, ["echo"], stream), b'{"error":"unparseable_input"}\n')
        self.assertEqual(stream.asked, [ijson.MAX_INPUT + 1])
        self.assertEqual(calls, [])

    def test_an_unknown_command_reads_nothing(self):
        stream = Unbounded()
        self.assertEqual(run(table()[0], ["nope"], stream), b'{"error":"unsupported_command"}\n')
        self.assertEqual(stream.asked, [])


class Serving(unittest.TestCase):
    """`serve` is the whole argument list of a process that serves, and only where the build gives a `serving`
    function. It is no command: inside a stream, or in a build that serves nothing, it is unknown."""

    def test_the_whole_argument_list_serve_runs_the_serving_function_on_the_streams(self):
        seen = []
        stdin, stdout = io.BytesIO(b"in"), io.BytesIO()

        def serving(given_in, given_out):
            seen.append((given_in, given_out))
            return 7

        self.assertEqual(core.run(table()[0], ["serve"], stdin, stdout, serving), 7)
        self.assertEqual(seen, [(stdin, stdout)])
        self.assertEqual((stdin.read(), stdout.getvalue()), (b"in", b""))   # the framing is the serving function's

    def test_anything_else_is_a_one_shot_call_and_serve_is_no_command(self):
        def serving(*streams):
            raise AssertionError("not asked to serve")

        commands, calls = table()
        for argv in (["serve", "x"], ["serve", "serve"], ["echo"], [], ["x", "serve"]):
            out = io.BytesIO()
            core.run(commands, argv, io.BytesIO(b"{}"), out, serving)
            self.assertEqual(out.getvalue(), b'{"seen":{}}\n' if argv == ["echo"] else UNSUPPORTED, argv)
        out = io.BytesIO()
        core.run(commands, ["serve"], io.BytesIO(b"{}"), out)   # a build that serves nothing
        self.assertEqual(out.getvalue(), UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()
