"""Serve mode: one process that answers many requests, each with the bytes the one-shot command gives.

A request is a header line `<command> <length>` and then exactly `<length>` bytes: the stdin of a one-shot call. The
header is lowercase letters and `-`, one space and a canonical decimal length (`0`, or no leading zero), at most
`HEADER_MAX` bytes before the line feed. The answer is the one-shot stdout line, flushed before the next header is
read. Nothing else is ever written to stdout.

This module only frames. The answer to a request is `core.run` over the table the one-shot call uses and a stream
that ends after the body, so the order of the refusals (the command first, then the size, then the JSON) and every
byte of every answer are the one-shot ones by construction, and nothing here decides a code. The only state that
outlives a request is the memo of verdicts (`verifier.Verdicts`), which saves questions and never decides an answer.

A stream that cannot be framed ends the process: a header that is no frame (`Unframed`) and a stream that ends inside
a body (`Truncated`) raise, so the exit is nonzero, the traceback is on stderr and stdout holds only the answers
already given. A stream that ends where a header would begin ends the process with exit 0. A length over the input
limit is answered by `core.run` (`unparseable_input`) and its body is then discarded exactly, in chunks, so it is
never held in memory; the body of an unknown command is discarded the same way.

The memo is valid only while the verifier is the same one: before each request the verifier's `identity()` is read, and
a changed identity, or a check that fails, empties the memo. A failed check does not answer anything itself: the
request runs with no memo, and the spawn's own check says `verifier_unavailable` exactly where a one-shot call would.
"""
import re

from . import core, verifier

MEMO_CAP = 262144   # verdicts held: measured about 200 to 250 bytes each, so about 50 to 60 MiB when full
HEADER_MAX = 64
CHUNK = 65536
HEADER = re.compile(rb"([a-z-]+) (0|[1-9][0-9]*)\n")
_UNSET = object()


class Unframed(Exception):
    """The header line is no frame, so the stream cannot be told apart from its bodies."""


class Truncated(Exception):
    """The stream ended before the body its header announced."""


class Bounded:
    """The body of one request as the stdin of `core.run`: it ends after `length` bytes, whatever follows."""

    def __init__(self, stream, length):
        self.stream, self.left = stream, length

    def read(self, size=-1):
        """Up to `size` bytes of the body (all of it when `size` is negative or `None`): as many as asked unless the
        body ends first, as a buffered stream gives them."""
        want = self.left if size is None or size < 0 else min(size, self.left)
        out = b""
        while len(out) < want:
            got = self.stream.read(want - len(out))
            if not got:
                raise Truncated("the stream ended %d bytes before the end of a body" % self.left)
            out += got
            self.left -= len(got)
        return out

    def drain(self):
        """Discard what `core.run` did not read, `CHUNK` bytes at a time."""
        while self.left:
            got = self.stream.read(min(CHUNK, self.left))
            if not got:
                raise Truncated("the stream ended %d bytes before the end of a body" % self.left)
            self.left -= len(got)


def _identity(vitni):
    """What the verifier is now, or `_UNSET` when its check fails: no identity, so nothing remembered is trusted."""
    try:
        return vitni.identity()
    except verifier.VerifierUnavailable:
        return _UNSET


def serve(table, vitni, verdicts, stdin, stdout):
    """Answer the requests of `stdin` on `stdout` over the command table `table`, until the stream ends between
    requests (return 0). `vitni` is the verifier the table asks and `verdicts` the memo it was built with."""
    last = _UNSET
    while True:
        header = stdin.readline(HEADER_MAX + 1)
        if header == b"":
            return 0
        found = HEADER.fullmatch(header)
        if found is None:
            raise Unframed("not a request header: %r" % header[:HEADER_MAX])
        ident = _identity(vitni)
        if ident is _UNSET or ident != last:   # a failed check never matches, even the failure before it
            verdicts.clear()
        last = ident
        body = Bounded(stdin, int(found[2]))
        try:
            core.run(table, [found[1].decode("ascii")], body, stdout)
            body.drain()
        finally:
            stdout.flush()


def run(build_commands, vitni, stdin, stdout, cap=MEMO_CAP):
    """`serve` over the table `build_commands(vitni, verdicts=...)` makes with a new memo of at most `cap` verdicts: the
    one place a serve process gets its table and its memo."""
    verdicts = verifier.Verdicts(cap)
    return serve(build_commands(vitni, verdicts=verdicts), vitni, verdicts, stdin, stdout)
