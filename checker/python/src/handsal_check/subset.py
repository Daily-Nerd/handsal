"""Canonical subset recognizer (ACT-04), grammar only.

A canonical value is the UTF-8 bytes of one JSON value of any root kind built
only from objects, arrays, strings and `null`; no whitespace outside strings;
object keys unique, ASCII and in strictly ascending byte order; strings only of
bytes 0x20 to 0x7E except `"` and `\\`, so there is no escape; nesting at most
MAX_DEPTH; at most MAX_PAYLOAD bytes; nothing after the root.

The root-must-be-an-object rule belongs to the callers that check payloads,
headers and genesis documents. This module is the grammar and nothing else.
The recognizer works on bytes, so invalid UTF-8 and a byte order mark fail as
bytes outside the string alphabet, with no decoding step to disagree about.
"""
from . import encoding

MAX_PAYLOAD = 16384
MAX_DEPTH = 8

OK = "ok"
NOT_CANONICAL = "payload_not_canonical_subset"
TOO_LARGE = "payload_too_large"


class SubsetError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _bad():
    return SubsetError(NOT_CANONICAL)


class _Parser:
    def __init__(self, raw):
        self.raw = raw
        self.i = 0

    def peek(self):
        return self.raw[self.i:self.i + 1]

    def take(self, token):
        if self.peek() != token:
            raise _bad()
        self.i += 1

    def string(self):
        self.take(b'"')
        start = self.i
        while True:
            byte = self.raw[self.i:self.i + 1]
            if not byte:
                raise _bad()
            if byte == b'"':
                break
            if not encoding.is_plain_char(chr(byte[0])):
                raise _bad()
            self.i += 1
        text = self.raw[start:self.i].decode("ascii")
        self.i += 1
        return text

    def value(self, depth):
        head = self.peek()
        if head == b'"':
            return self.string()
        if head == b"n":
            if self.raw[self.i:self.i + 4] != b"null":
                raise _bad()
            self.i += 4
            return None
        if head == b"{":
            return self.obj(depth + 1)
        if head == b"[":
            return self.array(depth + 1)
        raise _bad()

    def obj(self, depth):
        if depth > MAX_DEPTH:
            raise _bad()
        self.take(b"{")
        out = {}
        if self.peek() == b"}":
            self.i += 1
            return out
        previous = None
        while True:
            key = self.string()
            if previous is not None and not previous < key:   # unsorted or duplicate
                raise _bad()
            previous = key
            self.take(b":")
            out[key] = self.value(depth)
            if self.peek() == b",":
                self.i += 1
                continue
            self.take(b"}")
            return out

    def array(self, depth):
        if depth > MAX_DEPTH:
            raise _bad()
        self.take(b"[")
        out = []
        if self.peek() == b"]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth))
            if self.peek() == b",":
                self.i += 1
                continue
            self.take(b"]")
            return out


def parse(raw):
    """The value of the canonical bytes `raw`, or raise SubsetError(reason)."""
    if len(raw) > MAX_PAYLOAD:
        raise SubsetError(TOO_LARGE)
    parser = _Parser(raw)
    value = parser.value(0)
    if parser.i != len(raw):
        raise _bad()
    return value


def recognize(raw):
    """`(True, "ok")` or `(False, reason)` for the bytes `raw`."""
    try:
        parse(raw)
    except SubsetError as err:
        return False, err.reason
    return True, OK
