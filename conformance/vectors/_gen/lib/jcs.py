"""Generator-side emitter for the profile's canonical subset (ACT-04, ACT-05).

Written independently of the checker (CF-06): this module is the single owner
of the bytes that vector anchors are made from, so it imports nothing from the
checker and nothing outside the standard library.

The subset: UTF-8 JSON built only from objects, arrays, strings and the
literal `null`. No numbers, no `true`/`false`, no whitespace outside strings,
object keys unique, ASCII and sorted by byte order. A string holds only bytes
0x20 to 0x7E except `"` and `\\`, and there are no backslash escapes at all,
so a string can be written verbatim. Nesting is at most MAX_DEPTH containers
and the whole value at most MAX_PAYLOAD bytes.

Anything the subset cannot express is refused with JcsError instead of being
coerced. A general JSON serializer is never used (ACT-05).
"""

MAX_PAYLOAD = 16384
MAX_DEPTH = 8

NOT_CANONICAL = "payload_not_canonical_subset"
TOO_LARGE = "payload_too_large"


class JcsError(ValueError):
    def __init__(self, message, reason=NOT_CANONICAL):
        super().__init__(message)
        self.reason = reason


def _is_plain_char(ch):
    return " " <= ch <= "~" and ch != '"' and ch != "\\"


def _string(text, what):
    for ch in text:
        if not _is_plain_char(ch):
            raise JcsError("%s holds a character outside the subset: %r" % (what, ch))
    return '"' + text + '"'


def _emit(value, depth, out):
    if value is None:
        out.append("null")
    elif type(value) is str:
        out.append(_string(value, "string"))
    elif type(value) is dict:
        depth += 1
        if depth > MAX_DEPTH:
            raise JcsError("nesting deeper than %d" % MAX_DEPTH)
        for key in value:
            if type(key) is not str:
                raise JcsError("object key is not a string: %r" % (key,))
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("ascii", "replace"))):
            if i:
                out.append(",")
            out.append(_string(key, "key"))
            out.append(":")
            _emit(value[key], depth, out)
        out.append("}")
    elif type(value) is list:
        depth += 1
        if depth > MAX_DEPTH:
            raise JcsError("nesting deeper than %d" % MAX_DEPTH)
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _emit(item, depth, out)
        out.append("]")
    else:
        # bool, int, float, bytes, tuple, set and everything else
        raise JcsError("type %s is not in the subset" % type(value).__name__)


def emit(value):
    """Return the canonical bytes of `value`, or raise JcsError."""
    out = []
    _emit(value, 0, out)
    raw = "".join(out).encode("ascii")
    if len(raw) > MAX_PAYLOAD:
        raise JcsError("%d bytes exceeds MAX_PAYLOAD" % len(raw), TOO_LARGE)
    return raw


class _Reject(Exception):
    pass


class _Parser:
    def __init__(self, text):
        self.s = text
        self.i = 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def expect(self, ch):
        if self.peek() != ch:
            raise _Reject()
        self.i += 1

    def string(self):
        self.expect('"')
        start = self.i
        while True:
            ch = self.peek()
            if ch == "":
                raise _Reject()
            if ch == '"':
                break
            if not _is_plain_char(ch):
                raise _Reject()
            self.i += 1
        text = self.s[start:self.i]
        self.i += 1
        return text

    def value(self, depth):
        ch = self.peek()
        if ch == '"':
            return self.string()
        if ch == "n" and self.s.startswith("null", self.i):
            self.i += 4
            return None
        if ch == "{":
            if depth + 1 > MAX_DEPTH:
                raise _Reject()
            self.i += 1
            if self.peek() == "}":
                self.i += 1
                return {}
            previous = None
            while True:
                key = self.string()
                # strictly ascending: out of order and duplicate are both refused
                if previous is not None and not previous < key:
                    raise _Reject()
                previous = key
                self.expect(":")
                self.value(depth + 1)
                if self.peek() == ",":
                    self.i += 1
                    continue
                self.expect("}")
                return {}
        if ch == "[":
            if depth + 1 > MAX_DEPTH:
                raise _Reject()
            self.i += 1
            if self.peek() == "]":
                self.i += 1
                return []
            while True:
                self.value(depth + 1)
                if self.peek() == ",":
                    self.i += 1
                    continue
                self.expect("]")
                return []
        raise _Reject()


def recognize(raw):
    """Return (True, None) or (False, reason) for the bytes `raw`.

    Used by the generator only to check ACT-05 (emit, recognize, compare).
    """
    if len(raw) > MAX_PAYLOAD:
        return False, TOO_LARGE
    try:
        text = raw.decode("utf-8")
        parser = _Parser(text)
        parser.value(0)
        if parser.i != len(text):
            raise _Reject()
    except (UnicodeDecodeError, _Reject):
        return False, NOT_CANONICAL
    return True, None
