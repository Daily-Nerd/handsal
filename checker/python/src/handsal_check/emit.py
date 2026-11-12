"""Emitters (ACT-05, CF-03).

`emit_subset` writes a value of the canonical subset: keys sorted by byte
order, no whitespace, strings verbatim (`/` unescaped), arrays in the given
order. It refuses everything the subset cannot express instead of coercing it.
A general JSON serializer is never used for signed bytes.

`emit_result` writes a command result line body: RFC 8785 style JSON with
sorted keys, `true`, `false`, `null`, integers and strings. Result objects are
not signed values, so they may carry booleans and integers.
"""
from . import encoding, subset

MAX_PAYLOAD = subset.MAX_PAYLOAD
MAX_DEPTH = subset.MAX_DEPTH


class EmitError(ValueError):
    pass


def _subset(value, depth, out):
    kind = type(value)
    if value is None:
        out.append("null")
    elif kind is str:
        if not encoding.is_plain_text(value):
            raise EmitError("string outside the subset alphabet")
        out.append('"' + value + '"')
    elif kind is dict:
        if depth + 1 > MAX_DEPTH:
            raise EmitError("nesting deeper than %d" % MAX_DEPTH)
        for key in value:
            if type(key) is not str:
                raise EmitError("object key is not a string")
        out.append("{")
        for i, key in enumerate(sorted(value)):
            if i:
                out.append(",")
            _subset(key, depth + 1, out)
            out.append(":")
            _subset(value[key], depth + 1, out)
        out.append("}")
    elif kind is list:
        if depth + 1 > MAX_DEPTH:
            raise EmitError("nesting deeper than %d" % MAX_DEPTH)
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _subset(item, depth + 1, out)
        out.append("]")
    else:
        raise EmitError("type %s is not in the subset" % kind.__name__)


def emit_subset(value):
    """The canonical bytes of `value`, or raise EmitError."""
    out = []
    _subset(value, 0, out)
    raw = "".join(out).encode("ascii")
    if len(raw) > MAX_PAYLOAD:
        raise EmitError("over MAX_PAYLOAD")
    return raw


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
            "\t": "\\t"}


def _result_string(text):
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch < " ":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _result(value, out):
    kind = type(value)
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif kind is int:
        out.append(str(value))
    elif kind is str:
        out.append(_result_string(value))
    elif kind is list:
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _result(item, out)
        out.append("]")
    elif kind is dict:
        for key in value:
            if type(key) is not str:
                raise EmitError("object key is not a string")
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))):
            if i:
                out.append(",")
            out.append(_result_string(key))
            out.append(":")
            _result(value[key], out)
        out.append("}")
    else:
        raise EmitError("type %s has no result form" % kind.__name__)


def emit_result(value):
    """The UTF-8 bytes of the result object `value`, without the trailing LF."""
    out = []
    _result(value, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError:
        raise EmitError("string is not encodable as UTF-8") from None
