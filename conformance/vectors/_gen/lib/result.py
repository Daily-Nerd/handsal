"""Anchor lines: a checker result object as one JCS line (CF-03).

A result line is RFC 8785 JSON: sorted keys, no whitespace, strings with the
minimal escapes. Unlike the signed subset (lib/jcs.py) it carries booleans,
null and integers. Anchors are authored with this serializer from the expected
behaviour; no checker code is involved (CF-06). Standard library only.
"""

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
            "\t": "\\t"}


def _string(text):
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch < " ":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _utf16_key(key):
    return key.encode("utf-16-be")


def _emit(value, out):
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif type(value) is int:
        out.append(str(value))
    elif type(value) is str:
        out.append(_string(value))
    elif type(value) is list:
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _emit(item, out)
        out.append("]")
    elif type(value) is dict:
        for key in value:
            if type(key) is not str:
                raise TypeError("object key is not a string: %r" % (key,))
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _emit(value[key], out)
        out.append("}")
    else:
        raise TypeError("type %s has no result form" % type(value).__name__)


def line(value):
    """The one-line JCS text of `value` (no trailing LF)."""
    out = []
    _emit(value, out)
    return "".join(out)
