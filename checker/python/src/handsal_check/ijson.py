"""I-JSON reader for command stdin (CF-03 input framing, RFC 7493).

stdin must be UTF-8 JSON with no duplicate member name at any depth, no lone
surrogate, at most MAX_INPUT bytes and at most MAX_NESTING levels (arrays and
objects together, the root is level 1). The size is judged first, before any
parsing. Every refusal is `Unparseable`; the caller maps it to the
`unparseable_input` result. `subset` reads raw bytes and uses `check_size` only.
"""
import json

MAX_INPUT = 16777216
MAX_NESTING = 64


class Unparseable(Exception):
    pass


def check_size(raw):
    if len(raw) > MAX_INPUT:
        raise Unparseable("stdin is over MAX_INPUT bytes")


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Unparseable("duplicate member name")
        out[key] = value
    return out


def _refuse_constant(name):
    raise Unparseable("not JSON: %s" % name)


def _has_lone_surrogate(text):
    return any("\ud800" <= ch <= "\udfff" for ch in text)


def _walk(value):
    """Refuse a lone surrogate or a level beyond MAX_NESTING, without recursion."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if type(item) is str:
            if _has_lone_surrogate(item):
                raise Unparseable("lone surrogate")
        elif type(item) is list or type(item) is dict:
            if depth + 1 > MAX_NESTING:
                raise Unparseable("nesting is over MAX_NESTING")
            if type(item) is list:
                stack.extend((member, depth + 1) for member in item)
            else:
                for key, member in item.items():
                    if _has_lone_surrogate(key):
                        raise Unparseable("lone surrogate")
                    stack.append((member, depth + 1))


def loads(raw):
    """The value of the I-JSON bytes `raw`, or raise Unparseable."""
    check_size(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Unparseable("not UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_refuse_constant)
    except (ValueError, RecursionError):
        raise Unparseable("not JSON") from None
    _walk(value)
    return value
