"""I-JSON reader for command stdin (CF-03 input framing, RFC 7493).

stdin must be UTF-8 JSON with no duplicate member name at any depth, no lone
surrogate and at most MAX_INPUT bytes. The size is judged first, before any
parsing. Every refusal is `Unparseable`; the caller maps it to the
`unparseable_input` result. `subset` reads raw bytes and uses `check_size` only.
"""
import json

MAX_INPUT = 16777216


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


def _walk_for_surrogates(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is str:
            if _has_lone_surrogate(item):
                raise Unparseable("lone surrogate")
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is dict:
            for key, member in item.items():
                if _has_lone_surrogate(key):
                    raise Unparseable("lone surrogate")
                stack.append(member)


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
    _walk_for_surrogates(value)
    return value
