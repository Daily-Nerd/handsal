"""Vector file schema: the single owner of what a valid vector is.

Both the harness (run.py) and the vector writer import `validate`, so the
writer cannot emit a document the harness would reject.

Vector: one JSON object,
  {name, command, input | input_raw | input_hex, anchor, pad?, exit?}
  anchor     REQUIRED string: the exact expected stdout line, without the LF.
  input      any JSON value, sent as compact UTF-8 JSON plus one LF.
  input_raw  a string, sent as its UTF-8 bytes with nothing added.
  input_hex  lowercase hex, sent as the decoded bytes with nothing added.
             The only way to send bytes that are not valid UTF-8.
  pad        non-empty path (keys and indexes) to a string inside `input`.
  exit       expected exit code, an int from 0 to 255, default 0.
Exactly one of input, input_raw, input_hex. Unknown keys are refused.
"""

import re

KEYS = frozenset(("name", "command", "input", "input_raw", "input_hex", "anchor", "pad", "exit"))
INPUT_FORMS = ("input", "input_raw", "input_hex")
_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")


class VectorError(Exception):
    pass


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def pad_slot(value, path, name):
    """Return (parent, key) of the string that `path` points to in `value`."""
    if not isinstance(path, list) or not path:
        raise VectorError("%s: pad must be a non-empty path" % name)
    if not all(isinstance(s, str) or _is_int(s) for s in path):
        raise VectorError("%s: pad steps must be keys or indexes" % name)
    try:
        parent = value
        for step in path[:-1]:
            parent = parent[step]
        target = parent[path[-1]]
    except (KeyError, IndexError, TypeError):
        raise VectorError("%s: pad path not found in input" % name)
    if not isinstance(target, str):
        raise VectorError("%s: pad target is not a string" % name)
    return parent, path[-1]


def validate(vector, where=None):
    """Raise VectorError unless `vector` is a document the harness accepts."""
    prefix = "%s: " % where if where else ""

    def fail(text):
        raise VectorError(prefix + text)

    if not isinstance(vector, dict):
        fail("vector is not an object")
    for key in ("name", "command"):
        if not isinstance(vector.get(key), str) or not vector[key]:
            fail("missing %s" % key)
    name = vector["name"]
    unknown = sorted(set(vector) - KEYS)
    if unknown:
        fail("vector %s has unknown keys %s" % (name, unknown))
    if "anchor" not in vector:
        fail("vector %s has no anchor" % name)
    if not isinstance(vector["anchor"], str):
        fail("anchor of %s must be the exact output line as a string" % name)
    forms = [k for k in INPUT_FORMS if k in vector]
    if len(forms) != 1:
        fail("vector %s needs exactly one of input, input_raw and input_hex" % name)
    if "input_raw" in vector:
        raw = vector["input_raw"]
        if not isinstance(raw, str):
            fail("input_raw of %s must be a string" % name)
        try:
            raw.encode("utf-8")
        except UnicodeEncodeError:
            fail("input_raw of %s is not encodable as UTF-8, use input_hex" % name)
    if "input_hex" in vector:
        text = vector["input_hex"]
        if not isinstance(text, str) or not _HEX.match(text):
            fail("input_hex of %s must be even-length lowercase hex" % name)
    if "pad" in vector:
        if "input" not in vector:
            fail("pad needs input, not input_raw or input_hex")
        try:
            pad_slot(vector["input"], vector["pad"], name)
        except VectorError as err:
            fail(str(err))
    if "exit" in vector:
        code = vector["exit"]
        if not _is_int(code) or not 0 <= code <= 255:
            fail("exit of %s must be an int from 0 to 255" % name)
    return vector
