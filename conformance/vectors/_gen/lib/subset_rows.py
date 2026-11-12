"""Shared helper for rows that feed raw bytes to the checker `subset` command.

Anchors state the expected behaviour (ACT-04). Before a row is written the
generator's own recognizer (lib/jcs.py, independent of any checker) must agree
with the stated verdict, so a wrong table entry aborts the run instead of
shipping a wrong anchor (CF-06, CF-07).
"""
from . import jcs, result

OK = "ok"
BAD = jcs.NOT_CANONICAL
BIG = jcs.TOO_LARGE


def anchor(reason):
    """The `subset` result line for `reason` (`ok` or a payload reason code)."""
    return result.line({"canonical": reason == OK, "reason": reason})


def add(writer, name, raw, reason):
    """Write the `subset` row `name` over the bytes `raw`, expecting `reason`."""
    good, found = jcs.recognize(raw)
    if (OK if good else found) != reason:
        raise AssertionError("%s: table says %s, recognizer says %s" % (name, reason, found or OK))
    try:
        text = raw.decode("utf-8")
        form = {"input_raw": text}
    except UnicodeDecodeError:
        form = {"input_hex": raw.hex()}
    return writer.add(name, "subset", anchor(reason), **form)
