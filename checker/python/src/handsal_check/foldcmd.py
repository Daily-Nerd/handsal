"""The `fold` command: its input (FO-01, GP-07, GP-14) and the steps (VR-02 step 6, GP-15, FO-16).

`run` checks the pin (VR-02 step 6 (a) to (h), `pinfile`), then folds the lineage in GP-15 order, per
document from the original on (`epoch.fold_lineage`), and writes the result of the last epoch
(`fold_out`): the state, `fork`, or `at_beyond_tip`. A refusal is `{"error": code}`; a verifier that
cannot answer is `{"error": "verifier_unavailable"}`. The render size check (GP-15 step 5) belongs to the
render (`render_genesis.render_size`), which is the default of `render_size`.

Lineage entries are `{doc, sigs}`. A `doc` may be any JSON value here: a document that is not an object
is the fold result `genesis_schema`, not a bad input. `acts` and `sigs` are lists of texts; a text
that is no act is ignored by the fold, but an item that is not even a string is a mistyped input.
`pin` is the probe object of the conformance build; the production build takes neither `pin` nor `now`
and reads them in-process (CF-08).
"""
from collections import namedtuple

from . import epoch, errors, fold_out, pinfile, render_genesis, schema, verifier

FoldInput = namedtuple("FoldInput", "acts at lineage org pin")


def _malformed():
    return errors.Malformed()


def check_texts(items):
    """Every item of a list of act texts is a string (a text that is no act is the fold's to ignore)."""
    if not all(type(item) is str for item in items):
        raise _malformed()


def check_lineage(lineage):
    """A lineage is a list of `{doc, sigs}` with `sigs` a list of texts (GP-07)."""
    for entry in lineage:
        if type(entry) is not dict or set(entry) != {"doc", "sigs"} or type(entry["sigs"]) is not list:
            raise _malformed()
        check_texts(entry["sigs"])


def parse_input(value, conformance_build=True):
    """The `FoldInput` of the command JSON `value`, or raise Malformed."""
    if type(value) is not dict:
        raise _malformed()
    if conformance_build:
        if "pin" not in value:
            raise _malformed()
    elif "pin" in value or "now" in value:
        raise _malformed()
    for key in ("acts", "lineage"):
        if type(value.get(key)) is not list:
            raise _malformed()
    check_texts(value["acts"])
    check_lineage(value["lineage"])
    if not schema.is_hashstr(value.get("org")):
        raise _malformed()
    at = value.get("at")
    if "at" in value and not schema.is_decimal(at):
        raise _malformed()
    pin = pinfile.Probe.from_json(value["pin"]) if conformance_build else None
    return FoldInput(value["acts"], at, value["lineage"], value["org"], pin)


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The fold result for `inp`: the state, `fork`, `at_beyond_tip` or `{"error": code}`."""
    try:
        pinfile.check(inp.pin, inp.org, profiles, pinfile.ends(inp.lineage), allow_fixture)
        epochs = epoch.fold_lineage(inp.lineage, inp.acts, reg, profiles, allow_fixture, vitni, render_size)
        return fold_out.result(epochs, inp.at)
    except errors.Refused as err:
        return {"error": err.code}
    except verifier.VerifierUnavailable:
        return {"error": "verifier_unavailable"}
