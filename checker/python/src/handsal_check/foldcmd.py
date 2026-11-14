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


def read_chain(value, conformance_build):
    """`(acts, lineage)` of a `check-act`, `recheck-act` or `enrolled` input. The conformance build takes them as
    data. The production build reads them from the store (CF-09, CF-08) and takes no such input: one that carries
    either is Malformed, and the placeholders it returns are filled in process before the steps run."""
    if not conformance_build:
        if "acts" in value or "lineage" in value:
            raise _malformed()
        return [], []
    acts, lineage = value.get("acts"), value.get("lineage")
    if type(acts) is not list or type(lineage) is not list:
        raise _malformed()
    check_texts(acts)
    check_lineage(lineage)
    return acts, lineage


def read_view(value, conformance_build):
    """`(synced_at, tip_statement)` of a `check-act` or `enrolled` input: data of the conformance build, the
    store's in production (the same rule as `read_chain`)."""
    if not conformance_build:
        if "synced_at" in value or "tip_statement" in value:
            raise _malformed()
        return None, None
    synced_at, tip = value.get("synced_at"), value.get("tip_statement")
    if type(synced_at) is not str or not schema.is_time(synced_at):
        raise _malformed()
    if "tip_statement" not in value or not (tip is None or type(tip) is str):
        raise _malformed()
    return synced_at, tip


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
