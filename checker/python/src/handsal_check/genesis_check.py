"""`genesis-check` (CF-03, GP-21): every link of a lineage, from the original, and the pin line.

Input `{acts, lineage}` and nothing else; the last lineage entry is the candidate document with its
signatures. The lineage is folded in GP-15 order per document (`epoch.fold_lineage`): GP-03 for the
original, GP-19 for each change against the path to its H in the epoch before it. The first failure
is the answer, so `valid:true` means every link is authorized; a caller can withhold evidence, which
fails closed, but cannot select it. No act tree is walked and no fork is looked at: a fork in an old
epoch never fails a later one.

Output `{pin, reason, valid}`. When valid, `pin` is the exact pin line of GP-05 (one JCS line and its
LF) for the last document: `pinfile.line` is the only writer of that form, so the pin helper and the
checker agree. Otherwise `pin` is null and `reason` the first failing code, or `verifier_unavailable`.
"""
from collections import namedtuple

from . import epoch, errors, foldcmd, genesis, pinfile, render_genesis, verifier

GenesisInput = namedtuple("GenesisInput", "acts lineage")


def parse_input(value):
    """The `GenesisInput` of the command JSON, or raise Malformed: exactly `acts` and `lineage`."""
    if type(value) is not dict or set(value) != {"acts", "lineage"}:
        raise errors.Malformed()
    for key in ("acts", "lineage"):
        if type(value[key]) is not list:
            raise errors.Malformed()
    foldcmd.check_texts(value["acts"])
    foldcmd.check_lineage(value["lineage"])
    return GenesisInput(value["acts"], value["lineage"])


def _failure(reason):
    return {"pin": None, "reason": reason, "valid": False}


def run(inp, reg, profiles, allow_fixture, vitni, render_size=render_genesis.render_size):
    """The result of the first failing link, or `valid:true` with the pin line."""
    try:
        if not inp.lineage:
            raise errors.Refused("lineage_broken")
        epochs = epoch.fold_lineage(inp.lineage, inp.acts, reg, profiles, allow_fixture, vitni, render_size)
    except errors.Refused as err:
        return _failure(err.code)
    except verifier.VerifierUnavailable:
        return _failure("verifier_unavailable")
    last = epochs[-1].doc
    line = pinfile.line(genesis.doc_hash(last), epochs[0].root.id, last["profile"])
    return {"pin": line.decode("ascii"), "reason": "ok", "valid": True}
