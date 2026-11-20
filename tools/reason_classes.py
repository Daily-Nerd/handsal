"""The class of a reason code: one owner, `conformance/reason-classes.json`.

`classify(command, code)` is total over the section 11 index. A code the table does not name raises
`ReasonClassError`; there is no default class and no catch-all, because a catch-all would let a census pass with
a code nobody reviewed. A code whose meaning differs by command (`stale_view` under `recheck-act`, `lineage_broken`
under the store commands) is a row of `by_command`, visible as an override of the code's default. `by_command`
keys on the command name alone, so it cannot tell the signer's `render` from the checker's `render`: a code they
share has one class.

What two of the classes promise a consumer, because both are easy to read as more than they say:

  membership   the same evidence always gives the same answer, whatever the clock or the network. Holding more
               evidence may change it (`at_beyond_tip`, `fork`, `local_key_unknown`), so an answer is cached by
               the evidence it was given for, never by the position or the key that was asked about.
  validity     the bytes of one act, signed or about to be signed, with the attachments bound to it, break a
               rule. That holds for those bytes for good.

`known_gaps` is the one optional key: overrides no vector shows yet, each with why (`check_catalog.class_holes`).
It is this repository's census ledger and no part of the classification: a consumer of the table ignores it.

The table is not a core file (`manifest.CORE_FILES`): it moves no hash. It is append-only across tags, which
`tools/check_catalog.py` checks against the previous tag.

Standard library only.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "conformance" / "reason-classes.json"

CLASSES = ("membership", "freshness", "validity", "time", "environment", "input", "admission", "capacity", "ok")


class ReasonClassError(Exception):
    pass


def check(table):
    """The table itself, or `ReasonClassError`: the class set is exactly the nine, and every row names one of them."""
    if not (isinstance(table, dict) and isinstance(table.get("default"), dict)
            and isinstance(table.get("by_command"), dict)):
        raise ReasonClassError("the table needs `classes`, `default` and `by_command`")
    if sorted(table.get("classes") or []) != sorted(CLASSES):
        raise ReasonClassError("`classes` is not exactly the nine: %s" % ", ".join(CLASSES))
    gaps = table.get("known_gaps", {})
    if not (isinstance(gaps, dict) and all(isinstance(k, str) and k.count("/") == 1 and isinstance(v, str)
                                           for k, v in gaps.items())):
        raise ReasonClassError('`known_gaps` maps "command/code" to why its vector is missing')
    rows = list(table["default"].items())
    for command, per in table["by_command"].items():
        if not isinstance(per, dict):
            raise ReasonClassError("`by_command.%s` is not an object" % command)
        stray = sorted(set(per) - set(table["default"]))
        if stray:
            raise ReasonClassError("`by_command.%s` overrides a code with no default: %s" % (command, ", ".join(stray)))
        rows += [("%s/%s" % (command, code), kind) for code, kind in per.items()]
    for where, kind in rows:
        if kind not in CLASSES:
            raise ReasonClassError("%s names %r, which is not a class" % (where, kind))
    return table


def load(path=TABLE):
    try:
        table = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise ReasonClassError("cannot read %s (%s)" % (path, err)) from err
    return check(table)


def classify(command, code, table=None):
    """The class of `code` answered by `command`: the command's override when it has one, else the code's default."""
    table = load() if table is None else table
    override = table["by_command"].get(command, {}).get(code)
    if override is not None:
        return override
    if code not in table["default"]:
        raise ReasonClassError("reason code %r has no class" % code)
    return table["default"][code]
