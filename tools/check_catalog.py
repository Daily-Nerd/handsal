"""Catalog check: every hole in the vector set, reported (CF-07, CF-02).

Usage: check_catalog.py [--root DIR] [--vr02-steps N]

Reads `spec/profile.md`, `conformance/vector-ids.json` and every file in
`conformance/vectors/`, and lists every hole it finds. It writes nothing and
never invents a vector: a hole is listed so the generator author can fill it.
Exit 0 when there is no hole, 1 otherwise, 2 when an input is unreadable.

Hole kinds:
  missing-file     an id of vector-ids.json with no file on disk
  extra-file       a vector file whose name is not an id of vector-ids.json
  name-mismatch    a file whose name is not its vector `name` with `/` as `.`
  no-anchor        a vector with no string `anchor` (CF-02)
  unreadable       a vector file that is not a JSON object
  duplicate-id     an id twice in vector-ids.json
  count-mismatch   `active_count` or `ship_count` disagrees with the list
  code-uncovered   a section 11 reason code that no vector shows (CF-07)
  order-missing    an ordering vector the spec names that is not on disk
  pair-uncovered   a VR-02 adjacent pair the spec does not list a vector for

A code is covered when a vector's anchor carries it as the top-level `reason`
or `error` string. Ordering vectors (`ord/*`, `wit/ord-*`, `gen/order-*`) hold two defects by
design, so they never count as an only-defect vector. That is a proxy: the
anchor shows the code, it does not prove the code is the only defect.

Standard library only.
"""
import argparse
import json
import re
import sys
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

VR02_STEPS = 16

# CF-07 names this one GP-15 pair as having no vector. The exemption is only
# valid while the spec text still says so; survey() checks the text.
GP15_EXEMPT_SENTENCE = "One adjacent pair of GP-15 has no vector"

Hole = namedtuple("Hole", "kind subject detail")

TICKED = re.compile(r"`([^`]+)`")


class CatalogCheckError(Exception):
    pass


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as err:
        raise CatalogCheckError("cannot read %s (%s)" % (path, err)) from err


def _section(spec, heading):
    start = spec.find(heading)
    if start < 0:
        raise CatalogCheckError("spec has no %r" % heading)
    end = spec.find("\n## ", start + len(heading))
    return spec[start:end if end >= 0 else len(spec)]


def _line(text, prefix):
    for line in text.splitlines():
        if line.startswith(prefix):
            return line
    raise CatalogCheckError("spec has no line starting %r" % prefix)


# Rows of the section 11 table whose codes belong to a component other than the
# checker. A code is the checker's unless every row that lists it is one of these.
NON_CHECKER_WHERE = ("signer exit codes", "pin helper (GP-21)")


def _table_rows(block):
    """[(codes, where)] for the section 11 table rows."""
    rows = []
    for line in block.splitlines():
        if line.startswith("|") and not line.startswith("|---") and not line.startswith("| Code"):
            cells = line.split("|")
            rows.append((TICKED.findall(cells[1]), cells[2].strip()))
    return rows


def _unique(codes, skip):
    seen, ordered = set(), []
    for code in codes:
        if code not in seen and code not in skip:
            seen.add(code)
            ordered.append(code)
    return ordered


def spec_codes(spec):
    """(codes in spec order, retired codes, CF-07 excepted codes) from the spec text."""
    block = _section(spec, "## 11. Reason codes")
    codes = [c for row, _ in _table_rows(block) for c in row]
    codes += TICKED.findall(_line(block, "Fold error codes"))
    retired = set(TICKED.findall(_line(block, "Retired codes")))
    cf07 = _line(spec, "Every reason code defined here, except")
    excepted = set(TICKED.findall(cf07.split("MUST")[0]))
    return _unique(codes, retired), retired, excepted


def checker_codes(spec):
    """The section 11 codes the checker itself produces, in spec order.

    Leaves out a code only when every table row listing it is a signer exit code
    or a pin helper row (SG-08, GP-21); the checker never returns those.
    """
    block = _section(spec, "## 11. Reason codes")
    other, mine = set(), set()
    for row, where in _table_rows(block):
        (other if where.startswith(NON_CHECKER_WHERE) else mine).update(row)
    mine |= set(TICKED.findall(_line(block, "Fold error codes")))
    codes, _retired, _excepted = spec_codes(spec)
    return [c for c in codes if c in mine or c not in other]


def ordering_vectors(spec):
    """([(label, [ids])] for VR-02, [ids] for GP-15) from the CF-07 text."""
    line = _line(spec, "Ordering vectors for VR-02:")
    vr02 = []
    for segment in line.split(":", 1)[1].split(";"):
        ids = TICKED.findall(segment)
        label = segment.split("`")[0].strip()
        if ids:
            vr02.append((label, ids))
    gp15 = TICKED.findall(_line(spec, "Ordering vectors for GP-15:"))
    return vr02, gp15


def _is_ordering(name):
    return name.startswith(("ord/", "wit/ord-", "gen/order-"))


def _anchor_codes(anchor):
    try:
        doc = json.loads(anchor)
    except (TypeError, ValueError):
        return set()
    if not isinstance(doc, dict):
        return set()
    return {doc[k] for k in ("reason", "error") if isinstance(doc.get(k), str)}


def anchor_codes(root=ROOT, include_ordering=True):
    """The codes shown by the anchors of the vector files on disk (top-level `reason` or `error`)."""
    shown = set()
    vdir = Path(root) / "conformance" / "vectors"
    for path in sorted(vdir.iterdir()):
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("name"), str):
            if include_ordering or not _is_ordering(doc["name"]):
                shown |= _anchor_codes(doc.get("anchor"))
    return shown


def _load_vectors(vectors_dir, holes):
    """{name: vector} for every readable file; records the file-level holes."""
    found = {}
    if not vectors_dir.is_dir():
        raise CatalogCheckError("no vector directory at %s" % vectors_dir)
    for path in sorted(vectors_dir.iterdir()):
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("name"), str):
            holes.append(Hole("unreadable", path.name, "not a vector object with a name"))
            continue
        name = doc["name"]
        if path.name != name.replace("/", ".") + ".json":
            holes.append(Hole("name-mismatch", path.name, "holds the vector named %s" % name))
        if not isinstance(doc.get("anchor"), str):
            holes.append(Hole("no-anchor", name, path.name))
        found[name] = doc
    return found


def _planned_rows(path):
    """{id: expected text} from effective-rows.json, empty when the file is absent."""
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))["rows"]
    except (OSError, ValueError, KeyError):
        return {}
    return {i: str(r.get("expected", "")) for i, r in rows.items() if isinstance(r, dict)}


def survey(root=ROOT, steps=VR02_STEPS):
    """Every hole in the tree under `root`, in a stable order."""
    root = Path(root)
    holes = []
    spec = _read(root / "spec" / "profile.md")
    try:
        listing = json.loads(_read(root / "conformance" / "vector-ids.json"))
        ids = listing["ids"]
    except (ValueError, KeyError, TypeError) as err:
        raise CatalogCheckError("vector-ids.json unreadable (%s)" % err) from err

    found = _load_vectors(root / "conformance" / "vectors", holes)

    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        holes.append(Hole("duplicate-id", dup, "listed more than once"))
    expected_ship = len(set(ids)) - (1 if listing.get("conditional") else 0)
    if listing.get("active_count") != len(set(ids)):
        holes.append(Hole("count-mismatch", "active_count",
                          "%r listed, %d ids" % (listing.get("active_count"), len(set(ids)))))
    if listing.get("ship_count") != expected_ship:
        holes.append(Hole("count-mismatch", "ship_count",
                          "%r listed, expected %d" % (listing.get("ship_count"), expected_ship)))

    conditional = set(listing.get("conditional") or [])
    for name in sorted(set(ids) - set(found)):
        holes.append(Hole("missing-file", name, "conditional" if name in conditional else ""))
    for name in sorted(set(found) - set(ids)):
        holes.append(Hole("extra-file", name, "not in vector-ids.json"))

    codes, _retired, excepted = spec_codes(spec)
    shown = set()
    for name, doc in found.items():
        if not _is_ordering(name):
            shown |= _anchor_codes(doc.get("anchor"))
    planned = _planned_rows(root / "conformance" / "effective-rows.json")
    for code in codes:
        if code not in excepted and code not in shown:
            rows = sorted(i for i, text in planned.items() if "`%s`" % code in text)
            detail = "no only-defect vector on disk"
            if rows:
                detail += "; catalog rows: " + ", ".join(rows)
            holes.append(Hole("code-uncovered", code, detail))

    vr02, gp15 = ordering_vectors(spec)
    if GP15_EXEMPT_SENTENCE not in spec:
        raise CatalogCheckError("the GP-15 exemption is no longer in CF-07: %r" % GP15_EXEMPT_SENTENCE)
    listed = {label for label, _ in vr02}
    for k in range(1, steps):
        label = "%d/%d" % (k, k + 1)
        if label not in listed:
            holes.append(Hole("pair-uncovered", "VR-02 %s" % label, "no ordering vector listed"))
    named = [i for _, group in vr02 for i in group] + list(gp15)
    for name in named:
        if name not in found:
            holes.append(Hole("order-missing", name, "named in CF-07"))

    return sorted(holes, key=lambda h: (h.kind, h.subject))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--vr02-steps", type=int, default=VR02_STEPS)
    args = parser.parse_args(argv)
    try:
        holes = survey(args.root, args.vr02_steps)
    except CatalogCheckError as err:
        print("catalog check failed: %s" % err, file=sys.stderr)
        return 2
    for hole in holes:
        print("%-15s %s%s" % (hole.kind, hole.subject, ("  (%s)" % hole.detail) if hole.detail else ""))
    print("%d holes" % len(holes))
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())
