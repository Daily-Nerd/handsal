"""Derive the shipping vector ids and one effective row per id from the catalog.

Usage: extract_vector_ids.py CATALOG_DIR [--out-dir DIR]

CATALOG_DIR holds the catalog notes. The tool reads these five files:

  spec-vectors-catalog.md          catalog, sections 1 to 19
  spec-part3.md                    section 14, the `wit` group
  spec-vectors-catalog-part2.md    sections 22 and 23
  spec-vectors-catalog-part3.md    sections 26 to 28
  spec-vectors-catalog-part4.md    sections 26.1, 27.4, 27.5, 28.9, 28.10, 30

and writes two files (default DIR is conformance/ next to this tool):

  vector-ids.json       active ids, retired ids, the Windows-conditional pair
  effective-rows.json   one {covers, input, expected} per active id

Layer order (lowest first, a later layer wins). It follows the notices at the
top of each note: the main catalog is amended by part2 section 23, part3 is
"authoritative over both earlier notes", part4 is "authoritative over the
three earlier notes", part3 27.3 is "authoritative over 27, 27.1 and 27.2",
part4 27.4 is "authoritative over 27 to 27.3", and section 30 says "later
layer wins". Sections that define ids (22, 28.x) sit below the sections of the
same note that amend ids (23, 27.x).

   0  catalog        sections 1 to 19
   1  spec-part3-14  the `wit` group (added before part2)
   2  part2-22       new vectors
   3  part2-23       changed expectations and inputs
   4  part3-28       new vectors (28.1 to 28.8)
   5  part3-27       changed expectations
   6  part3-27.1     remap and anchored inputs
   7  part3-27.3     iteration 4 re-anchors
   8  part4-28       new vectors (28.9, 28.10)
   9  part4-27.4     changed inputs and expectations
  10  part4-30       apply-time re-anchors

Resolution is field by field, in layer order. A full row (id, req, input,
expect) sets all three fields. An amendment row sets what it states: "now"
cells set the expectation, or the input when the cell starts with "input";
"anchored input" cells set the input; mixed cells set the expectation when
they start with "expectation", else the input; a "req" cell sets covers.
Fields an amendment does not state are inherited from the layers below.

Two rows for one id in one layer fail with LayerConflict unless they are
byte-identical. A row in a section with no layer, a table of unknown shape,
and an amendment without a base row fail with CatalogError. Nothing is
resolved silently.

Public text. The cells come from working notes and carry process wording:
review rounds, judge labels, iteration numbers. Every copied cell and id goes
through scrub(): provenance clauses are cut, the normative term "judged" is
written "examined" (as in the profile), and backtick spans (reason codes,
values) are never touched. A cell that still matches PROCESS_WORDS afterwards
fails with CatalogError naming the id. Each row in effective-rows.json also
carries "layers" (the layers that contributed, lowest first) and, when a field
was chosen by the mixed-cell rule above, "heuristic": "<field>", so a generator
author checks that row by hand.

Retired: input cell starting with RETIRED, ids in the bullets of section 26
(part3) and 26.1 (part4) except the ids after "replaced by". A retired id
never ships, whatever other rows say about it.

Active ids are all others. The pair cls/win-hello-* is conditional: one of
the two is dropped at the tag, so shipping count = active count - 1.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_text import PROCESS_WORDS  # noqa: E402

CONDITIONAL = [
    "cls/win-hello-biometric-only-maintainer-ok",
    "cls/win-hello-pin-capable-maintainer-refused",
]

LAYERS = [
    "catalog", "spec-part3-14", "part2-22", "part2-23", "part3-28",
    "part3-27", "part3-27.1", "part3-27.3", "part4-28", "part4-27.4",
    "part4-30",
]
RANK = {name: i for i, name in enumerate(LAYERS)}

# file -> (strict, section matcher). strict: a row in an unmapped section fails.
FILES = {
    "spec-vectors-catalog.md": (True, "cat"),
    "spec-part3.md": (False, "sp3"),
    "spec-vectors-catalog-part2.md": (True, "p2"),
    "spec-vectors-catalog-part3.md": (True, "p3"),
    "spec-vectors-catalog-part4.md": (True, "p4"),
}

HEADING = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)?)\.?(?:\s|$)")
ANY_HEADING = re.compile(r"^#{1,4}\s")
ID = re.compile(r"`([a-z0-9]+/[A-Za-z0-9._-]+)`")
ID_CELL = re.compile(r"^\s*(?:`[a-z0-9]+/[A-Za-z0-9._-]+`\s*(?:,\s*)?)+$")
REPLACED_BY = re.compile(r"replaced by\s+(?:`[^`]+`(?:,\s*|\s+and\s+)?)+")


class CatalogError(Exception):
    pass


class LayerConflict(CatalogError):
    pass


def layer_of(kind, section):
    """Layer name for a section number, or None when the section has none."""
    if section is None:
        return None
    major = section.split(".")[0]
    if kind == "cat":
        return "catalog" if major.isdigit() and 1 <= int(major) <= 19 else None
    if kind == "sp3":
        return "spec-part3-14" if section == "14" else None
    if kind == "p2":
        if major == "22":
            return "part2-22"
        return "part2-23" if section == "23" else None
    if kind == "p3":
        if major == "28":
            return "part3-28"
        return {"27": "part3-27", "27.1": "part3-27.1",
                "27.3": "part3-27.3"}.get(section)
    if kind == "p4":
        if section in ("28.9", "28.10"):
            return "part4-28"
        return {"27.4": "part4-27.4", "27.5": "part4-27.4",
                "30": "part4-30"}.get(section)
    return None


def split_cells(line):
    """Split a table row on pipes that are outside backtick spans."""
    s = line.strip()
    if not (s.startswith("|") and s.endswith("|")):
        return None
    cells, cur, tick = [], [], False
    for ch in s[1:-1]:
        if ch == "`":
            tick = not tick
        if ch == "|" and not tick:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


def table_shape(header, where):
    h = [c.lower() for c in header]
    if h[0] != "id":
        raise CatalogError(f"{where}: table does not start with an id column")
    n = len(h)
    if n == 2:
        return "mixed2"
    if n == 3:
        return "now" if h[1] == "was" else "mixed3"
    if n == 4:
        return "anchor" if h[1] == "new req" and h[2] == "anchored input" else "full"
    if n == 5 and h[2] == "cmd":
        return "full5"
    raise CatalogError(f"{where}: unknown table shape {header}")


class Row:
    __slots__ = ("ident", "layer", "shape", "cells", "where")

    def __init__(self, ident, layer, shape, cells, where):
        self.ident, self.layer, self.shape = ident, layer, shape
        self.cells, self.where = tuple(cells), where

    def same_as(self, other):
        return (self.shape, self.cells) == (other.shape, other.cells)


def strip_replaced(text):
    return REPLACED_BY.sub("", text)


def parse_file(path, kind, strict):
    rows, retired = [], set()
    section = None
    shape = None
    header_seen = False
    ret_section = False
    lines = path.read_text(encoding="utf-8").splitlines()
    for no, raw in enumerate(lines, 1):
        where = f"{path.name}:{no}"
        if ANY_HEADING.match(raw):
            m = HEADING.match(raw)
            section = m.group(1) if m else None
            shape, header_seen = None, False
            ret_section = (kind == "p3" and section == "26") or \
                          (kind == "p4" and section == "26.1")
            continue
        if ret_section and raw.startswith("- "):
            retired.update(ID.findall(strip_replaced(raw)))
            continue
        cells = split_cells(raw)
        if cells is None:
            shape, header_seen = None, False
            continue
        if re.fullmatch(r"[-: |]+", raw.strip()):
            continue
        if not ID_CELL.match(cells[0]):
            shape = table_shape(cells, where) if (cells[0].lower() == "id" and
                                                  layer_of(kind, section)) else None
            header_seen = True
            continue
        layer = layer_of(kind, section)
        if layer is None:
            if strict:
                raise CatalogError(f"{where}: vector row in section {section!r} has no layer")
            continue
        if shape is None:
            raise CatalogError(f"{where}: vector row without a table header")
        if len(cells) != len(table_header_len(shape)):
            raise CatalogError(f"{where}: {len(cells)} cells, shape {shape}")
        for ident in ID.findall(cells[0]):
            rows.append(Row(ident, layer, shape, cells[1:], where))
    return rows, retired


def table_header_len(shape):
    return {"mixed2": range(2), "now": range(3), "mixed3": range(3),
            "anchor": range(4), "full": range(4), "full5": range(5)}[shape]


def apply_row(cur, heur, row):
    """Apply one row to cur. heur maps a field to True while its value came
    from the mixed-cell rule; a later explicit row for the field clears it."""
    c = row.cells

    def explicit(**kw):
        cur.update(kw)
        for k in kw:
            heur.pop(k, None)

    def guessed(field, value):
        cur[field] = value
        heur[field] = True

    if row.shape == "full":
        explicit(covers=c[0], input=c[1], expected=c[2])
    elif row.shape == "full5":
        explicit(covers=c[0], input=c[2], expected=c[3])
    elif row.shape == "now":
        explicit(**{"input" if c[1].lower().startswith("input") else "expected": c[1]})
    elif row.shape == "anchor":
        explicit(covers=c[0], input=c[1])
    elif row.shape == "mixed3":
        explicit(covers=c[0])
        guessed("expected" if c[1].lower().startswith("expectation") else "input", c[1])
    elif row.shape == "mixed2":
        guessed("expected" if c[0].lower().startswith("expectation") else "input", c[0])


class Result:
    def __init__(self, effective, retired, multi_layer, layers, heuristic, scrubbed):
        self.effective = effective
        self.layers = layers
        self.heuristic = heuristic
        self.scrubbed = scrubbed
        self.retired = retired
        self.multi_layer = multi_layer
        self.active = sorted(effective)
        self.conditional = list(CONDITIONAL)
        self.ship_count = len(self.active) - 1


def build(catalog_dir):
    root = Path(catalog_dir)
    rows, retired = [], set()
    for name, (strict, kind) in FILES.items():
        path = root / name
        if not path.is_file():
            raise CatalogError(f"missing catalog file: {path}")
        r, ret = parse_file(path, kind, strict)
        rows.extend(r)
        retired |= ret
    # Orig-style retirement: the input cell of a full row starts with RETIRED.
    for row in rows:
        if row.shape in ("full", "full5"):
            inp = row.cells[1] if row.shape == "full" else row.cells[2]
            if inp.startswith("RETIRED"):
                retired.add(row.ident)

    by_id = {}
    for row in rows:
        by_id.setdefault(row.ident, []).append(row)

    effective, multi_layer, layers, heuristic, scrubbed = {}, {}, {}, {}, []
    for ident in sorted(by_id):
        group = by_id[ident]
        per_layer = {}
        for row in group:
            per_layer.setdefault(row.layer, []).append(row)
        for layer, same in per_layer.items():
            for other in same[1:]:
                if not same[0].same_as(other):
                    raise LayerConflict(
                        f"{ident}: two different rows in layer {layer}: "
                        f"{same[0].where} and {other.where}")
        ordered = sorted(per_layer, key=RANK.__getitem__)
        if len(ordered) > 1:
            multi_layer[ident] = ordered
        if ident in retired:
            continue
        cur, heur = {}, {}
        for layer in ordered:
            apply_row(cur, heur, per_layer[layer][0])
        missing = {"covers", "input", "expected"} - set(cur)
        if missing:
            raise CatalogError(
                f"{ident}: no base row sets {sorted(missing)} "
                f"(first seen at {group[0].where})")
        row = {}
        for field in ("covers", "input", "expected"):
            row[field] = scrub(cur[field], ident)
            if row[field] != cur[field]:
                if ident not in scrubbed:
                    scrubbed.append(ident)
        pid = public_id(ident)
        if pid in effective:
            raise CatalogError(f"{ident}: public id {pid} collides with another id")
        effective[pid] = row
        layers[pid] = ordered
        if heur:
            heuristic[pid] = sorted(heur)[0] if len(heur) == 1 else sorted(heur)
        if pid != ident:
            scrubbed.append(ident)
    for ident in CONDITIONAL:
        if ident not in effective:
            raise CatalogError(f"conditional id not active: {ident}")
    retired = {public_id(i) for i in retired}
    multi_layer = {public_id(i): v for i, v in multi_layer.items()}
    return Result(effective, retired, multi_layer, layers, heuristic, scrubbed)


# Provenance clauses, cut in this order. Each pattern names one shape found in
# the catalog; anything left over trips the PROCESS_WORDS check in scrub().
SCRUB_RULES = [
    (re.compile(r"\s*\(iteration \d+\):"), ":"),
    (re.compile(r"\(iteration \d+: "), "("),
    (re.compile(r"^(?:both )?round-\d+ judges?(?:'s?)? [A-Z]?\s?"), ""),
    (re.compile(r"^judge [A-Z] C\d+ \(round \d+\): "), ""),
    (re.compile(r"\s*\(round-\d+ judge [A-Z] \d+\)"), ""),
    (re.compile(r"\s+of round-\d+ judge [A-Z] \d+"), ""),
    (re.compile(r"; discriminates round-\d+ judge [A-Z] \d+"), ""),
    (re.compile(r", round-\d+ judge [A-Z] \d+, judge [A-Z] \d+"), ""),
    (re.compile(r"; round-\d+ judge [A-Z] \d+"), ""),
    (re.compile(r"; round \d+, judge [A-Z] \d+"), ""),
    (re.compile(r"; judge [A-Z] \d+, judge [A-Z] C\d+"), ""),
    (re.compile(r" in round \d+, judge [A-Z] \d+"), ""),
    (re.compile(r"round \d+, judge [A-Z] \d+; "), ""),
    (re.compile(r"so the row discriminates judge [A-Z] \d+'s two"), "so the row discriminates the two"),
    (re.compile(r"\(round \d+: "), "("),
    (re.compile(r"\s*\(template amended in round \d+\)"), ""),
    (re.compile(r", removed in round \d+"), ""),
    (re.compile(r"\s*\(OT-\d+\)"), ""),
    (re.compile(r"\bjudged\b"), "examined"),
]
_TICKS = re.compile(r"`[^`]*`")


class Scrubbed(str):
    """A scrubbed string; only the type tells the caller nothing was needed."""


def scrub(text, ident):
    """Cut process wording out of one copied cell. Fail loudly when it stays."""
    out = text
    for pat, repl in SCRUB_RULES:
        out = pat.sub(repl, out)
    out = out.strip()
    if _TICKS.findall(out) != _TICKS.findall(text):
        raise CatalogError(f"{ident}: scrubbing would change a backtick span: {text!r}")
    m = PROCESS_WORDS.search(out)
    if m:
        raise CatalogError(f"{ident}: cannot scrub {m.group(0)!r} without changing the cell: {text!r}")
    return out


def public_id(ident):
    """An id with the process term written as the profile writes it."""
    out = re.sub(r"judged", "examined", ident)
    m = PROCESS_WORDS.search(out)
    if m:
        raise CatalogError(f"{ident}: id holds process wording {m.group(0)!r}")
    return out


def dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("catalog_dir")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parents[1] / "conformance"))
    args = ap.parse_args(argv)
    src, out = Path(args.catalog_dir), Path(args.out_dir)
    if not src.is_dir():
        print(f"error: not a directory: {src}", file=sys.stderr)
        return 2
    try:
        res = build(src)
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    ids = {
        "active_count": len(res.active),
        "conditional": res.conditional,
        "ids": res.active,
        "retired": sorted(res.retired),
        "retired_count": len(res.retired),
        "ship_count": res.ship_count,
    }
    (out / "vector-ids.json").write_text(dump(ids), encoding="utf-8")
    rows = {}
    for ident, row in res.effective.items():
        rows[ident] = dict(row, layers=res.layers[ident])
        if ident in res.heuristic:
            rows[ident]["heuristic"] = res.heuristic[ident]
    (out / "effective-rows.json").write_text(dump({"rows": rows}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
