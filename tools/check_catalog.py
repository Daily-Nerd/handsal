"""Catalog check: every hole in the vector set, reported (CF-07, CF-02).

Usage: check_catalog.py [--root DIR] [--vr02-steps N] [--final | --owner-signed]

Reads the profile parts (`manifest.PROFILE_FILES`), `conformance/vector-ids.json` and every vector file
(`manifest.vector_files`: every file under `conformance/vectors/` but the generator folder, among them the owner-signed `conformance/vectors/prod/`), and lists every hole it finds. It writes nothing and
never invents a vector: a hole is listed so the generator author can fill it.
Exit 0 when there is no hole, 1 otherwise, 2 when an input is unreadable.

An id that waits for an owner step is listed in `pending` (the owner-signed ids, whose case name begins with
`prodk-`, CF-08) in vector-ids.json. Its file is signed by the owner and lives in `conformance/vectors/prod/`, a
directory the generator never writes. Without a file the id is no hole, and it is printed as pending. `--final` is
the check at the tag: every such id without a file is a hole, and so is a registry class whose status is `pending-spike` (KC-02).
Every other active id is one the tree can build, so a missing file is a hole at once.

Hole kinds:
  missing-file     an id of vector-ids.json with no file on disk (pending ids only with --final)
  pending-stale    a `pending` id whose file is in the generator's directory, or that is not an active id
  owner-misplaced  a file in `conformance/vectors/prod/` whose id is not `pending`
  owner-stale      an owner-signed file (`conformance/vectors/prod/`) whose genesis documents name no
                   production profile, or one outside the supported set (the catalog's productions plus the
                   unreleased current core of `conformance/pins.json`; before founding the catalog is empty and the
                   current core is the only valid one), or whose newest named edition is not the current core. The
                   tree holds the signed set of the current core only: the set of an edition that has shipped stays
                   in the tag that shipped it ("belongs to <label>, it stays in tag <tag>") and runs from there
                   (CF-15). A file that names an earlier edition and the current core is not stale
  wire-differs     an edition whose registry differs from the first edition's in its wire part (GP-23, I3): every
                   key but the key classes, the fixture-only classes, the policy bounds and the registry label.
                   Read from `profiles/<label>/spec/registry.json` and from the unreleased `spec/registry.json`
  class-pending    with --final: a registry class that is still `pending-spike`
  extra-file       a vector file whose name is not an id of vector-ids.json
  name-mismatch    a file whose name is not its vector `name` with `/` as `.`
  no-anchor        a vector with no string `anchor` (CF-02)
  unreadable       a vector file that is not a JSON object
  duplicate-id     an id twice in vector-ids.json
  count-mismatch   `active_count` disagrees with the list
  code-uncovered   a section 11 reason code that no vector shows (CF-07)
  order-missing    an ordering vector the spec names that is not on disk and is not pending (a pending one is
                   a `missing-file` hole at `--final`)
  pair-uncovered   a VR-02 adjacent pair the spec does not list a vector for
  class-table      `conformance/reason-classes.json` missing or malformed
  class-unresolved a (command, code) a vector shows that the class table cannot classify
  class-override-unshown  an override row of the class table that no vector shows (bar its `known_gaps`)
  class-gap-stale  a `known_gaps` row of the class table that is no longer an override, or that a vector now shows

A code is covered when a vector's anchor carries it as the top-level `reason`
or `error` string. Ordering vectors (`ord/*`, `wit/ord-*`, `gen/order-*`) hold two defects by
design, so they never count as an only-defect vector. That is a proxy: the
anchor shows the code, it does not prove the code is the only defect.

Standard library only.
"""
import argparse
import importlib.util
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

def _manifest():
    """tools/manifest.py, the one owner of the core list. Loaded by path (under `-I` a script's own
    directory is not on the import path)."""
    spec = importlib.util.spec_from_file_location("handsal_manifest", Path(__file__).with_name("manifest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    return name.startswith(("ord/", "wit/ord-", "gen/order-", "prf/order-"))


def catalog_rows(root):
    """The rows of `profiles/catalog.json`, oldest first; a tree without the file has none. A row that is no object
    with a string `label` and `production` is a loud error: the supported set is read from here."""
    path = Path(root) / "profiles" / "catalog.json"
    if not path.is_file():
        return []
    try:
        rows = json.loads(_read(path))
    except ValueError as err:
        raise CatalogCheckError("profiles/catalog.json unreadable (%s)" % err) from err
    if not isinstance(rows, list):
        raise CatalogCheckError("profiles/catalog.json is not a list")
    for row in rows:
        if not (isinstance(row, dict) and isinstance(row.get("label"), str) and isinstance(row.get("production"), str)):
            raise CatalogCheckError("profiles/catalog.json: a row has no string label and production")
    return rows


def owner_signed_ids(root):
    """The ids the owner run signs: the `pending` ids of vector-ids.json, which are exactly the owner-signed ids
    (CF-08). The generator's owner run reads the list from here."""
    listing = json.loads(_read(Path(root) / "conformance" / "vector-ids.json"))
    return set(listing.get("pending") or [])


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
    for path in _manifest().vector_files(root):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("name"), str):
            if include_ordering or not _is_ordering(doc["name"]):
                shown |= _anchor_codes(doc.get("anchor"))
    return shown


def _load_vectors(root, holes):
    """({name: vector}, {name of an owner-signed vector}) for every readable file; records the file-level holes."""
    found, owner_signed = {}, set()
    owner_dir = Path(root) / _manifest().OWNER_SIGNED_DIR
    manifest = _manifest()
    try:
        paths = list(manifest.vector_files(root))
    except (manifest.ManifestError, OSError) as err:
        raise CatalogCheckError(str(err)) from err
    for path in paths:
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
        if name in found:
            holes.append(Hole("duplicate-id", name, "a file in each vector directory"))
        found[name] = doc
        if Path(path).is_relative_to(owner_dir):
            owner_signed.add(name)
    return found, owner_signed


def _planned_rows(path):
    """{id: expected text} from effective-rows.json, empty when the file is absent."""
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))["rows"]
    except (OSError, ValueError, KeyError):
        return {}
    return {i: str(r.get("expected", "")) for i, r in rows.items() if isinstance(r, dict)}


def profiles_named(vector):
    """The set of `profile` values the genesis documents of a vector's lineage carry."""
    lineage = vector.get("input", {}).get("lineage") if isinstance(vector.get("input"), dict) else None
    if not isinstance(lineage, list):
        return set()
    return {entry["doc"].get("profile") for entry in lineage
            if isinstance(entry, dict) and isinstance(entry.get("doc"), dict)}


def production_profile(root):
    """The current production profile, as `repin.py` wrote it to `conformance/pins.json`."""
    try:
        value = json.loads(_read(Path(root) / "conformance" / "pins.json"))["production_profile"]
    except (ValueError, KeyError, TypeError) as err:
        raise CatalogCheckError("conformance/pins.json has no production_profile (%s)" % err) from err
    if not isinstance(value, str):
        raise CatalogCheckError("conformance/pins.json: production_profile is not a string")
    return value


# The registry's evaluation part and its own label: everything else is the wire, and an unclassified key is wire by
# default, so a forgotten key fails closed (GP-23). `checker/python/src/handsal_check/registry.py` lists the same two
# names for its `Wire` projection; `tools/tests/test_catalog.py` fails when the two lists differ.
NOT_WIRE_KEYS = ("fixture_only", "key_classes", "registry_version")
EVALUATION_CONSTANTS = ("clock_skew_s", "max_tip_age_s", "max_validity_s", "max_view_age_s", "persons", "relays")


def wire_part(doc):
    """The part of a registry document every edition shares (I3): all but `NOT_WIRE_KEYS`, and of `constants` all but
    the policy bounds."""
    part = {key: value for key, value in doc.items() if key not in NOT_WIRE_KEYS}
    if isinstance(part.get("constants"), dict):
        part["constants"] = {k: v for k, v in part["constants"].items() if k not in EVALUATION_CONSTANTS}
    return part


def _read_registry(path):
    try:
        doc = json.loads(_read(path))
    except ValueError as err:
        raise CatalogCheckError("%s unreadable (%s)" % (path, err)) from err
    if not isinstance(doc, dict):
        raise CatalogCheckError("%s is not an object" % path)
    return doc


def _differing(first, other):
    """The names at which two wire parts differ: a top-level key, or `constants.<name>`."""
    names = []
    for key in sorted(set(first) | set(other)):
        if key == "constants" and isinstance(first.get(key), dict) and isinstance(other.get(key), dict):
            names += ["constants." + n for n in sorted(set(first[key]) | set(other[key]))
                      if first[key].get(n) != other[key].get(n)]
        elif first.get(key) != other.get(key):
            names.append(key)
    return names


def wire_holes(root, rows):
    """`wire-differs` for every registry whose wire part is not the first edition's: each later frozen edition
    (`profiles/<label>/spec/registry.json`) and the unreleased current registry (`spec/registry.json`). An edition
    never changes the wire (GP-23); a tree with no edition has nothing to compare."""
    if not rows:
        return []
    root = Path(root)
    base = wire_part(_read_registry(root / "profiles" / rows[0]["label"] / "spec" / "registry.json"))
    holes = []
    later = [(row["label"], root / "profiles" / row["label"] / "spec" / "registry.json") for row in rows[1:]]
    for subject, path in later + [("spec/registry.json", root / "spec" / "registry.json")]:
        names = _differing(base, wire_part(_read_registry(path)))
        if names:
            holes.append(Hole("wire-differs", subject, "its wire part differs from %s at: %s"
                              % (rows[0]["label"], ", ".join(names))))
    return holes


def stale_reason(named, rows, current):
    """Why an owner-signed vector is stale, or None (CF-08). `named` is the set of production profiles its lineage
    names, `rows` the catalog, `current` the unreleased current core. The tree holds the signed set of the current
    core only: a file that names no profile, or one outside the supported set (the catalog's productions and the
    current core), or one whose newest named edition (by catalog position, the current core last) is not the
    current core, is stale. An earlier edition's set stays in its tag."""
    if not named:
        return "names no profile"
    productions = [row["production"] for row in rows]
    order = productions + [current] * (current not in productions)
    outside = sorted(str(p) for p in named if p not in order)
    if outside:
        return ("names %s, outside the supported set (%s): remove it, it stays in its tag, and its id waits for a "
                "new signing run" % (", ".join(outside), ", ".join(order)))
    newest = max(named, key=order.index)
    if newest == current:
        return None
    row = rows[productions.index(newest)]
    return "belongs to %s, it stays in tag %s" % (row["label"], row["tag"])


def pending_ids(root=ROOT):
    """The ids that wait for an owner step: `pending` of vector-ids.json, and have no file yet."""
    root = Path(root)
    listing = json.loads(_read(root / "conformance" / "vector-ids.json"))
    found, _ = _load_vectors(root, [])
    return set(listing.get("pending") or []) - set(found)


def survey(root=ROOT, steps=VR02_STEPS, final=False):
    """Every hole in the tree under `root`, in a stable order."""
    root = Path(root)
    holes = []
    manifest = _manifest()
    try:
        spec = manifest.read_profile(root)
    except manifest.ManifestError as err:
        raise CatalogCheckError(str(err)) from err
    try:
        listing = json.loads(_read(root / "conformance" / "vector-ids.json"))
        ids = listing["ids"]
    except (ValueError, KeyError, TypeError) as err:
        raise CatalogCheckError("vector-ids.json unreadable (%s)" % err) from err

    found, owner_signed = _load_vectors(root, holes)

    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        holes.append(Hole("duplicate-id", dup, "listed more than once"))
    if listing.get("active_count") != len(set(ids)):
        holes.append(Hole("count-mismatch", "active_count",
                          "%r listed, %d ids" % (listing.get("active_count"), len(set(ids)))))

    waiting = set(listing.get("pending") or [])
    for name in sorted(set(ids) - set(found)):
        if name in waiting and not final:
            continue
        holes.append(Hole("missing-file", name, "pending" if name in waiting else ""))
    for name in sorted(waiting):
        if name not in set(ids):
            holes.append(Hole("pending-stale", name, "not an active id"))
        elif name in found and name not in owner_signed:
            holes.append(Hole("pending-stale", name, "has a file in the generator's directory"))
    for name in sorted(owner_signed - waiting):
        holes.append(Hole("owner-misplaced", name, "only a pending id is signed by the owner"))
    if owner_signed:
        rows = catalog_rows(root)
        current = production_profile(root)
        for name in sorted(owner_signed):
            reason = stale_reason(profiles_named(found[name]), rows, current)
            if reason:
                holes.append(Hole("owner-stale", name, reason))
    holes.extend(wire_holes(root, catalog_rows(root)))
    if final:
        try:
            classes = json.loads(_read(root / "spec" / "registry.json"))["key_classes"]
        except (ValueError, KeyError, TypeError) as err:
            raise CatalogCheckError("registry.json unreadable (%s)" % err) from err
        for entry in classes:
            if isinstance(entry, dict) and entry.get("status") == "pending-spike":
                holes.append(Hole("class-pending", str(entry.get("id")), "a tagged registry has none (KC-02)"))
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
        if name not in found and name not in waiting:
            holes.append(Hole("order-missing", name, "named in CF-07"))

    return sorted(holes, key=lambda h: (h.kind, h.subject))


CLASS_TABLE = "conformance/reason-classes.json"

def _reason_classes():
    """tools/reason_classes.py, the one owner of the class table's shape and of `classify`. Loaded by path, as the
    manifest is."""
    spec = importlib.util.spec_from_file_location("handsal_reason_classes", Path(__file__).with_name("reason_classes.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def observed_pairs(root):
    """{(command, code)} that the vectors on disk show: a vector's `command` with the top-level `reason` or `error`
    of its anchor."""
    manifest = _manifest()
    try:
        paths = list(manifest.vector_files(root))
    except (manifest.ManifestError, OSError) as err:
        raise CatalogCheckError(str(err)) from err
    pairs = set()
    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("command"), str):
            pairs |= {(doc["command"], code) for code in _anchor_codes(doc.get("anchor"))}
    return pairs


def class_holes(root):
    """Census 3 and 4 of the reason class table: every (command, code) a vector shows resolves to a class
    (`class-unresolved`), and every override is shown by a vector (`class-override-unshown`) unless the table's
    `known_gaps` names it. A gap is a ledger of what is missing, not a waiver: the vector would move the profile
    hash, so it waits for the edition cut. A gap whose override is gone or is now shown by a vector is stale and a
    hole (`class-gap-stale`), so the ledger can only shrink. A missing or unreadable table is `class-table`."""
    root = Path(root)
    classes = _reason_classes()
    try:
        table = classes.load(root / CLASS_TABLE)
    except classes.ReasonClassError as err:
        return [Hole("class-table", CLASS_TABLE, str(err))]
    pairs = observed_pairs(root)
    holes = []
    for command, code in sorted(pairs):
        try:
            classes.classify(command, code, table)
        except classes.ReasonClassError as err:
            holes.append(Hole("class-unresolved", "%s/%s" % (command, code), str(err)))
    gaps = {tuple(key.split("/", 1)) for key in table.get("known_gaps", {})}
    overrides = {(command, code) for command, per in table["by_command"].items() for code in per}
    for command, code in sorted(overrides - pairs - set(gaps)):
        holes.append(Hole("class-override-unshown", "%s/%s" % (command, code), "no vector shows this override"))
    for command, code in sorted(gaps):
        if (command, code) not in overrides:
            holes.append(Hole("class-gap-stale", "%s/%s" % (command, code), "no longer an override: drop the gap"))
        elif (command, code) in pairs:
            holes.append(Hole("class-gap-stale", "%s/%s" % (command, code), "a vector shows it now: drop the gap"))
    return holes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--vr02-steps", type=int, default=VR02_STEPS)
    parser.add_argument("--final", action="store_true", help="the tag check: pending ids are holes")
    parser.add_argument("--owner-signed", action="store_true",
                        help="print the ids the owner run signs and 'N owner-signed' as the last line; no check")
    args = parser.parse_args(argv)
    if args.owner_signed:
        try:
            ids = sorted(owner_signed_ids(args.root))
        except CatalogCheckError as err:
            print("catalog check failed: %s" % err, file=sys.stderr)
            return 2
        for name in ids:
            print(name)
        print("%d owner-signed" % len(ids))
        return 0
    try:
        holes = survey(args.root, args.vr02_steps, final=args.final) + class_holes(args.root)
        waiting = [] if args.final else sorted(pending_ids(args.root) - {h.subject for h in holes})
    except CatalogCheckError as err:
        print("catalog check failed: %s" % err, file=sys.stderr)
        return 2
    for hole in holes:
        print("%-15s %s%s" % (hole.kind, hole.subject, ("  (%s)" % hole.detail) if hole.detail else ""))
    for name in waiting:
        print("%-15s %s" % ("pending", name))
    print("%d holes, %d pending" % (len(holes), len(waiting)))
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())
