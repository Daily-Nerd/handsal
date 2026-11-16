"""Catalog check: every hole in the vector set, reported (CF-07, CF-02).

Usage: check_catalog.py [--root DIR] [--vr02-steps N] [--final]

Reads the profile parts (`manifest.PROFILE_FILES`), `conformance/vector-ids.json` and every vector file
(`manifest.vector_files`: every file under `conformance/vectors/` but the generator folder, among them the owner-signed `conformance/vectors/prod/`), and lists every hole it finds. It writes nothing and
never invents a vector: a hole is listed so the generator author can fill it.
Exit 0 when there is no hole, 1 otherwise, 2 when an input is unreadable.

One switch (CF-08 S8): while `profiles/catalog.json` lists fewer than two editions, the group `prf` is pending
by rule. Its ids are no hole at `--final`, and a `prf/` row of effective-rows.json that shows exactly one reason
code counts as the only-defect vector of that code (CF-07); an ordering row never does, it carries a second defect.
With two editions both revert: the ids are holes and the codes need a vector on disk. No code is named here.

An id that waits for an owner step is listed in `pending` (production-key vectors, CF-08) in
vector-ids.json. Its file is signed by the owner (T7.2) and lives in `conformance/vectors/prod/`, a directory the
generator never writes. Without a file the id is no hole, and it is printed as pending. `--final` is
the check at the tag: every such id without a file is a hole, and so is a registry class whose status is `pending-spike` (KC-02).

Hole kinds:
  missing-file     an id of vector-ids.json with no file on disk (pending ids only with --final)
  pending-stale    a `pending` id whose file is in the generator's directory, or that is not an active id
  owner-misplaced  a file in `conformance/vectors/prod/` whose id is not `pending`
  owner-stale      an owner-signed file (`conformance/vectors/prod/`, or `prod/<label>/` for one edition's set)
                   whose genesis documents name no production profile, or one outside the supported set: the
                   catalog's productions plus the unreleased current core of `conformance/pins.json` (before
                   founding the catalog is empty and the current core is the only valid one). A set that names
                   only supported editions is never stale and never removed. A file under `prod/<label>/` must
                   name that edition as the newest it names (a cross-edition set is signed in the newer
                   edition's run); a directory that is no catalog label holds only stale files (CF-08)
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


CROSS_EDITION_GROUP = "prf/"
EDITIONS_NEEDED = 2


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


def edition_count(root):
    """How many editions `profiles/catalog.json` lists; a tree without the file has none."""
    return len(catalog_rows(root))


def pending_by_rule(root, names):
    """The names of `names` that wait for a second edition: the group `prf`, while the catalog has fewer than two."""
    if edition_count(root) >= EDITIONS_NEEDED:
        return set()
    return {n for n in names if n.startswith(CROSS_EDITION_GROUP)}


def owner_signed_ids(root):
    """The ids the owner run signs: `pending` of vector-ids.json without the ids that wait for a second edition.
    `pending` holds both kinds (CF-08); this is the one place that tells them apart, and the generator's owner run
    reads it from here."""
    listing = json.loads(_read(Path(root) / "conformance" / "vector-ids.json"))
    waiting = set(listing.get("pending") or [])
    return waiting - pending_by_rule(root, waiting)


def rule_anchored_codes(root, codes, on_disk):
    """The codes that a pending-by-rule id shows as its only defect (CF-07): the `prf/` ids with no file whose
    row in effective-rows.json is no ordering vector and names exactly one of `codes`."""
    planned = _planned_rows(Path(root) / "conformance" / "effective-rows.json")
    shown = set()
    for name in pending_by_rule(root, planned):
        if name in on_disk or _is_ordering(name):
            continue
        named = [c for c in set(TICKED.findall(planned[name])) if c in codes]
        if len(named) == 1:
            shown.add(named[0])
    return shown


def _anchor_codes(anchor):
    try:
        doc = json.loads(anchor)
    except (TypeError, ValueError):
        return set()
    if not isinstance(doc, dict):
        return set()
    return {doc[k] for k in ("reason", "error") if isinstance(doc.get(k), str)}


def anchor_codes(root=ROOT, include_ordering=True):
    """The codes shown by the anchors of the vector files on disk (top-level `reason` or `error`), and the codes
    of the ids that are pending by rule (`rule_anchored_codes`)."""
    shown, on_disk = set(), set()
    for path in _manifest().vector_files(root):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("name"), str):
            on_disk.add(doc["name"])
            if include_ordering or not _is_ordering(doc["name"]):
                shown |= _anchor_codes(doc.get("anchor"))
    try:
        codes, _retired, _excepted = spec_codes(_manifest().read_profile(root))
    except _manifest().ManifestError as err:
        raise CatalogCheckError(str(err)) from err
    return shown | rule_anchored_codes(root, set(codes), on_disk)


def _owner_label(root, path):
    """`(True, label)` for a file under the owner-signed directory: `label` is the edition directory it is kept in,
    None when it sits directly in it. `(False, None)` for any other vector."""
    try:
        parts = Path(path).relative_to(Path(root) / _manifest().OWNER_SIGNED_DIR).parts
    except ValueError:
        return False, None
    return True, (parts[0] if len(parts) > 1 else None)


def _load_vectors(root, holes):
    """({name: vector}, {name of an owner-signed vector}, {name: label of the edition directory it is kept in})
    for every readable file; records the file-level holes."""
    found, owner_signed, kept_for = {}, set(), {}
    manifest = _manifest()
    try:
        paths = list(manifest.vector_files(root))
    except (manifest.ManifestError, OSError) as err:
        raise CatalogCheckError(str(err)) from err
    for path in paths:
        owned, label = _owner_label(root, path)
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
        if owned:
            owner_signed.add(name)
        if label is not None:
            kept_for[name] = label
    return found, owner_signed, kept_for


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


def stale_reason(named, label, rows, supported):
    """Why an owner-signed vector is stale, or None (CF-08). `named` is the set of production profiles its lineage
    names, `label` the edition directory it is kept in (None directly in `prod/`), `rows` the catalog, `supported`
    the catalog productions plus the unreleased current core. A set that names only supported editions is never
    stale; one that names none, or one outside the set, is. A file kept for an edition names that edition as
    the newest it names: the cross-edition sets are signed in the newer edition's run."""
    if not named:
        return "names no profile"
    outside = sorted(str(p) for p in named if p not in supported)
    if outside:
        return ("names %s, outside the supported set (%s): remove it, it stays in its tag, and its id waits for a "
                "new signing run" % (", ".join(outside), ", ".join(supported)))
    if label is None:
        return None
    productions = [row["production"] for row in rows]
    mine = [row["production"] for row in rows if row["label"] == label]
    if not mine:
        return "kept under prod/%s/, which is no edition of the catalog" % label
    newest = max((productions.index(p) if p in productions else len(productions)) for p in named)
    if newest != productions.index(mine[0]):
        return "kept for %s (%s) but its newest named edition is another: %s" % (
            label, mine[0], ", ".join(sorted(map(str, named))))
    return None


def pending_ids(root=ROOT):
    """The ids that wait for an owner step: `pending` of vector-ids.json, and have no file yet."""
    root = Path(root)
    listing = json.loads(_read(root / "conformance" / "vector-ids.json"))
    found, _, _ = _load_vectors(root, [])
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

    found, owner_signed, kept_for = _load_vectors(root, holes)

    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        holes.append(Hole("duplicate-id", dup, "listed more than once"))
    if listing.get("active_count") != len(set(ids)):
        holes.append(Hole("count-mismatch", "active_count",
                          "%r listed, %d ids" % (listing.get("active_count"), len(set(ids)))))

    waiting = set(listing.get("pending") or [])
    by_rule = pending_by_rule(root, waiting)
    for name in sorted(set(ids) - set(found)):
        if name in by_rule or (name in waiting and not final):
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
        productions = [row["production"] for row in rows]
        current = production_profile(root)
        supported = productions + [current] * (current not in productions)
        for name in sorted(owner_signed):
            reason = stale_reason(profiles_named(found[name]), kept_for.get(name), rows, supported)
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
    shown = rule_anchored_codes(root, set(codes), set(found))
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--vr02-steps", type=int, default=VR02_STEPS)
    parser.add_argument("--final", action="store_true", help="the tag check: pending ids are holes")
    args = parser.parse_args(argv)
    try:
        holes = survey(args.root, args.vr02_steps, final=args.final)
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
