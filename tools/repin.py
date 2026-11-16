"""Re-pin after a change to a core file: one owner for every pin that has to stay.

Usage: repin.py --check | --write | --freeze LABEL --tag TAG [--root DIR]

A core file (the profile parts under spec/, spec/registry.json, conformance/CONTRACT.md, the two fixture
files; the list is `CORE_FILES` in tools/manifest.py) is covered by the profile hash (CF-01), so an edit moves the hash and everything derived
from it. The values below are the ones that must be written down, because a pin computed by a
different path from the code under test is a real check and a copy of the code's own answer is
not. Everything else derives from the files at test time and has no literal anywhere.

Written by this tool, never by hand:
  conformance/pins.json   the two profile hashes of the current edition, the two organization ids and
                          `profiles`, the two hashes of every catalog row in catalog order. The generator
                          tests, the bundle manifest test, the Rust tests and the Swift tests
                          read it; no test file carries a copy.
  the Swift table         `Profiles.coreManifest` in signer/apple/Sources/HandsalCore/Profiles.swift.
                          Swift cannot embed a file outside its package, so the table is a
                          copy of the core file hashes, and a test compares it with the files.
  the Swift blocks        one block per catalog row between the lines `// handsal:editions begin` and
                          `// handsal:editions end` (the contract with the signer). A block is the
                          element `FrozenEdition(label:production:fixture:coreManifest:fixtureKids:registryJSON:)`
                          of an array literal, framed by `// handsal:edition begin LABEL` and
                          `// handsal:edition end LABEL`; `registryJSON` is the frozen `spec/registry.json`
                          verbatim as a raw multi-line string. The core table rows inside a block are never
                          taken for the live table: the live rows are the ones outside the region.

The catalog (`profiles/catalog.json`, CF-01, GP-22) is read here, never edited by `--write`: a row is
`{label, production, fixture, bundle, tag}`, append-only, with no commit (a commit would make the row
contain its own commit). `--write` writes only the current edition; for every row it checks that the
frozen directory still hashes to the row (computed with openssl) and that the Swift block is what the
frozen files give, and a row, a frozen file or an existing block that differs is an error: the tool only
appends. `--freeze LABEL --tag TAG` is the one step that appends: it copies the current manifest,
registry and fixture kids into `profiles/LABEL/` (the same relative paths as the checker data dir),
appends the row, and then writes the `profiles` pins and the new Swift block. The bundle hash in the row
is computed from the current tree before the write and again after it; they must be equal (the
bundle covers the core and the vector files, never `profiles/`), and a difference undoes the freeze.

Checked, not written (their own tools write them):
  checker/python/src/handsal_check/data/core-manifest.json   checker/python/sync_core.py
  spec/MANIFEST.json                                         tools/manifest.py --write

Every hash here is computed with `openssl dgst -sha256`, never with the code under test, and the
JSON is assembled with the standard library. The organization ids are the hash of the original
document of two vectors, so regenerate the vectors first: the tool refuses a vector whose
`profile` is not the fixture profile it computed.

Order after editing a core file:
  1. checker/python/sync_core.py          the checker's copy of the core
  2. conformance/vectors/_gen/generate.py regenerate the vectors
  3. tools/repin.py --write               the pins and the Swift table
  4. tools/manifest.py --write            the bundle manifest

Exit 0 when nothing drifts (--check) or after writing (--write, --freeze); 1 when --check finds a drift;
2 when an input is missing, a catalog row would have to change, a freeze is refused, or openssl is not
available. Standard library and openssl.
"""
import argparse
import base64
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]



def _manifest():
    """tools/manifest.py, the one owner of the core list and of the bundle hash. Loaded by path: under `-I` a
    script's own directory is not on the import path. Only the list and the bundle hash are shared; every
    profile hash here still comes from openssl."""
    spec = importlib.util.spec_from_file_location("handsal_manifest", Path(__file__).with_name("manifest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MANIFEST = _manifest()
CORE_FILES = MANIFEST.CORE_FILES
CATALOG = "profiles/catalog.json"
ROW_KEYS = MANIFEST.CATALOG_ROW_FIELDS
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
KID = re.compile(r"[A-Za-z0-9_-]+\Z")
# the three files of a frozen edition, with the same relative paths as the checker's data directory
FROZEN_MANIFEST = "core-manifest.json"
FROZEN_REGISTRY = "spec/registry.json"
FROZEN_KIDS = "conformance/fixtures/fixture-kids.json"
EDITIONS_BEGIN = "// handsal:editions begin"
EDITIONS_END = "// handsal:editions end"
PINS = "conformance/pins.json"
SWIFT = "signer/apple/Sources/HandsalCore/Profiles.swift"
CHECKER_CORE = "checker/python/src/handsal_check/data/core-manifest.json"
# the original documents of ORG and of WIT_ORG, as the vectors carry them
ORG_VECTOR = "conformance/vectors/cli.genesis-check-original-ok.json"
WIT_ORG_VECTOR = "conformance/vectors/wit.genesis-check-relay-ok.json"


class RepinError(Exception):
    pass


def sha256(raw):
    exe = shutil.which("openssl")
    if exe is None:
        raise RepinError("openssl is not available")
    done = subprocess.run([exe, "dgst", "-sha256", "-binary"], input=raw, capture_output=True)
    if done.returncode != 0 or len(done.stdout) != 32:
        raise RepinError("openssl dgst failed: %s" % done.stderr.decode("utf-8", "replace").strip())
    return done.stdout


def hashstr(raw):
    return "u" + base64.urlsafe_b64encode(b"\x12\x20" + sha256(raw)).rstrip(b"=").decode("ascii")


def canonical(value):
    """The sorted, compact form of the plain ASCII objects hashed here (the JCS of them)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read(root, rel):
    try:
        return (Path(root) / rel).read_bytes()
    except OSError as err:
        raise RepinError("cannot read %s (%s)" % (rel, err)) from err


def core_manifest(root):
    return {rel: hashstr(read(root, rel)) for rel in CORE_FILES}


def profile_hash(kind, core):
    return hashstr(canonical({"core": core, "kind": kind}))


def original_document(root, rel):
    try:
        return json.loads(read(root, rel))["input"]["lineage"][0]["doc"]
    except (ValueError, KeyError, IndexError, TypeError) as err:
        raise RepinError("%s has no original document (%s)" % (rel, err)) from err


def read_catalog(root):
    """The rows of `profiles/catalog.json` (none when the file is absent). A row is closed, a label is one safe
    path segment, and no label, tag or hash repeats."""
    path = Path(root) / CATALOG
    if not path.exists():
        return []
    try:
        rows = json.loads(read(root, CATALOG))
    except ValueError as err:
        raise RepinError("%s is not JSON (%s)" % (CATALOG, err)) from err
    if not isinstance(rows, list):
        raise RepinError("%s is not a list" % CATALOG)
    labels, tags, hashes = set(), set(), set()
    for row in rows:
        if not isinstance(row, dict) or tuple(row) != ROW_KEYS or not all(isinstance(v, str) for v in row.values()):
            raise RepinError("%s: a row has exactly the string keys %s, in that order" % (CATALOG, ", ".join(ROW_KEYS)))
        if not LABEL.match(row["label"]) or not row["tag"].strip():
            raise RepinError("%s: %r is not a safe label with a tag" % (CATALOG, row["label"]))
        pair = {row["production"], row["fixture"]}
        if row["label"] in labels or row["tag"] in tags or len(pair) != 2 or pair & hashes:
            raise RepinError("%s repeats a label, a tag or a hash (%s)" % (CATALOG, row["label"]))
        labels.add(row["label"])
        tags.add(row["tag"])
        hashes |= pair
    return rows


def frozen_edition(root, row):
    """(core manifest, registry text, kids) of the frozen directory of `row`, checked with openssl against the row:
    both profile hashes, and the registry and kid bytes against the manifest. The tool never repairs a mismatch."""
    folder = Path(root) / "profiles" / row["label"]

    def fail(what):
        return RepinError("catalog row %s: %s; a row and a frozen directory are never edited, only appended"
                          % (row["label"], what))

    try:
        manifest = json.loads(read(folder, FROZEN_MANIFEST))
    except ValueError as err:
        raise fail("%s is not JSON (%s)" % (FROZEN_MANIFEST, err)) from err
    if not isinstance(manifest, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in manifest.items()):
        raise fail("%s is not an object of strings" % FROZEN_MANIFEST)
    if (profile_hash("production", manifest), profile_hash("fixture", manifest)) != (row["production"], row["fixture"]):
        raise fail("the frozen manifest does not hash to the row")
    registry, kids = read(folder, FROZEN_REGISTRY), read(folder, FROZEN_KIDS)
    if manifest.get(FROZEN_REGISTRY) != hashstr(registry) or manifest.get(FROZEN_KIDS) != hashstr(kids):
        raise fail("the frozen registry or kid file does not hash to the manifest")
    try:
        kid_list = json.loads(kids)
    except ValueError as err:
        raise fail("the kid file is not JSON") from err
    if not isinstance(kid_list, list) or not all(isinstance(k, str) and KID.match(k) for k in kid_list):
        raise fail("the kid file is not a list of kids")
    try:
        text = registry.decode("utf-8")
    except UnicodeDecodeError as err:
        raise fail("the registry is not UTF-8") from err
    if "\r" in text or '"""#' in text or "\\#" in text:
        raise fail("the registry cannot be embedded verbatim in a Swift raw string")
    return manifest, text, kid_list


def edition_block(root, row):
    """The Swift block of one catalog row, every line ending in a newline."""
    manifest, registry, kids = frozen_edition(root, row)
    lines = ["    // handsal:edition begin %s" % row["label"],
             "    FrozenEdition(",
             '        label: "%s",' % row["label"],
             '        production: "%s",' % row["production"],
             '        fixture: "%s",' % row["fixture"],
             "        coreManifest: ["]
    lines += ['            "%s": "%s",' % (rel, manifest[rel]) for rel in sorted(manifest)]
    lines += ["        ],", "        fixtureKids: ["]
    lines += ['            "%s",' % kid for kid in kids]
    lines += ["        ],", '        registryJSON: #"""']
    return "\n".join(lines) + "\n" + registry + '\n"""#),\n    // handsal:edition end %s\n' % row["label"]


def edition_blocks(root):
    return [edition_block(root, row) for row in read_catalog(root)]


def catalog_pins(root):
    """[{label, production, fixture}] in catalog order, each recomputed from its frozen manifest with openssl."""
    pins = []
    for row in read_catalog(root):
        frozen_edition(root, row)
        pins.append({"label": row["label"], "production": row["production"], "fixture": row["fixture"]})
    return pins


def compute(root):
    """{pins, core}: every value, computed from the files under `root`."""
    core = core_manifest(root)
    fixture = profile_hash("fixture", core)
    docs = {"org_id": original_document(root, ORG_VECTOR), "wit_org_id": original_document(root, WIT_ORG_VECTOR)}
    for name, doc in docs.items():
        if doc.get("profile") != fixture:
            raise RepinError("%s: the vectors name another profile than the files give: regenerate them first" % name)
    pins = {
        "fixture_profile": fixture,
        "production_profile": profile_hash("production", core),
        "org_id": hashstr(canonical(docs["org_id"])),
        "profiles": catalog_pins(root),
        "wit_org_id": hashstr(canonical(docs["wit_org_id"])),
    }
    return pins, core


def pins_text(pins):
    return json.dumps(pins, indent=2, sort_keys=True) + "\n"


TABLE_ROW = re.compile(r'^(\s*)"((?:conformance|spec)/[^"]+)": "[^"]*",$')


def _region(lines):
    """(begin, end) line indexes of the editions markers, or None when the file has none."""
    begins = [i for i, line in enumerate(lines) if line.strip() == EDITIONS_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == EDITIONS_END]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0] > ends[0]:
        raise RepinError("%s needs one `%s` line before one `%s` line" % (SWIFT, EDITIONS_BEGIN, EDITIONS_END))
    return begins[0], ends[0]


def _live_rows(lines, core):
    out, seen = [], set()
    for line in lines:
        m = TABLE_ROW.match(line)
        if m:
            path = m.group(2)
            if path not in core:
                raise RepinError("%s holds a row for %s, which is no core file" % (SWIFT, path))
            seen.add(path)
            line = '%s"%s": "%s",' % (m.group(1), path, core[path])
        out.append(line)
    return out, seen


def swift_text(text, core, blocks=()):
    """`text` with the `coreManifest` rows set to `core` and the edition region holding `blocks`.

    The region is append-only: what it holds now must be a prefix of what the catalog gives, so an edited
    block, or a catalog that lost a row, is an error and never a rewrite. A row for an unknown path is an error."""
    lines = text.split("\n")
    region = _region(lines)
    expected = "".join(blocks)
    if region is None:
        if blocks:
            raise RepinError("%s has no `%s` and `%s` lines for the catalog editions" % (SWIFT, EDITIONS_BEGIN, EDITIONS_END))
        head, middle, tail = lines, [], []
    else:
        begin, end = region
        held = "".join(line + "\n" for line in lines[begin + 1:end])
        if not expected.startswith(held):
            raise RepinError("%s: an existing edition block is not what the frozen files give; blocks are only appended"
                             % SWIFT)
        head, middle, tail = lines[:begin + 1], expected.split("\n")[:-1] if expected else [], lines[end:]
    live_head, seen_head = _live_rows(head, core)
    live_tail, seen_tail = _live_rows(tail, core)
    if (seen_head | seen_tail) != set(core):
        raise RepinError("%s has no row for %s" % (SWIFT, ", ".join(sorted(set(core) - (seen_head | seen_tail)))))
    return "\n".join(live_head + middle + live_tail)


def drift(root):
    """[(file, what to run)] for every pin that is not what the files give."""
    root = Path(root)
    pins, core = compute(root)
    found = []
    if read(root, PINS).decode("utf-8") != pins_text(pins):
        found.append((PINS, "repin.py --write"))
    current = read(root, SWIFT).decode("utf-8")
    if current != swift_text(current, core, edition_blocks(root)):
        found.append((SWIFT, "repin.py --write"))
    try:
        shipped = json.loads(read(root, CHECKER_CORE))
    except ValueError:
        shipped = None
    if shipped != core:
        found.append((CHECKER_CORE, "checker/python/sync_core.py"))
    return found


def write(root):
    """The pins and the Swift file for the current edition and the catalog. Every text is built before any file is
    written, so a refusal leaves the tree as it was. Nothing under `profiles/` is opened for writing."""
    root = Path(root)
    pins, core = compute(root)
    swift = swift_text(read(root, SWIFT).decode("utf-8"), core, edition_blocks(root))
    (root / PINS).write_text(pins_text(pins), encoding="utf-8")
    (root / SWIFT).write_text(swift, encoding="utf-8")
    return pins


def freeze(root, label, tag):
    """Append the current edition to the catalog: the frozen directory, the row, the pins and the Swift block."""
    root = Path(root)
    if not LABEL.match(label):
        raise RepinError("freeze: %r is not a label (one path segment of letters, digits, dot, dash, underscore)" % label)
    if not tag.strip():
        raise RepinError("freeze: the tag is empty; the owner names it before the freeze")
    found = drift(root)
    if found:
        raise RepinError("freeze: the pins are not current (%s); run the re-pin steps first, a freeze changes no value"
                         % ", ".join(name for name, _ in found))
    rows = read_catalog(root)
    pins, core = compute(root)
    if label in {r["label"] for r in rows} or (root / "profiles" / label).exists():
        raise RepinError("freeze: the label %s is already used" % label)
    if tag in {r["tag"] for r in rows}:
        raise RepinError("freeze: the tag %s is already used by an earlier row" % tag)
    if pins["production_profile"] in {r["production"] for r in rows}:
        raise RepinError("freeze: the current core already is a catalog edition; a new edition needs a core change")
    bundle = MANIFEST.bundle_hash(root)
    row = {"label": label, "production": pins["production_profile"], "fixture": pins["fixture_profile"],
           "bundle": bundle, "tag": tag}
    folder, catalog = root / "profiles" / label, root / CATALOG
    old_catalog = catalog.read_bytes() if catalog.exists() else None
    made_profiles = not (root / "profiles").exists()
    try:
        for rel, raw in ((FROZEN_MANIFEST, (json.dumps(core, indent=2, sort_keys=True) + "\n").encode("utf-8")),
                         (FROZEN_REGISTRY, read(root, "spec/registry.json")),
                         (FROZEN_KIDS, read(root, "conformance/fixtures/fixture-kids.json"))):
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_bytes(raw)
        catalog.write_text(json.dumps(rows + [row], indent=2) + "\n", encoding="utf-8")
        if MANIFEST.bundle_hash(root) != bundle:
            raise RepinError("freeze: the bundle hash moved when profiles/ was written; the bundle covers profiles/ "
                             "and the row would be a fixed point: stop and report")
        write(root)
    except BaseException:
        shutil.rmtree(root / "profiles" if made_profiles else folder, ignore_errors=True)
        if old_catalog is not None:
            catalog.write_bytes(old_catalog)
        raise
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--freeze", metavar="LABEL", help="append the current edition to the catalog (needs --tag)")
    parser.add_argument("--tag", help="the tag name the owner chose for the edition being frozen")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args(argv)
    if args.freeze is not None and args.tag is None:
        parser.error("--freeze needs --tag")
    try:
        if args.freeze is not None:
            row = freeze(args.root, args.freeze, args.tag)
            print("froze %s: production %s, fixture %s, bundle %s, tag %s"
                  % (row["label"], row["production"], row["fixture"], row["bundle"], row["tag"]))
            return 0
        if args.write:
            pins = write(args.root)
            for name in sorted(pins):
                if name != "profiles":
                    print("%-20s %s" % (name, pins[name]))
            for entry in pins["profiles"]:
                print("%-20s %s" % ("profile " + entry["label"], entry["production"]))
            return 0
        found = drift(args.root)
    except RepinError as err:
        print("repin failed: %s" % err, file=sys.stderr)
        return 2
    for name, fix in found:
        print("drift: %s (run %s)" % (name, fix))
    if not found:
        print("pins ok")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
