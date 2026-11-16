"""The core manifest and the two profile hashes (CF-01, GP-18).

Single owner of the profile hash computation. Anything that needs a profile
hash (generators, tests, the release step) calls this module; no one keeps a
copy of the value.

The core manifest maps each core file path to the hashstr of its raw bytes.
The core files are the normative text (the profile parts), the registry, the
contract and the fixtures. `CORE_FILES` below is the one list: `repin.py` reads it
from here, and `tools/tests/test_core_files.py` fails when the checker, the Swift
table, the Rust table or the spec's CF-01 names a different set. Vectors are not core files: they embed the profile hash in their
genesis `profile`, so hashing them in would make the hash its own input.

    production profile = hashstr(JCS({"core": <core manifest>, "kind": "production"}))
    fixture profile    = hashstr(JCS({"core": <core manifest>, "kind": "fixture"}))

The JCS input is an object of strings, nested once, with plain ASCII keys and
values, so the canonical bytes are the sorted keys with no whitespace. The
emitter below refuses anything else instead of coercing it.

The bundle manifest is a third, separate thing (CF-01): the core manifest plus
one entry per vector file, and its hash. `spec/MANIFEST.json` records it so a
tag can publish the bundle hash. It holds no profile hash, and no profile hash
reads it: the core list below does not name it.

Usage: manifest.py                 print both profile hashes
       manifest.py --write         write spec/MANIFEST.json
       manifest.py --check         exit 0 when spec/MANIFEST.json matches the tree
       (--root DIR picks another tree; --check exits 1 on a mismatch, 2 when the
       manifest is unreadable)
Standard library only.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CORE_FILES = (
    "conformance/CONTRACT.md",
    "conformance/fixtures/fixture-kids.json",
    "conformance/fixtures/keys.json",
    "spec/profile-checks.md",
    "spec/profile-interfaces.md",
    "spec/profile-part3.md",
    "spec/profile.md",
    "spec/registry.json",
)

# The profile text is more than one file (it is split by section, each part under the size cap of
# tools/tests/test_spec_ids.py); every part is a core file, so a part nobody lists cannot be edited
# without the hash moving, and a part that is listed but absent is an error, not a skip.
PROFILE_FILES = tuple(rel for rel in CORE_FILES if rel.startswith("spec/profile"))

KINDS = ("production", "fixture")


class ManifestError(Exception):
    pass


def hashstr(raw):
    """`u` + base64url(0x12 0x20 || sha256(raw)), the profile's hash-string."""
    digest = b"\x12\x20" + hashlib.sha256(raw).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _string(text):
    for ch in text:
        if not (" " <= ch <= "~") or ch in '"\\':
            raise ManifestError("character outside the canonical subset: %r" % ch)
    return '"' + text + '"'


def _emit(value):
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, dict):
        members = sorted((_string(k), _emit(v)) for k, v in value.items())
        return "{" + ",".join(k + ":" + v for k, v in members) + "}"
    raise ManifestError("unsupported value: %r" % type(value).__name__)


def core_manifest(root=ROOT):
    """{path: hashstr(raw bytes)} for every core file under `root`."""
    root = Path(root)
    out = {}
    for rel in CORE_FILES:
        path = root / rel
        try:
            raw = path.read_bytes()
        except OSError as err:
            raise ManifestError("core file unreadable: %s (%s)" % (rel, err)) from err
        out[rel] = hashstr(raw)
    return out


def read_profile(root=ROOT):
    """The profile text: every part in `PROFILE_FILES` order, one LF between parts.

    Every reader of the normative text (the catalog check, the guard tests) goes through here, so a
    reader cannot see a different set than the hash covers."""
    root = Path(root)
    parts = []
    for rel in PROFILE_FILES:
        try:
            parts.append((root / rel).read_text(encoding="utf-8"))
        except OSError as err:
            raise ManifestError("profile part unreadable: %s (%s)" % (rel, err)) from err
    return "\n".join(parts)


def profile_hash(kind, root=ROOT):
    if kind not in KINDS:
        raise ValueError("kind must be one of %s, got %r" % (KINDS, kind))
    doc = {"core": core_manifest(root), "kind": kind}
    return hashstr(_emit(doc).encode("ascii"))


def production_profile(root=ROOT):
    return profile_hash("production", root)


def fixture_profile(root=ROOT):
    return profile_hash("fixture", root)


BUNDLE_FILE = "spec/MANIFEST.json"
# The fields of a row of `profiles/catalog.json`, in the order the repin tool writes them (GP-22). The one place the
# list is written: the repin tool and the harness read it from here.
CATALOG_ROW_FIELDS = ("label", "production", "fixture", "bundle", "tag")
VECTORS_DIR = "conformance/vectors"
# The vectors the owner signs once with production keys (PRODK, CF-08). They sit in their own directory so that
# the generator, which owns the files directly in VECTORS_DIR and rewrites them on every run, can never delete or
# regenerate them. The set of the current core lives directly in this directory; a set kept for one edition lives
# in `<OWNER_SIGNED_DIR>/<label>/`. The bundle covers both, as it covers every vector file wherever it sits.
OWNER_SIGNED_DIR = VECTORS_DIR + "/prod"
# The one folder under VECTORS_DIR that holds no vector: the generator and its tests.
GENERATOR_DIR = VECTORS_DIR + "/_gen"


def is_vector_path(rel):
    """Whether the repository path `rel` (with `/`) is a vector file of the bundle: anything under `VECTORS_DIR`
    except the generator folder. The one rule behind `vector_files` and the tag run, which asks it of git paths."""
    return rel.startswith(VECTORS_DIR + "/") and not _in_generator(rel)


def _in_generator(rel):
    return rel == GENERATOR_DIR or rel.startswith(GENERATOR_DIR + "/")


def vector_files(root=ROOT):
    """Every vector file under `root`, sorted by path: one walk of `VECTORS_DIR` that leaves out `GENERATOR_DIR`.

    The one owner of where vectors live. The vectors directory must exist; the owner-signed one does not until
    the owner step has run.
    """
    root = Path(root)
    base = root / VECTORS_DIR
    if not base.is_dir():
        raise ManifestError("vector directory unreadable: %s (not a directory)" % VECTORS_DIR)
    failures = []
    out = []
    for here, dirs, names in os.walk(base, onerror=failures.append):
        dirs[:] = sorted(d for d in dirs if not _in_generator((Path(here) / d).relative_to(root).as_posix()))
        out.extend(Path(here) / n for n in sorted(names) if (Path(here) / n).is_file())
    if failures:
        raise ManifestError("vector directory unreadable: %s (%s)" % (VECTORS_DIR, failures[0]))
    return sorted(out, key=lambda path: path.relative_to(root).as_posix())


def bundle_files(root=ROOT):
    """{path: hashstr} for the core and every vector file (`vector_files`)."""
    root = Path(root)
    files = dict(core_manifest(root))
    for path in vector_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            files[rel] = hashstr(path.read_bytes())
        except OSError as err:
            raise ManifestError("vector unreadable: %s (%s)" % (rel, err)) from err
    return files


def bundle_hash_of(files):
    return hashstr(_emit(files).encode("ascii"))


def bundle_hash(root=ROOT):
    """hashstr(JCS(core manifest plus every vector file)) (CF-01)."""
    return bundle_hash_of(bundle_files(root))


def write_bundle_manifest(root=ROOT):
    root = Path(root)
    files = bundle_files(root)
    doc = {"bundle": bundle_hash_of(files), "files": files}
    (root / BUNDLE_FILE).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_bundle_manifest(root=ROOT):
    """Problems between spec/MANIFEST.json and the tree; an empty list means a match."""
    root = Path(root)
    try:
        doc = json.loads((root / BUNDLE_FILE).read_text(encoding="utf-8"))
        recorded, recorded_hash = doc["files"], doc["bundle"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise ManifestError("bundle manifest unreadable: %s (%s)" % (BUNDLE_FILE, err)) from err
    if not isinstance(recorded, dict) or set(doc) != {"bundle", "files"}:
        raise ManifestError("bundle manifest malformed: %s" % BUNDLE_FILE)
    actual = bundle_files(root)
    problems = []
    for path in sorted(set(recorded) | set(actual)):
        if path not in actual:
            problems.append("listed but not on disk: %s" % path)
        elif path not in recorded:
            problems.append("on disk but not listed: %s" % path)
        elif recorded[path] != actual[path]:
            problems.append("hash differs: %s" % path)
    if recorded_hash != bundle_hash_of(recorded):
        problems.append("bundle hash is not the hash of the listed files")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="profile hashes and the bundle manifest")
    parser.add_argument("--root", default=str(ROOT))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.write:
            write_bundle_manifest(args.root)
            return 0
        if args.check:
            problems = check_bundle_manifest(args.root)
            for line in problems:
                print(line)
            print("bundle manifest: %s" % ("MISMATCH" if problems else "ok"))
            return 1 if problems else 0
        print("production %s" % production_profile(args.root))
        print("fixture    %s" % fixture_profile(args.root))
        return 0
    except ManifestError as err:
        print("manifest failed: %s" % err, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
