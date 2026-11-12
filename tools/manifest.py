"""The core manifest and the two profile hashes (CF-01, GP-18).

Single owner of the profile hash computation. Anything that needs a profile
hash (generators, tests, the release step) calls this module; no one keeps a
copy of the value.

The core manifest maps each core file path to the hashstr of its raw bytes.
The core files are the normative text, the registry, the contract and the
fixtures. Vectors are not core files: they embed the profile hash in their
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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CORE_FILES = (
    "conformance/CONTRACT.md",
    "conformance/fixtures/fixture-kids.json",
    "conformance/fixtures/keys.json",
    "spec/profile.md",
    "spec/registry.json",
)

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
VECTORS_DIR = "conformance/vectors"


def bundle_files(root=ROOT):
    """{path: hashstr} for the core and every file directly in the vectors directory.

    Sub-directories (the generator in `_gen/`) hold no vector and are not listed.
    """
    root = Path(root)
    files = dict(core_manifest(root))
    vdir = root / VECTORS_DIR
    try:
        entries = sorted(vdir.iterdir())
    except OSError as err:
        raise ManifestError("vector directory unreadable: %s (%s)" % (VECTORS_DIR, err)) from err
    for path in entries:
        if not path.is_file():
            continue
        try:
            files["%s/%s" % (VECTORS_DIR, path.name)] = hashstr(path.read_bytes())
        except OSError as err:
            raise ManifestError("vector unreadable: %s (%s)" % (path.name, err)) from err
    return files


def _bundle_hash_of(files):
    return hashstr(_emit(files).encode("ascii"))


def bundle_hash(root=ROOT):
    """hashstr(JCS(core manifest plus every vector file)) (CF-01)."""
    return _bundle_hash_of(bundle_files(root))


def write_bundle_manifest(root=ROOT):
    root = Path(root)
    files = bundle_files(root)
    doc = {"bundle": _bundle_hash_of(files), "files": files}
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
    if recorded_hash != _bundle_hash_of(recorded):
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
