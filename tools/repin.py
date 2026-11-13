"""Re-pin after a change to a core file: one owner for every pin that has to stay.

Usage: repin.py --check | --write [--root DIR]

A core file (spec/profile.md, spec/registry.json, conformance/CONTRACT.md, the two fixture
files) is covered by the profile hash (CF-01), so an edit moves the hash and everything derived
from it. The values below are the ones that must be written down, because a pin computed by a
different path from the code under test is a real check and a copy of the code's own answer is
not. Everything else derives from the files at test time and has no literal anywhere.

Written by this tool, never by hand:
  conformance/pins.json   the two profile hashes and the two organization ids. The generator
                          tests, the bundle manifest test, the Rust tests and the Swift tests
                          read it; no test file carries a copy.
  the Swift table         `Profiles.coreManifest` in signer/apple/Sources/HandsalCore/Profiles.swift.
                          Swift cannot embed a file outside its package, so the table is a
                          copy of the five file hashes, and a test compares it with the files.

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

Exit 0 when nothing drifts (--check) or after writing (--write); 1 when --check finds a drift;
2 when an input is missing or openssl is not available. Standard library and openssl.
"""
import argparse
import base64
import json
import re
import shutil
import subprocess
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
        "wit_org_id": hashstr(canonical(docs["wit_org_id"])),
    }
    return pins, core


def pins_text(pins):
    return json.dumps(pins, indent=2, sort_keys=True) + "\n"


TABLE_ROW = re.compile(r'^(\s*)"((?:conformance|spec)/[^"]+)": "[^"]*",$')


def swift_text(text, core):
    """`text` with the `coreManifest` rows set to `core`; a row for an unknown path is an error."""
    out, seen = [], set()
    for line in text.split("\n"):
        m = TABLE_ROW.match(line)
        if m:
            path = m.group(2)
            if path not in core:
                raise RepinError("%s holds a row for %s, which is no core file" % (SWIFT, path))
            seen.add(path)
            line = '%s"%s": "%s",' % (m.group(1), path, core[path])
        out.append(line)
    if seen != set(core):
        raise RepinError("%s has no row for %s" % (SWIFT, ", ".join(sorted(set(core) - seen))))
    return "\n".join(out)


def drift(root):
    """[(file, what to run)] for every pin that is not what the files give."""
    root = Path(root)
    pins, core = compute(root)
    found = []
    if read(root, PINS).decode("utf-8") != pins_text(pins):
        found.append((PINS, "repin.py --write"))
    if read(root, SWIFT).decode("utf-8") != swift_text(read(root, SWIFT).decode("utf-8"), core):
        found.append((SWIFT, "repin.py --write"))
    try:
        shipped = json.loads(read(root, CHECKER_CORE))
    except ValueError:
        shipped = None
    if shipped != core:
        found.append((CHECKER_CORE, "checker/python/sync_core.py"))
    return found


def write(root):
    root = Path(root)
    pins, core = compute(root)
    (root / PINS).write_text(pins_text(pins), encoding="utf-8")
    swift = read(root, SWIFT).decode("utf-8")
    (root / SWIFT).write_text(swift_text(swift, core), encoding="utf-8")
    return pins


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args(argv)
    try:
        if args.write:
            pins = write(args.root)
            for name in sorted(pins):
                print("%-20s %s" % (name, pins[name]))
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
