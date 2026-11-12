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

Usage: manifest.py   (prints both profile hashes)
Standard library only.
"""
import base64
import hashlib
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


def main():
    print("production %s" % production_profile())
    print("fixture    %s" % fixture_profile())
    return 0


if __name__ == "__main__":
    sys.exit(main())
