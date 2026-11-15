"""The core files the checker carries, and the one check that they are the profile's.

The profile hash covers the core files (CF-01; the list is `CORE_FILES`, kept equal to
`tools/manifest.py` by `tools/tests/test_core_files.py`). The checker needs the bytes
of two of them (the registry and the fixture kid list) and the hash of all of
them, so it ships those two files plus `core-manifest.json`, the
`{path: hashstr}` map. `read_checked` hands out a file only if its bytes hash
to the manifest entry. The packaged files are refreshed from the repo by
`checker/python/sync_core.py`; a test fails when they drift.

Reading goes through `importlib.resources`, so the same code runs from an
unpacked tree and from inside a zipapp (the production artifact, T4.5). `DATA_DIR`
is the real directory, for the writer (`sync_core.py`) and the tests that copy
it; a reader that names no directory takes `PACKAGED`.

A failure here is a broken installation, not bad input: it raises
`CoreDataError` and the command crashes loudly instead of running on a
registry it cannot vouch for.
"""
import json
from importlib import resources
from pathlib import Path

from . import encoding

DATA_DIR = Path(__file__).resolve().parent / "data"
PACKAGED = resources.files(__package__).joinpath("data")
MANIFEST = "core-manifest.json"
CORE_FILES = (
    "conformance/CONTRACT.md",
    "conformance/fixtures/fixture-kids.json",
    "conformance/fixtures/keys.json",
    "spec/profile-interfaces.md",
    "spec/profile-part3.md",
    "spec/profile.md",
    "spec/registry.json",
)
REGISTRY = "spec/registry.json"
FIXTURE_KIDS = "conformance/fixtures/fixture-kids.json"


class CoreDataError(Exception):
    pass


def _root(data_dir):
    return PACKAGED if data_dir is None else Path(data_dir)


def load_manifest(data_dir=None):
    """The core manifest `{path: hashstr}`, or raise CoreDataError."""
    try:
        doc = json.loads(_root(data_dir).joinpath(MANIFEST).read_bytes())
    except (OSError, ValueError) as err:
        raise CoreDataError("core manifest unreadable: %s" % err) from err
    if type(doc) is not dict or tuple(sorted(doc)) != CORE_FILES:
        raise CoreDataError("core manifest does not list exactly the core files")
    for rel, value in doc.items():
        if not encoding.is_hashstr(value):
            raise CoreDataError("core manifest entry is not a hashstr: %s" % rel)
    return doc


def read_checked(rel, data_dir=None):
    """The bytes of the packaged core file `rel`, if they hash to the manifest entry."""
    manifest = load_manifest(data_dir)
    if rel not in manifest:
        raise CoreDataError("not a core file: %s" % rel)
    try:
        raw = _root(data_dir).joinpath(rel).read_bytes()
    except OSError as err:
        raise CoreDataError("core file unreadable: %s (%s)" % (rel, err)) from err
    if encoding.hashstr(raw) != manifest[rel]:
        raise CoreDataError("core file does not match the manifest: %s" % rel)
    return raw
