"""The core files the checker carries, and the one check that they are the profile's.

The profile hash covers the core files (CF-01; the list is `CORE_FILES`, kept equal to
`tools/manifest.py` by `tools/tests/test_core_files.py`). The checker needs the bytes
of two of them (the registry and the fixture kid list) and the hash of all of
them, so it ships those two files plus `core-manifest.json`, the
`{path: hashstr}` map. `read_checked` hands out a file only if its bytes hash
to the manifest entry. The packaged files are refreshed from the repo by
`checker/python/sync_core.py`; a test fails when they drift.

That is the current edition. A frozen edition (GP-22) has its own directory under `profiles/` with the same
relative paths and its own manifest; its list of files is whatever its core had, so `read_manifest` checks only
that every entry is a hashstr, and `read_listed` hands out a file of any edition against its own manifest. Only
the current edition is held to `CORE_FILES` (`load_manifest`).

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


def root(data_dir=None):
    """The directory the data is read from: `data_dir`, or the packaged data."""
    return PACKAGED if data_dir is None else Path(data_dir)


def read_manifest(edition):
    """The manifest `{path: hashstr}` of the edition directory `edition`, checked against its own key list: a frozen
    edition lists whatever files its core had (D4), so the only shape asked of it is hashstr values."""
    try:
        doc = json.loads(edition.joinpath(MANIFEST).read_bytes())
    except (OSError, ValueError) as err:
        raise CoreDataError("core manifest unreadable: %s" % err) from err
    if type(doc) is not dict:
        raise CoreDataError("core manifest is not an object")
    for rel, value in doc.items():
        if not encoding.is_hashstr(value):
            raise CoreDataError("core manifest entry is not a hashstr: %s" % rel)
    return doc


def load_manifest(data_dir=None):
    """The core manifest `{path: hashstr}` of the current edition, or raise CoreDataError. Only the current
    edition is held to the list of today's core files (`CORE_FILES`); a frozen one is read by `read_manifest`."""
    doc = read_manifest(root(data_dir))
    if tuple(sorted(doc)) != CORE_FILES:
        raise CoreDataError("core manifest does not list exactly the core files")
    return doc


def read_listed(edition, manifest, rel):
    """The bytes of `rel` under the edition directory `edition`, if they hash to the entry of `manifest`."""
    if rel not in manifest:
        raise CoreDataError("not a core file: %s" % rel)
    try:
        raw = edition.joinpath(rel).read_bytes()
    except OSError as err:
        raise CoreDataError("core file unreadable: %s (%s)" % (rel, err)) from err
    if encoding.hashstr(raw) != manifest[rel]:
        raise CoreDataError("core file does not match the manifest: %s" % rel)
    return raw


def read_checked(rel, data_dir=None):
    """The bytes of the packaged core file `rel`, if they hash to the manifest entry."""
    return read_listed(root(data_dir), load_manifest(data_dir), rel)
