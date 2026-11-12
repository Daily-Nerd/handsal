"""Profiles (CF-01, GP-07, GP-18): the two hashes, what is implemented, the fixture kid list.

A profile hash is the hashstr of the canonical bytes of
`{"core": <core manifest>, "kind": "production" | "fixture"}`. The checker holds
the core manifest (`coredata`) and computes both hashes from it with its own
emitter, so the profiles it implements are a function of the files it carries,
not a second constant to keep in step. Version 1 implements exactly these two.

The fixture kid list is read through `coredata.read_checked`, so it is the list
the profile hash covers. This module only answers "is this kid listed?"; what a
listed kid means under each profile is GP-18, decided by the fold.
"""
from . import coredata, emit, encoding, errors, ijson

KINDS = ("production", "fixture")


def profile_hash(kind, manifest):
    """The profile hash of `kind` over the core `manifest` (a `{path: hashstr}` map)."""
    if kind not in KINDS:
        raise ValueError("kind must be one of %s, got %r" % (KINDS, kind))
    return encoding.hashstr(emit.emit_subset({"core": manifest, "kind": kind}))


class Profiles:
    def __init__(self, manifest, fixture_kids):
        self.production = profile_hash("production", manifest)
        self.fixture = profile_hash("fixture", manifest)
        self.fixture_kids = frozenset(fixture_kids)

    def kind(self, profile):
        """`"production"`, `"fixture"` or None for a value that is no implemented profile."""
        if type(profile) is not str:
            return None
        if profile == self.production:
            return "production"
        if profile == self.fixture:
            return "fixture"
        return None

    def implemented(self, profile):
        return self.kind(profile) is not None

    def is_fixture_kid(self, kid):
        return type(kid) is str and kid in self.fixture_kids

    def check_document(self, profile, first_kind, allow_fixture):
        """GP-15 step 2 for one lineage document; returns its kind or raises Refused.

        `first_kind` is the kind of the lineage's original document (None when this document is
        the original). `profile_mismatch` first: an unimplemented profile. Then `fixture_profile`:
        a fixture profile where the build refuses it (`allow_fixture` false, CF-08), or a document
        whose kind differs from the original's (a lineage mixing the two, GP-07).
        """
        kind = self.kind(profile)
        if kind is None:
            raise errors.Refused("profile_mismatch")
        if kind == "fixture" and not allow_fixture:
            raise errors.Refused("fixture_profile")
        if first_kind is not None and kind != first_kind:
            raise errors.Refused("fixture_profile")
        return kind


def load(data_dir=None):
    """The profiles of the core data packaged under `data_dir`."""
    manifest = coredata.load_manifest(data_dir)
    raw = coredata.read_checked(coredata.FIXTURE_KIDS, data_dir)
    try:
        kids = ijson.loads(raw)
    except ijson.Unparseable as err:
        raise coredata.CoreDataError("fixture kid list is not I-JSON: %s" % err) from err
    if type(kids) is not list or not all(type(k) is str for k in kids):
        raise coredata.CoreDataError("fixture kid list is not a list of strings")
    return Profiles(manifest, kids)
