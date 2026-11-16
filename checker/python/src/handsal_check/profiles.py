"""The supported set of editions (CF-01, GP-07, GP-15 step 2, GP-18, GP-22).

A profile hash is the hashstr of the canonical bytes of
`{"core": <core manifest>, "kind": "production" | "fixture"}`. An **edition** is one core: it has two hashes,
the registry of its rules and its list of fixture kids. The **catalog** (`profiles/catalog.json`) is the ordered,
append-only list of the editions released so far, oldest first; each has a frozen directory `profiles/<label>/`
with the same relative paths as the packaged data (`core-manifest.json`, `spec/registry.json`,
`conformance/fixtures/fixture-kids.json`). The last edition is the current one. The current core is the newest
frozen edition, or a new unreleased edition after it, and never an older one (C4); before the founding release
there is no catalog, which is an empty catalog and one current edition.

This module is the one owner of the edition set. A document's `profile` is resolved here once, at GP-15 step 2
(`ProfileSet.check_document`) and at the pin read (`ProfileSet.resolve`); everything after reads the `Profile`
that comes back and never asks which edition it is. The position of an edition is private to this module and is
the only order there is (a `label` is a display name, never parsed or compared).

The fixture kid list of an edition is read through `coredata.read_listed`, so it is the list that edition's
hashes cover. This module only answers "is this kid listed?"; what a listed kid means under each kind is GP-18,
decided by the fold. Kid lists are append-only across editions (GP-22): a kid listed by an edition stays listed in
every newer one.
"""
import re
from collections import namedtuple

from . import coredata, emit, encoding, errors, ijson, registry

KINDS = ("production", "fixture")
CATALOG = ("profiles", "catalog.json")
ROW_KEYS = ("bundle", "fixture", "label", "production", "tag")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")   # one path segment: a label names a directory
CURRENT = "current"   # the label of an edition that is not released yet


def profile_hash(kind, manifest):
    """The profile hash of `kind` over the core `manifest` (a `{path: hashstr}` map)."""
    if kind not in KINDS:
        raise ValueError("kind must be one of %s, got %r" % (KINDS, kind))
    return encoding.hashstr(emit.emit_subset({"core": manifest, "kind": kind}))


class Version(namedtuple("Version", "position label reg fixture_kids")):
    """One edition's rules: its place in the catalog, its display label, its registry, its fixture kids."""
    __slots__ = ()

    def is_fixture_kid(self, kid):
        return type(kid) is str and kid in self.fixture_kids


Profile = namedtuple("Profile", "hash fixture version")   # what a document names; `fixture` is a bool
Edition = namedtuple("Edition", "version production fixture")   # a version with its two hashes


class ProfileSet:
    """The supported editions, oldest first. Immutable."""

    def __init__(self, editions):
        self._editions = list(editions)
        if not self._editions:
            raise coredata.CoreDataError("a profile set lists at least one edition")
        self._by_hash = {}
        previous = None
        for position, edition in enumerate(self._editions):
            version = edition.version
            if version.position != position:
                raise coredata.CoreDataError("editions are not in catalog order")
            for fixture, value in ((False, edition.production), (True, edition.fixture)):
                if value in self._by_hash:
                    raise coredata.CoreDataError("a profile hash is listed twice: %s" % value)
                self._by_hash[value] = Profile(value, fixture, version)
            if previous is not None and not previous.fixture_kids <= version.fixture_kids:
                raise coredata.CoreDataError("a fixture kid of %s is not listed by %s (GP-22)"
                                             % (previous.label, version.label))
            previous = version
        wire = self._editions[0].version.reg.wire
        if any(edition.version.reg.wire.canonical() != wire.canonical() for edition in self._editions):
            raise coredata.CoreDataError("an edition changes the wire part of the registry (GP-23, I3)")
        self.wire = wire   # the one wire view of every edition: acts are parsed once for a whole lineage

    @property
    def current(self):
        """The newest edition."""
        return self._editions[-1].version

    def editions(self):
        return list(self._editions)

    def production_hashes(self):
        """The production hash of every edition, in catalog order (SG-02)."""
        return [edition.production for edition in self._editions]

    def fixture_hashes(self):
        return [edition.fixture for edition in self._editions]

    def resolve(self, value):
        """The `Profile` that `value` names, or None for anything that is no listed hash."""
        if type(value) is not str:
            return None
        return self._by_hash.get(value)

    def check_document(self, value, previous, allow_fixture):
        """GP-15 step 2 for one lineage document; returns its `Profile` or raises Refused.

        `previous` is the `Profile` of the document before it (None for the original). `profile_mismatch` first:
        a hash no edition lists. Then `fixture_profile`: a fixture hash where the build refuses it (`allow_fixture`
        false, CF-08), or a document whose kind differs from the previous one's (a lineage mixing the two, GP-07:
        equal at every link is equal to the original). Then, for a change only, `profile_downgrade` (GP-24, I4): an
        edition older than the previous document's, by catalog position. The same edition and any newer one pass.
        The kinds are equal by then, so a mix is never a downgrade; this is the only place positions are compared.
        """
        profile = self.resolve(value)
        if profile is None:
            raise errors.Refused("profile_mismatch")
        if profile.fixture and not allow_fixture:
            raise errors.Refused("fixture_profile")
        if previous is not None and profile.fixture != previous.fixture:
            raise errors.Refused("fixture_profile")
        if previous is not None and profile.version.position < previous.version.position:
            raise errors.Refused("profile_downgrade")
        return profile


def parse_catalog(raw):
    """The rows of the catalog in `raw`, in order, or raise CoreDataError. A row is closed: `label`, `production`,
    `fixture`, `bundle`, `tag`; the label is one safe path segment and no label or hash repeats."""
    try:
        rows = ijson.loads(raw)
    except ijson.Unparseable as err:
        raise coredata.CoreDataError("catalog is not I-JSON: %s" % err) from err
    if type(rows) is not list:
        raise coredata.CoreDataError("catalog is not a list")
    labels, hashes = set(), set()
    for row in rows:
        if type(row) is not dict or tuple(sorted(row)) != ROW_KEYS:
            raise coredata.CoreDataError("catalog row does not have exactly %s" % (ROW_KEYS,))
        if type(row["label"]) is not str or not LABEL.match(row["label"]):
            raise coredata.CoreDataError("catalog label is not a safe name: %r" % (row["label"],))
        if type(row["tag"]) is not str or not row["tag"]:
            raise coredata.CoreDataError("catalog tag is not a name: %r" % (row["tag"],))
        for key in ("production", "fixture", "bundle"):
            if not encoding.is_hashstr(row[key]):
                raise coredata.CoreDataError("catalog %s is not a hashstr" % key)
        pair = {row["production"], row["fixture"]}
        if row["label"] in labels or len(pair) != 2 or pair & hashes:
            raise coredata.CoreDataError("catalog repeats a label or a profile hash")
        labels.add(row["label"])
        hashes |= pair
    return rows


def check_extends(previous, rows):
    """GP-22 S3: every row of the `previous` catalog is in `rows`, in the same place with the same two hashes. An
    empty `previous` (the previous tag has no catalog) is an empty prefix. Raises CoreDataError otherwise."""
    for place, old in enumerate(previous):
        new = rows[place] if place < len(rows) else None
        if new is None or (new["production"], new["fixture"]) != (old["production"], old["fixture"]):
            raise coredata.CoreDataError("the catalog does not keep edition %s in place %d" % (old["label"], place))


def _kids(raw):
    try:
        kids = ijson.loads(raw)
    except ijson.Unparseable as err:
        raise coredata.CoreDataError("fixture kid list is not I-JSON: %s" % err) from err
    if type(kids) is not list or not all(type(k) is str for k in kids):
        raise coredata.CoreDataError("fixture kid list is not a list of strings")
    return frozenset(kids)


def _edition(directory, manifest, position, label, production, fixture):
    for rel in (coredata.REGISTRY, coredata.FIXTURE_KIDS):
        if rel not in manifest:
            raise coredata.CoreDataError("%s: the manifest does not list %s" % (label, rel))
    reg = registry.parse(coredata.read_listed(directory, manifest, coredata.REGISTRY))
    kids = _kids(coredata.read_listed(directory, manifest, coredata.FIXTURE_KIDS))
    return Edition(Version(position, label, reg, kids), production, fixture)


def _frozen(root, position, row):
    """The edition of catalog `row`: its directory must hash to the row's two hashes (GP-22 S4)."""
    directory = root.joinpath("profiles", row["label"])
    manifest = coredata.read_manifest(directory)
    for kind in KINDS:
        if profile_hash(kind, manifest) != row[kind]:
            raise coredata.CoreDataError("%s: the frozen manifest does not hash to the catalog's %s profile"
                                         % (row["label"], kind))
    return _edition(directory, manifest, position, row["label"], row["production"], row["fixture"])


def load(data_dir=None):
    """The `ProfileSet` of the data packaged under `data_dir`: the frozen editions of the catalog, then the current
    core unless it is the newest frozen edition. A current core equal to an older edition is refused (C4)."""
    root = coredata.root(data_dir)
    catalog = root.joinpath(*CATALOG)
    rows = parse_catalog(catalog.read_bytes()) if catalog.is_file() else []
    manifest = coredata.load_manifest(data_dir)
    production, fixture = profile_hash("production", manifest), profile_hash("fixture", manifest)
    editions = [_frozen(root, position, row) for position, row in enumerate(rows)]
    listed = [edition.production for edition in editions]
    if production in listed:
        if listed.index(production) != len(listed) - 1:
            raise coredata.CoreDataError("the current core is an older edition than the newest (GP-22)")
    else:
        editions.append(_edition(root, manifest, len(editions), CURRENT, production, fixture))
    return ProfileSet(editions)
