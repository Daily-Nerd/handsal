"""Synthetic editions for the profile-set tests (GP-22 to GP-24).

Two forms, for two kinds of test. `Workspace` is a temporary copy of the packaged data directory to which
frozen editions can be added on disk, so the loader reads real files. `synthetic_set` builds a `ProfileSet`
in memory, so a rule test can name an older and a newer edition without a tree. Neither touches the repo.
"""
import json
import shutil
import tempfile
from pathlib import Path

from handsal_check import coredata, encoding, ijson, profiles, registry

CATALOG = "profiles/catalog.json"
EDITION_FILES = (coredata.REGISTRY, coredata.FIXTURE_KIDS)


def dump(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def registry_doc(version, edit=None):
    """The packaged registry with `registry_version` set to `version`: an edition that differs from the real one
    in one wire-neutral value, so its manifest and both hashes differ. `edit(doc)` changes the document further."""
    doc = ijson.loads(coredata.read_checked(coredata.REGISTRY))
    doc["registry_version"] = version
    if edit is not None:
        edit(doc)
    return doc


class GuardedWire:
    """A wire that fails the test on anything a parser may not read: an evaluation constant, a class, a policy
    bound, any attribute the wire view does not have. It answers what the real wire answers, so a parser handed
    this value and the real one must give the same result."""

    def __init__(self, wire):
        self._wire = wire

    methods = property(lambda self: self._wire.methods)
    act_extra_key_types = property(lambda self: self._wire.act_extra_key_types)

    def method(self, name):
        return self._wire.method(name)

    def number(self, *path):
        if path[0] in registry.EVALUATION_CONSTANTS:
            raise AssertionError("a parser read the evaluation constant %s" % path[0])
        return self._wire.number(*path)

    def __getattr__(self, name):
        raise AssertionError("a parser read %s, which is no part of the wire" % name)


def production_of(profile_set):
    """The production hash of the newest edition of `profile_set`: the one a document under test names."""
    return profile_set.production_hashes()[-1]


def fixture_of(profile_set):
    """The fixture hash of the newest edition of `profile_set`."""
    return profile_set.fixture_hashes()[-1]


def without_fixture_kids(profile_set):
    """The same editions with no fixture kid listed, for tests where fixture keys sign a production document."""
    return profiles.ProfileSet([
        profiles.Edition(profiles.Version(v.position, v.label, v.reg, frozenset()), production, fixture)
        for v, production, fixture in profile_set.editions()])


def make_registry(version, edit=None):
    return registry.Registry(registry_doc(version, edit))


def synthetic_set(count=2, kids=None, edits=None):
    """A `ProfileSet` of `count` editions named e1, e2, ..., oldest first. `kids` is a list of fixture kid lists, one
    per edition (default: none listed). Every edition has its own registry value and its own two hashes."""
    kids = kids or [[] for _ in range(count)]
    editions = []
    for position in range(count):
        label = "e%d" % (position + 1)
        manifest = {coredata.REGISTRY: encoding.hashstr(label.encode())}
        version = profiles.Version(position, label, make_registry(str(position + 1), (edits or {}).get(position)),
                                   frozenset(kids[position]))
        editions.append(profiles.Edition(version, profiles.profile_hash("production", manifest),
                                         profiles.profile_hash("fixture", manifest)))
    return profiles.ProfileSet(editions)


class Workspace:
    """A temporary packaged data directory (`data`) that frozen editions can be added to."""

    def __init__(self, case):
        self.tmp = Path(tempfile.mkdtemp())
        case.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / "data"
        shutil.copytree(coredata.DATA_DIR, self.data)
        self.rows = []

    def _write_catalog(self):
        target = self.data / CATALOG
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(dump(self.rows))

    def _row(self, label, manifest):
        return {"label": label,
                "production": profiles.profile_hash("production", manifest),
                "fixture": profiles.profile_hash("fixture", manifest),
                "bundle": encoding.hashstr(b"bundle " + label.encode()),
                "tag": "tag-" + label}

    def freeze(self, label, version=None, kids=None, extra_core=(), edit=None):
        """Add a frozen edition `label` and append its catalog row. Its registry differs from the real one in
        `registry_version`; `kids` is its fixture kid list (default: the real one); `extra_core` names core paths
        its manifest lists that the directory does not carry (a version whose file list differs from today's)."""
        edition = self.data / "profiles" / label
        files = {coredata.REGISTRY: dump(registry_doc(version or label, edit)),
                 coredata.FIXTURE_KIDS: dump(json.loads((self.data / coredata.FIXTURE_KIDS).read_bytes())
                                             if kids is None else kids)}
        manifest = {rel: encoding.hashstr(raw) for rel, raw in files.items()}
        for rel in extra_core:
            manifest[rel] = encoding.hashstr(rel.encode())
        for rel, raw in files.items():
            (edition / rel).parent.mkdir(parents=True, exist_ok=True)
            (edition / rel).write_bytes(raw)
        (edition / coredata.MANIFEST).write_bytes(dump(manifest))
        self.rows.append(self._row(label, manifest))
        self._write_catalog()
        return self.rows[-1]

    def freeze_current(self, label):
        """Add the current core as a frozen edition: the edition the repo is at after a tag."""
        edition = self.data / "profiles" / label
        for rel in (coredata.MANIFEST,) + EDITION_FILES:
            (edition / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.data / rel, edition / rel)
        manifest = json.loads((self.data / coredata.MANIFEST).read_bytes())
        self.rows.append(self._row(label, manifest))
        self._write_catalog()
        return self.rows[-1]

    def rewrite(self, rel, edit):
        """Replace the bytes of `rel` (relative to the data directory) by `edit(bytes)`."""
        path = self.data / rel
        path.write_bytes(edit(path.read_bytes()))

    def catalog(self):
        return json.loads((self.data / CATALOG).read_bytes())

    def set_catalog(self, rows):
        self.rows = rows
        self._write_catalog()
