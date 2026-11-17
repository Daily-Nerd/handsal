"""The profile set (GP-22, GP-15 step 2, GP-05 S6, CF-01, CF-08): the loader, the frozen data, the rules.

The real repo has no `profiles/` directory until the founding freeze, so every case that needs a frozen
edition builds a temporary tree (`profile_sets.Workspace`) or an in-memory set (`profile_sets.synthetic_set`). The
real-repo cases are written over the real catalog and are trivial while it is empty.
"""
import ast
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from handsal_check import (acts, chain, checkact, coredata, encoding, epoch, errors, genesis, genesis_check, genesis_sigs,
                           profiles, recheck, registry, render, render_attach, render_genesis)

from . import test_sync
from .act_builder import FakeVitni, genesis_sign, head_of, kid_of
from .checkact_world import NOW, Scenario, probe_for
from .fold_world import World
from .genesis_fixtures import change, device, edit, policy
from .profile_sets import CATALOG, GuardedWire, Workspace, dump, registry_doc, synthetic_set

ROOT = Path(__file__).resolve().parents[3]
PROJECT = Path(__file__).resolve().parents[1]
UNKNOWN = encoding.hashstr(b"an edition no catalog entry lists")
WIRE_DIGEST = "uEiAgAeRs0Do396Yp2uhzY4UYe8T--TzRzTrXazRS9vedyg"   # the canonical bytes of the wire part, hashed
EVALUATION_NAMES = ("key_classes", "fixture_only", "classes", "lookup_class", "persons", "relays", "clock_skew_s",
                    "max_validity_s", "max_view_age_s", "max_tip_age_s")
PARSERS = ("acts", "chain", "envelope", "schema", "genesis_sigs", "render")


def code_of(call, *args):
    try:
        call(*args)
    except errors.Refused as err:
        return err.code
    return None


def tools_core_files():
    spec = importlib.util.spec_from_file_location("tools_manifest", ROOT / "tools" / "manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CORE_FILES


def real_catalog():
    """The catalog of the repo: `[]` until the founding freeze."""
    path = ROOT / CATALOG
    return json.loads(path.read_bytes()) if path.exists() else []


def current_hashes(data_dir):
    manifest = coredata.load_manifest(data_dir)
    return profiles.profile_hash("production", manifest), profiles.profile_hash("fixture", manifest)


class Loader(unittest.TestCase):
    def test_no_catalog_is_an_empty_catalog_and_one_current_edition(self):
        ws = Workspace(self)
        self.assertFalse((ws.data / CATALOG).exists())
        got = profiles.load(ws.data)
        production, fixture = current_hashes(ws.data)
        self.assertEqual(got.production_hashes(), [production])
        self.assertEqual(got.fixture_hashes(), [fixture])
        self.assertEqual((got.current.position, got.resolve(production).version), (0, got.current))

    def test_the_real_repo_lists_its_catalog_and_the_current_core(self):
        count = len(real_catalog())   # 0 until the founding freeze: one current edition and no frozen one
        self.assertIn(len(profiles.load().production_hashes()), {max(count, 1), count + 1})

    def test_a_frozen_edition_before_the_current_core(self):
        ws = Workspace(self)
        row = ws.freeze("e1")
        got = profiles.load(ws.data)
        production, fixture = current_hashes(ws.data)
        self.assertEqual(got.production_hashes(), [row["production"], production])
        self.assertEqual(got.fixture_hashes(), [row["fixture"], fixture])
        old = got.resolve(row["production"])
        self.assertEqual((old.hash, old.fixture, old.version.position, old.version.label), (row["production"], False, 0, "e1"))
        self.assertEqual(old.version.reg.version, "e1")
        self.assertEqual((got.current.position, got.current.reg.version), (1, "1"))
        new = got.resolve(fixture)
        self.assertEqual((new.fixture, new.version), (True, got.current))

    def test_the_current_core_equal_to_the_newest_frozen_edition_is_that_edition(self):
        ws = Workspace(self)
        ws.freeze("e1")
        row = ws.freeze_current("e2")
        got = profiles.load(ws.data)
        self.assertEqual(got.production_hashes()[-1], row["production"])
        self.assertEqual((len(got.production_hashes()), got.current.position, got.current.label), (2, 1, "e2"))

    def test_resolve_answers_none_for_anything_that_is_no_listed_hash(self):
        got = synthetic_set(2)
        self.assertIsNone(got.resolve(UNKNOWN))
        for not_a_string in (None, 5, b"x", ["a"], {}):
            self.assertIsNone(got.resolve(not_a_string))

    def test_resolve_answers_the_edition_and_the_kind_of_a_hash(self):
        got = synthetic_set(3)
        for position, (production, fixture) in enumerate(zip(got.production_hashes(), got.fixture_hashes())):
            self.assertEqual(got.resolve(production), profiles.Profile(production, False, got.resolve(production).version))
            self.assertEqual(got.resolve(production).version.position, position)
            self.assertEqual((got.resolve(fixture).fixture, got.resolve(fixture).version.position), (True, position))
        self.assertEqual(got.current.position, 2)


class CatalogShape(unittest.TestCase):
    def row(self, **over):
        value = {"label": "edition-1", "production": encoding.hashstr(b"p"), "fixture": encoding.hashstr(b"f"),
                 "bundle": encoding.hashstr(b"b"), "tag": "v1.0.0"}
        value.update(over)
        return value

    def refused(self, rows):
        with self.assertRaises(coredata.CoreDataError):
            profiles.parse_catalog(dump(rows))

    def test_a_good_catalog_parses_in_order(self):
        rows = [self.row(), self.row(label="edition-2", production=encoding.hashstr(b"p2"),
                                      fixture=encoding.hashstr(b"f2"), tag="v2.0.0")]
        self.assertEqual(profiles.parse_catalog(dump(rows)), rows)
        self.assertEqual(profiles.parse_catalog(dump([])), [])

    def test_the_shape_is_closed(self):
        self.refused({})
        self.refused([5])
        self.refused([{k: v for k, v in self.row().items() if k != "tag"}])
        self.refused([{**self.row(), "commit": "abc"}])
        self.refused([self.row(production="nope")])
        self.refused([self.row(fixture=5)])
        self.refused([self.row(bundle=None)])
        self.refused([self.row(tag="")])
        self.refused([self.row(tag=5)])

    def test_a_label_is_one_safe_path_segment(self):
        for label in ("", ".", "..", "../x", "a/b", "a\\b", ".hidden", "x y", 5, None):
            self.refused([self.row(label=label)])

    def test_a_repeated_label_or_hash_is_refused(self):
        other = self.row(label="edition-2", production=encoding.hashstr(b"p2"), fixture=encoding.hashstr(b"f2"))
        self.refused([self.row(), {**other, "label": "edition-1"}])
        self.refused([self.row(), {**other, "production": self.row()["production"]}])
        self.refused([self.row(), {**other, "fixture": self.row()["fixture"]}])
        self.refused([self.row(), {**other, "fixture": self.row()["production"]}])

    def test_bytes_that_are_not_json_are_refused(self):
        for raw in (b"", b"{", b"\xff", b"[1,]"):
            with self.assertRaises(coredata.CoreDataError):
                profiles.parse_catalog(raw)


class FrozenData(unittest.TestCase):
    def refused(self, ws):
        with self.assertRaises(coredata.CoreDataError):
            profiles.load(ws.data)

    def test_every_edition_has_a_frozen_manifest_that_hashes_to_its_two_profiles(self):   # GP-22 S4
        for row in real_catalog():   # trivial until the founding freeze; computed here without the loader
            edition = ROOT / "profiles" / row["label"]
            manifest = json.loads((edition / coredata.MANIFEST).read_bytes())
            self.assertEqual(profiles.profile_hash("production", manifest), row["production"])
            self.assertEqual(profiles.profile_hash("fixture", manifest), row["fixture"])
            for rel in (coredata.REGISTRY, coredata.FIXTURE_KIDS):
                self.assertEqual(encoding.hashstr((edition / rel).read_bytes()), manifest[rel])
        ws = Workspace(self)
        ws.freeze("e1")
        ws.freeze("e2")
        got = profiles.load(ws.data)
        self.assertEqual(got.production_hashes()[:2], [row["production"] for row in ws.catalog()])

    def test_a_frozen_edition_that_does_not_hash_to_its_row_is_refused(self):
        for member in ("production", "fixture"):
            ws = Workspace(self)
            ws.freeze("e1")
            rows = ws.catalog()
            rows[0][member] = encoding.hashstr(b"another")
            ws.set_catalog(rows)
            self.refused(ws)

    def test_a_frozen_registry_or_kid_list_that_does_not_hash_to_the_manifest_is_refused(self):
        for rel in (coredata.REGISTRY, coredata.FIXTURE_KIDS):
            ws = Workspace(self)
            ws.freeze("e1")
            ws.rewrite("profiles/e1/" + rel, lambda raw: raw + b" ")
            self.refused(ws)

    def test_a_frozen_manifest_must_list_the_registry_and_the_kid_list_as_hashstrs(self):
        for edit in (lambda m: m.pop(coredata.REGISTRY), lambda m: m.pop(coredata.FIXTURE_KIDS),
                     lambda m: m.update({coredata.REGISTRY: "nope"}), lambda m: m.clear()):
            ws = Workspace(self)
            ws.freeze("e1")
            path = ws.data / "profiles" / "e1" / coredata.MANIFEST
            manifest = json.loads(path.read_bytes())
            edit(manifest)
            path.write_bytes(dump(manifest))
            self.refused(ws)

    def test_a_listed_edition_without_its_directory_or_files_is_refused(self):
        ws = Workspace(self)
        ws.freeze("e1")
        shutil.rmtree(ws.data / "profiles" / "e1")
        self.refused(ws)
        ws = Workspace(self)
        ws.freeze("e1")
        (ws.data / "profiles" / "e1" / coredata.REGISTRY).unlink()
        self.refused(ws)

    def test_a_frozen_manifest_is_checked_against_its_own_key_list(self):   # GP-22
        ws = Workspace(self)
        ws.freeze("e1", extra_core=("spec/profile-part4.md", "spec/profile-checks.md"))
        frozen = json.loads((ws.data / "profiles" / "e1" / coredata.MANIFEST).read_bytes())
        self.assertNotEqual(sorted(frozen), sorted(coredata.load_manifest(ws.data)))
        self.assertEqual(len(profiles.load(ws.data).production_hashes()), 2)

    def test_fixture_kids_are_append_only_across_editions(self):   # GP-22 S6
        real = json.loads((coredata.DATA_DIR / coredata.FIXTURE_KIDS).read_bytes())
        a, b = real[0], real[1]
        ws = Workspace(self)
        ws.freeze("e1", kids=[a])
        ws.freeze("e2", kids=[a, b])
        self.assertEqual(len(profiles.load(ws.data).production_hashes()), 3)   # the current list holds both and more
        ws = Workspace(self)
        ws.freeze("e1", kids=[a, b])
        ws.freeze("e2", kids=[a])
        self.refused(ws)
        ws = Workspace(self)
        ws.freeze("e1", kids=[a, "a-kid-the-current-list-lacks"])
        self.refused(ws)   # the current edition is the newest too: it may not drop a kid an edition listed

    def test_a_synthetic_set_refuses_a_newer_edition_that_drops_a_kid(self):
        synthetic_set(2, kids=[["k1"], ["k1", "k2"]])
        with self.assertRaises(coredata.CoreDataError):
            synthetic_set(2, kids=[["k1", "k2"], ["k1"]])

    def test_the_current_core_is_never_an_older_edition(self):   # GP-22 S7
        ws = Workspace(self)
        ws.freeze_current("e1")
        ws.freeze("e2")
        self.refused(ws)
        ws = Workspace(self)
        ws.freeze_current("e1")
        self.assertEqual(profiles.load(ws.data).current.label, "e1")   # the newest
        ws = Workspace(self)
        ws.freeze("e1")
        self.assertEqual(profiles.load(ws.data).current.position, 1)   # a new one
        real = profiles.load()   # the real repo, trivially
        self.assertEqual(real.production_hashes()[-1], current_hashes(None)[0])


class Prefix(unittest.TestCase):
    def rows(self, count):
        return [{"label": "e%d" % i, "production": encoding.hashstr(b"p%d" % i), "fixture": encoding.hashstr(b"f%d" % i),
                 "bundle": encoding.hashstr(b"b%d" % i), "tag": "v%d" % i} for i in range(count)]

    def test_a_release_keeps_every_edition_the_previous_tag_listed(self):   # GP-22 S3
        previous = self.rows(2)
        profiles.check_extends(previous, previous)
        profiles.check_extends(previous, self.rows(3))
        profiles.check_extends([], self.rows(1))    # the first catalog: the previous tag has none, an empty prefix
        profiles.check_extends([], [])
        for broken in (self.rows(1), [], list(reversed(self.rows(2))),
                       [{**previous[0], "production": encoding.hashstr(b"other")}, previous[1]],
                       [previous[0], {**previous[1], "fixture": encoding.hashstr(b"other")}],
                       [self.rows(3)[2]] + previous):
            with self.assertRaises(coredata.CoreDataError):
                profiles.check_extends(previous, broken)

    def test_a_row_may_change_what_the_hashes_do_not_cover(self):
        previous = self.rows(1)
        profiles.check_extends(previous, [{**previous[0], "tag": "renamed", "label": "other", "bundle": encoding.hashstr(b"z")}])

    def test_this_release_extends_the_catalog_of_the_previous_tag(self):
        top = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if top.returncode != 0:
            self.skipTest("not a git checkout: the previous tag cannot be read")
        tag = subprocess.run(["git", "-C", str(ROOT), "describe", "--tags", "--abbrev=0", "HEAD^"], capture_output=True,
                             text=True)
        self.assertEqual(tag.returncode, 0, "no previous tag is reachable: fetch the tags (CF-15)")
        name = tag.stdout.strip()
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-tree", "--name-only", name, CATALOG],
                                capture_output=True, text=True, check=True).stdout.strip()
        if listed:
            raw = subprocess.run(["git", "-C", str(ROOT), "show", "%s:%s" % (name, CATALOG)], capture_output=True,
                                 check=True).stdout
            previous = profiles.parse_catalog(raw)
        else:
            previous = []   # the first catalog: the previous tag has no `profiles/catalog.json`
        profiles.check_extends(previous, real_catalog())


class SyncTool(unittest.TestCase):
    def script(self):
        spec = importlib.util.spec_from_file_location("sync_core", PROJECT / "sync_core.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def tree(self, root, times=False):
        """`{relative path: bytes}` of every file under `root`, with its modification time when `times`."""
        return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns) if times else p.read_bytes()
                for p in sorted(root.rglob("*")) if p.is_file()}

    def repo_with_frozen_editions(self):
        ws = Workspace(self)
        ws.freeze("e1")
        ws.freeze("e2")
        root = ws.tmp / "repo"
        shutil.copytree(ws.data / "profiles", root / "profiles")
        for rel in tools_core_files():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, root / rel)
        return root

    def test_a_sync_tool_never_touches_a_frozen_edition(self):   # CF-01 S4
        script, root = self.script(), self.repo_with_frozen_editions()
        dest = root.parent / "out"
        before = self.tree(root / "profiles", times=True)
        script.sync(root, dest)
        self.assertEqual(self.tree(root / "profiles", times=True), before)   # no byte and no modification time moved
        self.assertEqual(self.tree(dest / "profiles"), self.tree(root / "profiles"))   # the packaged copy is a byte copy
        after_first = self.tree(dest)
        script.sync(root, dest)
        self.assertEqual(self.tree(dest), after_first)   # a second run is a no-op
        self.assertEqual(self.tree(root / "profiles", times=True), before)

    def test_the_packaged_copy_of_the_set_is_the_set_the_loader_reads(self):
        script, root = self.script(), self.repo_with_frozen_editions()
        dest = root.parent / "out"
        script.sync(root, dest)
        got = profiles.load(dest)
        self.assertEqual(got.production_hashes()[:2], [row["production"] for row in json.loads((root / CATALOG).read_bytes())])

    def test_a_sync_writes_the_current_edition_only_and_drops_a_packaged_edition_the_repo_no_longer_has(self):
        script, root = self.script(), self.repo_with_frozen_editions()
        dest = root.parent / "out"
        script.sync(root, dest)
        shutil.rmtree(root / "profiles")
        script.sync(root, dest)
        self.assertFalse((dest / "profiles").exists())
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["conformance", "core-manifest.json", "spec"])


class DocumentOverASet(unittest.TestCase):
    """GP-15 step 2 over an injected set: `profile_mismatch`, then `fixture_profile`, the mix by kind."""

    def setUp(self):
        self.set = synthetic_set(3)
        self.prod, self.fix = self.set.production_hashes(), self.set.fixture_hashes()

    def check(self, value, previous=None, allow_fixture=True):
        return code_of(self.set.check_document, value, previous, allow_fixture)

    def test_a_well_formed_hash_of_no_entry_is_profile_mismatch_wherever_it_sits(self):   # GP-22 S2
        every_previous = [None] + [self.set.resolve(h) for h in self.prod + self.fix]
        for previous in every_previous:
            for allow in (True, False):
                self.assertEqual(self.check(UNKNOWN, previous, allow), "profile_mismatch")
        for not_a_hash in (None, 5, "nope", ["x"]):
            self.assertEqual(self.check(not_a_hash), "profile_mismatch")

    def test_a_listed_hash_of_any_edition_is_a_profile_that_names_its_edition(self):
        for position, (production, fixture) in enumerate(zip(self.prod, self.fix)):
            got = self.set.check_document(production, None, False)
            self.assertEqual((got.hash, got.fixture, got.version.position), (production, False, position))
            got = self.set.check_document(fixture, None, True)
            self.assertEqual((got.hash, got.fixture, got.version.position), (fixture, True, position))

    def test_a_fixture_hash_of_any_edition_is_refused_where_the_build_refuses_it(self):
        for fixture in self.fix:
            self.assertEqual(self.check(fixture, None, False), "fixture_profile")

    def test_the_mix_is_by_kind_and_equal_at_every_link_is_equal_to_the_original(self):
        production_chain = [self.set.check_document(h, None, True) for h in self.prod]
        fixture_chain = [self.set.check_document(h, None, True) for h in self.fix]
        for chain, other, hashes in ((production_chain, fixture_chain, self.fix), (fixture_chain, production_chain, self.prod)):
            for previous in chain:
                for value in (chain_hash.hash for chain_hash in chain):
                    older = self.set.resolve(value).version.position < previous.version.position
                    self.assertEqual(self.check(value, previous), "profile_downgrade" if older else None)   # I4
                for value in hashes:
                    self.assertEqual(self.check(value, previous), "fixture_profile")

    def test_a_mismatch_is_decided_before_the_mix_and_before_the_build(self):
        previous = self.set.resolve(self.fix[0])
        self.assertEqual(self.check(UNKNOWN, previous, False), "profile_mismatch")


def set_binding(doc):
    doc["binding"] = "another"


def widen_persons(doc):
    doc["constants"]["persons"]["max"] = "20"


def add_constant(doc):
    doc["constants"]["future_bound"] = {"min": "1", "max": "9"}


def add_top_key(doc):
    doc["a_new_part"] = {}


class WireView(unittest.TestCase):
    """GP-23, I3: what a parser may read is one value for every edition, and a type of its own."""

    def test_the_projection_reproduces_the_digest_of_the_wire_part_recorded_in_t16_1(self):
        wire = registry.load().wire
        self.assertEqual(len(wire.canonical()), 3939)
        self.assertEqual(encoding.hashstr(wire.canonical()), WIRE_DIGEST)
        self.assertEqual(encoding.hashstr(profiles.load().wire.canonical()), WIRE_DIGEST)

    def test_the_wire_view_is_identical_in_every_edition(self):   # GP-23 S4
        got = synthetic_set(3, edits={1: widen_persons})
        self.assertEqual({e.version.reg.wire.canonical() for e in got.editions()}, {got.wire.canonical()})
        ws = Workspace(self)
        ws.freeze("e1", edit=widen_persons)
        ws.freeze("e2")
        loaded = profiles.load(ws.data)
        self.assertEqual({e.version.reg.wire.canonical() for e in loaded.editions()}, {loaded.wire.canonical()})
        self.assertEqual(encoding.hashstr(loaded.wire.canonical()), WIRE_DIGEST)

    def test_an_edition_whose_wire_differs_is_refused_at_the_set_and_at_load(self):
        with self.assertRaises(coredata.CoreDataError):
            synthetic_set(2, edits={1: set_binding})
        ws = Workspace(self)
        ws.freeze("e1", edit=set_binding)
        with self.assertRaises(coredata.CoreDataError):
            profiles.load(ws.data)

    def test_a_class_or_a_policy_bound_read_through_the_wire_is_an_attribute_error(self):
        wire = registry.load().wire
        for name in ("key_classes", "fixture_only", "classes", "lookup_class", "persons", "relays", "clock_skew_s"):
            with self.assertRaises(AttributeError, msg=name):
                getattr(wire, name)
        for name in registry.EVALUATION_CONSTANTS:
            with self.assertRaises(AttributeError, msg=name):
                wire.number(name, "min")
        self.assertEqual(wire.number("MAX_DEPTH"), registry.load().number("MAX_DEPTH"))

    def test_an_unclassified_key_is_wire_and_two_editions_that_differ_in_it_are_refused(self):
        wired = registry.Registry(registry_doc('1', add_constant))
        self.assertEqual(wired.wire.number("future_bound", "max"), 9)
        self.assertNotEqual(wired.wire.canonical(), registry.load().wire.canonical())
        with self.assertRaises(coredata.CoreDataError):
            synthetic_set(2, edits={1: add_constant})
        synthetic_set(2, edits={0: add_constant, 1: add_constant})   # the same extra key in both is the same wire
        ws = Workspace(self)
        ws.freeze("e1", edit=add_constant)
        with self.assertRaises(coredata.CoreDataError):
            profiles.load(ws.data)

    def test_every_frozen_registry_parses_with_the_closed_top_keys(self):
        for path in sorted((ROOT / "profiles").glob("*/" + coredata.REGISTRY)):   # none until the founding freeze
            registry.parse(path.read_bytes())
        ws = Workspace(self)
        ws.freeze("e1")
        ws.freeze("e2", edit=widen_persons)
        profiles.load(ws.data)
        bad = Workspace(self)
        bad.freeze("e1", edit=add_top_key)
        with self.assertRaises(registry.RegistryError):
            profiles.load(bad.data)

    def test_act_parsing_reads_nothing_that_depends_on_a_profile(self):   # GP-23 S2
        world = World()
        step = world.device_add("alice2", ("alice", "bob"))
        real = profiles.load().wire
        guarded = GuardedWire(real)
        self.assertEqual(sorted(chain.Bag(step.acts, guarded, world.id).groups), sorted(chain.Bag(step.acts, real, world.id).groups))
        self.assertTrue(chain.Bag(step.acts, guarded, world.id).groups)
        text = world.sigs(world.doc, ("alice", "bob", "carol"))[0]
        read = lambda wire: genesis_sigs.read(text, world.doc, genesis.doc_hash(world.doc), world.id, wire)
        self.assertEqual(read(guarded).id, read(real).id)
        genesis_sigs.check_possession(world.doc, world.sigs(world.doc, ("alice", "bob", "carol")), world.id, guarded,
                                      FakeVitni())
        self.assertEqual(acts.parse(step.primary.jws, guarded, chain.CHAIN_ACTS).id, step.primary.id)

    def test_no_parser_module_names_a_class_a_policy_bound_or_a_registry(self):
        src = PROJECT / "src" / "handsal_check"
        for name in PARSERS:
            tree = ast.parse((src / (name + ".py")).read_text())
            attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            self.assertEqual(attributes & set(EVALUATION_NAMES), set(), name)
            self.assertNotIn("reg", names, name)
            self.assertNotIn("registry", names, name)


ALL = ("alice", "bob", "carol")


def widen(doc):
    """An edition that only adds: a wider `persons` bound and one more active class (I2 holds)."""
    doc["constants"]["persons"]["max"] = "20"
    doc["key_classes"].append({"id": "extra-bio", "alg": "ES256", "hardware_bound": True,
                               "per_signature_user_verification": True, "user_verification": "biometric_only",
                               "status": "active"})


def narrow_persons(doc):
    doc["constants"]["persons"]["min"] = "3"


def forbid_class(doc):
    doc["key_classes"] = [c for c in doc["key_classes"] if c["id"] != "test-sw-p256"]


def fold(profile_set, entries, acts=(), allow_fixture=True):
    texts = [t for item in acts for t in (item.acts if hasattr(item, "acts") else [item.jws])]
    return epoch.fold_lineage(entries, texts, profile_set, allow_fixture, FakeVitni(), lambda doc, previous: None)


def code_of_fold(*args, **kw):
    try:
        fold(*args, **kw)
    except errors.Refused as err:
        return err.code
    return None


def original(w, names=ALL):
    return {"doc": w.doc, "sigs": w.sigs(w.doc, names)}


FOUR = ALL + ("dave",)


def rotated(profile, w, head, persons="2", people=ALL):
    """A change under `profile` that lists new keys for every person (a full rotation), and its signatures: the
    new keys for possession and `alice` and `bob` (two persons) for authority."""
    new = [device(name + "2", label="phone") for name in people]
    doc = change(profile, w.id, genesis.doc_hash(w.doc), head, people=people, devices=new, pol=policy(persons))
    return {"doc": doc, "sigs": w.sigs(doc, [name + "2" for name in people] + ["alice", "bob"])}


class PerEpoch(unittest.TestCase):
    """GP-23 (I5), GP-19, GP-20: an epoch is read under its own document's profile, a change's authority under the
    previous document's, over an injected set of editions that differ in data."""

    def test_an_original_and_a_change_each_name_their_own_edition(self):   # GP-24 S1, GP-23 S1
        got = synthetic_set(2)
        first, second = got.fixture_hashes()
        w = World(profile=first)
        entry = rotated(second, w, w.id)
        epochs = fold(got, [original(w), entry])
        self.assertEqual([e.profile.version.position for e in epochs], [0, 1])
        self.assertEqual([e.profile.version.reg.version for e in epochs], ["1", "2"])
        text = entry["sigs"][0]
        reads = {e.version.position: genesis_sigs.read(text, entry["doc"], genesis.doc_hash(entry["doc"]), w.id,
                                                        e.version.reg.wire).id for e in got.editions()}
        self.assertEqual(len(set(reads.values())), 1)   # possession under P2 and authority under P1 read one act

    def test_a_change_is_authorized_by_the_previous_documents_rule_not_the_new_ones(self):   # GP-19 S10
        got = synthetic_set(2)
        first, second = got.fixture_hashes()
        met_p1 = World(profile=first, people=FOUR, persons="2")   # two persons sign: P1 asks for two, P2 for three
        self.assertEqual(len(fold(got, [original(met_p1, FOUR), rotated(second, met_p1, met_p1.id, "3", FOUR)])), 2)
        met_p2 = World(profile=first, people=FOUR, persons="3")   # the P1 document asks for three: two are not enough
        self.assertEqual(code_of_fold(got, [original(met_p2, FOUR), rotated(second, met_p2, met_p2.id, "2", FOUR)]),
                         "genesis_change_unauthorized")

    def test_the_new_documents_policy_is_checked_against_its_own_editions_bounds(self):   # GP-19 S10, GP-15 step 3
        got = synthetic_set(2, edits={1: narrow_persons})
        first, second = got.fixture_hashes()
        w = World(profile=first, people=FOUR, persons="2")
        self.assertEqual(len(fold(got, [original(w, FOUR)])), 1)   # P1 accepts two persons
        self.assertEqual(code_of_fold(got, [original(w, FOUR), rotated(second, w, w.id, "2", FOUR)]),
                         "policy_out_of_bounds")
        self.assertEqual(len(fold(got, [original(w, FOUR), rotated(second, w, w.id, "3", FOUR)])), 2)

    def test_the_path_of_the_previous_epoch_is_validated_under_the_previous_profile(self):   # GP-19 S11
        alice2 = kid_of("alice2")
        got = synthetic_set(2, kids=[[], [alice2]])   # the second edition refuses alice2 as a fixture key
        first, second = got.production_hashes()
        w = World(profile=first)
        add = w.device_add("alice2", ("alice", "bob"))
        beside = w.device_add("bob2", ("bob", "carol"))   # a fork at the root: FO-24 is not applied on the path
        doc = change(second, w.id, genesis.doc_hash(w.doc), add.id)
        entry = {"doc": doc, "sigs": w.sigs(doc, ALL)}
        epochs = fold(got, [original(w), entry], acts=[add, beside])
        self.assertEqual([e.profile.version.position for e in epochs], [0, 1])
        again = World(profile=second)   # the same acts, an original that names the edition that refuses alice2
        step = again.device_add("alice2", ("alice", "bob"))
        doc = change(second, again.id, genesis.doc_hash(again.doc), step.id)
        self.assertEqual(code_of_fold(got, [original(again), {"doc": doc, "sigs": again.sigs(doc, ALL)}], acts=[step]),
                         "genesis_head_unknown")

    def test_a_carry_is_byte_identical_and_the_new_documents_edition_decides_acceptance(self):   # GP-20 S4
        alice2 = kid_of("alice2")
        keep = synthetic_set(2, kids=[[], []])
        refuse = synthetic_set(2, kids=[[], [alice2]])
        carried = [device(name, label="phone" if name == "alice2" else "laptop") for name in (*ALL, "alice2")]
        for got, expected in ((keep, None), (refuse, "fixture_key")):
            first, second = got.production_hashes()
            w = World(profile=first)
            add = w.device_add("alice2", ("alice", "bob"))
            doc = change(second, w.id, genesis.doc_hash(w.doc), add.id, devices=carried)
            sigs = w.sigs(doc, (*ALL, "alice2"))
            self.assertEqual(code_of_fold(got, [original(w), {"doc": doc, "sigs": sigs}], acts=[add]), expected)
        w = World(profile=keep.production_hashes()[0])
        add = w.device_add("alice2", ("alice", "bob"))
        doc = change(keep.production_hashes()[1], w.id, genesis.doc_hash(w.doc), add.id, devices=carried)
        epochs = fold(keep, [original(w), {"doc": doc, "sigs": w.sigs(doc, (*ALL, "alice2"))}], acts=[add])
        self.assertEqual(len(epochs[1].doc["devices"]), 4)
        edited = [dict(d, label="tablet") if d["person"] == "alice" and d["label"] == "phone" else d for d in carried]
        doc = change(keep.production_hashes()[1], w.id, genesis.doc_hash(w.doc), add.id, devices=edited)
        self.assertEqual(code_of_fold(keep, [original(w), {"doc": doc, "sigs": w.sigs(doc, (*ALL, "alice2"))}],
                                      acts=[add]), "genesis_device_changed")


class AcrossAnEpochChange(unittest.TestCase):
    """VR-17, VR-12, RN-09 over a production set whose second edition refuses a kid the first one lists nowhere."""

    def setUp(self):
        self.kid = kid_of("alice2")
        self.set = synthetic_set(2, kids=[[], [self.kid]])
        self.first, self.second = self.set.production_hashes()

    def lineage(self, original_profile=None, signer="alice2"):
        """A P1 original, alice's added device alice2, and a P2 change at that add, pinned at the change."""
        w = World(profile=original_profile or self.first)
        add = w.device_add("alice2", ("alice", "bob"))
        doc = change(self.second, w.id, genesis.doc_hash(w.doc), add.id)
        scenario = Scenario(w)
        scenario.lineage = [scenario.lineage[0], {"doc": doc, "sigs": w.sigs(doc, ALL)}]
        act = scenario.verdict(signer=signer, head=head_of(add.id))
        return scenario.value(act, acts=add.acts, pin=probe_for(doc, w.id)), act

    def recheck(self, value):
        timed = ("next", "now", "seen", "synced_at", "tip_statement")
        inp = recheck.parse_input({k: v for k, v in value.items() if k not in timed})
        return recheck.run(inp, self.set, True, FakeVitni())["reason"]

    def test_an_act_of_the_first_epoch_is_rechecked_by_the_first_editions_rule_after_a_re_pin(self):   # VR-17 S19, S20
        value, act = self.lineage(signer="alice")   # S19: the head is in the first epoch, the pin at the second
        self.assertEqual(self.recheck(value), "ok")
        self.assertEqual(checkact.run(checkact.parse_input(value), self.set, True, FakeVitni())["reason"], "stale_view")
        value, act = self.lineage()   # S20: the key was added by a rule the second edition would refuse
        self.assertEqual(self.recheck(value), "ok")
        refused, _ = self.lineage(original_profile=self.second)   # the same act where the second edition's rule reads it
        self.assertNotEqual(self.recheck(refused), "ok")

    def test_a_change_renders_with_the_previous_document_under_its_own_edition(self):   # RN-09 S7
        w = World(profile=self.first)
        previous = edit(w.doc, ["devices"], sorted(w.doc["devices"] + [device("alice2", label="phone")],
                                                  key=lambda d: d["kid"]))   # lists the kid the second edition refuses
        previous["profile"] = self.first
        head = encoding.hashstr(b"head")
        doc = change(self.second, w.id, genesis.doc_hash(previous), head)
        act = genesis_sign("alice", doc, w.id)
        payload = json.loads(encoding.b64u_decode(act.jws.split(".")[1]))
        got = render_attach.render_payload(render.Input({"document": doc, "previous": previous}, act.kid, payload["method"],
                                                         payload), self.set)
        for line in render_genesis.lines(doc, previous):   # one text, whatever editions the two documents name
            self.assertIn(line, got.text)
        self.assertTrue(got.first_line.startswith("Change ORG ("))
        with self.assertRaises(errors.Refused):   # the same previous document alone under the second edition is refused
            genesis.check_alone(dict(previous, profile=self.second), genesis.Context(self.set, True))

    def test_a_valid_successor_under_the_next_edition_supersedes_a_pin_of_the_first(self):   # VR-12, GP-24 S10
        class Case(test_sync.Case):
            profile_set = self.set

            def setUp(inner):
                super().setUp()
                inner.s = Scenario(World(profile=self.first))
                inner.org = inner.s.w.id

            def runTest(inner):
                w = inner.s.w
                step = w.device_add("alice2", ("alice", "bob"))
                doc = change(self.second, w.id, genesis.doc_hash(w.doc), step.id, devices=None)
                entry = {"doc": doc, "sigs": w.sigs(doc, ALL)}
                inner.assertEqual(inner.sync(step.acts, docs=inner.s.lineage + [entry]),
                                  {"reason": "epoch_superseded", "synced_at": NOW})
                inner.assertEqual(inner.stored().next, "yes")
        result = unittest.TextTestRunner(stream=io.StringIO()).run(Case())
        self.assertEqual((result.errors, result.failures), ([], []))


def bound(reg, name):
    return int(reg.number(name, "min")), int(reg.number(name, "max"))


def narrowing(profile_set):
    """The policy bounds of an edition that are narrower than the previous edition's, as `(edition, name)`."""
    found = []
    for older, newer in zip(profile_set.editions(), profile_set.editions()[1:]):
        for name in registry.EVALUATION_CONSTANTS:
            (old_min, old_max), (new_min, new_max) = bound(older.version.reg, name), bound(newer.version.reg, name)
            if new_min > old_min or new_max < old_max:
                found.append((newer.version.label, name))
    return found


def rejected_by_the_next(profile_set):
    """What the first edition accepts and the second does not: a valid original re-profiled (I2), its carry and its
    role-holder classes (KC-03, KC-08, GP-20). `[]` when the second accepts all of it."""
    first, second = profile_set.fixture_hashes()[:2]
    found = []
    w = World(profile=first)
    ctx = genesis.Context(profile_set, True)
    previous = genesis.check_document(w.doc, ctx)
    for member in (w.doc, rotated(first, w, w.id)["doc"]):
        again = dict(member, profile=second)
        try:
            genesis.check_document(again, ctx, previous)
        except errors.Refused as err:
            found.append(err.code)
    try:
        fold(profile_set, [original(w), {"doc": (d := change(second, w.id, genesis.doc_hash(w.doc), w.id)),
                                          "sigs": w.sigs(d, ALL)}])
    except errors.Refused as err:
        found.append(err.code)
    return found


class Migrability(unittest.TestCase):
    """GP-24 I2 over an injected two-edition set."""

    def test_policy_bounds_never_narrow_between_adjacent_editions(self):   # GP-24 S12
        self.assertEqual(narrowing(profiles.load()), [])
        self.assertEqual(narrowing(synthetic_set(3, edits={1: widen, 2: widen})), [])
        self.assertEqual(narrowing(synthetic_set(2, edits={1: narrow_persons})), [("e2", "persons")])

    def test_kc03_kc08_and_the_carry_rules_accept_in_the_next_edition_what_the_previous_accepted(self):   # GP-24 S13
        self.assertEqual(rejected_by_the_next(synthetic_set(2)), [])
        self.assertEqual(rejected_by_the_next(synthetic_set(2, edits={1: widen})), [])
        def weaken(doc):   # the next edition no longer calls its one class biometric_only (KC-08)
            for entry in doc["key_classes"]:
                if entry["id"] == "apple-se-bio":
                    entry["user_verification"] = "biometric_or_pin"
        self.assertNotEqual(rejected_by_the_next(synthetic_set(2, edits={1: weaken})), [])

    def test_a_valid_document_reprofiled_to_the_next_edition_passes_steps_1_to_5(self):   # GP-24 S6
        got = synthetic_set(2, edits={1: widen})
        first, second = got.fixture_hashes()
        ctx = genesis.Context(got, True)
        w = World(profile=first)
        previous_profile = genesis.check_document(w.doc, ctx)
        entry = rotated(first, w, w.id)
        valid = entry["doc"]
        genesis.check_document(valid, ctx, previous_profile)   # D is valid under P1: steps 1 to 3
        again = dict(valid, profile=second)                    # D', equal in every member but the profile
        profile = genesis.check_document(again, ctx, previous_profile)   # steps 1 to 3 under P2
        genesis.check_link(again, w.doc, w.id)                 # step 4
        render_genesis.render_size(again, w.doc)               # step 5
        self.assertEqual(profile.version.position, 1)


def next_change(w, previous, profile, **kw):
    """A change under `profile` at the root of the epoch of `previous`, signed by the three devices."""
    doc = change(profile, w.id, genesis.doc_hash(previous), genesis.doc_hash(previous), **kw)
    return {"doc": doc, "sigs": w.sigs(doc, ALL)}


class Downgrade(unittest.TestCase):
    """GP-24 I4, GP-15 step 2: a change may keep the edition or move to any newer one, never to an older one. The
    comparison is by catalog position, after `profile_mismatch` and `fixture_profile`, before every code of step 3."""

    def setUp(self):
        self.set = synthetic_set(3, edits={1: widen, 2: widen})
        self.fixture = self.set.fixture_hashes()
        self.production = self.set.production_hashes()

    def lineage(self, hashes, **kw):
        """Documents named by `hashes`, each a change at the root of the one before; the original first."""
        w = World(profile=hashes[0])
        entries, previous = [original(w)], w.doc
        for profile in hashes[1:]:
            entry = next_change(w, previous, profile, **kw)
            entries.append(entry)
            previous = entry["doc"]
        return w, entries

    def code(self, hashes, **kw):
        w, entries = self.lineage(hashes, **kw)
        return code_of_fold(self.set, entries)

    def test_a_downgrade_is_refused_over_a_synthetic_two_edition_set(self):   # GP-24 S3
        p1, p2 = self.fixture[:2]
        self.assertEqual(self.code([p2, p1]), "profile_downgrade")
        q1, q2 = self.production[:2]
        self.assertEqual(self.code([q2, q1]), "profile_downgrade")   # the same in the production kind

    def test_a_downgrade_after_a_migration_is_refused_for_the_third_document(self):   # GP-24 S4
        p1, p2 = self.fixture[:2]
        w, entries = self.lineage([p1, p2])
        self.assertEqual(len(fold(self.set, entries)), 2)
        entries.append(next_change(w, entries[-1]["doc"], p1))
        self.assertEqual(code_of_fold(self.set, entries), "profile_downgrade")

    def test_a_second_change_under_the_same_edition_is_the_second_epoch_of_it(self):   # GP-24 S5
        p1, p2 = self.fixture[:2]
        w, entries = self.lineage([p1, p2, p2])
        self.assertEqual([e.profile.version.position for e in fold(self.set, entries)], [0, 1, 1])

    def test_a_change_may_name_any_newer_edition_not_only_the_next_or_the_current(self):   # GP-24 S11
        p1, _, p3 = self.fixture
        w, entries = self.lineage([p1, p3])
        self.assertEqual([e.profile.version.position for e in fold(self.set, entries)], [0, 2])
        w, entries = self.lineage([self.fixture[1], p3])
        self.assertEqual(len(fold(self.set, entries)), 2)

    def test_a_downgrade_that_also_lists_an_unknown_class_is_a_downgrade(self):   # GP-24 S7, GP-15 S4
        p1, p2 = self.fixture[:2]
        pol = policy(classes=(("apple-se-bio", "biometric_only"), ("extra-bio", "biometric_only")))
        self.assertEqual(self.code([p2, p1], pol=pol), "profile_downgrade")
        w, entries = self.lineage([p1, p2], pol=pol)   # the same document in the right order names a class P2 knows
        self.assertEqual(code_of_fold(self.set, entries), None)
        w, entries = self.lineage([p1, p1], pol=pol)   # and under P1, which does not know it, step 3 refuses it
        self.assertNotIn(code_of_fold(self.set, entries), (None, "profile_downgrade"))

    def test_a_fixture_mix_is_decided_before_a_downgrade(self):   # GP-24 S8, S9, GP-15 S4
        self.assertEqual(self.code([self.fixture[1], self.production[0]]), "fixture_profile")   # fixture P2, production P1
        self.assertEqual(self.code([self.fixture[0], self.production[1]]), "fixture_profile")   # fixture P1, production P2
        self.assertEqual(self.code([self.production[0], self.fixture[1]]), "fixture_profile")   # and the reverse
        self.assertEqual(self.code([self.production[1], self.fixture[0]]), "fixture_profile")

    def test_an_unlisted_hash_is_a_mismatch_before_a_downgrade(self):
        w, entries = self.lineage([self.fixture[1], encoding.hashstr(b"no edition")])
        self.assertEqual(code_of_fold(self.set, entries), "profile_mismatch")

    def test_the_comparison_lives_in_the_set_and_needs_a_previous_document(self):
        p1, p2 = (self.set.resolve(h) for h in self.fixture[:2])
        self.assertEqual(code_of(self.set.check_document, p1.hash, p2, True), "profile_downgrade")
        self.assertEqual(self.set.check_document(p2.hash, p1, True), p2)
        self.assertEqual(self.set.check_document(p2.hash, p2, True), p2)
        self.assertEqual(self.set.check_document(p1.hash, None, True), p1)   # an original is never a downgrade

    def test_the_code_comes_out_of_genesis_check(self):
        w, entries = self.lineage([self.fixture[1], self.fixture[0]])
        got = genesis_check.run(genesis_check.parse_input({"acts": [], "lineage": entries}), self.set, True, FakeVitni())
        self.assertEqual((got["valid"], got["reason"]), (False, "profile_downgrade"))


def identical_active_classes(profile_set):
    """`(newer edition, class)` for every class that is `active` in an edition and absent or different in the next
    (I2: the entry is identical in `alg`, `hardware_bound`, `per_signature_user_verification`, `user_verification`)."""
    found = []
    for older, newer in zip(profile_set.editions(), profile_set.editions()[1:]):
        now = newer.version.reg.classes(False)
        for cls_id, entry in older.version.reg.classes(False).items():
            if entry.status == "active" and (cls_id not in now or now[cls_id][:5] != entry[:5]
                                             or now[cls_id].status != "active"):
                found.append((newer.version.label, cls_id))
    return found


class ClassesAcrossEditions(unittest.TestCase):
    def test_every_active_class_of_an_edition_is_identical_in_the_next(self):   # GP-24 S6, I2
        self.assertEqual(identical_active_classes(profiles.load()), [])   # the real set, trivially
        self.assertEqual(identical_active_classes(synthetic_set(3, edits={1: widen, 2: widen})), [])

        def drop(doc):
            doc["key_classes"] = [c for c in doc["key_classes"] if c["id"] != "apple-se-bio"]

        def alter(doc):
            for entry in doc["key_classes"]:
                if entry["id"] == "apple-se-bio":
                    entry["hardware_bound"] = False
        self.assertEqual(identical_active_classes(synthetic_set(2, edits={1: drop})), [("e2", "apple-se-bio")])
        self.assertEqual(identical_active_classes(synthetic_set(2, edits={1: alter})), [("e2", "apple-se-bio")])


class Zipapp(unittest.TestCase):
    def test_the_zipapp_reads_its_frozen_editions_through_importlib_resources(self):
        spec = importlib.util.spec_from_file_location("pk_build_zipapp", PROJECT / "packaging" / "build_zipapp.py")
        build_zipapp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build_zipapp)
        ws = Workspace(self)
        row = ws.freeze("e1")
        src = ws.tmp / "src"
        shutil.copytree(PROJECT / "src", src)
        shutil.rmtree(src / "handsal_check" / "data")
        shutil.copytree(ws.data, src / "handsal_check" / "data")
        build_zipapp.build(src, ws.tmp / "app.pyz")
        code = ("import sys; sys.path.insert(0, %r)\nfrom handsal_check import profiles\n"
                "import handsal_check; assert handsal_check.__file__.startswith(%r)\n"
                "print(profiles.load().production_hashes()[0])" % (str(ws.tmp / "app.pyz"), str(ws.tmp / "app.pyz")))
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, row["production"]), out.stderr)


FOUNDING_LABEL = "edition-1"
FOUNDING_PARENT_TAG = "v0.2.0"   # the last tag before the founding release: it carries no catalog (the first-catalog case)
FREEZE_PATHS = ("profiles/", "conformance/pins.json", "checker/python/src/handsal_check/data/profiles/",
                "signer/apple/Sources/HandsalCore/Profiles.swift")


def git(*args, check=True):
    return subprocess.run(["git", "-C", str(ROOT)] + list(args), capture_output=True, check=check)


def row_commit(repo, label):
    """The commit that last added the catalog row of the label (git lists the newest first), or None."""
    hits = subprocess.run(["git", "-C", str(repo), "log", "--format=%H", "-S" + json.dumps(label), "--", CATALOG],
                          capture_output=True, check=True).stdout.split()
    return hits[0].decode() if hits else None


def load_script(path):
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        spec = importlib.util.spec_from_file_location("founding_" + path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(ROOT / "tools"))


class Founded(unittest.TestCase):
    """The real repo once the founding edition is frozen (GP-22, CF-01, CF-15): the cases the empty catalog could
    only pass trivially. One test per case. The founding edition is the first row, whatever follows it."""

    def row(self):
        rows = real_catalog()
        self.assertEqual(rows[0]["label"], FOUNDING_LABEL, "the catalog starts with the founding edition")
        return rows[0]

    def test_the_frozen_manifest_hashes_to_the_two_hashes_of_the_row_and_of_the_pins(self):   # GP-22 S4
        row = self.row()
        frozen = json.loads((ROOT / "profiles" / FOUNDING_LABEL / "core-manifest.json").read_bytes())
        self.assertEqual(profiles.profile_hash("production", frozen), row["production"])
        self.assertEqual(profiles.profile_hash("fixture", frozen), row["fixture"])
        pins = json.loads((ROOT / "conformance" / "pins.json").read_bytes())
        self.assertEqual(pins["profiles"], [{"label": r["label"], "production": r["production"], "fixture": r["fixture"]}
                                            for r in real_catalog()])
        for rel in ("spec/registry.json", "conformance/fixtures/fixture-kids.json"):
            self.assertEqual(encoding.hashstr((ROOT / "profiles" / FOUNDING_LABEL / rel).read_bytes()), frozen[rel], rel)

    def test_the_packaged_catalog_and_frozen_directory_are_a_byte_copy_of_profiles(self):   # CF-01 S4
        self.row()
        packaged = Path(coredata.DATA_DIR) / "profiles"
        want = {str(p.relative_to(ROOT / "profiles")): p.read_bytes() for p in (ROOT / "profiles").rglob("*") if p.is_file()}
        got = {str(p.relative_to(packaged)): p.read_bytes() for p in packaged.rglob("*") if p.is_file()}
        self.assertEqual(got, want)

    def test_the_first_catalog_extends_the_empty_catalog_of_the_last_tag(self):   # GP-22 S3, first catalog
        listed = git("ls-tree", "--name-only", FOUNDING_PARENT_TAG, CATALOG, check=False)
        self.assertEqual(listed.returncode, 0, "the tag %s is not fetched" % FOUNDING_PARENT_TAG)
        self.assertEqual(listed.stdout.strip(), b"", "the last tag carries no catalog: its catalog is empty")
        self.row()
        profiles.check_extends([], real_catalog())

    def test_the_current_core_is_the_newest_catalog_entry(self):   # GP-22 S7, C4
        """The current core is the newest row, or a new unreleased edition after it, and the pins follow it."""
        self.row()
        rows = real_catalog()
        newest = (rows[-1]["production"], rows[-1]["fixture"])
        current = current_hashes(None)
        pins = json.loads((ROOT / "conformance" / "pins.json").read_bytes())
        self.assertEqual((pins["production_profile"], pins["fixture_profile"]), current)
        loaded = profiles.load()
        frozen = [r["production"] for r in rows]
        if current == newest:
            self.assertEqual(loaded.current.label, rows[-1]["label"])
            self.assertEqual(loaded.production_hashes(), frozen)
        else:
            self.assertNotIn(current[0], frozen)
            self.assertNotIn(current[1], [r["fixture"] for r in rows])
            self.assertEqual(loaded.current.label, profiles.CURRENT)
            self.assertEqual(loaded.production_hashes(), frozen + [current[0]])

    def test_the_freeze_changes_only_the_paths_it_owns_and_makes_the_row_and_files_of_the_tree(self):   # CF-01 S4
        """Replays the freeze that made the newest row on the tree before the commit that added that row (or HEAD
        when the row is not committed yet), then the checker's sync: every changed path is one of the listed ones,
        and the row and every file it writes, the catalog included, are what the repo holds."""
        self.row()
        row = real_catalog()[-1]
        added = row_commit(ROOT, row["label"])
        base = (added + "^") if added else "HEAD"
        self.assertEqual(git("rev-parse", "--verify", "-q", base, check=False).returncode, 0,
                         "the history before the freeze commit is not fetched (CF-15: fetch the whole history)")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        archive = subprocess.Popen(["git", "-C", str(ROOT), "archive", base], stdout=subprocess.PIPE)
        subprocess.run(["tar", "-x", "-C", str(tmp)], stdin=archive.stdout, check=True)
        self.assertEqual(archive.wait(), 0)

        def files():
            return {str(p.relative_to(tmp)): p.read_bytes() for p in tmp.rglob("*") if p.is_file()}
        before = files()
        made = load_script(ROOT / "tools" / "repin.py").freeze(tmp, row["label"], row["tag"])
        load_script(PROJECT / "sync_core.py").sync(tmp, tmp / "checker" / "python" / "src" / "handsal_check" / "data")
        after = files()
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        self.assertTrue(changed)
        self.assertEqual([k for k in changed if not k.startswith(FREEZE_PATHS)], [], "a path the freeze does not own")
        self.assertEqual(made, row)   # the same row, bundle hash included: the freeze moved no pinned value
        for rel in changed:
            if rel.startswith("profiles/"):
                self.assertEqual(after[rel], (ROOT / rel).read_bytes(), rel)

    def test_the_freeze_replay_takes_the_newest_commit_that_added_the_row(self):   # CF-01 S4
        """A label can leave the catalog (an undone freeze) and come back: the replay starts before the latest
        addition, never before the first one."""
        repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, True)

        def run(*args):
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
                            "-c", "commit.gpgsign=false"] + list(args), capture_output=True, check=True)
        run("init", "-q")
        (repo / "profiles").mkdir()
        catalog = repo / CATALOG
        commits = []
        for text in ('[{"label": "edition-9"}]', "[]", '[{"label": "edition-9", "again": 1}]', '[{"label": "edition-9", "x": 2}]'):
            catalog.write_text(text)
            run("add", ".")
            run("commit", "-q", "-m", "c%d" % len(commits))
            commits.append(subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                                          check=True).stdout.decode().strip())
        self.assertEqual(row_commit(repo, "edition-9"), commits[2])
        self.assertIsNone(row_commit(repo, "edition-8"))

    def test_the_bundle_hash_of_the_tree_is_the_bundle_of_the_newest_row(self):   # CF-15
        """While the tree is the newest row's core its bundle is the row's; once the core moves on, the tree's bundle
        is another one and the row's bundle is the one its tag recomputes (the tag run of the conformance harness)."""
        self.row()
        newest = real_catalog()[-1]
        bundle = load_script(ROOT / "tools" / "manifest.py").bundle_hash(ROOT)
        if current_hashes(None) == (newest["production"], newest["fixture"]):
            self.assertEqual(bundle, newest["bundle"])
        else:
            self.assertNotEqual(bundle, newest["bundle"])


if __name__ == "__main__":
    unittest.main()
