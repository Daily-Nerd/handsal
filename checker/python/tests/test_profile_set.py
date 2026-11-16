"""T16.4 the profile set (GP-22, GP-15 step 2, GP-05 S6, CF-01, CF-08): the loader, the frozen data, the rules.

The real repo has no `profiles/` directory until the founding freeze (T16.17), so every case that needs a frozen
edition builds a temporary tree (`profile_sets.Workspace`) or an in-memory set (`profile_sets.synthetic_set`). The
real-repo cases are written over the real catalog and are trivial while it is empty.
"""
import ast
import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from handsal_check import acts, chain, coredata, encoding, errors, genesis, genesis_sigs, profiles, registry

from .act_builder import FakeVitni
from .fold_world import World
from .profile_sets import CATALOG, GuardedWire, Workspace, dump, registry_doc, synthetic_set

ROOT = Path(__file__).resolve().parents[3]
PROJECT = Path(__file__).resolve().parents[1]
UNKNOWN = encoding.hashstr(b"an edition no catalog entry lists")
WIRE_DIGEST = "uEiAgAeRs0Do396Yp2uhzY4UYe8T--TzRzTrXazRS9vedyg"   # T16.1: the canonical bytes of the wire part, hashed
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
        count = len(real_catalog())   # 0 until the founding freeze (T16.17): one current edition and no frozen one
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
        for row in real_catalog():   # trivial until T16.17; computed here without the loader
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

    def test_a_frozen_manifest_is_checked_against_its_own_key_list(self):   # D4
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
                    self.assertEqual(self.check(value, previous), None)   # any edition of the same kind
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
        for path in sorted((ROOT / "profiles").glob("*/" + coredata.REGISTRY)):   # none until T16.17
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


if __name__ == "__main__":
    unittest.main()
