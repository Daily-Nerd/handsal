"""One list of core files, and the profile text that is split across several of them (CF-01).

The profile hash covers a list of files. Several tools, a Swift table and a Rust table each need that
list, and none of them can import the others, so the list lives in one owner (`manifest.CORE_FILES`)
and every other place is compared with it here. A tool that hashes or reads a different set fails
this file, not a release.

The profile is one normative text in several files, each at most MAX_PROFILE_PART_BYTES (a part
grows by editing, so it keeps room under the 256 KiB cap of test_spec_ids). The parts are
contiguous runs of sections, so a section number names one place.
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402
import repin  # noqa: E402
from . import test_repin  # noqa: E402

MAX_PROFILE_PART_BYTES = 200 * 1024
PROFILE_GLOB = "profile*.md"


def profile_parts():
    return sorted((ROOT / "spec").glob(PROFILE_GLOB))


def core_in_text(text):
    """The paths CF-01 names in its core manifest sentence."""
    sentence = re.search(r"\*\*Core manifest\*\*: (.*?)\.\n", text, re.S).group(1)
    return [path for path in re.findall(r"`([^`]+)`", sentence) if "/" in path]


def live_table_paths(swift):
    """The rows of the live `coreManifest` table: the rows outside the generated edition region of repin.py, whose
    frozen blocks list the core files of an older edition."""
    live = re.sub(r"^\s*// handsal:editions begin$.*?^\s*// handsal:editions end$", "", swift, flags=re.M | re.S)
    return re.findall(r'^\s*"((?:conformance|spec)/[^"]+)": "u', live, re.M)


class OneOwner(unittest.TestCase):
    def setUp(self):
        self.owner = list(manifest.CORE_FILES)

    def test_the_list_is_sorted_and_has_no_duplicate(self):
        self.assertEqual(self.owner, sorted(set(self.owner)))

    def test_every_profile_part_is_a_core_file_and_no_core_spec_file_is_missing(self):
        parts = ["spec/%s" % p.name for p in profile_parts()]
        self.assertGreater(len(parts), 1, "the profile is meant to be split (test_spec_ids, 256 KiB)")
        self.assertEqual([f for f in self.owner if f.startswith("spec/profile")], parts)

    def test_repin_reads_the_same_list(self):
        self.assertEqual(list(repin.CORE_FILES), self.owner)

    def test_the_checker_ships_the_same_list(self):
        text = (ROOT / "checker/python/src/handsal_check/coredata.py").read_text(encoding="utf-8")
        self.assertNotIn("CORE_FILES", text.replace("`CORE_FILES`", ""))   # the checker holds no copy of the list
        script = (ROOT / "checker/python/sync_core.py").read_text(encoding="utf-8")
        self.assertIn("tools/manifest.py", script.replace('"tools" / "manifest.py"', "tools/manifest.py"))
        shipped = json.loads((ROOT / "checker/python/src/handsal_check/data/core-manifest.json").read_text())
        self.assertEqual(sorted(shipped), self.owner)

    def test_the_swift_table_has_one_row_per_file(self):
        text = (ROOT / "signer/apple/Sources/HandsalCore/Profiles.swift").read_text(encoding="utf-8")
        self.assertEqual(sorted(live_table_paths(text)), self.owner)

    def test_the_live_table_reading_skips_the_frozen_edition_blocks(self):
        text = ('        "spec/a.md": "uA",\n    // handsal:editions begin\n            "spec/old.md": "uB",\n'
                '    // handsal:editions end\n        "spec/z.md": "uC",\n')
        self.assertEqual(live_table_paths(text), ["spec/a.md", "spec/z.md"])

    def test_the_rust_table_embeds_each_file_once(self):
        text = (ROOT / "signer/windows/core/profiles.rs").read_text(encoding="utf-8")
        rows = re.findall(r'\("([^"]+)", include_bytes!\("\.\./\.\./\.\./([^"]+)"\)\)', text)
        self.assertEqual([a for a, _ in rows], self.owner)
        self.assertEqual([a for a, _ in rows], [b for _, b in rows])
        self.assertIn("CORE_FILES: [(&str, &[u8]); %d]" % len(self.owner), text)

    def test_the_spec_names_the_same_list(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in profile_parts())
        self.assertEqual(sorted(core_in_text(text)), self.owner)

    def not_the_catalog(self, files):
        """GP-22 S8: no list of core files names the catalog or anything under `profiles/`."""
        self.assertEqual([f for f in files if f == "profiles/catalog.json" or f.startswith("profiles/")], [])

    def test_the_catalog_is_not_a_core_file(self):
        """GP-22 S8: a catalog among the core files would move the hash of every older edition (a fixed point)."""
        self.not_the_catalog(self.owner)
        self.not_the_catalog(core_in_text("\n".join(p.read_text(encoding="utf-8") for p in profile_parts()) + "\n"))
        self.not_the_catalog(json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"])
        self.not_the_catalog(json.loads((ROOT / "checker/python/src/handsal_check/data/core-manifest.json").read_text()))
        self.not_the_catalog(repin.CORE_FILES)
        with self.assertRaises(AssertionError):   # the test fails when the catalog is added to a list
            self.not_the_catalog(self.owner + ["profiles/catalog.json"])
        with self.assertRaises(AssertionError):
            self.not_the_catalog(self.owner + ["profiles/edition-1/core-manifest.json"])

    def test_the_errata_file_is_not_a_core_file(self):
        """CF-01 S5: spec/errata.md records editorial fixes between rule editions and moves no hash."""
        errata = ROOT / "spec" / "errata.md"
        self.assertTrue(errata.is_file(), "spec/errata.md is missing")
        self.assertNotIn("spec/errata.md", self.owner)
        self.assertNotIn("spec/errata.md", core_in_text("\n".join(p.read_text(encoding="utf-8") for p in profile_parts()) + "\n"))
        files = json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"]
        self.assertNotIn("spec/errata.md", files)
        self.assertIn("never changes what any verifier, signer or consumer answers", errata.read_text(encoding="utf-8"))

    def test_the_bundle_manifest_lists_every_core_file(self):
        files = json.loads((ROOT / "spec/MANIFEST.json").read_text())["files"]
        self.assertEqual(sorted(f for f in files if not f.startswith("conformance/vectors/")), self.owner)

    def test_the_contract_names_every_profile_part(self):
        text = (ROOT / "conformance/CONTRACT.md").read_text(encoding="utf-8")
        for path in profile_parts():
            self.assertIn("spec/" + path.name, text)


class SplitProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parts = {p.name: p.read_text(encoding="utf-8") for p in profile_parts()}

    def test_each_part_leaves_room_to_grow(self):
        for name, text in self.parts.items():
            self.assertLessEqual(len(text.encode("utf-8")), MAX_PROFILE_PART_BYTES, name)

    def test_sections_are_contiguous_and_each_belongs_to_one_part(self):
        seen = []
        for name in sorted(self.parts, key=lambda n: (n != "profile.md", n)):
            nums = [int(m) for m in re.findall(r"^## (\d+)\.", self.parts[name], re.M)]
            self.assertEqual(nums, sorted(nums), name)
            seen += nums
        self.assertEqual(seen, list(range(0, 15)))

    def test_every_part_opens_with_a_title_and_names_its_place(self):
        for name, text in self.parts.items():
            self.assertTrue(text.startswith("# handsal profile, version 1"), name)

    def test_no_part_names_an_ordinal_of_its_own(self):
        """The parts are four, and a title that says "part 2" or "second part" goes stale at the next split."""
        for name, text in self.parts.items():
            head = "\n".join(text.split("\n")[:4])
            self.assertNotRegex(head, r"(?i)\bpart \d\b|\b(second|third|fourth) part\b", name)

    def test_the_reading_guide_names_every_part(self):
        guide = self.parts["profile.md"].split("## 1. ")[0]
        for name in self.parts:
            self.assertIn("spec/" + name, guide)

    def test_a_requirement_id_has_one_heading_in_one_part(self):
        heads = [h for text in self.parts.values() for h in re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M)]
        self.assertEqual(len(heads), len(set(heads)))

    def test_every_id_the_text_cites_has_a_heading_or_is_retired(self):
        text = "\n".join(self.parts.values())
        known = set(re.findall(r"^#{3,4} ([A-Z]+-\d\d)\b", text, re.M))
        req = json.loads((ROOT / "spec/requirements.json").read_text())
        known |= {r["id"] for r in req["retired"]}
        cited = set(re.findall(r"\b((?:ACT|KC|GP|FO|VR|RN|CF|SG|WT)-\d\d)\b", text))
        self.assertEqual(sorted(cited - known), [])

    def test_every_section_number_the_text_cites_exists(self):
        text = "\n".join(self.parts.values())
        heads = set(re.findall(r"^#{2,3} (\d+(?:\.\d+)?)\.? ", text, re.M))
        cited = set(re.findall(r"\bsections? (\d+(?:\.\d+)?)\b", text))
        self.assertEqual(sorted(c for c in cited if c not in heads), [])


class CatalogWriters(test_repin.CatalogFixture, unittest.TestCase):
    """CF-01 S4: the tools that write core data write only the current edition and append to the catalog."""

    def test_repin_writes_only_the_current_edition_and_appends_the_catalog(self):
        frozen = {k: v for k, v in test_repin.snapshot(self.tmp).items() if k.startswith("profiles/")}
        self.assertEqual(self.run_tool("--write")[0], 0)
        manifest.write_bundle_manifest(self.tmp)   # the third writer: the bundle manifest
        self.assertEqual({k: v for k, v in test_repin.snapshot(self.tmp).items() if k.startswith("profiles/")}, frozen)
        pins = json.loads((self.tmp / repin.PINS).read_text())
        core_b, pins_b, _o, _w = test_repin.expected(test_repin.CORE_B)
        self.assertEqual(pins["profiles"], [{"label": "edition-1", "production": pins_b["production_profile"],
                                             "fixture": pins_b["fixture_profile"]}])
        self.assertEqual(pins["production_profile"], self.pins["production_profile"])
        self.assertNotEqual(pins["production_profile"], pins_b["production_profile"])
        swift = (self.tmp / repin.SWIFT).read_text()
        for rel, digest in self.core.items():   # the live table is the current edition's
            self.assertIn('        "%s": "%s",' % (rel, digest), swift)
        self.assertEqual(self.blocks(), ["edition-1"])
        block = swift.split("// handsal:edition begin edition-1")[1].split("// handsal:edition end edition-1")[0]
        for rel, digest in core_b.items():
            self.assertIn('"%s": "%s",' % (rel, digest), block)
        self.assertIn(pins_b["production_profile"], block)
        self.assertIn(pins_b["fixture_profile"], block)
        self.assertIn('"k1"', block)
        self.assertIn(test_repin.CORE_B["spec/registry.json"].decode(), block)
        listed = json.loads((self.tmp / manifest.BUNDLE_FILE).read_text())["files"]
        self.assertEqual([f for f in listed if f.startswith("profiles/")], [])


# ---- the three tables and the catalog (GP-22 S5, GP-23 S3, SG-02 S3) ----------------------------------------------

SWIFT_PROFILES = "signer/apple/Sources/HandsalCore/Profiles.swift"
RUST_PROFILES = "signer/windows/core/profiles.rs"
CATALOG = "profiles/catalog.json"
PINS = "conformance/pins.json"
PY_DATA = "checker/python/src/handsal_check/data"
SWIFT_GUARDED = ("signer/apple/Sources",)
RUST_GUARDED = ("signer/windows/core", "signer/windows/src")
PROFILES_FILES = (SWIFT_PROFILES, RUST_PROFILES)
Edition = tuple   # (label, production, fixture)


def _rows(raw):
    return [(r["label"], r["production"], r["fixture"]) for r in json.loads(raw)]


def _json_hash(core, kind):
    return manifest.hashstr(json.dumps({"core": core, "kind": kind}, sort_keys=True, separators=(",", ":")).encode("ascii"))


def swift_region(text):
    match = re.search(r"^\s*// handsal:editions begin$(.*?)^\s*// handsal:editions end$", text, re.M | re.S)
    return match.group(1) if match else ""


def swift_editions(text):
    """[(label, production, fixture)] of the generated `FrozenEdition` blocks, in file order."""
    region = re.sub(r'#"""\n.*?\n"""#', "", swift_region(text), flags=re.S)   # a registry text is no row
    return re.findall(r'FrozenEdition\(\s*label: "([^"]+)",\s*production: "([^"]+)",\s*fixture: "([^"]+)"', region)


def swift_live_production(text):
    """The production hash of the live `coreManifest` table (the rows outside the generated region)."""
    live = re.sub(r"^\s*// handsal:editions begin$.*?^\s*// handsal:editions end$", "", text, flags=re.M | re.S)
    core = dict(re.findall(r'^\s*"((?:conformance|spec)/[^"]+)": "(u[^"]+)",$', live, re.M))
    return _json_hash(core, "production")


def rust_editions(text):
    """[(label, production, fixture)] of the `VERSIONS` rows, in file order."""
    match = re.search(r"pub const VERSIONS: &\[FrozenRow<'static>\] = &\[(.*?)\];", text, re.S)
    body = match.group(1) if match else ""
    return re.findall(r'FrozenRow\s*\{\s*label:\s*"([^"]+)",\s*production:\s*"([^"]+)",\s*fixture:\s*"([^"]+)"', body)


def tables(root):
    """Every list of editions the repository keeps: the catalog, its pins, and the Python, Swift and Rust readers."""
    root = Path(root)
    pins = json.loads((root / PINS).read_text(encoding="utf-8"))
    packaged = root / PY_DATA / "profiles" / "catalog.json"
    return {
        "catalog": _rows((root / CATALOG).read_text(encoding="utf-8")) if (root / CATALOG).is_file() else [],
        "pins": [(r["label"], r["production"], r["fixture"]) for r in pins["profiles"]],
        "python": _rows(packaged.read_text(encoding="utf-8")) if packaged.is_file() else [],
        "swift": swift_editions((root / SWIFT_PROFILES).read_text(encoding="utf-8")),
        "rust": rust_editions((root / RUST_PROFILES).read_text(encoding="utf-8")),
    }


def table_problems(found):
    """One line per table that is not the catalog (same editions, same order, same hashes)."""
    return ["%s lists %s, the catalog lists %s" % (name, rows, found["catalog"])
            for name, rows in found.items() if name != "catalog" and rows != found["catalog"]]


def version_lists(root):
    """What `version` shows as `profiles`, per implementation: the frozen productions, then the live core's
    production unless it is the newest frozen edition. Each language reads its own live core."""
    root = Path(root)
    frozen = tables(root)

    def listing(rows, live):
        out = [production for _label, production, _fixture in rows]
        return out if out and out[-1] == live else out + [live]

    py_core = json.loads((root / PY_DATA / "core-manifest.json").read_text(encoding="utf-8"))
    return {
        "swift": listing(frozen["swift"], swift_live_production((root / SWIFT_PROFILES).read_text(encoding="utf-8"))),
        "rust": listing(frozen["rust"], manifest.production_profile(root)),
        "python": listing(frozen["python"], _json_hash(py_core, "production")),
    }


def hash_comparisons(text):
    """The lines of `text` that compare a profile's `.production` or `.fixture` hash with something."""
    receiver = r"[\w?&*()\[\]:]+(?:\.[\w?&*()\[\]:]+)*"   # something.production, never the implicit `.fixture`
    pattern = re.compile(r"(==|!=)\s*%s\.(production|fixture)\b|\.(production|fixture)\)?\s*(==|!=)" % receiver)
    return [line.strip() for line in text.splitlines() if pattern.search(line)]


def comparisons_outside(root, folders, suffix, owner):
    found = []
    for folder in folders:
        for path in sorted((Path(root) / folder).rglob("*" + suffix)):
            rel = path.relative_to(root).as_posix()
            if rel != owner:
                found += ["%s: %s" % (rel, line) for line in hash_comparisons(path.read_text(encoding="utf-8"))]
    return found


def write_tree(root, editions=(), swift=None, rust=None, python=None, pins=None, current=None):
    """A throwaway repository holding only what the table guards read, consistent unless a drift is given."""
    root = Path(root)
    core_bytes = {rel: ("core file %s\n" % rel).encode() for rel in manifest.CORE_FILES}
    for rel, raw in core_bytes.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(raw)
    core = {rel: manifest.hashstr(raw) for rel, raw in core_bytes.items()}
    now = manifest.production_profile(root) if current is None else current
    rows = [{"label": l, "production": p, "fixture": f, "bundle": "ub", "tag": "t-" + l} for l, p, f in editions]

    def swift_text():
        live = "".join('        "%s": "%s",\n' % kv for kv in sorted(core.items()))
        blocks = "".join('    // handsal:edition begin %s\n    FrozenEdition(\n        label: "%s",\n        production: "%s",\n'
                         '        fixture: "%s",\n        registryJSON: #"""\n{"label": "x", "production": "y"}\n"""#),\n'
                         '    // handsal:edition end %s\n' % (l, l, p, f, l) for l, p, f in (editions if swift is None else swift))
        return ("    static let coreManifest: [String: String] = [\n" + live + "    ]\n    // handsal:editions begin\n"
                + blocks + "    // handsal:editions end\n")

    def rust_text():
        body = "".join('    FrozenRow { label: "%s", production: "%s", fixture: "%s", manifest: b"", registry: b"", kids: b"" },\n'
                       % (l, p, f) for l, p, f in (editions if rust is None else rust))
        return "pub const VERSIONS: &[FrozenRow<'static>] = &[\n" + body + "];\n"

    files = {
        CATALOG: json.dumps(rows),
        PINS: json.dumps({"production_profile": now, "profiles": [{"label": l, "production": p, "fixture": f}
                                                                  for l, p, f in (editions if pins is None else pins)]}),
        SWIFT_PROFILES: swift_text(), RUST_PROFILES: rust_text(),
        PY_DATA + "/core-manifest.json": json.dumps(core),
        PY_DATA + "/profiles/catalog.json": json.dumps([dict(r) for r in rows] if python is None else
                                                       [{"label": l, "production": p, "fixture": f, "bundle": "ub", "tag": "t"}
                                                        for l, p, f in python]),
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return core


TWO = [("edition-1", "uP1", "uF1"), ("edition-2", "uP2", "uF2")]


class EditionTables(unittest.TestCase):
    """GP-22 S5, GP-23 S3, SG-02 S3. Every guard is seen red against a drift planted in a throwaway tree."""

    def setUp(self):
        import shutil
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_the_three_tables_list_the_same_editions_in_the_same_order(self):
        """GP-22 S5: Python, Swift and Rust agree with the catalog, which equals the pins `repin.py` wrote."""
        found = tables(ROOT)
        self.assertEqual(table_problems(found), [])
        self.assertEqual(found["swift"], found["catalog"])

    def test_a_consistent_throwaway_tree_has_no_table_problem(self):
        write_tree(self.tmp, TWO)
        self.assertEqual(table_problems(tables(self.tmp)), [])
        write_tree(self.tmp, [])
        self.assertEqual(table_problems(tables(self.tmp)), [])

    def test_a_drift_planted_in_any_table_is_seen(self):
        plants = {
            "a Swift block removed": dict(swift=TWO[:1]),
            "a Rust hash changed": dict(rust=[TWO[0], ("edition-2", "uP2", "uXX")]),
            "a Rust row removed": dict(rust=TWO[:1]),
            "the Swift rows swapped": dict(swift=[TWO[1], TWO[0]]),
            "a pins row missing": dict(pins=TWO[:1]),
            "the packaged catalog one behind": dict(python=TWO[:1]),
            "a fixture hash changed in Swift": dict(swift=[TWO[0], ("edition-2", "uP2", "uXX")]),
        }
        for what, plant in plants.items():
            with self.subTest(what):
                write_tree(self.tmp, TWO, **plant)
                self.assertNotEqual(table_problems(tables(self.tmp)), [])

    def test_a_registry_text_inside_a_block_is_not_taken_for_a_row(self):
        write_tree(self.tmp, TWO)
        self.assertEqual(len(tables(self.tmp)["swift"]), 2)

    def test_no_profile_hash_comparison_outside_the_swift_and_rust_profile_files(self):
        """GP-23 S3: one question about a hash, asked in one file per language."""
        self.assertEqual(comparisons_outside(ROOT, SWIFT_GUARDED, ".swift", SWIFT_PROFILES), [])
        self.assertEqual(comparisons_outside(ROOT, RUST_GUARDED, ".rs", RUST_PROFILES), [])
        self.assertTrue(hash_comparisons((ROOT / SWIFT_PROFILES).read_text(encoding="utf-8")), "the owner file asks the question")
        self.assertTrue(hash_comparisons((ROOT / RUST_PROFILES).read_text(encoding="utf-8")))

    def test_a_planted_hash_comparison_is_seen_and_a_kind_or_a_flag_is_not(self):
        planted = ["if profile == profiles.production { return }", "if hash != edition.fixture {", "x.production == y",
                   "if (match.edition.production == hash) {", "let same = doc.profile == Self::current().fixture;"]
        for line in planted:
            with self.subTest(line):
                self.assertTrue(hash_comparisons(line), line)
        for line in ("if match?.kind == .fixture { fail() }", "let fixture = match?.kind != .production", "Some(profile) => (profile.edition, profile.fixture),",
                     '"spec": .string(context.profiles.production)])', "let productionHashes = editions.map(\\.production)"):
            with self.subTest(line):
                self.assertEqual(hash_comparisons(line), [])
        for folder, suffix, owner, name in (("signer/apple/Sources/HandsalCore", ".swift", SWIFT_PROFILES, "Planted.swift"),
                                            ("signer/windows/core", ".rs", RUST_PROFILES, "planted.rs")):
            (self.tmp / folder).mkdir(parents=True, exist_ok=True)
            (self.tmp / folder / name).write_text("if hash == edition.production { }\n", encoding="utf-8")
            guarded = SWIFT_GUARDED if suffix == ".swift" else RUST_GUARDED
            self.assertEqual(len(comparisons_outside(self.tmp, guarded, suffix, owner)), 1, name)

    def test_the_signer_version_lists_the_checker_production_hashes(self):
        """SG-02 S3: the signer's `profiles` (Swift and Rust) are the checker's production hashes, the live core last.
        Red while a language still holds a core table that the files moved past: closed by the re-pin of T16.14."""
        lists = version_lists(ROOT)
        self.assertEqual(lists["swift"], lists["python"], "Swift table")
        self.assertEqual(lists["rust"], lists["python"], "Rust table")
        pins = json.loads((ROOT / PINS).read_text(encoding="utf-8"))
        self.assertEqual(lists["python"][-1], pins["production_profile"], "spec is the last member (SG-02)")

    def test_a_throwaway_tree_with_one_live_core_lists_it_once_and_the_newest_frozen_edition_is_not_repeated(self):
        core = write_tree(self.tmp, [])
        live = manifest.production_profile(self.tmp)
        self.assertEqual(version_lists(self.tmp), {"swift": [live], "rust": [live], "python": [live]})
        write_tree(self.tmp, [("edition-1", live, "uF")])
        self.assertEqual(version_lists(self.tmp), {"swift": [live], "rust": [live], "python": [live]})
        self.assertEqual(core, json.loads((self.tmp / PY_DATA / "core-manifest.json").read_text()))

    def test_a_drift_planted_in_a_language_live_table_or_list_is_seen(self):
        write_tree(self.tmp, [("edition-1", "uP1", "uF1")])
        base = version_lists(self.tmp)
        self.assertEqual(base["swift"], base["python"])
        swift = self.tmp / SWIFT_PROFILES
        swift.write_text(re.sub(r'("spec/registry.json": ")u[^"]+', r"\1uPLANTED", swift.read_text()), encoding="utf-8")
        self.assertNotEqual(version_lists(self.tmp)["swift"], version_lists(self.tmp)["python"])
        write_tree(self.tmp, [("edition-1", "uP1", "uF1")], rust=[])
        lists = version_lists(self.tmp)
        self.assertNotEqual(lists["rust"], lists["python"])


if __name__ == "__main__":
    unittest.main()
