"""The re-pin tool (CF-01): one owner for the pins that must stay.

Expected values are computed here with hashlib and json only, a different path from the tool's
openssl calls, so a tool that agreed with itself would still fail.
"""
import base64
import contextlib
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import manifest  # noqa: E402
import repin  # noqa: E402


def hashstr(raw):
    digest = b"\x12\x20" + hashlib.sha256(raw).digest()
    return "u" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


CORE = {
    "conformance/CONTRACT.md": b"contract\n",
    "conformance/fixtures/fixture-kids.json": b'["k1"]\n',
    "conformance/fixtures/keys.json": b'{"alice":"x"}\n',
    "spec/profile-checks.md": b"# profile, checks\n",
    "spec/profile-display.md": b"# profile, display\n",
    "spec/profile-interfaces.md": b"# profile, part 2\n",
    "spec/profile-part3.md": b"# profile, part 3\n",
    "spec/profile.md": b"# profile\n",
    "spec/registry.json": b'{"methods":[]}\n',
}
SWIFT = """public struct Profiles {
    public static let coreManifest: [String: String] = [
        "conformance/CONTRACT.md": "old",
        "conformance/fixtures/fixture-kids.json": "old",
        "conformance/fixtures/keys.json": "old",
        "spec/profile-checks.md": "old",
        "spec/profile-display.md": "old",
        "spec/profile-interfaces.md": "old",
        "spec/profile-part3.md": "old",
        "spec/profile.md": "old",
        "spec/registry.json": "old",
    ]
}
"""


SWIFT_EDITIONS = SWIFT.replace("    ]\n}\n", """    ]

    // handsal:editions begin
    // handsal:editions end
}
""")


def expected(core_bytes):
    core = {rel: hashstr(raw) for rel, raw in core_bytes.items()}
    fixture = hashstr(jcs({"core": core, "kind": "fixture"}))
    org = {"devices": [], "org": None, "profile": fixture}
    wit = {"devices": [], "org": None, "policy": "relay", "profile": fixture}
    pins = {"fixture_profile": fixture, "org_id": hashstr(jcs(org)),
            "production_profile": hashstr(jcs({"core": core, "kind": "production"})),
            "profiles": [],
            "wit_org_id": hashstr(jcs(wit))}
    return core, pins, org, wit


def make_tree(root, core_bytes=CORE):
    root = Path(root)
    core, pins, org, wit = expected(core_bytes)
    for rel, raw in core_bytes.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(raw)
    for rel, doc in ((repin.ORG_VECTOR, org), (repin.WIT_ORG_VECTOR, wit)):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(json.dumps({"input": {"lineage": [{"doc": doc, "sigs": []}]}}), encoding="utf-8")
    (root / repin.SWIFT).parent.mkdir(parents=True, exist_ok=True)
    (root / repin.SWIFT).write_text(SWIFT, encoding="utf-8")
    (root / repin.CHECKER_CORE).parent.mkdir(parents=True, exist_ok=True)
    (root / repin.CHECKER_CORE).write_text(json.dumps(core), encoding="utf-8")
    (root / repin.PINS).write_text("{}\n", encoding="utf-8")
    return core, pins


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.core, self.pins = make_tree(self.tmp)

    def run_tool(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = repin.main(list(argv) + ["--root", str(self.tmp)])
        return code, out.getvalue()

    def test_compute_matches_hashlib(self):
        pins, core = repin.compute(self.tmp)
        self.assertEqual(core, self.core)
        self.assertEqual(pins, self.pins)

    def test_write_sets_the_pins_file_and_the_swift_rows_and_nothing_else(self):
        before = (self.tmp / repin.CHECKER_CORE).read_bytes()
        self.assertEqual(self.run_tool("--write")[0], 0)
        self.assertEqual((self.tmp / repin.PINS).read_text(), json.dumps(self.pins, indent=2, sort_keys=True) + "\n")
        swift = (self.tmp / repin.SWIFT).read_text()
        for rel, digest in self.core.items():
            self.assertIn('"%s": "%s",' % (rel, digest), swift)
        self.assertIn("public static let coreManifest", swift)
        self.assertEqual((self.tmp / repin.CHECKER_CORE).read_bytes(), before)

    def test_check_is_clean_after_write_and_reports_each_drift(self):
        self.run_tool("--write")
        self.assertEqual(self.run_tool("--check"), (0, "pins ok\n"))
        (self.tmp / "spec/profile.md").write_bytes(b"# profile, edited\n")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 2, text)   # the vectors still name the old profile: regenerate first

    def test_check_names_the_file_that_drifted(self):
        self.run_tool("--write")
        (self.tmp / repin.PINS).write_text("{}\n")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 1)
        self.assertIn("drift: " + repin.PINS, text)
        self.assertNotIn(repin.SWIFT, text)

    def test_a_stale_checker_copy_points_to_sync_core(self):
        self.run_tool("--write")
        (self.tmp / repin.CHECKER_CORE).write_text("{}")
        code, text = self.run_tool("--check")
        self.assertEqual(code, 1)
        self.assertIn("sync_core.py", text)

    def test_a_stale_swift_table_is_a_drift(self):
        self.run_tool("--write")
        (self.tmp / repin.SWIFT).write_text(SWIFT)
        code, text = self.run_tool("--check")
        self.assertEqual((code, repin.SWIFT in text), (1, True))

    def test_vectors_that_name_another_profile_are_refused(self):
        doc = json.loads((self.tmp / repin.ORG_VECTOR).read_text())
        doc["input"]["lineage"][0]["doc"]["profile"] = "uEiOld"
        (self.tmp / repin.ORG_VECTOR).write_text(json.dumps(doc))
        code, _ = self.run_tool("--write")
        self.assertEqual(code, 2)
        self.assertEqual((self.tmp / repin.PINS).read_text(), "{}\n")

    def test_a_missing_core_file_is_exit_two(self):
        (self.tmp / "spec/profile.md").unlink()
        self.assertEqual(self.run_tool("--check")[0], 2)

    def test_a_swift_table_with_an_unknown_row_is_refused(self):
        (self.tmp / repin.SWIFT).write_text(SWIFT.replace('        "spec/registry.json": "old",\n',
                                                          '        "spec/registry.json": "old",\n        "spec/other.md": "old",\n'))
        self.assertEqual(self.run_tool("--write")[0], 2)

    def test_the_tool_needs_a_mode(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            repin.main(["--root", str(self.tmp)])


def snapshot(root):
    """{relative path: bytes} of every file under `root`: the whole tree, to prove a refusal wrote nothing."""
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


CORE_B = dict(CORE, **{"spec/profile.md": b"# profile, the second edition\n"})


def freeze_by_hand(root, label, tag, core_bytes=CORE):
    """An edition frozen without the tool: the three files, hashed here with hashlib, and the row appended."""
    root = Path(root)
    core, pins, _org, _wit = expected(core_bytes)
    folder = root / "profiles" / label
    for rel, raw in (("core-manifest.json", (json.dumps(core, indent=2, sort_keys=True) + "\n").encode()),
                     ("spec/registry.json", core_bytes["spec/registry.json"]),
                     ("conformance/fixtures/fixture-kids.json", core_bytes["conformance/fixtures/fixture-kids.json"])):
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_bytes(raw)
    catalog = root / "profiles" / "catalog.json"
    rows = json.loads(catalog.read_text()) if catalog.exists() else []
    rows.append({"label": label, "production": pins["production_profile"], "fixture": pins["fixture_profile"],
                 "bundle": hashstr(b"bundle " + label.encode()), "tag": tag})
    catalog.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return rows[-1]


class CatalogFixture:
    """A tree with one hand-frozen edition older than the current core; shared with `test_core_files.py`, which
    holds the test CF-01 S4 names."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.core, self.pins = make_tree(self.tmp)
        (self.tmp / repin.SWIFT).write_text(SWIFT_EDITIONS, encoding="utf-8")
        self.row1 = freeze_by_hand(self.tmp, "edition-1", "v1", CORE_B)

    def run_tool(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = repin.main(list(argv) + ["--root", str(self.tmp)])
        return code, out.getvalue() + err.getvalue()

    def blocks(self):
        text = (self.tmp / repin.SWIFT).read_text()
        return re.findall(r"^    // handsal:edition begin (\S+)$", text, re.M)


class Catalog(CatalogFixture, unittest.TestCase):
    """`--write` with a catalog: the current edition only, the `profiles` pins, one marked Swift block per edition."""

    def test_a_second_catalog_row_appends_a_block_and_leaves_the_first_block_as_it_was(self):
        self.run_tool("--write")
        first = (self.tmp / repin.SWIFT).read_text()
        freeze_by_hand(self.tmp, "edition-2", "v2", CORE)
        self.assertEqual(self.run_tool("--write")[0], 0)
        second = (self.tmp / repin.SWIFT).read_text()
        self.assertEqual(self.blocks(), ["edition-1", "edition-2"])
        begin = first.index("    // handsal:edition begin edition-1")
        end = first.index("    // handsal:edition end edition-1") + len("    // handsal:edition end edition-1\n")
        self.assertIn(first[begin:end], second)
        pins = json.loads((self.tmp / repin.PINS).read_text())
        self.assertEqual([r["label"] for r in pins["profiles"]], ["edition-1", "edition-2"])

    def test_an_attempted_edit_of_an_existing_row_exits_non_zero_and_writes_nothing(self):
        self.run_tool("--write")
        base = snapshot(self.tmp)
        catalog = self.tmp / "profiles" / "catalog.json"
        rows = json.loads(catalog.read_text())
        attempts = {
            "a row whose production hash was edited": lambda: catalog.write_text(
                json.dumps([dict(rows[0], production=hashstr(b"other"))], indent=2) + "\n"),
            "a row whose fixture hash was edited": lambda: catalog.write_text(
                json.dumps([dict(rows[0], fixture=hashstr(b"other"))], indent=2) + "\n"),
            "a frozen manifest that was edited": lambda: (self.tmp / "profiles/edition-1/core-manifest.json").write_text(
                (self.tmp / "profiles/edition-1/core-manifest.json").read_text().replace("u", "v", 1)),
            "a frozen registry that was edited": lambda: (self.tmp / "profiles/edition-1/spec/registry.json").write_bytes(b"{}\n"),
            "a frozen kid file that was edited": lambda: (self.tmp / "profiles/edition-1/conformance/fixtures/fixture-kids.json").write_bytes(b'["k2"]\n'),
            "a Swift block that was edited": lambda: (self.tmp / repin.SWIFT).write_text(
                (self.tmp / repin.SWIFT).read_text().replace('"k1",', '"k9",')),
            "a catalog that lost its row while the Swift block stays": lambda: catalog.write_text("[]\n"),
        }
        for what, attempt in attempts.items():
            with self.subTest(what):
                attempt()
                edited = snapshot(self.tmp)
                code, text = self.run_tool("--write")
                self.assertEqual(code, 2, text)
                self.assertEqual(snapshot(self.tmp), edited)
                for rel, raw in base.items():
                    (self.tmp / rel).write_bytes(raw)

    def test_a_catalog_row_that_is_not_closed_or_repeats_is_refused(self):
        catalog = self.tmp / "profiles" / "catalog.json"
        row = json.loads(catalog.read_text())[0]
        for what, rows in {"a missing key": [{k: v for k, v in row.items() if k != "tag"}],
                           "an extra key": [dict(row, commit="abc")],
                           "a repeated label": [row, dict(row, tag="v2")],
                           "a repeated tag": [row, dict(row, label="edition-2")],
                           "an unsafe label": [dict(row, label="../x")],
                           "not a list": {"rows": [row]}}.items():
            with self.subTest(what):
                catalog.write_text(json.dumps(rows), encoding="utf-8")
                self.assertEqual(self.run_tool("--write")[0], 2)

    def test_write_is_byte_stable(self):
        self.run_tool("--write")
        once = snapshot(self.tmp)
        self.assertEqual(self.run_tool("--write")[0], 0)
        self.assertEqual(snapshot(self.tmp), once)

    def test_check_is_clean_after_write_and_names_the_swift_file_when_a_block_is_missing(self):
        self.run_tool("--write")
        self.assertEqual(self.run_tool("--check")[0], 0)
        (self.tmp / repin.SWIFT).write_text(SWIFT_EDITIONS)
        code, text = self.run_tool("--check")
        self.assertEqual((code, repin.SWIFT in text), (1, True))

    def test_a_catalog_with_no_markers_in_the_swift_file_is_refused(self):
        (self.tmp / repin.SWIFT).write_text(SWIFT)
        before = snapshot(self.tmp)
        self.assertEqual(self.run_tool("--write")[0], 2)
        self.assertEqual(snapshot(self.tmp), before)

    def test_a_block_row_is_never_taken_for_a_live_table_row(self):
        """The live table is rewritten to the current hashes; a frozen block row keeps its own."""
        self.run_tool("--write")
        (self.tmp / "spec/profile.md").write_bytes(b"# profile, current moved on\n")
        core_now = {rel: hashstr(raw) for rel, raw in dict(CORE, **{"spec/profile.md": b"# profile, current moved on\n"}).items()}
        swift = repin.swift_text((self.tmp / repin.SWIFT).read_text(), core_now, repin.edition_blocks(self.tmp))
        self.assertIn('        "spec/profile.md": "%s",' % core_now["spec/profile.md"], swift)
        self.assertIn(hashstr(CORE_B["spec/profile.md"]), swift)


class Freeze(unittest.TestCase):
    """`--freeze <label> --tag <tag>`: the first edition of the catalog, and every later one, from the current tree."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.core, self.pins = make_tree(self.tmp)
        (self.tmp / repin.SWIFT).write_text(SWIFT_EDITIONS, encoding="utf-8")
        (self.tmp / "conformance" / "vectors" / "jcs.a.json").write_text('{"name":"jcs/a"}\n', encoding="utf-8")
        repin.main(["--write", "--root", str(self.tmp)])
        self.before = snapshot(self.tmp)

    def run_tool(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = repin.main(list(argv) + ["--root", str(self.tmp)])
        return code, out.getvalue() + err.getvalue()

    def freeze(self, label="edition-1", tag="v1.0.0"):
        return self.run_tool("--freeze", label, "--tag", tag)

    def test_freeze_creates_the_directory_and_the_row_from_the_current_tree(self):
        bundle = manifest.bundle_hash(self.tmp)
        self.assertEqual(self.freeze()[0], 0)
        folder = self.tmp / "profiles" / "edition-1"
        self.assertEqual(json.loads((folder / "core-manifest.json").read_text()), self.core)
        self.assertEqual((folder / "spec/registry.json").read_bytes(), CORE["spec/registry.json"])
        self.assertEqual((folder / "conformance/fixtures/fixture-kids.json").read_bytes(),
                         CORE["conformance/fixtures/fixture-kids.json"])
        self.assertEqual(sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()),
                         ["conformance/fixtures/fixture-kids.json", "core-manifest.json", "spec/registry.json"])
        rows = json.loads((self.tmp / "profiles" / "catalog.json").read_text())
        self.assertEqual(rows, [{"label": "edition-1", "production": self.pins["production_profile"],
                                 "fixture": self.pins["fixture_profile"], "bundle": bundle, "tag": "v1.0.0"}])
        self.assertEqual(list(rows[0]), ["label", "production", "fixture", "bundle", "tag"])

    def test_freeze_leaves_the_bundle_hash_unchanged_by_the_write_of_profiles(self):
        """The row has no commit and the bundle does not cover `profiles/`, so the row is no fixed point."""
        before = manifest.bundle_hash(self.tmp)
        self.freeze()
        self.assertEqual(manifest.bundle_hash(self.tmp), before)
        self.assertEqual(json.loads((self.tmp / "profiles" / "catalog.json").read_text())[0]["bundle"], before)
        manifest.write_bundle_manifest(self.tmp)
        self.assertFalse([f for f in json.loads((self.tmp / manifest.BUNDLE_FILE).read_text())["files"]
                          if f.startswith("profiles/")])

    def test_freeze_writes_the_pins_profiles_key_and_the_swift_block_and_no_pinned_value_moves(self):
        self.freeze()
        pins = json.loads((self.tmp / repin.PINS).read_text())
        base = json.loads(self.before[repin.PINS].decode())
        self.assertEqual({k: v for k, v in pins.items() if k != "profiles"}, {k: v for k, v in base.items() if k != "profiles"})
        self.assertEqual(pins["profiles"], [{"label": "edition-1", "production": self.pins["production_profile"],
                                             "fixture": self.pins["fixture_profile"]}])
        swift = (self.tmp / repin.SWIFT).read_text()
        self.assertIn("// handsal:edition begin edition-1", swift)
        self.assertEqual(self.run_tool("--check")[0], 0)

    def test_freeze_touches_only_the_catalog_the_frozen_directory_the_pins_and_the_swift_file(self):
        self.freeze()
        after = snapshot(self.tmp)
        changed = {k for k in set(after) | set(self.before) if after.get(k) != self.before.get(k)}
        self.assertEqual(changed, {"profiles/catalog.json", "profiles/edition-1/core-manifest.json",
                                   "profiles/edition-1/spec/registry.json",
                                   "profiles/edition-1/conformance/fixtures/fixture-kids.json",
                                   repin.PINS, repin.SWIFT})

    def test_freeze_refuses_a_bad_label_or_tag_and_writes_nothing(self):
        for label, tag in (("", "v1"), ("edition-1", ""), ("../x", "v1"), ("a/b", "v1"), (".hidden", "v1"),
                           ("edition 1", "v1"), ("edition-1", "  ")):
            with self.subTest(label=label, tag=tag):
                self.assertEqual(self.freeze(label, tag)[0], 2)
                self.assertEqual(snapshot(self.tmp), self.before)

    def test_freeze_refuses_a_missing_tag_argument(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.run_tool("--freeze", "edition-1")

    def test_freeze_refuses_a_repeated_label_or_tag_and_a_core_that_is_already_frozen(self):
        self.assertEqual(self.freeze("edition-1", "v1")[0], 0)
        base = snapshot(self.tmp)
        # the core did not move since the freeze: a second edition of the same bytes is no new edition
        self.assertEqual(self.freeze("edition-2", "v2")[0], 2)
        self.assertEqual(snapshot(self.tmp), base)
        # a core that moved is a new edition, but not under a label or a tag already used
        (self.tmp / "spec/profile.md").write_bytes(b"# profile, edition two\n")
        core = dict(CORE, **{"spec/profile.md": b"# profile, edition two\n"})
        fixture = expected(core)[1]["fixture_profile"]
        for rel in (repin.ORG_VECTOR, repin.WIT_ORG_VECTOR):
            doc = json.loads((self.tmp / rel).read_text())
            doc["input"]["lineage"][0]["doc"]["profile"] = fixture
            (self.tmp / rel).write_text(json.dumps(doc))
        self.assertEqual(repin.main(["--write", "--root", str(self.tmp)]), 0)
        (self.tmp / repin.CHECKER_CORE).write_text(json.dumps({rel: hashstr(raw) for rel, raw in core.items()}))
        base = snapshot(self.tmp)
        self.assertEqual(self.freeze("edition-1", "v2")[0], 2)   # the label is taken
        self.assertEqual(self.freeze("edition-2", "v1")[0], 2)   # the tag is taken
        self.assertEqual(snapshot(self.tmp), base)
        self.assertEqual(self.freeze("edition-2", "v2")[0], 0)
        self.assertEqual([r["label"] for r in json.loads((self.tmp / "profiles/catalog.json").read_text())],
                         ["edition-1", "edition-2"])

    def test_freeze_refuses_a_tree_whose_pins_are_not_current(self):
        (self.tmp / repin.PINS).write_text("{}\n")
        before = snapshot(self.tmp)
        self.assertEqual(self.freeze()[0], 2)
        self.assertEqual(snapshot(self.tmp), before)

    def test_a_bundle_that_moves_when_profiles_is_written_stops_the_freeze_and_leaves_the_tree_as_it_was(self):
        real = repin.MANIFEST.bundle_hash
        calls = []

        def moving(root):
            calls.append(root)
            return real(root) if len(calls) == 1 else hashstr(b"the bundle now covers profiles")

        repin.MANIFEST.bundle_hash = moving
        self.addCleanup(setattr, repin.MANIFEST, "bundle_hash", real)
        code, text = self.freeze()
        self.assertEqual(code, 2, text)
        self.assertIn("bundle", text)
        self.assertEqual(snapshot(self.tmp), self.before)
        self.assertFalse((self.tmp / "profiles").exists())


class RealTree(unittest.TestCase):
    def test_the_pins_are_what_the_files_give(self):
        """The one place a core edit turns red until `repin.py --write` and `sync_core.py` have run."""
        self.assertEqual(repin.drift(ROOT), [])

    def test_the_pins_file_holds_the_four_values_and_the_catalog_pins_and_nothing_else(self):
        pins = json.loads((ROOT / repin.PINS).read_text(encoding="utf-8"))
        self.assertEqual(sorted(pins), ["fixture_profile", "org_id", "production_profile", "profiles", "wit_org_id"])
        self.assertEqual(len({v for k, v in pins.items() if k != "profiles"}), 4)
        self.assertIsInstance(pins["profiles"], list)
        self.assertEqual(len(pins["profiles"]), len(json.loads((ROOT / "profiles" / "catalog.json").read_text()))
                         if (ROOT / "profiles" / "catalog.json").exists() else 0)


if __name__ == "__main__":
    unittest.main()
